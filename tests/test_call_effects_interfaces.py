"""The effects profile must survive every public boundary without silent fallback."""
from dataclasses import replace
from pathlib import Path
import sys
import runpy
import pytest

MODEL='bounded-direct-effects-calls.v1'


@pytest.mark.parametrize('command,flag,handler',[
    ('ghidra-decompile','--call-model','cmd_ghidra_decompile'),
    ('universal','--native-call-model','cmd_universal')])
def test_real_cli_parser_accepts_effects_profile(monkeypatch,tmp_path,command,flag,handler):
    import megazord
    seen=[]
    monkeypatch.setattr(megazord,handler,lambda args:seen.append(args) or 0)
    options=[command,str(tmp_path/'owned.dll'),flag,MODEL]
    if command=='universal':options+=['--out',str(tmp_path/'case'),'--native-reconstruction','--native-memory-model','bounded-bytes.v2']
    else:options+=['--memory-model','bounded-bytes.v2','--reconstruct-function','caller']
    monkeypatch.setattr(sys,'argv',['megazord',*options])
    assert megazord.main()==0 and len(seen)==1
    assert getattr(seen[0],'native_call_model' if command=='universal' else 'call_model')==MODEL


def test_mcp_schema_exposes_both_distinct_call_profiles():
    from aether_re.mcp_server import TOOLS
    tool=next(t for t in TOOLS if t['name']=='aether_ghidra_decompile')
    assert tool['inputSchema']['properties']['call_model']['enum']==['bounded-direct-pure-calls.v1',MODEL,'bounded-ms-x64-stack-values.v1']


def test_universal_unsupported_profile_retains_requested_call_model_without_worker(tmp_path,monkeypatch):
    import aether_re.ghidra_headless_bridge as bridge
    from aether_re.pipeline import CasePolicy,run_universal_case
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',lambda:pytest.fail('unsupported profile started native worker'))
    source=tmp_path/'owned.wasm';source.write_bytes(b'\0asm\x01\0\0\0')
    policy=replace(CasePolicy.static_only(),request_native_reconstruction=True,
        native_memory_model='bounded-bytes.v2',native_call_model=MODEL)
    report=run_universal_case(source,tmp_path/'case',policy).to_dict()
    assert report['native_reconstruction']['status']=='unsupported_profile'
    assert report['native_reconstruction']['requested_call_model']==MODEL
    assert report['certification_status']=='abstained'


def test_debug_return_adapter_retains_effect_contract_and_three_runtime_parameters(tmp_path):
    import aether_re.pdb_dia as dia
    fixture=runpy.run_path(str(Path(__file__).with_name('test_call_effects.py')))
    export=fixture['memory_export'](tmp_path)
    typed=runpy.run_path(str(Path(__file__).with_name('test_pdb_dia_contract.py')))['typed_payload']()
    typed.update(binary_sha256=export.target_sha256,pdb_sha256='c'*64,helper_sha256='d'*64,dia_dll_sha256='e'*64)
    typed['binding']=dict(status='verified',target_identity_bound=True,target_types_bound=True,
        binary_sha256=export.target_sha256,guid=typed['guid'],age=typed['age'])
    typed['validated_payload_sha256']=dia._payload_digest(typed)
    typed['validated_report_sha256']=dia._report_digest(typed)
    report=export.select_reconstruction('caller',debug_report=typed,memory_model='bounded-bytes.v2',call_model=MODEL)
    adapter=report['debug_return_adapter']
    assert adapter['effect_model']==report['effect_model']
    assert [p['name'] for p in adapter['runtime_parameters']]==['aether_memory','aether_calls','aether_effects']
    assert adapter['call_model']['schema']==MODEL and adapter['binary_equivalence_proved'] is False


def effect_bundle(tmp_path):
    from aether_re.intake import IntakeRequest,prepare_case
    from aether_re.kernel_contracts import AuthorizationPolicy,IntakeLimits
    from aether_re.native_memory_custody import publish_memory_derivation
    fixture=runpy.run_path(str(Path(__file__).with_name('test_call_effects.py')))
    export=fixture['memory_export'](tmp_path)
    auth=AuthorizationPolicy.from_dict(dict(schema='authorization-policy.v1',basis='owner',principal='owned-test',scope=['static-analysis']))
    parent=prepare_case(IntakeRequest(Path(export.binary_path),tmp_path/'input-map',auth,IntakeLimits(),False)).manifest_path.parent
    bundle=tmp_path/'map';publish_memory_derivation(parent,bundle,profile='pe',space_id=0)
    return export,bundle


def test_effects_profile_retains_verified_static_memory_binding_without_process_claim(tmp_path):
    export,bundle=effect_bundle(tmp_path)
    report=export.select_reconstruction('caller',memory_model='bounded-bytes.v2',call_model=MODEL,memory_derivation=bundle)
    assert report['status']=='complete'
    bound=report['memory_binding'];assert bound['status']=='bound' and bound['runtime_model']=='bounded-bytes.v2'
    assert bound['context']['target_sha256']==export.target_sha256
    assert bound['process_snapshot_proved'] is bound['binary_equivalence_proved'] is False
    assert len(report['runtime_parameters'])==3 and report['effect_model']['schema']=='bounded-operation-start-trace.v1'


def test_universal_effects_profile_reuses_one_verified_memory_admission(tmp_path,monkeypatch):
    import aether_re.ghidra_headless_bridge as bridge
    import aether_re.native_memory_custody as custody
    from aether_re.pipeline import CasePolicy,run_universal_case
    export,bundle=effect_bundle(tmp_path);source=Path(export.binary_path);calls=[]
    class Backend:
        def decompile_binary(self,path,**options):
            calls.append(path);export.binary_path=str(path);return export
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    original=custody.admit_memory_context;admissions=[]
    def admit(path):admissions.append(path);return original(path)
    monkeypatch.setattr(custody,'admit_memory_context',admit)
    policy=replace(CasePolicy.static_only(),request_native_reconstruction=True,native_memory_model='bounded-bytes.v2',
        native_call_model=MODEL,native_memory_derivation=str(bundle))
    report=run_universal_case(source,tmp_path/'case',policy).to_dict();native=report['native_reconstruction']
    assert len(admissions)==len(calls)==1 and native['attempted_functions']==native['reconstructed_functions']==2
    for item in native['functions'].values():
        reconstructed=item['reconstruction']
        assert len(reconstructed['runtime_parameters'])==3
        assert reconstructed['memory_binding']['status']=='bound'
        assert reconstructed['memory_binding']['process_snapshot_proved'] is False
    assert report['certification_status']=='abstained'
