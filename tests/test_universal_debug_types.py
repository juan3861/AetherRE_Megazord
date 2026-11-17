"""Debug return evidence is optional and cannot replace raw IR observations."""
import hashlib
import json
import runpy
from dataclasses import replace
from pathlib import Path

import pytest

import aether_re.pipeline as pipeline
import aether_re.pdb_dia as dia
import aether_re.ghidra_headless_bridge as bridge


def owned_case(tmp_path, monkeypatch, raw_bytes=None):
    raw=bytearray(256);raw[:2]=b'MZ';raw[60:64]=(128).to_bytes(4,'little');raw[128:132]=b'PE\0\0'
    if raw_bytes is not None:raw=bytearray(raw_bytes)
    target=tmp_path/'own.exe';target.write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
    fixture=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))
    typed=runpy.run_path(str(Path(__file__).with_name('test_pdb_dia_contract.py')))['typed_payload']()
    functions={}
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    for index,name in enumerate(('narrow','wide')):
        address='ram:'+format(0x401000+index*16,'x')
        data=json.loads(json.dumps(fixture['scalar_ir']()).replace('ram:401000',address))
        data['target_sha256']=digest
        checked=analyze_high_pcode(data,expected_target=digest,expected_address=address,evidence_sha256='b'*64)
        identity=digest+'!'+address
        functions[identity]=bridge.GhidraFunctionInfo(name,address,True,2,'int',function_id=identity,
            pcode_ir=data,ir_analysis=checked['summary'],normalized_ir=checked['graph'])
    exported=bridge.GhidraDecompilationResult(str(target),True,2,2,functions,'','',0,target_sha256=digest,status='complete')
    backend_calls=[]
    class Backend:
        def decompile_binary(self,path,**kwargs):
            backend_calls.append(Path(path));assert Path(path)!=target
            return exported
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    typed['symbols'].append(dict(typed['symbols'][0],name='wide',rva=0x1010,sym_index=11))
    typed.update(count=2,type_edges=4,binary_sha256=digest,pdb_sha256='c'*64,helper_sha256='d'*64,dia_dll_sha256='e'*64)
    typed['binding']=dict(status='verified',target_identity_bound=True,target_types_bound=True,binary_sha256=digest,guid='{12345678-1234-5678-1234-567812345678}',age=1)
    typed['type_coverage']=dict(status='observed_complete',functions_total=2,functions_with_signature=2,types=3)
    typed['validated_payload_sha256']=dia._payload_digest(typed);typed['validated_report_sha256']=dia._report_digest(typed)
    extracts=[]
    def extract(path,**kwargs):extracts.append((path,kwargs));return typed
    monkeypatch.setattr(dia,'extract_pdb_symbols',extract)
    options={key:tmp_path/name for key,name in [('debug_pdb','own.pdb'),('dia_helper','helper.exe'),('dia_dll','dia.dll')]}
    for p in options.values():p.write_bytes(b'own explicit analysis input')
    return target,exported,typed,extracts,backend_calls,options


@pytest.mark.parametrize('options',[
    dict(debug_pdb='own.pdb'),dict(debug_pdb='own.pdb',dia_helper='helper.exe'),
    dict(debug_pdb='',dia_helper='helper.exe',dia_dll='dia.dll'),
    dict(debug_pdb=True,dia_helper='helper.exe',dia_dll='dia.dll'),
    dict(debug_pdb='own.pdb',dia_helper='helper.exe',dia_dll='dia.dll',request_native_reconstruction=False),
])
def test_invalid_debug_policy_is_refused_before_intake(tmp_path,monkeypatch,options):
    policy=replace(pipeline.CasePolicy.static_only(),**dict({'request_native_reconstruction':True},**options))
    monkeypatch.setattr(pipeline,'prepare_case',lambda *a:pytest.fail('invalid debug policy reached intake'))
    with pytest.raises(ValueError,match='debug'):
        pipeline.run_universal_case(tmp_path/'absent.exe',tmp_path/'case',policy)


def test_universal_extracts_debug_once_over_intake_and_preserves_two_observations(tmp_path,monkeypatch):
    target,exported,typed,extracts,backend,options=owned_case(tmp_path,monkeypatch)
    policy=replace(pipeline.CasePolicy.static_only(),request_native_reconstruction=True,**options)
    out=tmp_path/'case';report=pipeline.run_universal_case(target,out,policy).to_dict();native=report['native_reconstruction']
    assert len(extracts)==1 and extracts[0][1]['binary_path']==backend[0] and backend[0]!=target
    assert native['debug_adapted_functions']==native['attempted_functions']==2
    assert native['debug_unavailable_functions']==0 and native['debug_types']['status']=='complete'
    assert native['status']=='complete' and report['certification_status']=='abstained'
    for item in native['functions'].values():
        r=item['reconstruction'];assert r['return_bits']==32 and r['debug_return_adapter']['contract']['return_bits']==8
        assert r['binary_equivalence_proved'] is False and r['debug_return_adapter']['abi_recovered'] is False
    artifact=out/'native_debug_types.json'
    assert json.loads(artifact.read_text(encoding='utf-8'))==typed
    assert native['debug_types']['report_sha256']==hashlib.sha256(artifact.read_bytes()).hexdigest()


@pytest.mark.parametrize('failure',['worker','mutation','wide_debug'])
def test_debug_failure_keeps_raw_ir_and_explicit_partial_counts(tmp_path,monkeypatch,failure):
    target,exported,typed,extracts,backend,options=owned_case(tmp_path,monkeypatch)
    if failure=='worker':typed.clear();typed.update(status='unavailable',code='helper_failed',count=0,symbols=[])
    elif failure=='mutation':typed['types'][1]['length']=8
    else:
        typed['types'][1]['length']=8
        typed['validated_payload_sha256']=dia._payload_digest(typed);typed['validated_report_sha256']=dia._report_digest(typed)
    report=pipeline.run_universal_case(target,tmp_path/'case',replace(pipeline.CasePolicy.static_only(),request_native_reconstruction=True,**options)).to_dict()
    native=report['native_reconstruction'];assert native['status']=='partial'
    assert native['reconstructed_functions']==native['debug_unavailable_functions']==2 and native['debug_adapted_functions']==0
    for item in native['functions'].values():
        r=item['reconstruction'];assert r['status']=='complete' and r['structured_c_source']
        assert r['debug_return_adapter']['status']=='unavailable'


def test_preobserved_debug_report_cannot_be_mixed_with_new_tools(tmp_path,monkeypatch):
    target,exported,typed,extracts,backend,options=owned_case(tmp_path,monkeypatch)
    identity=next(iter(exported.functions))
    with pytest.raises(ValueError,match='debug.*conflict'):
        exported.select_reconstruction(identity,debug_report=typed,**options)
    assert not extracts


def test_debug_report_publication_quota_keeps_raw_ir_available(tmp_path,monkeypatch):
    target,exported,typed,extracts,backend,options=owned_case(tmp_path,monkeypatch)
    monkeypatch.setattr(pipeline,'MAX_NATIVE_DEBUG_BYTES',32,raising=False)
    native=pipeline.run_universal_case(target,tmp_path/'case',replace(pipeline.CasePolicy.static_only(),request_native_reconstruction=True,**options)).to_dict()['native_reconstruction']
    assert native['reconstructed_functions']==2 and native['debug_adapted_functions']==0
    assert native['debug_types']['code']=='debug_report_output_budget'
    assert not (tmp_path/'case/native_debug_types.json').exists()


def test_cli_cannot_silently_ignore_debug_on_javascript_route(tmp_path,monkeypatch):
    from argparse import Namespace
    import megazord
    monkeypatch.setattr(megazord,'ReaStaticJavaScriptAdapter',lambda:pytest.fail('debug request reached JS backend'))
    with pytest.raises(ValueError,match='debug'):
        megazord.cmd_universal(Namespace(target=str(tmp_path/'app'),out=str(tmp_path/'case'),profile='js-electron',
            native_reconstruction=True,debug_pdb='own.pdb',dia_helper='helper.exe',dia_dll='dia.dll'))


def test_debug_evidence_cannot_overwrite_previous_publication(tmp_path,monkeypatch):
    target,exported,typed,extracts,backend,options=owned_case(tmp_path,monkeypatch)
    out=tmp_path/'case';out.mkdir();previous=out/'native_debug_types.json';previous.write_bytes(b'preserved evidence')
    with pytest.raises(ValueError,match='snapshot_destination_not_create_only'):
        pipeline.run_universal_case(target,out,replace(pipeline.CasePolicy.static_only(),request_native_reconstruction=True,**options))
    assert previous.read_bytes()==b'preserved evidence' and not backend


def test_debug_envelope_quota_counts_adapters_and_coverage(tmp_path,monkeypatch):
    target,exported,typed,extracts,backend,options=owned_case(tmp_path,monkeypatch)
    policy=replace(pipeline.CasePolicy.static_only(),request_native_reconstruction=True,**options)
    first=tmp_path/'first';pipeline.run_universal_case(target,first,policy)
    cap=(first/'native_reconstruction.json').stat().st_size-1
    monkeypatch.setattr(pipeline,'MAX_NATIVE_REPORT_BYTES',cap)
    second=tmp_path/'second';native=pipeline.run_universal_case(target,second,policy).to_dict()['native_reconstruction']
    assert native['truncated'] and native['attempted_functions']==native['debug_adapted_functions']==1
    assert native['debug_unavailable_functions']==0 and (second/'native_reconstruction.json').stat().st_size<=cap


@pytest.mark.parametrize('raw',[b'owned text without a native profile', b'\x7fELF'+bytes(252)])
def test_pdb_request_on_non_pe_remains_explicit_without_dia_worker(tmp_path,monkeypatch,raw):
    target,exported,typed,extracts,backend,options=owned_case(tmp_path,monkeypatch,raw)
    report=pipeline.run_universal_case(target,tmp_path/'case',replace(pipeline.CasePolicy.static_only(),request_native_reconstruction=True,**options)).to_dict()
    assert report['profile']!='native-pe'
    assert not extracts
    native=report['native_reconstruction']
    assert native['debug_types']['status']=='unavailable' and native['debug_types']['code']=='debug_types_require_native_pe'
