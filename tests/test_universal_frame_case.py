import hashlib,json,runpy
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import pytest
from aether_re.pipeline import CasePolicy,run_universal_case


def case_inputs(tmp_path,monkeypatch,refused=False,backend_success=True):
    import aether_re.ghidra_headless_bridge as bridge
    data=runpy.run_path(str(Path(__file__).with_name('test_pe_memory_map.py')))['fixture']()
    target=tmp_path/'own.dll';target.write_bytes(data);digest=hashlib.sha256(data).hexdigest()
    fact=tmp_path/'fact.json';fact.write_bytes((' {"target_sha256":"'+digest+'","note":"owned hypothesis"} \n').encode())
    calls=[]
    class Export:
        success=backend_success;target_sha256=digest;status='complete' if backend_success else 'failed'
        total_functions=2;worker_execution={'mode':'unit_test_stub'};artifact_dir=None;error_message=None
        functions={digest+'!ram:1000':SimpleNamespace(name='root',address='ram:1000',normalized_ir={'available':True}),
                   digest+'!ram:2000':SimpleNamespace(name='child',address='ram:2000',normalized_ir={'available':True})}
        def ir_coverage(self):return dict(total_functions=2,structurally_valid=2,partial=0,unavailable=0)
        def select_reconstruction(self,identity,**options):
            return dict(status='complete',structured_c_source='unsigned long long own(void){return 0;}',binary_equivalence_proved=False)
        def select_frame_program(self,selector,value):
            assert value['target_sha256']==digest and selector=='root'
            return dict(status='unsupported' if refused else 'complete',program_kind='derived_model',
                structured_c_source=None if refused else 'unsigned long long derived(void){return 0;}',
                errors=['controlled_refusal'] if refused else [],native_frame_fact_verified=False)
    class Backend:
        def decompile_binary(self,path,**options):
            assert Path(path).read_bytes()==data
            calls.append((path,options));return Export()
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    return target,fact,calls


@pytest.mark.parametrize('also_native',[False,True])
def test_derivation_uses_admitted_snapshot_once_with_separate_result(tmp_path,monkeypatch,also_native):
    target,fact,calls=case_inputs(tmp_path,monkeypatch)
    original=fact.read_bytes();out=tmp_path/'case'
    policy=replace(CasePolicy.static_only(),request_native_reconstruction=also_native,
                   derive_frame_function='root',frame_fact=fact)
    result=run_universal_case(target,out,policy)
    derived=result.derived_frame_program
    assert len(calls)==1 and Path(calls[0][0])!=target
    assert derived['status']=='complete' and derived['requested_programs']==1
    assert derived['attempted_programs']==derived['derived_programs']==1
    assert derived['refused_programs']==0
    assert result.certification_status=='abstained' and result.dynamic_status=='not_requested'
    assert result.original_source_recovered is False
    assert (result.native_reconstruction is not None)==also_native
    if also_native:assert result.native_reconstruction['attempted_functions']==2
    published=Path(derived['publication']['path']);payload=published.read_bytes()
    assert hashlib.sha256(payload).hexdigest()==derived['publication']['sha256']
    assert json.loads(payload)=={key:value for key,value in derived.items() if key!='publication'}
    assert (out/'derived_frame_fact.json').read_bytes()==original
    assert derived['fact_intake']['sha256']==hashlib.sha256(original).hexdigest()
    assert json.loads((out/'case_report.json').read_text())==json.loads(json.dumps(result.to_dict()))


@pytest.mark.parametrize('refused,backend_success',[(True,True),(False,False)])
def test_refusal_and_backend_failure_publish_honest_denominators(tmp_path,monkeypatch,refused,backend_success):
    target,fact,calls=case_inputs(tmp_path,monkeypatch,refused,backend_success)
    policy=replace(CasePolicy.static_only(),derive_frame_function='root',frame_fact=fact)
    result=run_universal_case(target,tmp_path/'case',policy).derived_frame_program
    assert result['derived_programs']==0
    if backend_success:
        assert result['attempted_programs']==1 and result['refused_programs']==1
        assert result['program']['structured_c_source'] is None
    else:assert result['attempted_programs']==0 and result['status']=='backend_failed'


def test_invalid_json_refuses_before_intake_or_backend(tmp_path,monkeypatch):
    import aether_re.pipeline as pipeline
    fact=tmp_path/'fact.json';fact.write_text('{"x":1e999}')
    monkeypatch.setattr(pipeline,'prepare_case',lambda *a,**k:pytest.fail('intake started'))
    policy=replace(CasePolicy.static_only(),derive_frame_function='root',frame_fact=fact)
    with pytest.raises(ValueError):run_universal_case(tmp_path/'not_needed',tmp_path/'case',policy)
    assert not (tmp_path/'case').exists()


def test_changed_fact_after_preflight_refuses_before_backend(tmp_path,monkeypatch):
    import aether_re.pipeline as pipeline
    target,fact,calls=case_inputs(tmp_path,monkeypatch);original=pipeline.prepare_case
    def change(*args,**kwargs):
        result=original(*args,**kwargs);fact.write_bytes(fact.read_bytes()+b' ');return result
    monkeypatch.setattr(pipeline,'prepare_case',change)
    policy=replace(CasePolicy.static_only(),derive_frame_function='root',frame_fact=fact)
    with pytest.raises(ValueError,match='changed'):run_universal_case(target,tmp_path/'case',policy)
    assert not calls and not (tmp_path/'case'/'case_report.json').exists()


def test_fact_target_mismatch_refuses_before_backend(tmp_path,monkeypatch):
    target,fact,calls=case_inputs(tmp_path,monkeypatch);fact.write_text('{"target_sha256":"'+('0'*64)+'"}')
    policy=replace(CasePolicy.static_only(),derive_frame_function='root',frame_fact=fact)
    with pytest.raises(ValueError,match='target'):run_universal_case(target,tmp_path/'case',policy)
    assert not calls


def test_default_case_serialization_omits_optional_derived_field(tmp_path):
    target=tmp_path/'x.bin';target.write_bytes(b'owned static bytes')
    result=run_universal_case(target,tmp_path/'case',CasePolicy.static_only())
    assert result.derived_frame_program is None
    assert 'derived_frame_program' not in result.to_dict()


def test_cli_rejects_derived_request_in_js_bypass_before_worker(tmp_path,monkeypatch):
    import megazord
    monkeypatch.setattr(megazord,'ReaStaticJavaScriptAdapter',lambda:pytest.fail('JS worker started'))
    args=Namespace(target='not-needed',out=str(tmp_path/'case'),profile='js-electron',derive_frame_function='root',frame_fact='fact.json')
    with pytest.raises(ValueError,match='frame'):megazord.cmd_universal(args)


@pytest.mark.parametrize('options',[
    {'derive_frame_function':'root'}, {'frame_fact':'fact.json'},
    {'derive_frame_function':True,'frame_fact':'fact.json'},
    {'derive_frame_function':'root','frame_fact':'fact.json','request_native_reconstruction':True,
     'native_memory_model':'bounded-bytes.v2'},
])
def test_invalid_frame_configuration_refuses_before_intake(tmp_path,monkeypatch,options):
    import aether_re.pipeline as pipeline
    monkeypatch.setattr(pipeline,'prepare_case',lambda *a,**k:pytest.fail('intake started'))
    with pytest.raises(ValueError,match='frame'):
        run_universal_case(tmp_path/'unused',tmp_path/'case',replace(CasePolicy.static_only(),**options))
    assert not (tmp_path/'case').exists()


def test_unauthorized_frame_request_refuses_before_reading_fact(tmp_path):
    policy=replace(CasePolicy.static_only(),authorization=SimpleNamespace(allows=lambda _:False),
                   derive_frame_function='root',frame_fact=tmp_path/'absent.json')
    with pytest.raises(ValueError,match='static_analysis_not_authorized'):
        run_universal_case(tmp_path/'unused',tmp_path/'case',policy)
    assert not (tmp_path/'case').exists()


def test_unsupported_profile_does_not_invoke_backend(tmp_path,monkeypatch):
    import aether_re.ghidra_headless_bridge as bridge
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',lambda:pytest.fail('backend started'))
    target=tmp_path/'owned.bin';target.write_bytes(b'owned static bytes')
    fact=tmp_path/'fact.json';fact.write_text(json.dumps({'target_sha256':hashlib.sha256(target.read_bytes()).hexdigest()}))
    result=run_universal_case(target,tmp_path/'case',replace(CasePolicy.static_only(),
        derive_frame_function='root',frame_fact=fact)).derived_frame_program
    assert result['status']=='unsupported_profile'
    assert result['requested_programs']==1 and result['attempted_programs']==result['derived_programs']==0


def test_export_target_mismatch_refuses_before_selection(tmp_path,monkeypatch):
    import aether_re.ghidra_headless_bridge as bridge
    target,fact,_=case_inputs(tmp_path,monkeypatch)
    class Backend:
        def decompile_binary(self,*a,**k):return SimpleNamespace(target_sha256='0'*64)
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    with pytest.raises(ValueError,match='target_mismatch'):
        run_universal_case(target,tmp_path/'case',replace(CasePolicy.static_only(),
            derive_frame_function='root',frame_fact=fact))
    assert not (tmp_path/'case'/'derived_frame_program.json').exists()
