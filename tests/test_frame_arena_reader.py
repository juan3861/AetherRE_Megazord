import copy,importlib.util,sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]

def load_file(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module

@pytest.fixture
def pair(tmp_path):
    helpers=load_file('_arena_interface_helpers',ROOT/'tests/test_frame_interfaces.py')
    result,fact=helpers.loaded(tmp_path)
    return result,fact

def test_reader_arena_is_explicit_and_preserves_default_and_inputs(pair):
    result,fact=pair;before=copy.deepcopy(result)
    fixed=result.select_frame_program('owned_pair_caller',fact)
    arena=result.select_frame_program('owned_pair_caller',fact,frame_runtime='invocation-arena.v1')
    assert fixed['status']=='complete' and 'frame_runtime' not in fixed
    assert arena['status']=='conditional_model' and arena['frame_runtime']=='invocation-arena.v1'
    assert arena['selected_functions']==fixed['selected_functions']
    assert arena['supplied_frame_fact_sha256']==fixed['supplied_frame_fact_sha256']
    assert not arena['production_admission'] and not arena['binary_equivalence_proved']
    assert result==before
    assert result.select_frame_program('owned_pair_caller',fact)==fixed

@pytest.mark.parametrize('runtime',['unknown','',True,{}])
def test_reader_refuses_unknown_runtime_before_intake(pair,runtime,monkeypatch):
    result,fact=pair
    monkeypatch.setattr(result,'select_reconstruction',lambda *a,**k:pytest.fail('intake before runtime validation'))
    with pytest.raises(ValueError,match='runtime_invalid'):
        result.select_frame_program('owned_pair_caller',fact,frame_runtime=runtime)

@pytest.mark.parametrize('base',[0,16,True,1048576.0])
def test_arena_refuses_fixed_placement_conflict(pair,base):
    result,fact=pair
    with pytest.raises(ValueError,match='fixed_base_conflict'):
        result.select_frame_program('owned_pair_caller',fact,frame_runtime='invocation-arena.v1',object_base=base)

@pytest.mark.parametrize('part',['root_ir','callee_ir','root_high','callee_high','storage','root_id','callee_id'])
def test_arena_revalidates_export_before_generation(pair,part):
    result,fact=pair
    info=result.get_unique_function('owned_pair' if part.startswith('callee') else 'owned_pair_caller')
    if part.endswith('_ir'):info.pcode_ir['operations'][0]['sequence']['time']+=1
    elif part.endswith('_high'):info.high_parameter_observation['parameters'][0]['name']='changed'
    elif part.endswith('_id'):info.function_id='0'*64+'!ram:1'
    else:info.storage_observation={}
    with pytest.raises(ValueError):
        result.select_frame_program('owned_pair_caller',fact,frame_runtime='invocation-arena.v1')

def test_observed_route_forwards_runtime_after_observation(pair,monkeypatch):
    import aether_re.native_frame_address as native
    import aether_re.native_caller_data as pair_data
    result,fact=pair;calls=[]
    monkeypatch.setattr(native,'observe_frame_address',lambda **options:copy.deepcopy(fact))
    witness_calls=[]
    def witness(**options):
        witness_calls.append(options)
        return dict(status='refused',error_message='unit forwarding fixture')
    monkeypatch.setattr(pair_data,'build_native_pair_observation',witness)
    real=result.select_frame_program
    def select(*args,**kwargs):
        calls.append(kwargs);return real(*args,**kwargs)
    monkeypatch.setattr(result,'select_frame_program',select)
    report=result.select_observed_frame_program('owned_pair_caller',target_bytes=b'not executed',
        language_sources={},object_bytes=16,frame_runtime='invocation-arena.v1')
    assert calls==[dict(object_base=0x100000,frame_runtime='invocation-arena.v1')]
    assert report['native_address_prefix_observed'] and not report['native_frame_fact_verified']
    assert len(witness_calls)==1 and witness_calls[0]['target_bytes']==b'not executed'
    assert report['native_pair_data_observation']['status']=='refused'

def test_observed_route_refuses_runtime_before_observation(pair,monkeypatch):
    result,fact=pair
    monkeypatch.setattr(result,'select_reconstruction',lambda *a,**k:pytest.fail('intake before runtime validation'))
    with pytest.raises(ValueError,match='runtime_invalid'):
        result.select_observed_frame_program('owned_pair_caller',target_bytes=b'',language_sources={},object_bytes=16,frame_runtime='bad')
