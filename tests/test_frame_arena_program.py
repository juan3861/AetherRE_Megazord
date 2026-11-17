import copy,importlib.util,json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
def module():
    import aether_re.frame_arena_program as value
    return value
def inputs():
    d=json.loads((ROOT/'tests/fixtures/frame_program_ir.json').read_text(encoding='utf-8'))
    return d['root'],d['callee'],d['frame_fact']
def test_wrapper_uses_literal_body_and_explicit_domain_guard():
    args=inputs();before=copy.deepcopy(args);report=module().build_frame_arena_program(*args)
    assert args==before and report['status']=='conditional_model'
    assert report['structured_c_source'].startswith(report['body']['emitted']['structured_c_source'])
    assert report['runtime_placement_domain_guarded'] and report['invocation_tokens_included']
    assert not report['native_frame_fact_verified'] and not report['production_admission']
    assert report['parameters']==['aether_v3','aether_v4']
@pytest.mark.parametrize('name',[None,'bad name','aether_arena_leave','aether_relocatable_body'])
def test_reserved_or_bad_names_refuse(name):
    with pytest.raises(ValueError):module().build_frame_arena_program(*inputs(),function_name=name)

@pytest.fixture(scope='module')
def native_wrapper(tmp_path_factory):
    import ctypes
    from aether_re.process import run_bounded
    report=module().build_frame_arena_program(*inputs());directory=tmp_path_factory.mktemp('wrapped-native')
    source=directory/'wrapped.c';dll=directory/'wrapped.dll'
    source.write_text(report['structured_c_source']+'\n'+(ROOT/'tests/fixtures/frame_arena_scenarios.c').read_text(encoding='utf-8')+'\n'+
        (ROOT/'tests/fixtures/frame_arena_wrapped_scenarios.c').read_text(encoding='utf-8'),encoding='utf-8')
    vc=Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207')
    worker=run_bounded([str(vc/'bin/Hostx64/x64/cl.exe'),'/nologo','/TC','/std:c17','/Od','/GS-','/LD',
        '/I'+str(vc/'include'),str(source),'/Fo'+str(directory/'wrapped.obj'),'/Fe'+str(dll),'/link','/NOENTRY','/NODEFAULTLIB',
        str(vc/'lib/x64/chkstk.obj')],cwd=str(directory),timeout=60,memory_limit_mb=512,output_limit_bytes=2*1024**2,require_process_tree=True)
    (directory/'COMPILER.json').write_text(json.dumps(worker,indent=2),encoding='utf-8')
    assert worker['returncode']==0 and worker['capture_complete'] and worker['process_tree_contained'],worker
    library=ctypes.CDLL(str(dll));fn=library.wrapped_scenario;fn.argtypes=[ctypes.c_uint];fn.restype=ctypes.c_uint
    return library,fn

@pytest.mark.parametrize('mode',range(7),ids=['normal','steps-error','arena-full','entry-overflow','space-error','trace-error','repeat'])
def test_native_generated_wrapper(native_wrapper,mode):
    library,fn=native_wrapper
    assert fn(mode)==0
