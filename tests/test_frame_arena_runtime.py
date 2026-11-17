import ctypes,json,os,sys
from pathlib import Path
import pytest

@pytest.fixture(scope='module')
def native_arena(tmp_path_factory):
    from aether_re.frame_arena_runtime import FRAME_ARENA_RUNTIME
    from aether_re.frame_relocation import emit_relocatable_frame_body
    from aether_re.process import run_bounded
    root=Path(__file__).resolve().parents[1]
    data=json.loads((root/'tests/fixtures/frame_program_ir.json').read_text(encoding='utf-8'))
    body=emit_relocatable_frame_body(data['root'],data['callee'],data['frame_fact'])
    directory=tmp_path_factory.mktemp('arena-native')
    source=directory/'arena.c';dll=directory/'arena.dll'
    source.write_text(body['emitted']['structured_c_source']+'\n'+FRAME_ARENA_RUNTIME+'\n'+
        (root/'tests/fixtures/frame_arena_scenarios.c').read_text(encoding='utf-8'),encoding='utf-8')
    vc=Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207')
    worker=run_bounded([str(vc/'bin/Hostx64/x64/cl.exe'),'/nologo','/TC','/std:c17','/Od','/GS-','/LD',
        '/I'+str(vc/'include'),str(source),'/Fo'+str(directory/'arena.obj'),'/Fe'+str(dll),
        '/link','/NOENTRY','/NODEFAULTLIB',str(vc/'lib/x64/chkstk.obj')],cwd=str(directory),timeout=60,memory_limit_mb=512,
        output_limit_bytes=2*1024**2,require_process_tree=True)
    (directory/'COMPILER.json').write_text(json.dumps(worker,indent=2),encoding='utf-8')
    assert worker['returncode']==0 and worker['capture_complete'] and worker['process_tree_contained'],worker
    library=ctypes.CDLL(str(dll));function=library.arena_scenario
    function.argtypes=[ctypes.c_uint];function.restype=ctypes.c_uint
    return library,function

@pytest.mark.parametrize('mode',range(10),ids=['nested-lifo','wrong-token','wrong-order','active-descriptor',
    'active-pointer','saved-descriptor','event-descriptor','geometry','token-exhaustion','depth-limit'])
def test_native_scope_protocol(native_arena,mode):
    library,function=native_arena
    assert function(mode)==0
