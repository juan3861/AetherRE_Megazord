import ctypes,json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture(scope='module')
def extra_native(tmp_path_factory):
    from aether_re.frame_relocation import emit_relocatable_frame_body
    from aether_re.frame_arena_runtime import FRAME_ARENA_RUNTIME
    from aether_re.process import run_bounded
    data=json.loads((ROOT/'tests/fixtures/frame_program_ir.json').read_text(encoding='utf-8'))
    body=emit_relocatable_frame_body(data['root'],data['callee'],data['frame_fact'])
    directory=tmp_path_factory.mktemp('arena-extra');source=directory/'extra.c';dll=directory/'extra.dll'
    source.write_text(body['emitted']['structured_c_source']+'\n'+FRAME_ARENA_RUNTIME+'\n'+
        (ROOT/'tests/fixtures/frame_arena_scenarios.c').read_text(encoding='utf-8')+'\n'+
        (ROOT/'tests/fixtures/frame_arena_extra_scenarios.c').read_text(encoding='utf-8'),encoding='utf-8')
    vc=Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207')
    worker=run_bounded([str(vc/'bin/Hostx64/x64/cl.exe'),'/nologo','/TC','/std:c17','/Od','/GS-','/LD',
        '/I'+str(vc/'include'),str(source),'/Fo'+str(directory/'extra.obj'),'/Fe'+str(dll),'/link','/NOENTRY','/NODEFAULTLIB',
        str(vc/'lib/x64/chkstk.obj')],cwd=str(directory),timeout=60,memory_limit_mb=512,
        output_limit_bytes=2*1024**2,require_process_tree=True)
    (directory/'COMPILER.json').write_text(json.dumps(worker,indent=2),encoding='utf-8')
    assert worker['returncode']==0 and worker['capture_complete'] and worker['process_tree_contained'],worker
    library=ctypes.CDLL(str(dll));fn=library.arena_extra_scenario
    fn.argtypes=[ctypes.c_uint];fn.restype=ctypes.c_uint
    return library,fn

@pytest.mark.parametrize('mode',range(3),ids=['serial-token-replay','body-error-unwind','nested-entry-fence'])
def test_extra_scope_protocol(extra_native,mode):
    library,fn=extra_native
    assert fn(mode)==0
