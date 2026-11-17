import io,json,runpy,sys
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
import pytest


def setup(tmp_path,monkeypatch):
    helper=runpy.run_path(str(Path(__file__).with_name('test_observed_frame_routes.py')))
    target,language,calls=helper['setup'](tmp_path,monkeypatch)
    runtime=runpy.run_path(str(Path(__file__).with_name('test_ghidra_runtime_lock.py')))
    g,j=runtime['roots'](tmp_path/'runtime')
    from aether_re.ghidra_runtime_lock import build_ghidra_runtime_lock
    lock=tmp_path/'runtime.json';lock.write_text(json.dumps(build_ghidra_runtime_lock(g,j)))
    import aether_re.ghidra_headless_bridge as bridge
    Old=bridge.GhidraHeadlessBridge;constructors=[]
    class Backend:
        def __init__(self,**kwargs):constructors.append(kwargs);self.inner=Old()
        def decompile_binary(self,*args,**kwargs):return self.inner.decompile_binary(*args,**kwargs)
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    return target,language,lock,calls,constructors,g,j


@pytest.mark.parametrize('route',['cli','mcp','universal'])
def test_runtime_reference_reaches_shared_worker(tmp_path,monkeypatch,capsys,route):
    target,language,lock,calls,constructors,*_=setup(tmp_path,monkeypatch)
    options=dict(target=str(target),observe_frame_function='root_native',frame_object_bytes=16,frame_language_dir=str(language),ghidra_runtime_lock=str(lock))
    if route=='cli':
        import megazord
        assert megazord.cmd_ghidra_decompile(Namespace(**options,out=str(tmp_path/'out.json')))==0
        capsys.readouterr()
    elif route=='mcp':
        from aether_re import mcp_server
        requests=[dict(jsonrpc='2.0',id=1,method='tools/list',params={}),dict(jsonrpc='2.0',id=2,method='tools/call',params=dict(name='aether_ghidra_decompile',arguments=options))]
        wire=''.join(json.dumps(r)+'\n' for r in requests).encode()
        monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(wire),encoding='utf-8'))
        assert mcp_server.run_mcp_server()==0
        messages=[json.loads(line) for line in capsys.readouterr().out.splitlines()]
        tool=next(t for t in messages[0]['result']['tools'] if t['name']=='aether_ghidra_decompile')
        assert 'ghidra_runtime_lock' in tool['inputSchema']['properties']
        assert json.loads(messages[1]['result']['content'][0]['text'])['success']
    else:
        from aether_re.pipeline import CasePolicy,run_universal_case
        policy=replace(CasePolicy.static_only(),observe_frame_function='root_native',frame_object_bytes=16,frame_language_dir=language,ghidra_runtime_lock=lock,request_native_reconstruction=True)
        report=run_universal_case(target,tmp_path/'case',policy)
        assert report.derived_frame_program['status']=='complete'
    assert len(calls)==1 and constructors==[{'runtime_lock':str(lock)}]


def test_create_and_verify_commands_use_complete_reference(tmp_path,monkeypatch,capsys):
    import megazord
    *_,g,j=setup(tmp_path,monkeypatch);lock=tmp_path/'created.json';report=tmp_path/'verified.json'
    monkeypatch.setattr(sys,'argv',['megazord.py','ghidra-runtime-lock','create','--ghidra-home',str(g),'--jdk-home',str(j),'--out',str(lock)])
    assert megazord.main()==0
    assert json.loads(lock.read_text())['bundles']['jdk']['files']['lib/modules']['bytes']==17
    monkeypatch.setattr(sys,'argv',['megazord.py','ghidra-runtime-lock','verify','--ghidra-home',str(g),'--jdk-home',str(j),'--lock',str(lock),'--out',str(report)])
    assert megazord.main()==0 and json.loads(report.read_text())['verified']
    capsys.readouterr()


def test_universal_runtime_option_requires_a_worker_request(tmp_path):
    from aether_re.pipeline import CasePolicy,run_universal_case
    policy=replace(CasePolicy.static_only(),ghidra_runtime_lock='lock.json')
    with pytest.raises(ValueError,match='runtime_lock_requires'):run_universal_case(tmp_path/'missing',tmp_path/'case',policy)


def test_runtime_request_cannot_bypass_json_or_explicit_js(tmp_path,monkeypatch,capsys):
    import megazord
    target,_,lock,calls,constructors,*_=setup(tmp_path,monkeypatch)
    assert megazord.cmd_ghidra_decompile(Namespace(target=str(target),ghidra_runtime_lock=str(lock),out=str(tmp_path/'out.c')))==1
    assert not calls and not constructors
    with pytest.raises(ValueError,match='runtime_lock_unsupported_explicit_profile'):
        megazord.cmd_universal(Namespace(target=str(target),out=str(tmp_path/'case'),profile='js-electron',native_reconstruction=True,ghidra_runtime_lock=str(lock)))
    capsys.readouterr()
