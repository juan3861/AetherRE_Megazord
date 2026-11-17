import copy,json,runpy
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
import pytest

@pytest.mark.parametrize('runtime,derive,observe',[
    ('bad','root',None),('',None,None),(True,'root',None),({},'root',None),
    ('invocation-arena.v1',None,None),('invocation-arena.v1','root','root'),
    ('invocation-arena.v1','',None),('invocation-arena.v1',None,False)])
def test_runtime_request_requires_one_explicit_valid_route(runtime,derive,observe):
    from aether_re.frame_request import validate_frame_runtime_request
    with pytest.raises(ValueError):validate_frame_runtime_request(runtime,derive,observe)

def test_runtime_request_keeps_disabled_default():
    from aether_re.frame_request import validate_frame_runtime_request
    validate_frame_runtime_request(None,None,None)
    validate_frame_runtime_request('invocation-arena.v1','root',None)
    validate_frame_runtime_request('invocation-arena.v1',None,'root')

@pytest.mark.parametrize('observed',[False,True],ids=['supplied','observed'])
def test_cli_mcp_arena_reports_match_and_keep_default_model(tmp_path,monkeypatch,capsys,observed):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    import aether_re.ghidra_headless_bridge as bridge
    if observed:
        helper=runpy.run_path(str(Path(__file__).with_name('test_native_frame_interfaces.py')))
        result,raw,language=helper['loaded'](tmp_path)
        target=tmp_path/'target.dll';target.write_bytes(raw)
        directory=tmp_path/'language';directory.mkdir()
        for name,data in language.items():(directory/name).write_bytes(data)
        options=dict(observe_frame_function='root_native',frame_object_bytes=16,frame_language_dir=str(directory))
    else:
        helper=runpy.run_path(str(Path(__file__).with_name('test_frame_interfaces.py')))
        result,fact=helper['loaded'](tmp_path)
        target=tmp_path/'target.dll';target.write_bytes(b'static test')
        path=tmp_path/'fact.json';path.write_text(json.dumps(fact))
        options=dict(derive_frame_function='owned_pair_caller',frame_fact=str(path))
    calls=[]
    class Backend:
        def decompile_binary(self,*args,**kwargs):calls.append(kwargs);return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    args=Namespace(target=str(target),out=None,frame_runtime='invocation-arena.v1',**options)
    assert cmd_ghidra_decompile(args)==0
    cli=json.loads(capsys.readouterr().out)
    mcp=AetherMcpDispatcher.handle_ghidra_decompile(str(target),frame_runtime='invocation-arena.v1',**options)
    model=cli['derived_frame_program']
    assert cli['success'] and mcp['success'] and model['status']=='conditional_model'
    assert model==json.loads(json.dumps(mcp['derived_frame_program']))
    assert not model['production_admission'] and not model['binary_equivalence_proved']
    assert len(calls)==2

@pytest.mark.parametrize('options',[dict(frame_runtime='bad'),dict(frame_runtime='invocation-arena.v1'),
    dict(frame_runtime='invocation-arena.v1',derive_frame_function='x',frame_fact='missing',out='x.c')])
def test_invalid_runtime_never_launches_cli_backend(tmp_path,monkeypatch,capsys,options):
    from megazord import cmd_ghidra_decompile
    import aether_re.ghidra_headless_bridge as bridge
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',lambda:pytest.fail('backend before validation'))
    assert cmd_ghidra_decompile(Namespace(target='missing',**options))==1
    assert not json.loads(capsys.readouterr().out)['success']

def test_universal_runtime_policy_and_js_cannot_bypass_validation(tmp_path,monkeypatch):
    from aether_re.pipeline import CasePolicy,run_universal_case
    from megazord import cmd_universal
    policy=replace(CasePolicy.static_only(),frame_runtime='invocation-arena.v1')
    with pytest.raises(ValueError,match='runtime'):
        run_universal_case(tmp_path/'missing',tmp_path/'out',policy)
    with pytest.raises(ValueError,match='runtime'):
        cmd_universal(Namespace(target='missing',out=str(tmp_path/'out'),profile='js-electron',frame_runtime='invocation-arena.v1'))

def test_universal_arena_case_retains_conditional_status_and_count(tmp_path):
    from aether_re.universal_frame import build_frame_case
    helper=runpy.run_path(str(Path(__file__).with_name('test_frame_interfaces.py')))
    result,fact=helper['loaded'](tmp_path);before=copy.deepcopy(result)
    report=build_frame_case(result,target_sha256=result.target_sha256,selector='owned_pair_caller',fact=fact,
        intake={'scope':'test'},profile='native-pe',frame_runtime='invocation-arena.v1')
    assert report['status']=='conditional_model' and report['derived_programs']==1
    assert report['attempted_programs']==1 and report['refused_programs']==0
    assert report['program']['frame_runtime']=='invocation-arena.v1'
    assert not report['native_admitted'] and not report['binary_equivalence_proved'] and result==before

def test_cli_parser_and_mcp_schema_expose_explicit_arena_choice(monkeypatch):
    import aether_re.mcp_server as server
    import megazord,sys
    seen=[]
    def capture(args):seen.append(args);return 0
    monkeypatch.setattr(megazord,'cmd_ghidra_decompile',capture)
    monkeypatch.setattr(megazord,'cmd_universal',capture)
    for command in ('ghidra-decompile','universal'):
        argv=['megazord.py',command,'x','--frame-runtime','invocation-arena.v1']
        if command=='universal':argv+=['--out','unused']
        monkeypatch.setattr(sys,'argv',argv)
        assert megazord.main()==0
        assert seen[-1].frame_runtime=='invocation-arena.v1'
    tool=next(tool for tool in server.TOOLS if tool['name']=='aether_ghidra_decompile')
    assert tool['inputSchema']['properties']['frame_runtime']['enum']==['invocation-arena.v1']

@pytest.mark.parametrize('observed',[False,True],ids=['supplied','observed'])
@pytest.mark.parametrize('also_native',[False,True])
def test_universal_arena_pipeline_publishes_one_export_and_conditional_model(tmp_path,monkeypatch,observed,also_native):
    import hashlib
    import aether_re.ghidra_headless_bridge as bridge
    from aether_re.pipeline import CasePolicy,run_universal_case
    helper=runpy.run_path(str(Path(__file__).with_name('test_native_frame_interfaces.py')))
    result,raw,language=helper['loaded'](tmp_path)
    target=tmp_path/'owned.dll';target.write_bytes(raw);calls=[]
    class Backend:
        def decompile_binary(self,path,**kwargs):
            assert Path(path).read_bytes()==raw and Path(path)!=target
            calls.append((path,kwargs));return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    if observed:
        directory=tmp_path/'language';directory.mkdir()
        for name,data in language.items():(directory/name).write_bytes(data)
        options=dict(observe_frame_function='root_native',frame_object_bytes=16,frame_language_dir=directory)
    else:
        model=result.select_observed_frame_program('root_native',target_bytes=raw,language_sources=language,object_bytes=16)
        fact=tmp_path/'fact.json';fact.write_text(json.dumps(model['native_address_observation']))
        options=dict(derive_frame_function='root_native',frame_fact=fact)
    policy=replace(CasePolicy.static_only(),frame_runtime='invocation-arena.v1',request_native_reconstruction=also_native,**options)
    report=run_universal_case(target,tmp_path/'case',policy)
    derived=report.derived_frame_program
    assert len(calls)==1 and derived['status']=='conditional_model'
    assert derived['requested_programs']==derived['attempted_programs']==derived['derived_programs']==1
    assert derived['refused_programs']==0 and not derived['native_admitted']
    assert report.certification_status=='abstained' and not report.original_source_recovered
    assert (report.native_reconstruction is not None)==also_native
    publication=derived['publication'];content=Path(publication['path']).read_bytes()
    assert hashlib.sha256(content).hexdigest()==publication['sha256']
    assert json.loads(content)==json.loads(json.dumps({k:v for k,v in derived.items() if k!='publication'}))
    assert json.loads((tmp_path/'case/case_report.json').read_text())==json.loads(json.dumps(report.to_dict()))

@pytest.mark.parametrize('runtime',['bad','invocation-arena.v1'])
def test_mcp_runtime_refuses_missing_route_before_backend(monkeypatch,runtime):
    import aether_re.ghidra_headless_bridge as bridge
    from aether_re.mcp_server import AetherMcpDispatcher
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',lambda:pytest.fail('backend before runtime validation'))
    report=AetherMcpDispatcher.handle_ghidra_decompile('missing',frame_runtime=runtime)
    assert not report['success'] and report['status']=='frame_runtime_configuration_invalid'

def test_actual_stdio_dispatch_forwards_arena_option(tmp_path,monkeypatch,capsys):
    import io,sys
    from aether_re import mcp_server
    helpers=runpy.run_path(str(Path(__file__).with_name('test_observed_frame_routes.py')))
    target,directory,calls=helpers['setup'](tmp_path,monkeypatch)
    arguments=dict(target=str(target),observe_frame_function='root_native',frame_object_bytes=16,
        frame_language_dir=str(directory),frame_runtime='invocation-arena.v1')
    requests=[dict(jsonrpc='2.0',id=1,method='initialize',params={}),
        dict(jsonrpc='2.0',id=2,method='tools/list',params={}),
        dict(jsonrpc='2.0',id=3,method='tools/call',params=dict(name='aether_ghidra_decompile',arguments=arguments))]
    wire=''.join(json.dumps(r)+'\n' for r in requests).encode('utf-8')
    monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(wire),encoding='utf-8'))
    assert mcp_server.run_mcp_server()==0
    messages=[json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [m['id'] for m in messages]==[1,2,3]
    payload=json.loads(messages[2]['result']['content'][0]['text'])
    assert payload['success'] and payload['derived_frame_program']['status']=='conditional_model'
    assert payload['derived_frame_program']['frame_runtime']=='invocation-arena.v1' and len(calls)==1

@pytest.mark.parametrize('key,value',[('schema','unexpected'),('status','complete'),('production_admission',True),
    ('binary_equivalence_proved',True),('invocation_tokens_included',False),('runtime_placement_domain_guarded',False)])
def test_conditional_success_requires_exact_model_contract(tmp_path,key,value):
    from aether_re.frame_request import frame_program_succeeded
    helper=runpy.run_path(str(Path(__file__).with_name('test_frame_interfaces.py')))
    result,fact=helper['loaded'](tmp_path)
    model=result.select_frame_program('owned_pair_caller',fact,frame_runtime='invocation-arena.v1')
    assert frame_program_succeeded(model,'invocation-arena.v1')
    model[key]=value
    assert not frame_program_succeeded(model,'invocation-arena.v1')
