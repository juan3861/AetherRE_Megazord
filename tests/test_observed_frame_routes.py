import hashlib,io,json,runpy,sys,tempfile
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
import pytest
from aether_re.pipeline import CasePolicy,run_universal_case


def setup(tmp_path,monkeypatch,bad_prefix=False):
    helper=runpy.run_path(str(Path(__file__).with_name('test_native_frame_interfaces.py')))
    exported,raw,language=helper['loaded'](tmp_path)
    if bad_prefix:
        raw=bytearray(raw);raw[512+0x294:512+0x297]=bytes.fromhex('4833c9');raw=bytes(raw)
        digest=hashlib.sha256(raw).hexdigest();summary=json.loads((tmp_path/'decompilation_summary.json').read_text())
        summary['target_sha256']=digest
        for row in summary['functions']:
            data=json.loads((tmp_path/row['ir_file']).read_text());data['target_sha256']=digest
            row['high_parameter_observation']['target_sha256']=digest
            (tmp_path/row['ir_file']).write_text(json.dumps(data,sort_keys=True))
        (tmp_path/'decompilation_summary.json').write_text(json.dumps(summary))
        from aether_re.ghidra_headless_bridge import _load_export
        exported.functions,*_=_load_export(tmp_path,digest);exported.target_sha256=digest
    target=tmp_path/'owned.dll';target.write_bytes(raw);directory=tmp_path/'language';directory.mkdir()
    for name,content in language.items():(directory/name).write_bytes(content)
    calls=[];exported.status='complete'
    class Backend:
        def decompile_binary(self,path,**options):
            assert Path(path).read_bytes()==raw;calls.append(Path(path));exported.binary_path=str(path);return exported
    import aether_re.ghidra_headless_bridge as bridge
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    monkeypatch.setattr(tempfile,'tempdir',str(tmp_path))
    return target,directory,calls


def options(target,directory,**extra):
    return dict(target=str(target),observe_frame_function='root_native',frame_object_bytes=16,frame_language_dir=str(directory),**extra)


def assert_model(program):
    assert program['status']=='complete' and program['native_address_prefix_observed'] is True
    assert program['frame_fact_origin']=='observed_native_address_prefix_with_requested_extent'
    assert program['native_frame_fact_verified'] is False and program['native_address_observation']['callee_effect_extent_proved'] is False


def test_raw_cli_observes_native_prefix_with_snapshots(tmp_path,monkeypatch,capsys):
    import megazord
    target,directory,calls=setup(tmp_path,monkeypatch);output=tmp_path/'report.json'
    assert megazord.cmd_ghidra_decompile(Namespace(**options(target,directory,out=str(output))))==0
    payload=json.loads(output.read_text(encoding='utf-8'));assert payload['success'];assert_model(payload['derived_frame_program'])
    receipt=payload['native_frame_input_receipt'];snapshot=Path(receipt['target']['snapshot_path'])
    assert calls==[snapshot] and snapshot!=target and snapshot.read_bytes()==target.read_bytes()
    assert receipt['language_toolchain_authenticity_proved'] is False
    capsys.readouterr()


def test_mcp_stdio_schema_and_dispatch_observed_route(tmp_path,monkeypatch,capsys):
    from aether_re import mcp_server
    target,directory,calls=setup(tmp_path,monkeypatch)
    requests=[dict(jsonrpc='2.0',id=1,method='initialize',params={}),dict(jsonrpc='2.0',id=2,method='tools/list',params={}),
        dict(jsonrpc='2.0',id=3,method='tools/call',params=dict(name='aether_ghidra_decompile',arguments=options(target,directory)))]
    wire=''.join(json.dumps(r)+'\n' for r in requests).encode('utf-8')
    monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(wire),encoding='utf-8'))
    assert mcp_server.run_mcp_server()==0
    messages=[json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [m['id'] for m in messages]==[1,2,3]
    tool=next(t for t in messages[1]['result']['tools'] if t['name']=='aether_ghidra_decompile')
    assert {'observe_frame_function','frame_object_bytes','frame_language_dir'}<=set(tool['inputSchema']['properties'])
    reply=messages[2]['result'];assert not reply.get('isError',False)
    payload=json.loads(reply['content'][0]['text']);assert payload['success'];assert_model(payload['derived_frame_program'])
    assert len(calls)==1 and calls[0]==Path(payload['native_frame_input_receipt']['target']['snapshot_path'])


@pytest.mark.parametrize('native',[False,True])
def test_universal_observed_route_reuses_one_export(tmp_path,monkeypatch,native):
    target,directory,calls=setup(tmp_path,monkeypatch);output=tmp_path/'case'
    policy=replace(CasePolicy.static_only(),observe_frame_function='root_native',frame_object_bytes=16,
        frame_language_dir=directory,request_native_reconstruction=native)
    report=run_universal_case(target,output,policy);envelope=report.derived_frame_program
    assert_model(envelope['program']);assert envelope['status']=='complete'
    assert envelope['requested_programs']==envelope['attempted_programs']==envelope['derived_programs']==1 and envelope['refused_programs']==0
    assert len(calls)==1 and calls[0]!=target and (report.native_reconstruction is not None)==native
    receipt=envelope['native_frame_input_receipt'];assert Path(receipt['target']['snapshot_path']).read_bytes()==target.read_bytes()
    assert report.certification_status=='abstained' and report.dynamic_status=='not_requested' and not report.original_source_recovered


@pytest.mark.parametrize('route',['cli','mcp','universal'])
def test_invalid_native_extent_refuses_before_backend(tmp_path,monkeypatch,capsys,route):
    target,directory,calls=setup(tmp_path,monkeypatch)
    if route=='cli':
        import megazord
        args=options(target,directory,out=str(tmp_path/'report.json'));args['frame_object_bytes']=True
        assert megazord.cmd_ghidra_decompile(Namespace(**args))==1
        assert json.loads(capsys.readouterr().out)['status']=='native_frame_configuration_invalid'
    elif route=='mcp':
        from aether_re.mcp_server import AetherMcpDispatcher
        args=options(target,directory);args['frame_object_bytes']=True
        assert AetherMcpDispatcher.handle_ghidra_decompile(**args)['status']=='native_frame_configuration_invalid'
    else:
        policy=replace(CasePolicy.static_only(),observe_frame_function='root_native',frame_object_bytes=True,frame_language_dir=directory)
        with pytest.raises(ValueError):run_universal_case(target,tmp_path/'case',policy)
    assert not calls


@pytest.mark.parametrize('route',['cli','mcp','universal'])
def test_native_prefix_refusal_is_preserved_without_model(tmp_path,monkeypatch,capsys,route):
    target,directory,calls=setup(tmp_path,monkeypatch,bad_prefix=True)
    if route=='cli':
        import megazord
        output=tmp_path/'refused.json'
        assert megazord.cmd_ghidra_decompile(Namespace(**options(target,directory,out=str(output))))==1
        payload=json.loads(output.read_text());assert not payload['success'] and payload['status']=='native_frame_observation_failed'
        assert 'derived_frame_program' not in payload and 'native_frame_input_receipt' in payload
        capsys.readouterr()
    elif route=='mcp':
        from aether_re.mcp_server import AetherMcpDispatcher
        payload=AetherMcpDispatcher.handle_ghidra_decompile(**options(target,directory))
        assert not payload['success'] and payload['status']=='native_frame_observation_failed'
        assert 'derived_frame_program' not in payload and 'native_frame_input_receipt' in payload
    else:
        policy=replace(CasePolicy.static_only(),observe_frame_function='root_native',frame_object_bytes=16,frame_language_dir=directory)
        envelope=run_universal_case(target,tmp_path/'case',policy).derived_frame_program
        assert envelope['status']=='refused' and envelope['program'] is None
        assert envelope['attempted_programs']==envelope['refused_programs']==1 and envelope['derived_programs']==0
        assert 'native_frame_input_receipt' in envelope
    assert len(calls)==1


def test_observed_request_is_not_ignored_by_explicit_js_bypass(tmp_path,monkeypatch):
    import megazord
    monkeypatch.setattr(megazord,'ReaStaticJavaScriptAdapter',lambda:pytest.fail('JS adapter started'))
    args=Namespace(target='unused',out=str(tmp_path/'case'),profile='js-electron',observe_frame_function='root',
        frame_object_bytes=16,frame_language_dir='unused')
    with pytest.raises(ValueError,match='frame'):megazord.cmd_universal(args)


@pytest.mark.parametrize('route',['cli','mcp'])
def test_raw_observed_route_retains_and_reports_export_artifacts(tmp_path,monkeypatch,capsys,route):
    target,directory,_=setup(tmp_path,monkeypatch)
    import aether_re.ghidra_headless_bridge as bridge
    previous=bridge.GhidraHeadlessBridge
    class RetainedBackend(previous):
        def decompile_binary(self,path,**options):
            assert options.get('temp_work_dir') is not None,'native export custody was not requested'
            result=super().decompile_binary(path,**options)
            result.artifact_dir=str(Path(options['temp_work_dir'])/'unit-worker')
            result.artifact_hashes={'unit-observed-export.json':'a'*64}
            return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',RetainedBackend)
    if route=='cli':
        import megazord
        output=tmp_path/'retained.json'
        assert megazord.cmd_ghidra_decompile(Namespace(**options(target,directory,out=str(output))))==0
        payload=json.loads(output.read_text());capsys.readouterr()
    else:
        from aether_re.mcp_server import AetherMcpDispatcher
        payload=AetherMcpDispatcher.handle_ghidra_decompile(**options(target,directory))
    assert payload['native_frame_export']['artifact_dir'].endswith('unit-worker')
    assert payload['native_frame_export']['artifact_hashes']=={'unit-observed-export.json':'a'*64}
