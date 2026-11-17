import copy,json
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch
import pytest
from aether_re.ghidra_headless_bridge import _load_export,GhidraDecompilationResult


def fixture():
    return json.loads((Path(__file__).parent/'fixtures/frame_program_ir.json').read_text())


def loaded(tmp_path):
    data=fixture();rows=[]
    (tmp_path/'functions').mkdir();(tmp_path/'ir').mkdir()
    for index,key in enumerate(('root','callee')):
        info=data[key];ir=info['pcode_ir'];name='owned_pair_caller' if key=='root' else 'owned_pair'
        source=f'functions/f{index}.c';irfile=f'ir/f{index}.json'
        (tmp_path/source).write_text('unsigned long long owned(void){return 0;}')
        (tmp_path/irfile).write_text(json.dumps(ir,sort_keys=True))
        rows.append(dict(name=name,address=ir['function_address'],params=len(info['high_parameter_observation']['parameters']),
            return_type='ulonglong',signature_source='ANALYSIS',signature='ulonglong '+name+'(void)',success=True,
            source_file=source,ir_file=irfile,high_parameter_observation=info['high_parameter_observation']))
    summary=dict(schema='aetherre-ghidra-export.v2',target_sha256=data['root']['pcode_ir']['target_sha256'],complete=True,
        total_functions=2,decompiled_functions=2,failed_functions=0,
        type_policy=dict(mode='observed_program_types',external_types_injected=False,legacy_type_injection_requested=False),functions=rows)
    (tmp_path/'decompilation_summary.json').write_text(json.dumps(summary))
    functions,*_=_load_export(tmp_path,summary['target_sha256'])
    result=GhidraDecompilationResult('not-executed',True,2,2,functions,'','',0,target_sha256=summary['target_sha256'])
    return result,data['frame_fact']


def test_reader_selects_both_validated_functions_without_mutating_export(tmp_path):
    result,fact=loaded(tmp_path);before=copy.deepcopy(result)
    report=result.select_frame_program('owned_pair_caller',fact)
    assert report['status']=='complete',report
    assert report['program_kind']=='derived_model' and report['native_frame_fact_verified'] is False
    assert report['selected_functions']['callee'].endswith('!ram:180001270')
    assert result==before


@pytest.mark.parametrize('part',['root_ir','callee_ir','root_high','callee_high','storage','root_id','callee_id'])
def test_reader_rejects_mutation_of_either_function(tmp_path,part):
    result,fact=loaded(tmp_path)
    name='owned_pair' if part.startswith('callee') else 'owned_pair_caller'
    info=result.get_unique_function(name)
    if part.endswith('_ir'):info.pcode_ir['operations'][0]['sequence']['time']+=1
    elif part.endswith('_high'):info.high_parameter_observation['parameters'][0]['name']='changed'
    elif part.endswith('_id'):info.function_id='0'*64+'!ram:1'
    else:info.storage_observation={}
    with pytest.raises(ValueError):result.select_frame_program('owned_pair_caller',fact)


def test_reader_missing_callee_and_bad_fact_are_refused(tmp_path):
    result,fact=loaded(tmp_path)
    wrong=copy.deepcopy(fact);wrong['target_sha256']='0'*64
    report=result.select_frame_program('owned_pair_caller',wrong)
    assert report['status']!='complete' and report['structured_c_source'] is None
    child=result.get_unique_function('owned_pair');result.functions.pop(child.function_id)
    with pytest.raises(ValueError,match='callee'):result.select_frame_program('owned_pair_caller',fact)


def test_reader_rejects_ambiguous_name(tmp_path):
    result,fact=loaded(tmp_path);info=copy.deepcopy(result.get_unique_function('owned_pair'))
    info.name='owned_pair_caller';result.functions[info.function_id]=info
    with pytest.raises(ValueError):result.select_frame_program('owned_pair_caller',fact)


def test_strict_bounded_fact_intake(tmp_path):
    from aether_re.frame_request import read_frame_fact
    fact=fixture()['frame_fact'];path=tmp_path/'fact.json';raw=json.dumps(fact).encode();path.write_bytes(raw)
    value,receipt=read_frame_fact(path)
    assert value==fact and receipt['bytes']==len(raw)
    assert receipt['native_fact_verified'] is False


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"a":NaN}',b'[]',b'\xff',b' '*65537,b'{"x":1e999}',b'{"x":-1e999}'],
                         ids=['duplicate','nonfinite','array','utf8','oversized','positive_overflow','negative_overflow'])
def test_bad_fact_intake_refuses(tmp_path,raw):
    from aether_re.frame_request import read_frame_fact
    path=tmp_path/'fact.json';path.write_bytes(raw)
    with pytest.raises(ValueError):read_frame_fact(path)


def test_request_options_require_explicit_nonconflicting_pair():
    from aether_re.frame_request import validate_frame_request
    validate_frame_request('owned','fact.json')
    validate_frame_request(None,None)
    for selector,fact,options in [(None,'fact.json',{}),('owned',None,{}),('owned','fact.json',dict(reconstruct_function='owned')),
            ('owned','fact.json',dict(memory_model='bounded-bytes.v2')),('owned','fact.json',dict(out='x.c'))]:
        with pytest.raises(ValueError):validate_frame_request(selector,fact,**options)


def test_cli_and_mcp_select_same_explicit_derived_model(tmp_path,monkeypatch,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    import aether_re.ghidra_headless_bridge as bridge
    result,fact=loaded(tmp_path)
    path=tmp_path/'fact.json';path.write_text(json.dumps(fact))
    target=tmp_path/'own.dll';target.write_bytes(b'static-only-test')
    calls=[]
    class Backend:
        def decompile_binary(self,*args,**kwargs):calls.append(kwargs);return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    args=Namespace(target=str(target),out=None,derive_frame_function='owned_pair_caller',frame_fact=str(path))
    assert cmd_ghidra_decompile(args)==0
    cli=json.loads(capsys.readouterr().out)
    assert 'function_reconstruction' not in cli
    assert cli['derived_frame_program']['program_kind']=='derived_model'
    mcp=AetherMcpDispatcher.handle_ghidra_decompile(str(target),derive_frame_function='owned_pair_caller',frame_fact=str(path))
    assert mcp['success'] and cli['derived_frame_program']==json.loads(json.dumps(mcp['derived_frame_program']))
    assert len(calls)==2


def test_bad_frame_request_does_not_launch_backend(tmp_path,monkeypatch,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    import aether_re.ghidra_headless_bridge as bridge
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',lambda:pytest.fail('backend launched before request validation'))
    args=Namespace(target='not-needed',out=None,derive_frame_function='owned',frame_fact=None)
    assert cmd_ghidra_decompile(args)==1
    assert json.loads(capsys.readouterr().out)['status']=='frame_configuration_invalid'
    response=AetherMcpDispatcher.handle_ghidra_decompile('not-needed',derive_frame_function='owned')
    assert response['status']=='frame_configuration_invalid'


@pytest.mark.parametrize('raw',['{"duplicate":0,"duplicate":1}','{"x":1e999}','{"x":-1e999}'],ids=['duplicate','positive_overflow','negative_overflow'])
def test_bad_fact_json_does_not_launch_backend(tmp_path,monkeypatch,capsys,raw):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    import aether_re.ghidra_headless_bridge as bridge
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',lambda:pytest.fail('backend launched with invalid fact'))
    path=tmp_path/'fact.json';path.write_text(raw)
    args=Namespace(target='not-needed',out=None,derive_frame_function='owned',frame_fact=str(path))
    assert cmd_ghidra_decompile(args)==1
    assert json.loads(capsys.readouterr().out)['status']=='frame_configuration_invalid'
    assert AetherMcpDispatcher.handle_ghidra_decompile('not-needed',derive_frame_function='owned',frame_fact=str(path))['status']=='frame_configuration_invalid'


def test_refused_model_is_preserved_by_both_handlers(tmp_path,monkeypatch,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    import aether_re.ghidra_headless_bridge as bridge
    result,fact=loaded(tmp_path);fact['target_sha256']='0'*64
    path=tmp_path/'fact.json';path.write_text(json.dumps(fact));target=tmp_path/'own.dll';target.write_bytes(b'own')
    class Backend:
        def decompile_binary(self,*args,**kwargs):return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    args=Namespace(target=str(target),out=None,derive_frame_function='owned_pair_caller',frame_fact=str(path))
    assert cmd_ghidra_decompile(args)==1
    cli=json.loads(capsys.readouterr().out)
    mcp=AetherMcpDispatcher.handle_ghidra_decompile(str(target),derive_frame_function='owned_pair_caller',frame_fact=str(path))
    assert not cli['success'] and not mcp['success']
    assert cli['derived_frame_program']==json.loads(json.dumps(mcp['derived_frame_program']))
    assert cli['derived_frame_program']['structured_c_source'] is None


def test_default_handlers_do_not_select_a_frame_program(tmp_path,monkeypatch,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    import aether_re.ghidra_headless_bridge as bridge
    result,fact=loaded(tmp_path);target=tmp_path/'own.dll';target.write_bytes(b'own')
    monkeypatch.setattr(result,'select_frame_program',lambda *a,**k:pytest.fail('default selected frame model'))
    class Backend:
        def decompile_binary(self,*args,**kwargs):return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=None))==0
    cli=json.loads(capsys.readouterr().out)
    mcp=AetherMcpDispatcher.handle_ghidra_decompile(str(target))
    assert 'derived_frame_program' not in cli and 'derived_frame_program' not in mcp


def test_intake_rejects_changed_metadata_during_read(tmp_path,monkeypatch):
    import aether_re.frame_request as request
    from types import SimpleNamespace
    path=tmp_path/'fact.json';path.write_text('{}')
    original=request.os.fstat;count=0
    def changed(fd):
        nonlocal count
        count+=1;info=original(fd)
        return SimpleNamespace(st_mode=info.st_mode,st_nlink=info.st_nlink,st_dev=info.st_dev,st_ino=info.st_ino,
            st_size=info.st_size,st_mtime_ns=info.st_mtime_ns+(1 if count==2 else 0),st_file_attributes=0)
    monkeypatch.setattr(request.os,'fstat',changed)
    with pytest.raises(ValueError,match='changed'):request.read_frame_fact(path)


def test_intake_rejects_directory(tmp_path):
    from aether_re.frame_request import read_frame_fact
    with pytest.raises(ValueError):read_frame_fact(tmp_path)
