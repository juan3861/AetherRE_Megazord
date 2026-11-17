from argparse import Namespace
from pathlib import Path
import json
import ast
from types import SimpleNamespace

from aether_re.ghidra_headless_bridge import GhidraDecompilationResult,GhidraFunctionInfo
import aether_re.ghidra_headless_bridge as bridge_module


def fake_export(monkeypatch,with_ir=False):
    calls=[];identity='a'*64+'!ram:401000'
    info=GhidraFunctionInfo('named_function','ram:401000',True,0,'int',decompiled_c='int named_function(void){return 7;}',function_id=identity)
    if with_ir:
        import runpy
        from aether_re.ghidra_pcode_ir import analyze_high_pcode
        data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
        projected=analyze_high_pcode(data,expected_target='a'*64,expected_address='ram:401000',evidence_sha256='b'*64)
        from dataclasses import replace
        info=replace(info,pcode_ir=data,ir_analysis=projected['summary'],normalized_ir=projected['graph'])
    result=GhidraDecompilationResult('owned.dll',True,1,1,{identity:info},info.decompiled_c,'',.1,
        target_sha256='a'*64,status='complete',type_policy={'mode':'observed_program_types','external_types_injected':False})
    class FakeBridge:
        def decompile_binary(self,*args,**kwargs): calls.append(kwargs);return result
    monkeypatch.setattr(bridge_module,'GhidraHeadlessBridge',FakeBridge)
    return calls,identity


def test_failed_cli_export_preserves_previous_source_output(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    result=GhidraDecompilationResult('owned.dll',False,0,0,{},'','',.1,error_message='worker failed')
    class FailedBridge:
        def decompile_binary(self,*args,**kwargs): return result
    monkeypatch.setattr(bridge_module,'GhidraHeadlessBridge',FailedBridge)
    target=tmp_path/'owned.dll';target.write_bytes(b'fixture')
    previous=tmp_path/'previous.c';previous.write_text('int valid_previous(void){return 9;}')
    before=previous.read_bytes()
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=str(previous)))!=0
    assert previous.read_bytes()==before


def test_successful_cli_export_does_not_overwrite_existing_artifact(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    fake_export(monkeypatch)
    target=tmp_path/'owned.dll';target.write_bytes(b'fixture')
    previous=tmp_path/'previous.c';previous.write_text('int valid_previous(void){return 9;}')
    before=previous.read_bytes()
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=str(previous)))!=0
    assert previous.read_bytes()==before


def test_mcp_exposes_inventory_identity_and_never_defaults_to_type_mutation(monkeypatch):
    from aether_re.mcp_server import AetherMcpDispatcher
    calls,identity=fake_export(monkeypatch)
    payload=AetherMcpDispatcher().handle_ghidra_decompile('owned.dll')
    assert calls[0]['script_name']=='DecompileAllFunctions.java'
    assert payload['status']=='complete'
    assert payload['type_policy']['external_types_injected'] is False
    assert payload['functions_summary'][identity]['name']=='named_function'
    assert payload['functions_returned']==1 and payload['functions_truncated'] is False


def test_cli_exposes_identity_name_status_and_observed_type_policy(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    calls,identity=fake_export(monkeypatch)
    target=tmp_path/'owned.dll';target.write_bytes(b'fixture')
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=None))==0
    payload=json.loads(capsys.readouterr().out)
    assert payload['status']=='complete'
    assert payload['type_policy']['external_types_injected'] is False
    assert payload['functions'][identity]['name']=='named_function'
    assert payload['functions_returned']==1 and payload['functions_truncated'] is False


def test_mcp_selected_function_returns_validated_ir_graph(monkeypatch):
    from aether_re.mcp_server import AetherMcpDispatcher
    calls,identity=fake_export(monkeypatch,with_ir=True)
    payload=AetherMcpDispatcher().handle_ghidra_decompile('owned.dll',ir_function='named_function')
    assert payload['success']
    assert payload['ir_coverage']['structurally_valid']==1
    assert payload['function_ir']['function_id']==identity
    assert any(node['kind']=='pcode-varnode' for node in payload['function_ir']['nodes'])


def test_selected_reconstruction_uses_high_pcode_and_returns_ctree(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    calls,identity=fake_export(monkeypatch,with_ir=True)
    target=tmp_path/'owned.dll';target.write_bytes(b'fixture')
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=None,reconstruct_function=identity))==0
    payload=json.loads(capsys.readouterr().out)
    assert payload['function_reconstruction']['status']=='complete'
    assert payload['function_reconstruction']['ctree']['status']=='complete'
    assert payload['function_reconstruction']['binary_equivalence_proved'] is False
    payload=AetherMcpDispatcher().handle_ghidra_decompile('owned.dll',reconstruct_function='named_function')
    assert payload['function_reconstruction']['status']=='complete'


def test_linked_debug_return_adapter_preserves_ir_translation(monkeypatch,tmp_path):
    import runpy
    from aether_re import pdb_dia
    context=runpy.run_path(str(Path(__file__).with_name('test_pdb_dia_contract.py')))
    _,identity=fake_export(monkeypatch,with_ir=True);result=bridge_module.GhidraHeadlessBridge().decompile_binary('owned.dll')
    data=context['typed_payload']();data['symbols'][0]['rva']=0x1000
    data.update(status='complete',binary_sha256='a'*64,pdb_sha256='b'*64,helper_sha256='c'*64,dia_dll_sha256='d'*64)
    data['binding']=dict(target_types_bound=True,binary_sha256='a'*64,guid=context['GUID'],age=1)
    data['validated_payload_sha256']=pdb_dia._payload_digest(data)
    data['validated_report_sha256']=pdb_dia._report_digest(data)
    seen=[]
    def extract(*args,**kwargs):seen.append(kwargs);return data
    monkeypatch.setattr(pdb_dia,'extract_pdb_symbols',extract)
    report=result.select_reconstruction(identity,debug_pdb=tmp_path/'owned.pdb',dia_helper=tmp_path/'helper.exe',dia_dll=tmp_path/'msdia.dll')
    adapter=report['debug_return_adapter']
    assert report['return_bits']==32 and adapter['contract']['return_bits']==8
    assert adapter['status']=='complete' and '255ULL' in adapter['structured_c_source']
    assert adapter['binary_equivalence_proved'] is False
    assert seen[0]['binary_path']==Path(result.binary_path)


def test_debug_configuration_cannot_be_ignored_without_reconstruction(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    calls,_=fake_export(monkeypatch)
    target=tmp_path/'own.dll';target.write_bytes(b'fixture')
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=None,debug_pdb='own.pdb'))!=0
    assert not calls
    assert AetherMcpDispatcher().handle_ghidra_decompile('own.dll',debug_pdb='own.pdb')['success'] is False
    assert not calls


def test_absent_reconstruction_never_publishes_or_reports_success(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    fake_export(monkeypatch,with_ir=True)
    target=tmp_path/'owned.dll';target.write_bytes(b'fixture');out=tmp_path/'missing.json'
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=str(out),reconstruct_function='absent'))!=0
    assert not out.exists()


def test_unsupported_reconstruction_is_explicit_and_never_publishes_source(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    from dataclasses import replace
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    _,identity=fake_export(monkeypatch,with_ir=True)
    result=bridge_module.GhidraHeadlessBridge().decompile_binary('owned.dll')
    previous=result.functions[identity];data=previous.pcode_ir;data['operations'][0]['opcode']='FUTURE_OPERATION'
    projected=analyze_high_pcode(data,expected_target='a'*64,expected_address='ram:401000',evidence_sha256='b'*64)
    result.functions[identity]=replace(previous,pcode_ir=data,ir_analysis=projected['summary'],normalized_ir=projected['graph'])
    target=tmp_path/'owned.dll';target.write_bytes(b'fixture');out=tmp_path/'unsupported.json'
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=str(out),reconstruct_function=identity))!=0
    assert not out.exists()
    payload=json.loads(capsys.readouterr().out)
    assert payload['function_reconstruction']['status']=='unsupported' and payload['success'] is False
    assert payload['function_reconstruction']['structured_c_source'] is None
    payload=AetherMcpDispatcher().handle_ghidra_decompile('owned.dll',reconstruct_function=identity)
    assert payload['success'] is False and payload['function_reconstruction']['status']=='unsupported'


def test_cli_selected_identity_returns_ir_and_missing_name_never_publishes(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    calls,identity=fake_export(monkeypatch,with_ir=True)
    target=tmp_path/'owned.dll';target.write_bytes(b'fixture')
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=None,ir_function=identity))==0
    assert json.loads(capsys.readouterr().out)['function_ir']['function_id']==identity
    output=tmp_path/'missing.json'
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=str(output),ir_function='absent'))!=0
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)['status']=='ir_selection_failed'


def test_summit_cannot_promote_unknown_behavior_using_a_structural_score(tmp_path):
    path=Path(__file__).resolve().parents[1]/'tools/e2e_full_sota_summit.py'
    tree=ast.parse(path.read_text(encoding='utf-8'))
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='test_ghidra_headless_and_ground_truth')
    for name in ('cjson.dll','cJSON.c'):
        target=tmp_path/'external_test_repos/cjson'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('fixture')
    result=SimpleNamespace(success=True,error_message=None,get_unique_function=lambda name:SimpleNamespace(success=True,decompiled_c='void cJSON_Delete(void){}'))
    metrics=dict(field_preservation_rate_pct=None,call_preservation_rate_pct=None,preserved_fields=[],
        structural_similarity_score_pct=25.,empirical_fidelity_score_pct=None,loop_structure_preserved=False,
        branch_structure_preserved=False,behavioral_comparison={'status':'unknown'})
    context=dict(Path=Path,PROJECT_ROOT=tmp_path,time=SimpleNamespace(time=lambda:1.),
        GhidraHeadlessBridge=lambda:SimpleNamespace(decompile_binary=lambda *a,**kw:result),
        evaluate_decompilation_against_ground_truth=lambda *a:metrics)
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),context)
    evidence=tmp_path/'evidence';evidence.mkdir()
    report=context[node.name](evidence)
    assert report['status']=='SEMANTIC_UNPROVED'
    assert report['structural_similarity_score_pct']==25.
    assert report['behavioral_comparison']['status']=='unknown'
