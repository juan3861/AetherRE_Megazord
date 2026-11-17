import json,runpy
from argparse import Namespace
from dataclasses import replace
from pathlib import Path

import pytest

import aether_re.ghidra_headless_bridge as bridge
from aether_re.ghidra_pcode_ir import analyze_high_pcode


def memory_export(monkeypatch):
    fixtures=runpy.run_path(str(Path(__file__).with_name('test_ghidra_interface_contract.py')))
    calls,identity=fixtures['fake_export'](monkeypatch,with_ir=True)
    result=bridge.GhidraHeadlessBridge().decompile_binary('own.dll');calls.clear()
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_memory.py')))['memory_ir'](True)
    checked=analyze_high_pcode(data,expected_target='a'*64,expected_address='ram:401000',evidence_sha256='b'*64)
    result.functions[identity]=replace(result.functions[identity],pcode_ir=data,ir_analysis=checked['summary'],normalized_ir=checked['graph'])
    return result,calls,identity


def test_bridge_memory_opt_in_is_separate_from_default_abstention(monkeypatch):
    result,calls,identity=memory_export(monkeypatch)
    assert result.select_reconstruction(identity)['status']=='unsupported'
    selected=result.select_reconstruction(identity,memory_model='bounded-bytes.v1')
    assert selected['status']=='complete' and selected['memory_model']['memory_writes']==1


def test_cli_and_mcp_require_explicit_model_and_pass_it_to_same_translation(tmp_path,monkeypatch,capsys):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    _,calls,identity=memory_export(monkeypatch)
    target=tmp_path/'own.dll';target.write_bytes(b'own static target')
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=None,reconstruct_function=identity,memory_model='bounded-bytes.v1'))==0
    selected=json.loads(capsys.readouterr().out)['function_reconstruction']
    assert selected['memory_model']['schema']=='bounded-bytes.v1'
    response=AetherMcpDispatcher().handle_ghidra_decompile(str(target),reconstruct_function=identity,memory_model='bounded-bytes.v1')
    assert response['success'] and response['function_reconstruction']['structured_c_source']==selected['structured_c_source']
    assert response['function_reconstruction']['binary_equivalence_proved'] is False


@pytest.mark.parametrize('model',['bounded-bytes.v1','host-pointers',True,{}])
def test_memory_configuration_is_rejected_before_backend_without_valid_selection(tmp_path,monkeypatch,capsys,model):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    _,calls,_=memory_export(monkeypatch)
    target=tmp_path/'own.dll';target.write_bytes(b'own')
    assert cmd_ghidra_decompile(Namespace(target=str(target),out=None,memory_model=model))!=0
    assert not calls
    assert AetherMcpDispatcher().handle_ghidra_decompile(str(target),memory_model=model)['success'] is False
    assert not calls


def test_universal_memory_policy_is_validated_before_intake(tmp_path,monkeypatch):
    import aether_re.pipeline as pipeline
    monkeypatch.setattr(pipeline,'prepare_case',lambda *a:pytest.fail('invalid memory request reached intake'))
    for options in [dict(native_memory_model='host'),dict(native_memory_model='bounded-bytes.v1',request_native_reconstruction=False)]:
        policy=replace(pipeline.CasePolicy.static_only(),**dict({'request_native_reconstruction':True},**options))
        with pytest.raises(ValueError,match='memory'):
            pipeline.run_universal_case(tmp_path/'absent',tmp_path/'case',policy)


def test_universal_passes_memory_hypothesis_and_keeps_debug_return_state_argument(tmp_path,monkeypatch):
    import aether_re.pipeline as pipeline
    from aether_re import pdb_dia
    context=runpy.run_path(str(Path(__file__).with_name('test_universal_debug_types.py')))
    target,result,typed,extracts,backend,options=context['owned_case'](tmp_path,monkeypatch)
    # The scalar fixture can also use the memory context to bound its steps.
    policy=replace(pipeline.CasePolicy.static_only(),request_native_reconstruction=True,native_memory_model='bounded-bytes.v1',**options)
    native=pipeline.run_universal_case(target,tmp_path/'case',policy).to_dict()['native_reconstruction']
    assert native['reconstructed_functions']==native['debug_adapted_functions']==2 and len(extracts)==1
    for item in native['functions'].values():
        report=item['reconstruction'];adapter=report['debug_return_adapter']
        assert report['memory_model']['schema']=='bounded-bytes.v1'
        assert 'struct aether_memory *aether_memory' in adapter['structured_c_source']
        assert 'aether_recovered(aether_memory, ' in adapter['structured_c_source']
        assert adapter['runtime_parameters']==report['runtime_parameters']
