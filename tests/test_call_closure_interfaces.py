"""Call composition is opt-in and invalid configurations stop before Ghidra."""
from argparse import Namespace
from pathlib import Path
import json,runpy
import pytest
import aether_re.ghidra_headless_bridge as bridge

f=runpy.run_path(str(Path(__file__).with_name('test_call_closure.py')))
MODEL='bounded-direct-pure-calls.v1'


def fake_bridge(monkeypatch,tmp_path):
    export=f['make_export'](tmp_path);calls=[]
    class Backend:
        def decompile_binary(self,target,**options):
            calls.append(options);export.binary_path=str(target);return export
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    return export,calls


def test_bridge_selects_explicit_call_model(tmp_path):
    export=f['make_export'](tmp_path)
    report=export.select_reconstruction('caller',memory_model='bounded-bytes.v2',call_model=MODEL)
    assert report['status']=='complete' and report['call_model']['schema']==MODEL
    assert report['abi_recovered'] is report['binary_equivalence_proved'] is False


@pytest.mark.parametrize('model,memory,error',[(True,'bounded-bytes.v2','ghidra_call_model_invalid'),
    ('unknown','bounded-bytes.v2','ghidra_call_model_invalid'),(MODEL,None,'requires_sparse_reconstruction'),
    (MODEL,'bounded-bytes.v1','requires_sparse_reconstruction')])
def test_bridge_requires_declared_sparse_runtime_and_known_model(tmp_path,model,memory,error):
    export=f['make_export'](tmp_path)
    with pytest.raises(ValueError,match=error):export.select_reconstruction('caller',memory_model=memory,call_model=model)


def test_cli_publishes_explicit_call_model(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    export,calls=fake_bridge(monkeypatch,tmp_path)
    code=cmd_ghidra_decompile(Namespace(target=export.binary_path,out=None,reconstruct_function='caller',memory_model='bounded-bytes.v2',call_model=MODEL))
    assert code==0
    payload=json.loads(capsys.readouterr().out)
    assert payload['function_reconstruction']['call_model']['schema']==MODEL and len(calls)==1


def test_bad_cli_call_configuration_cannot_start_a_worker(monkeypatch,tmp_path,capsys):
    from megazord import cmd_ghidra_decompile
    export,calls=fake_bridge(monkeypatch,tmp_path)
    code=cmd_ghidra_decompile(Namespace(target=export.binary_path,out=None,reconstruct_function='caller',call_model=MODEL))
    assert code!=0 and not calls
    assert json.loads(capsys.readouterr().out)['status']=='call_configuration_invalid'


def test_mcp_publishes_call_model_and_rejects_bad_config_before_worker(monkeypatch,tmp_path):
    from aether_re.mcp_server import AetherMcpDispatcher
    export,calls=fake_bridge(monkeypatch,tmp_path)
    dispatcher=AetherMcpDispatcher()
    invalid=dispatcher.handle_ghidra_decompile(export.binary_path,reconstruct_function='caller',call_model=MODEL)
    assert invalid['success'] is False and invalid['status']=='call_configuration_invalid' and not calls
    payload=dispatcher.handle_ghidra_decompile(export.binary_path,reconstruct_function='caller',memory_model='bounded-bytes.v2',call_model=MODEL)
    assert payload['success'] and payload['function_reconstruction']['call_model']['schema']==MODEL


def test_universal_policy_cannot_silently_ignore_a_call_model():
    from aether_re.pipeline import CasePolicy
    from aether_re.kernel_contracts import AuthorizationPolicy
    authorization=AuthorizationPolicy.from_dict(dict(schema='authorization-policy.v1',basis='owner',principal='unit-test',scope=['static-analysis']))
    with pytest.raises(ValueError,match='requires_sparse_reconstruction'):
        CasePolicy(authorization=authorization,native_call_model=MODEL).validate_native_memory()
    policy=CasePolicy(authorization=authorization,request_native_reconstruction=True,native_memory_model='bounded-bytes.v2',native_call_model=MODEL)
    policy.validate_native_memory()
