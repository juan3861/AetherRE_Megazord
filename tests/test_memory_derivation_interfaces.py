import hashlib,runpy,struct
from dataclasses import replace,FrozenInstanceError
from pathlib import Path
import pytest
import aether_re.native_memory_custody as custody

def owned_export(tmp_path,monkeypatch,profile='pe',sparse=False):
    from aether_re.intake import IntakeRequest,prepare_case
    from aether_re.kernel_contracts import AuthorizationPolicy,IntakeLimits
    import aether_re.ghidra_headless_bridge as bridge
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    tests=Path(__file__).parent
    data=runpy.run_path(str(tests/('test_pe_memory_map.py' if profile=='pe' else 'test_elf_memory_map.py')))['fixture']()
    if profile=='pe':struct.pack_into('<Q',data,152+24,0x400000)
    source=tmp_path/'own.dll';source.write_bytes(data);digest=hashlib.sha256(data).hexdigest()
    auth=AuthorizationPolicy.from_dict(dict(schema='authorization-policy.v1',basis='owner',principal='local-owner',scope=['static-analysis']))
    parent=prepare_case(IntakeRequest(source,tmp_path/'input',auth,IntakeLimits(),False)).manifest_path.parent
    bundle=tmp_path/'map';custody.publish_memory_derivation(parent,bundle,profile=profile,space_id=0,sparse=sparse)
    calls,identity=runpy.run_path(str(tests/'test_ghidra_interface_contract.py'))['fake_export'](monkeypatch,with_ir=True)
    result=bridge.GhidraHeadlessBridge().decompile_binary(source);calls.clear();info=result.functions[identity]
    ir=info.pcode_ir;ir['target_sha256']=digest
    checked=analyze_high_pcode(ir,expected_target=digest,expected_address=info.address,evidence_sha256='b'*64)
    info=replace(info,pcode_ir=ir,normalized_ir=checked['graph'],ir_analysis=checked['summary'])
    result=replace(result,target_sha256=digest,functions={identity:info})
    return source,bundle,result,identity,calls

def test_admitted_context_is_immutable_and_cannot_be_cross_bound(tmp_path,monkeypatch):
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    context=custody.admit_memory_context(bundle)
    expected=dict(target_sha256=result.target_sha256,space_id=0,image_base=0x400000,bits=64,endian='little')
    assert context.bind(**expected)['admission_scope']=='verified_bundle_snapshot'
    with pytest.raises((FrozenInstanceError,AttributeError)):context.directory='different'
    with pytest.raises(ValueError):context.bind(**{**expected,'target_sha256':'0'*64})

def test_bridge_binds_reference_and_reuses_one_admission(tmp_path,monkeypatch):
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    context=custody.admit_memory_context(bundle)
    monkeypatch.setattr(custody,'admit_memory_context',lambda *a:pytest.fail('cached admission repeated'))
    selected=result.select_reconstruction(identity,memory_model='bounded-bytes.v1',_memory_context=context)
    assert selected['memory_binding']['status']=='bound'
    assert selected['memory_binding']['context']['target_sha256']==result.target_sha256
    assert selected['memory_binding']['contiguous_runtime_compatible'] is True
    assert selected['binary_equivalence_proved'] is False

def test_bridge_reference_requires_explicit_memory_model(tmp_path,monkeypatch):
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    with pytest.raises(ValueError,match='memory'):result.select_reconstruction(identity,memory_derivation=bundle)
    selected=result.select_reconstruction(identity,memory_derivation=bundle,memory_model='bounded-bytes.v1')
    assert selected['memory_binding']['context']['base']==0x400000

def test_serialized_dict_cannot_impersonate_admitted_context(tmp_path,monkeypatch):
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    with pytest.raises(ValueError,match='memory'):result.select_reconstruction(identity,memory_model='bounded-bytes.v1',_memory_context={'target_sha256':result.target_sha256})

def test_admission_refuses_receipt_changed_during_verification(tmp_path,monkeypatch):
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    verify=custody.verify_memory_derivation
    def changed(directory):
        response=verify(directory)
        path=Path(directory)/'custody-receipt.json';path.write_bytes(path.read_bytes()+b' ')
        return response
    monkeypatch.setattr(custody,'verify_memory_derivation',changed)
    with pytest.raises(ValueError,match='changed'):custody.admit_memory_context(bundle)

@pytest.mark.parametrize('model',['bounded-bytes.v1','bounded-bytes.v2'])
def test_cli_and_mcp_forward_verified_reference(tmp_path,monkeypatch,capsys,model):
    from argparse import Namespace
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    import aether_re.ghidra_headless_bridge as bridge
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    class Backend:
        def decompile_binary(self,*a,**k):calls.append(k);return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    args=Namespace(target=str(source),out=None,reconstruct_function=identity,memory_model=model,memory_derivation=str(bundle))
    assert cmd_ghidra_decompile(args)==0
    cli=__import__('json').loads(capsys.readouterr().out)['function_reconstruction']
    assert cli['memory_binding']['context']['target_sha256']==result.target_sha256
    mcp=AetherMcpDispatcher().handle_ghidra_decompile(str(source),reconstruct_function=identity,memory_model=model,memory_derivation=str(bundle))
    assert mcp['success'] and mcp['function_reconstruction']['memory_binding']==cli['memory_binding']

@pytest.mark.parametrize('model',['bounded-bytes.v1','bounded-bytes.v2'])
def test_universal_admits_reference_once_and_reuses_it(tmp_path,monkeypatch,model):
    from aether_re.pipeline import CasePolicy,run_universal_case
    import aether_re.ghidra_headless_bridge as bridge
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    class Backend:
        def decompile_binary(self,*a,**k):calls.append(k);return result
    monkeypatch.setattr(bridge,'GhidraHeadlessBridge',Backend)
    admit=custody.admit_memory_context;admissions=[]
    def counted(path):admissions.append(str(path));return admit(path)
    monkeypatch.setattr(custody,'admit_memory_context',counted)
    policy=replace(CasePolicy.static_only(),request_native_reconstruction=True,native_memory_model=model,native_memory_derivation=str(bundle))
    native=run_universal_case(source,tmp_path/'case',policy).native_reconstruction
    assert len(admissions)==1 and native['reconstructed_functions']==1
    assert native['functions'][identity]['reconstruction']['memory_binding']['status']=='bound'

def test_reference_config_is_rejected_before_backend(tmp_path,monkeypatch,capsys):
    from argparse import Namespace
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    for ref,model,selector in ((True,'bounded-bytes.v1',identity),({},'bounded-bytes.v1',identity),(str(bundle),None,identity),(str(bundle),'bounded-bytes.v1',None)):
        args=Namespace(target=str(source),out=None,reconstruct_function=selector,memory_model=model,memory_derivation=ref)
        assert cmd_ghidra_decompile(args)!=0 and not calls
        assert AetherMcpDispatcher().handle_ghidra_decompile(str(source),reconstruct_function=selector,memory_model=model,memory_derivation=ref)['success'] is False
        assert not calls

def test_unsupported_translation_preserves_ir_with_unavailable_memory_binding(tmp_path,monkeypatch):
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    info=result.functions[identity];ir=info.pcode_ir;ir['varnodes'][0]['persistent']=True
    checked=analyze_high_pcode(ir,expected_target=result.target_sha256,expected_address=info.address,evidence_sha256='b'*64)
    result.functions[identity]=replace(info,pcode_ir=ir,normalized_ir=checked['graph'],ir_analysis=checked['summary'])
    selected=result.select_reconstruction(identity,memory_model='bounded-bytes.v1',memory_derivation=bundle)
    assert selected['status']=='unsupported' and selected['memory_binding']['status']=='unavailable'
    assert result.select_ir_graph(identity)==checked['graph']

@pytest.mark.parametrize('change',['base','space','bits','endian'])
def test_observed_ir_context_must_match_map(tmp_path,monkeypatch,change):
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch)
    info=result.functions[identity];ir=info.pcode_ir;context=ir['context']
    if change=='base':context['image_base']='ram:500000'
    elif change=='space':context['spaces'][0]['id']=433
    elif change=='bits':context['spaces'][0]['bits']=32
    else:context['endian']='big'
    checked=analyze_high_pcode(ir,expected_target=result.target_sha256,expected_address=info.address,evidence_sha256='b'*64)
    result.functions[identity]=replace(info,pcode_ir=ir,normalized_ir=checked['graph'],ir_analysis=checked['summary'])
    with pytest.raises(ValueError,match='memory_context_mismatch'):
        result.select_reconstruction(identity,memory_model='bounded-bytes.v1',memory_derivation=bundle)

def test_sparse_map_is_explicitly_refused_by_contiguous_runtime(tmp_path,monkeypatch):
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch,profile='elf',sparse=True)
    with pytest.raises(ValueError,match='requires_sparse_runtime'):
        result.select_reconstruction(identity,memory_model='bounded-bytes.v1',memory_derivation=bundle)

def test_sparse_map_accepts_explicit_sparse_runtime(tmp_path,monkeypatch):
    source,bundle,result,identity,calls=owned_export(tmp_path,monkeypatch,profile='elf',sparse=True)
    selected=result.select_reconstruction(identity,memory_model='bounded-bytes.v2',memory_derivation=bundle)
    assert selected['status']=='complete' and selected['memory_binding']['runtime_compatible'] is True
    assert selected['memory_binding']['contiguous_runtime_compatible'] is False
    assert selected['runtime_parameters']==[dict(name='aether_memory',c_type='struct aether_sparse_memory *')]
