import copy,json
from pathlib import Path
import pytest
from aether_re.frame_derivation import _digest,derive_frame_program

def inputs():
    p=json.loads((Path(__file__).parent/'fixtures/frame_program_ir.json').read_text(encoding='utf-8'))
    return p['root'],p['callee'],p['frame_fact']

def api():
    from aether_re.frame_relocation import derive_relocatable_frame,check_frame_relocation,specialize_frame_relocation
    return derive_relocatable_frame,check_frame_relocation,specialize_frame_relocation

def test_symbolic_ambient_preserves_source_and_transport():
    derive,check,_=api();args=inputs();before=copy.deepcopy(args);packet=derive(*args)
    assert args==before
    assert packet['status']=='conditional_model' and packet['placement_domain_enforced'] is False
    node=next(n for n in packet['derived_ir']['varnodes'] if n['id']==args[2]['ambient_varnode'])
    assert node==next(n for n in args[0]['pcode_ir']['varnodes'] if n['id']==node['id'])
    assert node['input'] and node['kind']=='register'
    assert check(*args,packet)['memory_links']
    assert not packet['native_frame_fact_verified'] and not packet['production_admission']

@pytest.mark.parametrize('base',[0,16,0x100000,0x300000,(1<<64)-4096])
def test_whole_specialized_ir_equals_existing_derivation(base):
    derive,_,specialize=api();root,callee,fact=inputs();packet=derive(root,callee,fact)
    actual=specialize(root,callee,fact,packet,object_base=base)
    expected=derive_frame_program(root['pcode_ir'],callee,fact,object_base=base)
    assert actual==expected['derived_ir']

@pytest.mark.parametrize('mutation',['operand','opcode','ambient','context','proof'])
def test_rehashed_tampering_cannot_inherit_transport(mutation):
    derive,check,_=api();root,callee,fact=inputs();packet=derive(root,callee,fact)
    ir=packet['derived_ir']
    if mutation=='operand':ir['operations'][0]['inputs']=list(reversed(ir['operations'][0]['inputs']))
    elif mutation=='opcode':ir['operations'][0]['opcode']='COPY'
    elif mutation=='ambient':next(n for n in ir['varnodes'] if n['id']==fact['ambient_varnode'])['offset']='40'
    elif mutation=='context':ir['context']['compiler_spec_id']='gcc'
    else:packet['static_provenance']['frame']['object_bytes']+=1
    packet['relocation']['symbolic_sha256']=_digest(ir)
    with pytest.raises(ValueError):check(root,callee,fact,packet)

@pytest.mark.parametrize('base',[True,-16,17,1<<64,(1<<64)-16])
def test_invalid_runtime_placement_refuses(base):
    derive,_,specialize=api();args=inputs();packet=derive(*args)
    with pytest.raises(ValueError):specialize(*args,packet,object_base=base)

@pytest.mark.parametrize('mutation',['extra_claim','nested_claim','nested_extra_claim','source_blocks'])
def test_provenance_cannot_add_unchecked_claims(mutation):
    derive,check,_=api();args=inputs();packet=derive(*args)
    if mutation=='extra_claim':packet['gate_passed']=True
    elif mutation=='nested_claim':packet['static_provenance']['production_admission']=True
    elif mutation=='nested_extra_claim':packet['static_provenance']['gate_passed']=True
    else:packet['static_provenance']['source_blocks']['caller']=[]
    with pytest.raises(ValueError):check(*args,packet)

def test_emitter_uses_symbolic_ir_input_without_textual_c_relocation():
    from aether_re.frame_relocation import emit_relocatable_frame_body
    from aether_re.ghidra_pcode_c import reconstruct_high_pcode
    root,callee,fact=inputs();before=copy.deepcopy((root,callee,fact))
    body=emit_relocatable_frame_body(root,callee,fact)
    assert (root,callee,fact)==before
    assert body['status']=='conditional_body' and body['runtime_domain_guard_required'] is True
    emitted=body['emitted'];assert emitted['status']=='complete' and emitted['linkage']=='internal'
    matches=[b for b in emitted['input_bindings'] if b['varnode']==fact['ambient_varnode']]
    assert len(matches)==1 and body['abstract_entry_parameter']==matches[0]['parameter']
    direct=reconstruct_high_pcode(body['packet']['derived_ir'],expected_target=root['pcode_ir']['target_sha256'],
        expected_address=root['pcode_ir']['function_address'],evidence_sha256=_digest(body['packet']['derived_ir']),
        function_name='aether_relocatable_body',memory_model='bounded-bytes.v2',internal_linkage=True)
    assert emitted==direct
