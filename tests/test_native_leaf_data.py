import copy,hashlib,importlib.util,json,runpy
from pathlib import Path
import pytest
P=Path(__file__).parent;ROOT=P.parent
BODY=bytes.fromhex('488d42054983f007488901488bc14c894108c3')

def module():
    from aether_re import native_leaf_data
    return native_leaf_data

def inputs():
    helper=runpy.run_path(str(ROOT/'tests/test_native_frame_address.py'))
    raw,data,high=helper['sample']();root=dict(pcode_ir=data,high_parameter_observation=high)
    callee=json.loads((ROOT/'tests/fixtures/frame_program_ir.json').read_text())['callee']
    raw[512+0x270:512+0x290]=BODY+b'\xcc'*(32-len(BODY))
    language=copy.deepcopy(helper['LANGUAGE'])
    language['ia.sinc']+=b'\ndefine register offset=0x80 size=8 [ R8 R9 R10 R11 R12 R13 R14 R15 ];'
    bind(raw,root,callee)
    return bytes(raw),root,callee,language

def bind(raw,root,callee):
    digest=hashlib.sha256(raw).hexdigest()
    for info in (root,callee):
        info['pcode_ir']['target_sha256']=info['high_parameter_observation']['target_sha256']=digest

def observe(args):
    raw,root,callee,language=args
    return module().observe_leaf_data_effects(root=root,callee=callee,target_bytes=raw,language_sources=language,object_bytes=16)

def test_observes_ordered_native_ir_data_effects_without_admission():
    args=inputs();before=copy.deepcopy(args);report=observe(args)
    assert args==before and report['status']=='observed'
    assert report['native_instruction_count']==6 and report['ir_operation_count']==7
    assert report['data_observables_equal'] and len(report['stores'])==2
    assert report['required_object_bytes']==16
    for field in ('binary_equivalence_proved','native_profile_admitted','abi_recovered','function_extent_proved','target_executed'):
        assert report[field] is False

@pytest.mark.parametrize('offset,value',[(3,6),(7,8),(11,0xD0),(16,16),(18,0x90),(19,0xC3)])
def test_rebound_native_mutation_refuses(offset,value):
    raw,root,callee,language=inputs();raw=bytearray(raw);raw[512+0x270+offset]=value
    bind(raw,root,callee)
    with pytest.raises(ValueError):observe((bytes(raw),root,callee,language))

@pytest.mark.parametrize('part',['constant','store_width','store_address','return','order','register'])
def test_rebound_ir_mutation_refuses(part):
    raw,root,callee,language=inputs();data=callee['pcode_ir'];nodes={n['id']:n for n in data['varnodes']}
    if part=='constant':nodes['v2']['offset']='6'
    elif part=='store_width':nodes['v0']['size']=4
    elif part=='store_address':nodes['v65']['offset']='10'
    elif part=='return':data['operations'][-1]['inputs'][1]='v0'
    elif part=='order':data['operations'][2]['sequence']['pc']='ram:18000127e'
    else:nodes['v58']['offset']='18'
    with pytest.raises(ValueError):observe((raw,root,callee,language))

@pytest.mark.parametrize('declaration',[b'',b'define register offset=0x88 size=8 [ R8 R9 R10 R11 R12 R13 R14 R15 ];',
    b'define register offset=0x80 size=8 [ R9 R8 R10 R11 R12 R13 R14 R15 ];',
    b'define register offset=0x80 size=8 [ R8 R9 R10 R11 R12 R13 R14 R15 ];\ndefine register offset=0x80 size=8 [ R8 R9 R10 R11 R12 R13 R14 R15 ];'])
def test_missing_or_conflicting_extended_register_layout_refuses(declaration):
    raw,root,callee,language=inputs();language['ia.sinc']=language['ia.sinc'].split(b'\n')[0]+b'\n'+declaration
    with pytest.raises(ValueError):observe((raw,root,callee,language))

def test_target_identity_and_direct_call_identity_refuse():
    raw,root,callee,language=inputs();callee['pcode_ir']['function_address']='ram:180001271'
    with pytest.raises(ValueError):observe((raw,root,callee,language))

def test_matching_ir_and_native_pointer_rebinding_cannot_claim_original_frame_extent():
    raw,root,callee,language=inputs();raw=bytearray(raw)
    # mov rcx,rdx; then the same data body. Both interpretations agree, but
    # the writes are no longer through the entry object's pointer.
    code=bytes.fromhex('488bca')+BODY
    raw[512+0x270:512+0x290]=code+b'\xcc'*(32-len(code))
    ir=callee['pcode_ir'];replacement='v_pointer_rebound'
    for op in ir['operations']:
        op['inputs']=[replacement if node=='v57' else node for node in op['inputs']]
        op['sequence']['pc']='ram:'+format(int(op['sequence']['pc'][4:],16)+3,'x')
    node=copy.deepcopy(next(n for n in ir['varnodes'] if n['id']=='v34'))
    node.update(id=replacement,offset='8',definition='o_pointer_rebound');ir['varnodes'].append(node)
    op=dict(id='o_pointer_rebound',opcode='COPY',sequence=dict(pc='ram:180001270',time=0,order=0),
        inputs=['v58'],output=replacement)
    ir['operations'].insert(0,op)
    for index,operation in enumerate(ir['operations']):operation['sequence']['order']=index
    ir['blocks'][0]['operations'].insert(0,'o_pointer_rebound');ir['blocks'][0]['stop']='ram:180001285'
    bind(raw,root,callee)
    with pytest.raises(ValueError,match='entry_object_pointer'):
        observe((bytes(raw),root,callee,language))

def test_requested_extent_must_contain_all_observed_stores():
    raw,root,callee,language=inputs()
    with pytest.raises(ValueError,match='requested_extent'):
        module().observe_leaf_data_effects(root=root,callee=callee,target_bytes=raw,language_sources=language,object_bytes=8)
