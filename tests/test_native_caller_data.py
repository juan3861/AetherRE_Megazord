import copy,importlib.util
from pathlib import Path
import pytest
from test_native_leaf_data import inputs,bind,BODY
P=Path(__file__).parent

def module():
    from aether_re import native_caller_data
    return native_caller_data

def observe(args):
    raw,root,callee,language=args
    return module().observe_pair_data_effects(root=root,callee=callee,target_bytes=raw,language_sources=language,object_bytes=16)

def test_full_linear_caller_data_and_stack_restoration():
    args=inputs();before=copy.deepcopy(args);report=observe(args)
    assert args==before and report['status']=='observed'
    assert report['ordered_data_events_equal'] and report['return_data_equal']
    assert report['caller_rsp_restored_before_ret'] and report['callee_rsp_preserved_before_ret']
    assert len(report['events'])==4 and report['callee_instruction_count']==6
    assert report['caller_instruction_count']==10
    assert not report['binary_equivalence_proved'] and not report['native_profile_admitted']

@pytest.mark.parametrize('offset,value',[(6,0xC1),(22,0x01),(26,0),(29,0x03),(33,40),(34,0x90)])
def test_rebound_caller_native_changes_refuse(offset,value):
    raw,root,callee,language=inputs();raw=bytearray(raw);raw[512+0x290+offset]=value;bind(raw,root,callee)
    with pytest.raises(ValueError):observe((bytes(raw),root,callee,language))

@pytest.mark.parametrize('part',['call_arguments','load_address','load_width','return','pc','load_before_write'])
def test_rebound_caller_ir_changes_refuse(part):
    raw,root,callee,language=inputs();ir=root['pcode_ir'];nodes={n['id']:n for n in ir['varnodes']}
    if part=='call_arguments':ir['operations'][1]['inputs'][2:4]=list(reversed(ir['operations'][1]['inputs'][2:4]))
    elif part=='load_address':nodes['v184']['offset']='0'
    elif part=='load_width':nodes['v51']['size']=4
    elif part=='return':ir['operations'][-1]['inputs'][1]='v43'
    elif part=='pc':ir['operations'][3]['sequence']['pc']='ram:1800012ab'
    else:nodes['v184']['offset']='10'
    with pytest.raises(ValueError):observe((raw,root,callee,language))

def test_coherent_native_and_ir_load_change_is_compared_instead_of_hardcoded():
    raw,root,callee,language=inputs();raw=bytearray(raw);raw[512+0x290+26]=0
    next(n for n in root['pcode_ir']['varnodes'] if n['id']=='v184')['offset']='0'
    bind(raw,root,callee);report=observe((bytes(raw),root,callee,language))
    assert report['return_expression']==('constant',0)

def test_balanced_larger_stack_allocation_preserves_data_witness():
    raw,root,callee,language=inputs();raw=bytearray(raw)
    for offset,value in [(3,72),(14,48),(33,72)]:raw[512+0x290+offset]=value
    bind(raw,root,callee);report=observe((bytes(raw),root,callee,language))
    assert report['caller_rsp_restored_before_ret'] and report['stack_allocation_bytes']==72

def test_callee_rsp_clobber_is_not_hidden_by_data_only_leaf_witness():
    raw,root,callee,language=inputs();raw=bytearray(raw)
    code=bytes.fromhex('488be2')+BODY
    raw[512+0x270:512+0x290]=code+b'\xcc'*(32-len(code))
    ir=callee['pcode_ir']
    for op in ir['operations']:op['sequence']['pc']='ram:'+format(int(op['sequence']['pc'][4:],16)+3,'x')
    node=copy.deepcopy(next(n for n in ir['varnodes'] if n['id']=='v34'))
    node.update(id='v_rsp_clobber',offset='20',definition='o_rsp_clobber');ir['varnodes'].append(node)
    ir['operations'].insert(0,dict(id='o_rsp_clobber',opcode='COPY',sequence=dict(pc='ram:180001270',time=0,order=0),inputs=['v58'],output='v_rsp_clobber'))
    for index,op in enumerate(ir['operations']):op['sequence']['order']=index
    ir['blocks'][0]['operations'].insert(0,'o_rsp_clobber');ir['blocks'][0]['stop']='ram:180001285'
    bind(raw,root,callee)
    with pytest.raises(ValueError,match='callee_rsp'):
        observe((bytes(raw),root,callee,language))

def test_coherent_reads_after_stack_release_refuse_lifetime_assumption():
    raw,root,callee,language=inputs();raw=bytearray(raw);at=512+0x290
    old=bytes(raw[at:at+35]);tail=old[20:]
    # Hoist ADD RSP,56 ahead of both loads; High IR is moved to matching PCs.
    new=old[:20]+tail[10:14]+tail[:10]+tail[14:]
    assert len(new)==35;raw[at:at+35]=new
    for op in root['pcode_ir']['operations']:
        if op['opcode'] in ('LOAD','PTRADD','INT_XOR'):
            op['sequence']['pc']='ram:'+format(int(op['sequence']['pc'][4:],16)+4,'x')
    bind(raw,root,callee)
    with pytest.raises(ValueError,match='stack_object_lifetime'):
        observe((bytes(raw),root,callee,language))

def test_arithmetic_after_stack_release_with_prior_loads_is_valid():
    raw,root,callee,language=inputs();raw=bytearray(raw);at=512+0x290;old=bytes(raw[at:at+35])
    raw[at:at+35]=old[:27]+old[30:34]+old[27:30]+old[34:]
    next(op for op in root['pcode_ir']['operations'] if op['opcode']=='INT_XOR')['sequence']['pc']='ram:1800012af'
    bind(raw,root,callee);report=observe((bytes(raw),root,callee,language))
    assert report['no_load_after_stack_release'] and report['return_data_equal']

def test_partially_overlapping_callee_words_are_outside_memory_model():
    raw,root,callee,language=inputs();raw=bytearray(raw);raw[512+0x270+17]=4
    next(n for n in callee['pcode_ir']['varnodes'] if n['id']=='v65')['offset']='4'
    bind(raw,root,callee)
    with pytest.raises(ValueError,match='aligned_object_store'):
        observe((bytes(raw),root,callee,language))

def test_native_narrow_load_is_refused():
    raw,root,callee,language=inputs();raw=bytearray(raw);raw[512+0x290+20]=0x40
    bind(raw,root,callee)
    with pytest.raises(ValueError):observe((bytes(raw),root,callee,language))
