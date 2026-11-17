"""Known PE layout and instruction encodings are independent of the observer."""
import copy,hashlib,json,struct
from pathlib import Path
import pytest

BASE=0x180000000
LANGUAGE={'ia.sinc':b'define register offset=0 size=8 [ RAX RCX RDX RBX RSP RBP RSI RDI ];',
          'x86.slaspec':b'@include "ia.sinc"', 'x86-64.slaspec':b'@include "x86.slaspec"'}


def sample(*,allocation=56,offset=-24,argument=1,through_rax=False):
    source=json.loads((Path(__file__).parent/'fixtures/frame_program_ir.json').read_text())['root']
    data=source['pcode_ir'];high=source['high_parameter_observation']
    raw=bytearray(2560);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,128)
    raw[128:132]=b'PE\0\0';struct.pack_into('<HHIIIHH',raw,132,0x8664,1,0,0,0,240,0x2022)
    o=152;struct.pack_into('<H',raw,o,0x20b);struct.pack_into('<Q',raw,o+24,BASE)
    struct.pack_into('<II',raw,o+32,4096,512);struct.pack_into('<II',raw,o+56,8192,512)
    struct.pack_into('<I',raw,o+108,16);struct.pack_into('<II',raw,o+112+3*8,0x1700,12)
    s=o+240;raw[s:s+8]=b'.text\0\0\0';struct.pack_into('<IIII',raw,s+8,2048,4096,2048,512)
    struct.pack_into('<I',raw,s+36,0x60000020)
    # sub rsp,imm8; mov r8,rdx; mov rdx,rcx; lea ARG,[rsp+disp8]; call rel32.
    lea='488d4424' if through_rax else {1:'488d4c24',2:'488d5424',3:'4c8d4424',4:'4c8d4c24'}[argument]
    code=bytes.fromhex('4883ec')+bytes([allocation])+bytes.fromhex('4c8bc2488bd1'+lea)+bytes([allocation+offset])
    if through_rax:code+=bytes.fromhex({1:'488bc8',2:'488bd0',3:'4c8bc0',4:'4c8bc8'}[argument])
    shift=3 if through_rax else 0
    code+=b'\xe8'+struct.pack('<i',0x1270-(0x12a4+shift))+bytes.fromhex('488b10488b40084833c24883c4')+bytes([allocation])+b'\xc3'
    assert len(code)==35+shift
    raw[512+0x290:512+0x290+len(code)]=code;raw[512+0x270]=0xc3
    struct.pack_into('<III',raw,512+0x700,0x1290,0x12b3+shift,0x1710);raw[512+0x710]=1
    if shift:
        for operation in data['operations'][1:]:
            operation['sequence']['pc']='ram:'+format(int(operation['sequence']['pc'].split(':')[1],16)+shift,'x')
        data['blocks'][0]['stop']='ram:'+format(int(data['blocks'][0]['stop'].split(':')[1],16)+shift,'x')
    nodes={node['id']:node for node in data['varnodes']};nodes['v181']['offset']=format(offset&((1<<64)-1),'x')
    call=next(op for op in data['operations'] if op['opcode']=='CALL')
    if argument<=3:call['inputs'][1],call['inputs'][argument]=call['inputs'][argument],call['inputs'][1]
    else:call['inputs']=[call['inputs'][0],'v122','v123','v122','v30']
    rebind(raw,data,high)
    return raw,data,high


def rebind(raw,data,high):
    digest=hashlib.sha256(raw).hexdigest();data['target_sha256']=high['target_sha256']=digest


def observe(raw,data,high,extent=16,language=None):
    from aether_re.native_frame_address import observe_frame_address
    return observe_frame_address(data=data,high=high,target_bytes=bytes(raw),
        language_sources=LANGUAGE if language is None else language,object_bytes=extent)


@pytest.mark.parametrize('allocation,offset,extent',[(56,-24,16),(56,-8,8),(88,-40,24)])
def test_observes_address_pc_range_and_explicit_extent(allocation,offset,extent):
    raw,data,high=sample(allocation=allocation,offset=offset);before=copy.deepcopy((raw,data,high,LANGUAGE))
    result=observe(raw,data,high,extent)
    assert result['status']=='observed' and result['native_address_prefix_observed'] is True
    assert result['entry_rsp_offset']==offset and result['allocated_bytes']==allocation
    assert result['requested_object_bytes']==extent and result['native_argument_register']=='rcx'
    assert result['function_address']==data['function_address'] and result['target_sha256']==hashlib.sha256(raw).hexdigest()
    assert result['native_code_sha256']==hashlib.sha256(raw[512+0x290:512+0x2b3]).hexdigest()
    assert result['pointer_pc']=='ram:18000129a' and result['call_pc']=='ram:18000129f'
    assert result['native_function_end_exclusive']=='ram:1800012b3'
    for key in ('native_frame_fact_verified','production_admission','callee_effect_extent_proved','abi_recovered',
                'original_source_recovered','target_executed','language_toolchain_authenticity_proved'):
        assert result[key] is False
    assert (raw,data,high,LANGUAGE)==before


@pytest.mark.parametrize('argument,register',[(1,'rcx'),(2,'rdx'),(3,'r8'),(4,'r9')])
def test_pointer_argument_is_resolved_from_ir_and_native_register(argument,register):
    raw,data,high=sample(argument=argument);result=observe(raw,data,high)
    assert result['call_argument_index']==argument and result['native_argument_register']==register


@pytest.mark.parametrize('argument,register',[(1,'rcx'),(2,'rdx'),(3,'r8'),(4,'r9')])
def test_lea_result_may_reach_argument_through_a_64bit_register_copy(argument,register):
    raw,data,high=sample(argument=argument,through_rax=True);result=observe(raw,data,high)
    assert result['native_argument_register']==register and result['pointer_native_register']=='rax'
    assert result['call_pc']=='ram:1800012a2' and result['entry_rsp_offset']==-24


@pytest.mark.parametrize('replacement',['488bca','8bc890'])
def test_unknown_or_narrow_argument_copy_refuses(replacement):
    raw,data,high=sample(through_rax=True);raw[512+0x29f:512+0x2a2]=bytes.fromhex(replacement);rebind(raw,data,high)
    with pytest.raises(ValueError):observe(raw,data,high)


def test_role_ids_and_block_names_are_not_fixture_constants():
    raw,data,high=sample();node_ids={n['id']:'node_'+n['id'] for n in data['varnodes']};op_ids={o['id']:'operation_'+o['id'] for o in data['operations']}
    for node in data['varnodes']:
        node['id']=node_ids[node['id']]
        if 'definition' in node:node['definition']=op_ids[node['definition']]
    for op in data['operations']:
        op['id']=op_ids[op['id']];op['inputs']=[node_ids[i] for i in op['inputs']]
        if 'output' in op:op['output']=node_ids[op['output']]
    data['entry_block']=data['blocks'][0]['id']='entry_observed'
    data['blocks'][0]['operations']=[op['id'] for op in data['operations']]
    for parameter in high['parameters']:
        parameter['instances']['observed']=[node_ids[i] for i in parameter['instances']['observed']]
    result=observe(raw,data,high)
    assert result['ambient_varnode']=='node_v160' and result['pointer_operation']=='operation_o0'


@pytest.mark.parametrize('mutation',['target','pointer_pc','call_pc','ambient','pointer_width','high_target','branch','offset',
    'call_target','prefix_opcode','extent_metadata','section_permissions','section_overlap','callee_unbacked'])
def test_disagreement_or_unsupported_prefix_refuses(mutation):
    raw,data,high=sample();nodes={n['id']:n for n in data['varnodes']}
    if mutation=='target':raw[-1]^=1
    elif mutation=='pointer_pc':data['operations'][0]['sequence']['pc']='ram:18000129b'
    elif mutation=='call_pc':data['operations'][1]['sequence']['pc']='ram:1800012a0'
    elif mutation=='ambient':nodes['v160']['offset']='28'
    elif mutation=='pointer_width':nodes['v181']['size']=4
    elif mutation=='high_target':high['target_sha256']='0'*64
    elif mutation=='branch':data['blocks'][0]['successors']=['b0'];data['blocks'][0]['predecessors']=['b0']
    elif mutation=='offset':nodes['v181']['offset']=format((-16)&((1<<64)-1),'x')
    elif mutation=='call_target':struct.pack_into('<i',raw,512+0x2a0,0x1271-0x12a4);rebind(raw,data,high)
    elif mutation=='prefix_opcode':raw[512+0x294:512+0x297]=bytes.fromhex('4833c9');rebind(raw,data,high)
    elif mutation=='extent_metadata':struct.pack_into('<I',raw,512+0x704,0x3000);rebind(raw,data,high)
    elif mutation=='section_permissions':struct.pack_into('<I',raw,152+240+36,0x40000040);rebind(raw,data,high)
    elif mutation=='section_overlap':
        struct.pack_into('<H',raw,134,2);raw[432:472]=raw[392:432];rebind(raw,data,high)
    elif mutation=='callee_unbacked':
        nodes['v42']['offset']=format(BASE+0x3000,'x');struct.pack_into('<i',raw,512+0x2a0,0x3000-0x12a4);rebind(raw,data,high)
    with pytest.raises(ValueError):observe(raw,data,high)


@pytest.mark.parametrize('extent',[True,0,4097])
def test_object_extent_is_bounded_and_not_a_boolean(extent):
    raw,data,high=sample()
    with pytest.raises(ValueError):observe(raw,data,high,extent)


@pytest.mark.parametrize('part',['layout','include','budget'])
def test_language_inputs_are_explicit_bounded_dependencies(part):
    raw,data,high=sample();language=copy.deepcopy(LANGUAGE)
    if part=='layout':language['ia.sinc']=language['ia.sinc'].replace(b'RSP',b'ESP')
    elif part=='include':language['x86-64.slaspec']=b''
    else:language['ia.sinc']=b'x'*(4*1024**2+1)
    with pytest.raises(ValueError):observe(raw,data,high,language=language)


def test_target_byte_budget_is_checked_before_parsing():
    raw,data,high=sample()
    with pytest.raises(ValueError):observe(bytes(32*1024**2+1),data,high)


def test_unaligned_pe_image_geometry_is_refused():
    raw,data,high=sample();struct.pack_into('<I',raw,152+56,8191);rebind(raw,data,high)
    with pytest.raises(ValueError):observe(raw,data,high)


def test_pe_headers_cannot_overlap_the_section_virtual_mapping():
    raw,data,high=sample();expanded=bytearray(10240)
    expanded[:512]=raw[:512];expanded[8192:]=raw[512:]
    struct.pack_into('<I',expanded,152+60,8192)
    struct.pack_into('<I',expanded,152+240+20,8192)
    rebind(expanded,data,high)
    with pytest.raises(ValueError):observe(expanded,data,high)
