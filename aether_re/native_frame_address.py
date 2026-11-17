"""Observe one bounded native/High-IR frame-address prefix, never admit a frame.

Preferred PE addresses and declared language bytes are explicit dependencies.
Object extent is requested, not inferred from callee effects or a source type.
No target execution, recovered ABI, equivalence or toolchain attestation follows.
"""
from __future__ import annotations

import hashlib,json,re,struct
import capstone
from .frame_derivation import _checked_ir,_binding,_single_block

MAX_TARGET_BYTES=32*1024**2
MAX_LANGUAGE_BYTES=4*1024**2
_GPRS={'rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',*(f'r{i}' for i in range(8,16))}
_LANGUAGE_NAMES=('ia.sinc','x86.slaspec','x86-64.slaspec')


def _require(condition,reason):
    if not condition:raise ValueError('native_frame_'+reason)


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _snapshot(value):
    _require(type(value) is dict,'input_object')
    try:raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    except (TypeError,ValueError,RecursionError) as error:raise ValueError('native_frame_input_json') from error
    _require(len(raw)<=1024**2,'input_budget')
    return json.loads(raw),_sha(raw)


def _address(value):
    _require(type(value) is str and re.fullmatch(r'ram:[0-9a-fA-F]{1,16}',value) is not None,'address')
    return int(value[4:],16)


def _pe_extent(raw,entry):
    """Map exact file bytes and one unique exception-table range, without loading."""
    _require(len(raw)>=64 and raw[:2]==b'MZ','pe_header')
    pe=struct.unpack_from('<I',raw,60)[0]
    _require(64<=pe<=len(raw)-24 and raw[pe:pe+4]==b'PE\0\0','pe_signature')
    machine,count,_,_,_,optional_size,_=struct.unpack_from('<HHIIIHH',raw,pe+4)
    optional=pe+24;table=optional+optional_size
    _require(machine==0x8664 and 1<=count<=96 and 240<=optional_size<=4096
             and table+count*40<=len(raw),'pe_layout')
    _require(struct.unpack_from('<H',raw,optional)[0]==0x20b,'pe_bits')
    base=struct.unpack_from('<Q',raw,optional+24)[0]
    section_alignment,file_alignment=struct.unpack_from('<II',raw,optional+32)
    image_size,headers=struct.unpack_from('<II',raw,optional+56)
    directories=struct.unpack_from('<I',raw,optional+108)[0]
    power=lambda n:n>0 and n&(n-1)==0
    _require(power(file_alignment) and 512<=file_alignment<=65536 and power(section_alignment)
             and file_alignment<=section_alignment<=1024**2 and 0<image_size<2**32 and image_size%section_alignment==0
             and base+image_size<=2**64 and table+count*40<=headers<=len(raw)
             and headers%file_alignment==0 and 4<=directories<=16,'pe_geometry')
    sections=[]
    for i in range(count):
        row=table+i*40;virtual_size,va,size,offset=struct.unpack_from('<IIII',raw,row+8)
        flags=struct.unpack_from('<I',raw,row+36)[0];span=max(virtual_size,size)
        _require(span>0 and va>=section_alignment and va>=headers and va%section_alignment==0 and va+span<=image_size,'section_memory')
        if size:_require(offset>=headers and offset%file_alignment==0 and size%file_alignment==0 and offset+size<=len(raw),'section_file')
        for previous in sections:
            _require(not (va<previous['va']+previous['span'] and previous['va']<va+span),'section_overlap')
            if size and previous['size']:
                _require(not (offset<previous['offset']+previous['size'] and previous['offset']<offset+size),'section_file_overlap')
        sections.append(dict(va=va,span=span,size=size,offset=offset,executable=bool(flags&0x20000000)))
    def mapped(rva,length,executable=False):
        _require(0<=rva<2**32 and 0<length and rva+length<=image_size,'mapped_range')
        candidates=[s for s in sections if s['va']<=rva and rva+length<=s['va']+s['size']]
        _require(len(candidates)==1 and (not executable or candidates[0]['executable']),'file_backing_or_execution_permission')
        offset=candidates[0]['offset']+rva-candidates[0]['va']
        return raw[offset:offset+length],offset
    directory,size=struct.unpack_from('<II',raw,optional+112+3*8)
    _require(directory>0 and 12<=size<=4096*12 and size%12==0,'exception_directory')
    exception_bytes,_=mapped(directory,size);ranges=[];previous_end=0
    for i in range(0,size,12):
        begin,end,unwind=struct.unpack_from('<III',exception_bytes,i)
        _require(previous_end<=begin<end<=image_size and unwind>0 and unwind%4==0,'exception_range')
        mapped(begin,end-begin,True);mapped(unwind,4);previous_end=end
        ranges.append((begin,end,unwind))
    selected=[r for r in ranges if base+r[0]==entry]
    _require(len(selected)==1,'function_extent')
    begin,end,unwind=selected[0];_require(end-begin<=4096,'function_budget')
    code,file_offset=mapped(begin,end-begin,True)
    return base,code,file_offset,base+end,mapped


def validate_language_sources(language_sources):
    """Validate declared source shape, without authenticating a compiled language."""
    _require(type(language_sources) is dict and set(language_sources)==set(_LANGUAGE_NAMES),'language_inputs')
    _require(all(type(language_sources[n]) is bytes and 0<len(language_sources[n])<=MAX_LANGUAGE_BYTES for n in _LANGUAGE_NAMES),'language_budget')
    declaration=re.search(rb'define register offset=0 size=8\s*\[([^\]]+)\];',language_sources['ia.sinc'])
    names=[] if declaration is None else declaration[1].split()
    _require(names==[b'RAX',b'RCX',b'RDX',b'RBX',b'RSP',b'RBP',b'RSI',b'RDI'],'register_layout')
    _require(b'@include "ia.sinc"' in language_sources['x86.slaspec']
             and b'@include "x86.slaspec"' in language_sources['x86-64.slaspec'],'language_chain')


def observe_frame_address(*,data,high,target_bytes,language_sources,object_bytes):
    """Bind actual PE prefix bytes/PCs to a conditional High-IR address role.

    Language bytes are caller-declared dependencies. The Windows x64 argument
    convention is an explicit model assumption; no native ABI is recovered.
    """
    _require(type(target_bytes) is bytes and 0<len(target_bytes)<=MAX_TARGET_BYTES,'target_budget')
    _require(type(object_bytes) is int and 1<=object_bytes<=4096,'object_extent')
    names=_LANGUAGE_NAMES
    validate_language_sources(language_sources)
    try:
        data,ir_digest=_snapshot(data);high,_=_snapshot(high)
        _require(type(data.get('varnodes')) is list and len(data['varnodes'])<=800
                 and type(data.get('operations')) is list and len(data['operations'])<=900,'ir_budget')
        _checked_ir(data,ir_digest);_single_block(data)
        context=data['context']
        _require(context['language_id']=='x86:LE:64:default' and context['compiler_spec_id']=='windows'
                 and context['endian']=='little' and context['address_bits']==64,'context')
        target_digest=_sha(target_bytes)
        _require(data['target_sha256']==high['target_sha256']==target_digest,'target_identity')
        binding=_binding(data,high,ir_digest)
        _require(len(binding['unbound_inputs'])==1,'ambient_input')
        nodes={n['id']:n for n in data['varnodes']};ambient=nodes[binding['unbound_inputs'][0]]
        _require(ambient['input'] and ambient['unaffected'] and not ambient['persistent']
                 and ambient['size']==8 and ambient['kind']=='register' and int(ambient['offset'],16)==32,'ambient_register')
        _require(any(s['name']==ambient['space'] and s['kind']=='register' for s in context['spaces']),'ambient_space')
        pointers=[o for o in data['operations'] if o['opcode']=='PTRSUB' and o['inputs'][0]==ambient['id']]
        calls=[o for o in data['operations'] if o['opcode']=='CALL']
        _require(len(pointers)==len(calls)==1,'unique_pointer_and_call')
        pointer,call=pointers[0],calls[0]
        _require(len(pointer['inputs'])==2 and nodes[pointer['output']]['size']==8,'pointer_shape')
        constant=nodes[pointer['inputs'][1]]
        _require(constant['kind']=='constant' and constant['size']==8,'pointer_width')
        delta=int(constant['offset'],16);delta=delta-(1<<64) if delta&(1<<63) else delta
        positions=[i for i,value in enumerate(call['inputs'][1:],1) if value==pointer['output']]
        _require(len(positions)==1 and 1<=positions[0]<=4,'pointer_argument')
        argument=positions[0];argument_register=('rcx','rdx','r8','r9')[argument-1]
        callee=nodes[call['inputs'][0]]
        _require(callee['kind']=='memory' and callee['space']=='ram' and callee['size']==8,'direct_callee')
        _require(data['operations'].index(pointer)<data['operations'].index(call),'ir_operation_order')
        entry=_address(data['function_address']);base,code,file_offset,end,mapped=_pe_extent(target_bytes,entry)
        _require(_address(context['image_base'])==base,'image_base')
        decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);decoder.detail=True
        instructions=list(decoder.disasm(code,entry))
        _require(0<len(instructions)<=128 and sum(i.size for i in instructions)==len(code),'decode_budget_or_gap')
        by_address={i.address:i for i in instructions}
        for operation in data['operations']:_require(_address(operation['sequence']['pc']) in by_address,'operation_pc')
        block=data['blocks'][0]
        _require(_address(block['start'])==entry and _address(block['stop']) in by_address,'block_pc')
        pointer_pc=_address(pointer['sequence']['pc']);call_pc=_address(call['sequence']['pc'])
        _require(entry<=pointer_pc<call_pc<=_address(block['stop'])<end,'prefix_order')
        native_call=by_address[call_pc];kind=capstone.x86
        _require(native_call.mnemonic=='call' and len(native_call.operands)==1
                 and native_call.operands[0].type==kind.X86_OP_IMM,'native_direct_call')
        callee_address=int(callee['offset'],16)
        _require(native_call.operands[0].imm&((1<<64)-1)==callee_address,'callee_target')
        mapped(callee_address-base,1,True)
        state={'rsp':0};allocation=0;observed=None;pointer_register=None
        for ins in instructions:
            if ins.address==call_pc:break
            operands=ins.operands
            if ins.mnemonic in ('sub','add') and len(operands)==2 and operands[0].type==kind.X86_OP_REG and operands[0].size==8 and ins.reg_name(operands[0].reg)=='rsp' and operands[1].type==kind.X86_OP_IMM:
                amount=operands[1].imm;_require(0<amount<=4096,'stack_adjustment')
                state['rsp']+=amount*(1 if ins.mnemonic=='add' else -1)
                _require(-4096<=state['rsp']<=0,'stack_budget');allocation=max(allocation,-state['rsp'])
            elif ins.mnemonic=='mov' and len(operands)==2 and all(o.type==kind.X86_OP_REG and o.size==8 for o in operands):
                destination=ins.reg_name(operands[0].reg);origin=ins.reg_name(operands[1].reg)
                _require(destination in _GPRS and origin in _GPRS and destination!='rsp','register_move')
                state[destination]=state.get(origin)
            elif ins.mnemonic=='lea' and len(operands)==2 and operands[0].type==kind.X86_OP_REG and operands[0].size==8 and operands[1].type==kind.X86_OP_MEM:
                destination=ins.reg_name(operands[0].reg);memory=operands[1].mem
                _require(destination in _GPRS and destination!='rsp' and not memory.index and not memory.segment,'lea_shape')
                origin=state.get(ins.reg_name(memory.base));_require(origin is not None,'lea_origin')
                state[destination]=origin+memory.disp
                if ins.address==pointer_pc:
                    observed=state[destination];pointer_register=destination
            else:raise ValueError('native_frame_prefix_instruction_unsupported')
        _require(by_address[pointer_pc].mnemonic=='lea' and observed==delta and state.get(argument_register)==delta,'native_ir_address_relation')
        _require(allocation==-state['rsp'] and allocation%16==8,'stack_alignment')
        _require(state['rsp']+32<=delta and delta+object_bytes<=0,'private_object_interval')
        prefix_length=call_pc+native_call.size-entry
        return dict(schema='observed-frame-address.v1',status='observed',native_address_prefix_observed=True,
            target_sha256=target_digest,function_address=data['function_address'],ir_payload_sha256=ir_digest,
            high_observation_sha256=binding['source_observation_sha256'],native_code_sha256=_sha(code),
            native_prefix_sha256=_sha(code[:prefix_length]),native_code_file_offset=file_offset,
            native_function_end_exclusive=f'ram:{end:x}',native_prefix_bytes=prefix_length,
            language_inputs_sha256={name:_sha(language_sources[name]) for name in names},
            ambient_varnode=ambient['id'],pointer_operation=pointer['id'],pointer_pc=pointer['sequence']['pc'],
            call_operation=call['id'],call_pc=call['sequence']['pc'],call_argument_index=argument,
            callee_address=f'ram:{callee_address:x}',entry_rsp_offset=delta,allocated_bytes=allocation,
            native_argument_register=argument_register,pointer_native_register=pointer_register,requested_object_bytes=object_bytes,
            decoder_version=capstone.__version__,native_frame_fact_verified=False,production_admission=False,
            callee_effect_extent_proved=False,abi_recovered=False,original_source_recovered=False,
            target_executed=False,language_toolchain_authenticity_proved=False,
            limitations=['one bounded straight-line address prefix at preferred PE addresses',
                'object extent is requested; callee effects, lifetime and source type are not inferred',
                'declared language bytes are not compiled-language or toolchain attestation',
                'Windows x64 argument convention is an explicit model assumption, not recovered ABI',
                'native control flow after the call and binary semantic equivalence are not proved'])
    except (KeyError,IndexError,TypeError,OverflowError,struct.error,RecursionError) as error:
        raise ValueError('native_frame_input_invalid') from error
