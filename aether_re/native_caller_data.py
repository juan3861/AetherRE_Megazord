"""Staged compositional data witness for one linear caller and verified leaf.

No target execution or whole machine equivalence. Stack effects use explicit
CALL/RET assumptions; data faults, flags and concurrent mutation are excluded.
"""
from __future__ import annotations
import hashlib
import json
import capstone
from capstone.x86_const import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
from .native_leaf_data import observe_leaf_data_effects,register_layout,GPRS,MASK
from aether_re.native_frame_address import _pe_extent,_address,_snapshot
from aether_re.frame_derivation import _binding

def need(condition,reason):
    if not condition:raise ValueError('native_caller_'+reason)

def constant(n):return ('constant',n&MASK)

def combine(operator,*expressions):
    terms=[];number=0
    def gather(expr):
        nonlocal number
        if expr[0]=='constant':number=(number+expr[1])&MASK if operator=='add' else number^expr[1]
        elif expr[0]==operator:
            for part in expr[1:]:gather(part)
        else:terms.append(expr)
    for expression in expressions:gather(expression)
    if operator=='xor':terms=[term for term in set(terms) if terms.count(term)%2]
    if number:terms.append(constant(number))
    terms.sort(key=repr)
    return constant(0) if not terms else terms[0] if len(terms)==1 else (operator,*terms)

def instantiate(expr,arguments):
    if expr[0]=='constant':return constant(expr[1])
    if expr[0]=='input':
        need(expr[1] in arguments and arguments[expr[1]] is not None,'unknown_call_input')
        return arguments[expr[1]]
    need(expr[0] in ('add','xor'),'leaf_expression')
    return combine(expr[0],*(instantiate(part,arguments) for part in expr[1:]))


def build_native_pair_observation(*,root,callee,target_bytes,language_sources,object_bytes,input_receipt=None):
    """Attach a bounded data observation independently of conditional derivation.

    Receipt failures propagate. Unsupported data projections carry a refusal.
    Direct in-memory callers bind hashes of their bytes without path custody.
    """
    target_sha=hashlib.sha256(target_bytes).hexdigest()
    if input_receipt is not None:
        from .native_frame_request import _checked_packet
        try:
            target_path=input_receipt['target'].get('snapshot_path',input_receipt['target']['path'])
        except (KeyError,TypeError,AttributeError) as error:
            raise ValueError('native_pair_input_receipt_invalid') from error
        _checked_packet(dict(target_bytes=target_bytes,language_sources=language_sources,
            target_path=target_path,receipt=input_receipt))
    root,root_digest=_snapshot(root);callee,callee_digest=_snapshot(callee)
    if root['pcode_ir']['target_sha256']!=target_sha or callee['pcode_ir']['target_sha256']!=target_sha:
        raise ValueError('native_pair_target_identity')
    binding=dict(target_sha256=target_sha,object_bytes=object_bytes,
        language_inputs_sha256={name:hashlib.sha256(raw).hexdigest() for name,raw in language_sources.items()})
    try:
        result=observe_pair_data_effects(root=root,callee=callee,target_bytes=target_bytes,
            language_sources=language_sources,object_bytes=object_bytes)
    except ValueError as error:
        # Domain errors carry fixed internal codes. Never publish arbitrary
        # exception text, paths or suffixes from dependencies.
        code=error.args[0].partition(':')[0] if error.args and type(error.args[0]) is str else ''
        integrity_codes={'native_leaf_target_identity','native_leaf_context','native_leaf_callee_identity',
            'native_leaf_one_call','native_leaf_register_layout','native_leaf_language_comments',
            'native_leaf_unbound_inputs','native_leaf_input_register'}
        if (not code.startswith(('native_leaf_','native_caller_')) or code in integrity_codes
                or code.endswith('_envelope')):
            raise
        category={
            'native_caller_unproved_call_clobber_use':'unproved_call_clobber_use',
            'native_caller_aligned_object_store':'aligned_object_store',
            'native_caller_stack_object_lifetime':'stack_object_lifetime',
            'native_caller_unsupported_instruction':'unsupported_instruction',
            'native_leaf_unsupported_instruction':'unsupported_instruction',
        }.get(code,'data_correspondence_refused')
        result=dict(schema='native-pair-data-correspondence.v1',status='refused',
            error_message='native_pair_'+category,ordered_data_events_equal=False,return_data_equal=False,
            binary_equivalence_proved=False,native_profile_admitted=False,abi_recovered=False,
            production_admission=False,target_executed=False,original_source_recovered=False)
    result.update(input_binding=binding,root_input_sha256=root_digest,callee_input_sha256=callee_digest,
        caller_ir_payload_sha256=_snapshot(root['pcode_ir'])[1],
        callee_ir_payload_sha256=_snapshot(callee['pcode_ir'])[1],
        selected_functions=dict(root=target_sha+'!'+root['pcode_ir']['function_address'],
            callee=target_sha+'!'+callee['pcode_ir']['function_address']))
    encoded=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
    result['witness_sha256']=hashlib.sha256(encoded).hexdigest()
    return result

def observe_pair_data_effects(*,root,callee,target_bytes,language_sources,object_bytes):
    try:return _observe(root,callee,target_bytes,language_sources,object_bytes)
    except (KeyError,IndexError,TypeError,OverflowError,RecursionError) as error:
        raise ValueError('native_caller_envelope') from error

def _observe(root,callee,target_bytes,language_sources,object_bytes):
    root,root_digest=_snapshot(root);callee,callee_digest=_snapshot(callee)
    leaf=observe_leaf_data_effects(root=root,callee=callee,target_bytes=target_bytes,
        language_sources=language_sources,object_bytes=object_bytes)
    ir=root['pcode_ir'];nodes={node['id']:node for node in ir['varnodes']}
    layout=register_layout(language_sources['ia.sinc'])
    base,code,offset,end,mapped=_pe_extent(target_bytes,_address(ir['function_address']))
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);decoder.detail=True
    instructions=list(decoder.disasm(code,_address(ir['function_address'])))
    need(0<len(instructions)<=64 and sum(i.size for i in instructions)==len(code),'complete_decode')
    need(instructions[-1].bytes==b'\xc3' and all(i.mnemonic!='ret' for i in instructions[:-1]),'single_final_ret')
    leafcode,_=mapped(_address(leaf['callee_address'])-base,leaf['window_bytes'],True)
    leafinstructions=[]
    for instruction in decoder.disasm(leafcode,_address(leaf['callee_address'])):
        leafinstructions.append(instruction)
        if instruction.mnemonic=='ret':break
        need('rsp' not in [instruction.reg_name(reg) for reg in instruction.regs_access()[1]],'callee_rsp_clobber')
    need(len(leafinstructions)==leaf['native_instruction_count'],'leaf_decode')
    pc_groups={instruction.address:[] for instruction in instructions};positions={pc:i for i,pc in enumerate(pc_groups)}
    previous=-1
    for operation in ir['operations']:
        pc=_address(operation['sequence']['pc'])
        need(pc in pc_groups and positions[pc]>=previous,'ir_pc_order');previous=positions[pc]
        pc_groups[pc].append(operation)
    ram=[space for space in ir['context']['spaces'] if space['name']=='ram']
    need(len(ram)==1,'ram_space');ram_id=ram[0]['id']
    values={}
    for node in nodes.values():
        if node['input']:
            need(node['kind']=='register' and node['size']==8 and int(node['offset'],16) in layout,'input_register')
            values[node['id']]=('input',layout[int(node['offset'],16)])
        elif node['kind']=='constant':values[node['id']]=constant(int(node['offset'],16))
    native={name:('input',name) for name in GPRS};entry_rsp=native['rsp']
    native_memory={};ir_memory={};native_events=[];ir_events=[]
    allocation=None;called=False;restored=False;returned=None;preserved_bindings={}
    callee_ir=callee['pcode_ir'];callee_nodes={node['id']:node for node in callee_ir['varnodes']}
    _,callee_ir_digest=_snapshot(callee_ir)
    parameters=_binding(callee_ir,callee['high_parameter_observation'],callee_ir_digest)['parameters']
    formal_registers=[]
    for index,parameter in enumerate(parameters):
        need(parameter['ordinal']==index,'formal_ordinal')
        formal=callee_nodes[parameter['input_varnodes'][0]]
        need(formal['kind']=='register' and formal['size']==8 and int(formal['offset'],16) in layout,'formal_register')
        name=layout[int(formal['offset'],16)];need(name in ('rcx','rdx','r8','r9'),'argument_register')
        formal_registers.append(name)
    def word(identity):
        need(identity in values and nodes[identity]['size']==8,'defined_word');return values[identity]
    def register(instruction,operand):
        name=instruction.reg_name(operand.reg)
        need(operand.type==X86_OP_REG and operand.size==8 and name in native,'word_register')
        return name
    def known(name):
        need(native[name] is not None,'unproved_call_clobber_use');return native[name]
    def address(instruction,operand):
        need(operand.type==X86_OP_MEM and not operand.mem.index and not operand.mem.segment,'memory_address')
        name=instruction.reg_name(operand.mem.base);need(name in native,'memory_base')
        return combine('add',known(name),constant(operand.mem.disp))
    def apply_leaf(arguments,memory,events):
        for store in leaf['stores']:
            abstract=instantiate(store['address'],{'rcx':('input','rcx')})
            parts=list(abstract[1:]) if abstract[0]=='add' else [abstract]
            terms=[part for part in parts if part[0]!='constant'];numbers=[part[1] for part in parts if part[0]=='constant']
            displacement=sum(numbers)&MASK
            need(terms==[('input','rcx')] and displacement%8==0 and displacement+8<=object_bytes,'aligned_object_store')
            addr=instantiate(store['address'],arguments);value=instantiate(store['value'],arguments)
            memory[addr]=value;events.append(dict(kind='store',pc=store['pc'],address=addr,value=value,bytes=8))
        return instantiate(leaf['returned_rax'],arguments)
    for instruction in instructions:
        args=instruction.operands;mnemonic=instruction.mnemonic;ops=pc_groups[instruction.address]
        expected=None;load_address=None;call_registers=None
        if mnemonic=='sub':
            need(not called and allocation is None and not ops and len(args)==2 and args[1].type==X86_OP_IMM,'stack_prologue')
            need(register(instruction,args[0])=='rsp' and 0<args[1].imm<=4096,'stack_allocation')
            allocation=args[1].imm;native['rsp']=combine('add',entry_rsp,constant(-allocation))
        elif mnemonic=='add':
            need(called and not restored and not ops and len(args)==2 and args[1].type==X86_OP_IMM,'stack_epilogue')
            need(register(instruction,args[0])=='rsp' and args[1].imm==allocation,'stack_restoration')
            native['rsp']=combine('add',known('rsp'),constant(args[1].imm));restored=True
        elif mnemonic=='lea':
            need(not called and len(args)==2,'pointer_lea');dest=register(instruction,args[0]);need(dest!='rsp','rsp_write')
            expected=address(instruction,args[1]);native[dest]=expected
            need([op['opcode'] for op in ops]==['PTRSUB'],'pointer_ir')
        elif mnemonic=='mov':
            need(len(args)==2,'move_shape');dest=register(instruction,args[0]);need(dest!='rsp','rsp_write')
            if args[1].type==X86_OP_REG:
                need(not called and not ops,'prefix_move');native[dest]=known(register(instruction,args[1]))
            else:
                need(not restored,'stack_object_lifetime')
                need(called and args[1].size==8,'load_width');load_address=address(instruction,args[1])
                need(load_address in native_memory,'load_defined_by_callee');expected=native_memory[load_address];native[dest]=expected
                need([op['opcode'] for op in ops] in (['LOAD'],['PTRADD','LOAD']),'load_ir')
                native_events.append(dict(kind='load',pc='ram:'+format(instruction.address,'x'),address=load_address,value=expected,bytes=8))
        elif mnemonic=='call':
            need(not called and allocation is not None and len(args)==1 and args[0].type==X86_OP_IMM,'one_direct_call')
            need(args[0].imm==_address(leaf['callee_address']),'call_target')
            need([op['opcode'] for op in ops] in (['CALL'],['CALL','CAST']),'call_ir')
            fact=leaf['caller_address_observation'];delta=fact['entry_rsp_offset']
            need(-allocation<=delta and delta+object_bytes<=0,'object_inside_stack_allocation')
            need(fact['call_argument_index']==1 and known('rcx')==combine('add',entry_rsp,constant(delta)),'entry_object_pointer')
            call_registers=dict(native);expected=apply_leaf(call_registers,native_memory,native_events)
            # Preservation is native-derived. Instantiate at the actual CALL
            # state, which can differ from caller entry (e.g. RBX holds an object).
            preserved_bindings={name:call_registers[name] for name in leaf['native_preserved_gprs']}
            rsp=known('rsp');native={name:None for name in GPRS}
            native.update(preserved_bindings);native.update(rax=expected,rsp=rsp);called=True
        elif mnemonic=='xor':
            need(called and len(args)==2,'return_xor');dest=register(instruction,args[0]);source=register(instruction,args[1])
            expected=combine('xor',known(dest),known(source));native[dest]=expected
            need([op['opcode'] for op in ops]==['INT_XOR'],'xor_ir')
        elif mnemonic=='ret':
            need(called and restored and not args and known('rsp')==entry_rsp,'rsp_before_ret')
            need([op['opcode'] for op in ops]==['RETURN'],'return_ir');expected=known('rax')
        else:raise ValueError('native_caller_unsupported_instruction:'+mnemonic)
        for operation in ops:
            opcode=operation['opcode'];inputs=operation['inputs'];output=operation.get('output')
            if opcode=='PTRSUB':
                need(len(inputs)==2,'pointer_arity');value=combine('add',word(inputs[0]),word(inputs[1]))
            elif opcode=='PTRADD':
                need(len(inputs)==3,'ptradd_arity');index=word(inputs[1]);scale=word(inputs[2])
                need(index[0]==scale[0]=='constant','ptradd_constants');value=combine('add',word(inputs[0]),constant(index[1]*scale[1]))
            elif opcode=='CALL':
                need(len(inputs)==len(formal_registers)+1 and nodes[inputs[0]]['kind']=='memory','call_arguments')
                actual={name:word(identity) for name,identity in zip(formal_registers,inputs[1:])}
                need(all(actual[name]==call_registers[name] for name in actual),'call_actual_mismatch')
                value=apply_leaf(actual,ir_memory,ir_events)
            elif opcode=='CAST':
                need(len(inputs)==1,'cast_arity');value=word(inputs[0])
            elif opcode=='LOAD':
                need(len(inputs)==2 and nodes[inputs[0]]['kind']=='constant' and values[inputs[0]]==constant(ram_id),'load_space')
                addr=word(inputs[1]);need(addr==load_address and addr in ir_memory,'load_address_or_definedness')
                value=ir_memory[addr];ir_events.append(dict(kind='load',pc=operation['sequence']['pc'],address=addr,value=value,bytes=8))
            elif opcode=='INT_XOR':
                need(len(inputs)==2,'xor_arity');value=combine('xor',word(inputs[0]),word(inputs[1]))
            elif opcode=='RETURN':
                need(len(inputs)==2 and nodes[inputs[0]]['kind']=='constant' and values[inputs[0]]==constant(0),'return_marker')
                returned=word(inputs[1]);need(returned==expected,'return_data_mismatch');continue
            else:raise ValueError('native_caller_unsupported_ir')
            need(output in nodes and output not in values and nodes[output]['size']==8,'single_assignment')
            values[output]=value
            if opcode!='PTRADD':need(value==expected,'instruction_data_mismatch')
    need(called and returned is not None and native_events==ir_events,'ordered_data_events')
    return dict(schema='native-pair-data-correspondence.v1',status='observed',root_input_sha256=root_digest,
        callee_input_sha256=callee_digest,target_sha256=ir['target_sha256'],leaf_witness=leaf,
        caller_native_code_sha256=hashlib.sha256(code).hexdigest(),caller_file_offset=offset,caller_end=end,
        caller_instruction_count=len(instructions),callee_instruction_count=len(leafinstructions),
        caller_ir_operations=len(ir['operations']),events=ir_events,return_expression=returned,
        ordered_data_events_equal=True,return_data_equal=True,caller_rsp_restored_before_ret=True,
        callee_rsp_preserved_before_ret=True,no_load_after_stack_release=True,stack_allocation_bytes=allocation,
        preserved_call_bindings=preserved_bindings,
        call_clobber_policy='unavailable GPR data except returned RAX, balanced RSP and native-proved preserved GPRs',
        assumptions=['valid nonoverflowing stack/data addresses','balanced architectural CALL/RET stack behavior',
            'declared Windows x64 argument roles','declared language layout'],
        excluded_observables=['flags','non-return registers','return-address memory and final RET control transfer',
            'faults and exceptions','concurrency','general function extent','general native lifetimes','ABI recovery'],
        binary_equivalence_proved=False,native_profile_admitted=False,abi_recovered=False,
        target_executed=False,production_admission=False,original_source_recovered=False)
