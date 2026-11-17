"""Staged native/High-IR leaf data witness, without executing target bytes.

Ordered 64-bit stores through RCX and returned RAX are compared to High IR.
GPR preservation is derived separately from the complete native interpretation
up to RET, using equality to each register's own entry expression.
This is not complete machine equivalence, recovered ABI or native admission.
"""
from __future__ import annotations
import hashlib,json,re
import capstone
from capstone.x86_const import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
from aether_re.native_frame_address import observe_frame_address,_pe_extent,_address,_snapshot
from aether_re.frame_derivation import _checked_ir,_single_block,_binding

MASK=(1<<64)-1
GPRS=['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',*(f'r{i}' for i in range(8,16))]

def need(condition,reason):
    if not condition:raise ValueError('native_leaf_'+reason)

def const(n):return ('constant',n&MASK)

def combine(op,a,b):
    if a[0]==b[0]=='constant':return const(a[1]+b[1] if op=='add' else a[1]^b[1])
    if a==const(0):return b
    if b==const(0):return a
    return (op,*sorted((a,b),key=repr))

def register_layout(raw):
    clean=re.sub(rb'/\*.*?\*/',b'',raw,flags=re.S)
    need(b'/*' not in clean and b'*/' not in clean,'language_comments')
    clean=re.sub(rb'(?m)#.*$',b'',clean)
    expected={8*i:name for i,name in enumerate(GPRS[:8])}
    expected.update({0x80+8*i:name for i,name in enumerate(GPRS[8:])})
    seen={};names=set()
    for match in re.finditer(rb'(?m)^\s*define register offset=(0x[0-9a-fA-F]+|[0-9]+) size=8\s*\[([^\]]+)\];',clean):
        base=int(match[1],0)
        for i,raw_name in enumerate(match[2].split()):
            name=raw_name.decode('ascii').lower();offset=base+8*i
            if offset in expected or name in GPRS:
                need(offset in expected and expected[offset]==name and offset not in seen and name not in names,'register_layout')
                seen[offset]=name;names.add(name)
    # Prefix-only routes historically accept the eight-register declaration.
    # A missing extended declaration limits the optional pair projection.
    # Conflicting declarations above remain invalid input.
    need(seen==expected,'register_layout_incomplete')
    return seen

def observe_leaf_data_effects(*,root,callee,target_bytes,language_sources,object_bytes,window_bytes=32):
    try:return _observe(root,callee,target_bytes,language_sources,object_bytes,window_bytes)
    except (KeyError,IndexError,TypeError,OverflowError,UnicodeError,RecursionError) as error:
        raise ValueError('native_leaf_envelope') from error

def _observe(root,callee,target_bytes,language_sources,object_bytes,window_bytes):
    need(type(window_bytes) is int and 1<=window_bytes<=256,'window_budget')
    root,_=_snapshot(root);callee,callee_digest=_snapshot(callee)
    prefix=observe_frame_address(data=root['pcode_ir'],high=root['high_parameter_observation'],
        target_bytes=target_bytes,language_sources=language_sources,object_bytes=object_bytes)
    layout=register_layout(language_sources['ia.sinc'])
    ir=callee['pcode_ir'];high=callee['high_parameter_observation']
    ir,ir_digest=_snapshot(ir)
    need(ir['target_sha256']==high['target_sha256']==hashlib.sha256(target_bytes).hexdigest(),'target_identity')
    need(ir['context']==root['pcode_ir']['context'],'context')
    _checked_ir(ir,ir_digest);_single_block(ir)
    bound=_binding(ir,high,ir_digest);need(not bound['unbound_inputs'],'unbound_inputs')
    calls=[op for op in root['pcode_ir']['operations'] if op['opcode']=='CALL']
    nodes_root={node['id']:node for node in root['pcode_ir']['varnodes']}
    need(len(calls)==1,'one_call')
    target=nodes_root[calls[0]['inputs'][0]]
    need(target['kind']=='memory' and target['space']=='ram' and int(target['offset'],16)==_address(ir['function_address']),'callee_identity')
    base,_,_,_,mapped=_pe_extent(target_bytes,_address(root['pcode_ir']['function_address']))
    start=_address(ir['function_address']);code,file_offset=mapped(start-base,window_bytes,True)
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);decoder.detail=True
    instructions=[];consumed=0
    for instruction in decoder.disasm(code,start):
        need(instruction.address==start+consumed and len(instructions)<32,'instruction_budget_or_gap')
        instructions.append(instruction);consumed+=instruction.size
        if instruction.mnemonic=='ret':break
    need(instructions and instructions[-1].mnemonic=='ret' and instructions[-1].bytes==b'\xc3','linear_ret')
    need(all(byte in (0xcc,0x90) for byte in code[consumed:]),'trailing_padding')
    groups={instruction.address:[] for instruction in instructions}
    positions={pc:i for i,pc in enumerate(groups)};previous=-1
    for operation in ir['operations']:
        pc=_address(operation['sequence']['pc']);need(pc in groups and positions[pc]>=previous,'operation_pc_order')
        previous=positions[pc];groups[pc].append(operation)
    nodes={node['id']:node for node in ir['varnodes']};values={}
    for node in nodes.values():
        if node['input']:
            need(node['kind']=='register' and node['size']==8 and int(node['offset'],16) in layout,'input_register')
            values[node['id']]=('input',layout[int(node['offset'],16)])
        elif node['kind']=='constant':values[node['id']]=const(int(node['offset'],16))
    spaces=[space for space in ir['context']['spaces'] if space['name']=='ram']
    need(len(spaces)==1 and spaces[0]['kind']=='memory' and spaces[0]['bits']==64 and spaces[0]['word_size']==1,'memory_space')
    ram_id=spaces[0]['id'];native={name:('input',name) for name in GPRS}
    stores=[];required=0;returned=None
    def word(identity):
        need(identity in values and nodes[identity]['size']==8,'defined_word')
        return values[identity]
    def reg(instruction,operand):
        name=instruction.reg_name(operand.reg)
        need(operand.type==X86_OP_REG and operand.size==8 and name in native,'native_register')
        return name
    def memory(instruction,operand):
        need(operand.type==X86_OP_MEM and not operand.mem.index and not operand.mem.segment,'native_memory')
        name=instruction.reg_name(operand.mem.base);need(name in native,'native_memory_base')
        return name,operand.mem.disp,combine('add',native[name],const(operand.mem.disp))
    for instruction in instructions:
        ops=groups[instruction.address];args=instruction.operands;mnemonic=instruction.mnemonic
        expected=None;native_store=None
        if mnemonic=='lea':
            need(len(args)==2,'lea_shape');dest=reg(instruction,args[0]);_,_,expected=memory(instruction,args[1])
            need(len(ops)==1 and ops[0]['opcode']=='INT_ADD','lea_ir')
            native[dest]=expected
        elif mnemonic=='xor':
            need(len(args)==2 and args[1].type==X86_OP_IMM,'xor_shape');dest=reg(instruction,args[0])
            expected=combine('xor',native[dest],const(args[1].imm));native[dest]=expected
            need(len(ops)==1 and ops[0]['opcode']=='INT_XOR','xor_ir')
        elif mnemonic=='mov':
            need(len(args)==2,'mov_shape')
            if args[0].type==X86_OP_REG:
                dest=reg(instruction,args[0]);src=reg(instruction,args[1]);expected=native[src];native[dest]=expected
                need(len(ops)==1 and ops[0]['opcode']=='COPY','copy_ir')
            else:
                name,offset,address=memory(instruction,args[0]);src=reg(instruction,args[1])
                need(name=='rcx' and args[0].size==8 and 0<=offset<=4088,'store_footprint')
                need(native['rcx']==('input','rcx'),'entry_object_pointer')
                required=max(required,offset+8);native_store=(address,native[src],8)
                need([op['opcode'] for op in ops] in (['STORE'],['PTRADD','STORE']),'store_ir')
        elif mnemonic=='ret':
            need(not args and len(ops)==1 and ops[0]['opcode']=='RETURN','return_ir')
        else:raise ValueError('native_leaf_unsupported_instruction:'+mnemonic)
        for op in ops:
            inputs=op['inputs'];opcode=op['opcode'];output=op.get('output')
            if opcode in ('INT_ADD','INT_XOR'):
                need(len(inputs)==2,'scalar_arity');value=combine('add' if opcode=='INT_ADD' else 'xor',word(inputs[0]),word(inputs[1]))
            elif opcode=='COPY':
                need(len(inputs)==1,'copy_arity');value=word(inputs[0])
            elif opcode=='PTRADD':
                need(len(inputs)==3,'ptradd_arity');index=word(inputs[1]);scale=word(inputs[2])
                need(index[0]==scale[0]=='constant','ptradd_constants')
                value=combine('add',word(inputs[0]),const(index[1]*scale[1]))
            elif opcode=='STORE':
                need(len(inputs)==3 and nodes[inputs[0]]['kind']=='constant' and values[inputs[0]]==const(ram_id),'store_space')
                observed=(word(inputs[1]),word(inputs[2]),nodes[inputs[2]]['size'])
                need(observed==native_store,'store_data_mismatch')
                stores.append(dict(pc=op['sequence']['pc'],address=observed[0],value=observed[1],bytes=observed[2]))
                continue
            elif opcode=='RETURN':
                need(len(inputs)==2 and nodes[inputs[0]]['kind']=='constant' and values[inputs[0]]==const(0),'return_marker')
                returned=word(inputs[1]);need(returned==native['rax'],'return_data_mismatch');continue
            else:raise ValueError('native_leaf_unsupported_ir')
            need(output in nodes and nodes[output]['size']==8 and output not in values,'single_assignment')
            values[output]=value
            if opcode!='PTRADD':need(value==expected,'scalar_data_mismatch')
    need(stores and required<=object_bytes,'requested_extent')
    preserved=[name for name in GPRS if native[name]==('input',name)]
    return dict(schema='native-leaf-data-correspondence.v1',status='observed',data_observables_equal=True,
        target_sha256=ir['target_sha256'],callee_input_sha256=callee_digest,ir_payload_sha256=ir_digest,
        caller_address_observation=prefix,callee_address=ir['function_address'],window_bytes=window_bytes,
        file_offset=file_offset,native_code_sha256=hashlib.sha256(code[:consumed]).hexdigest(),
        native_window_sha256=hashlib.sha256(code).hexdigest(),native_instruction_count=len(instructions),
        ir_operation_count=len(ir['operations']),stores=stores,returned_rax=returned,required_object_bytes=required,
        native_preserved_gprs=preserved,
        preservation_scope='native GPR values before RET equal their own entry values; no ABI convention assumed',
        language_inputs_sha256={name:hashlib.sha256(raw).hexdigest() for name,raw in language_sources.items()},
        disassembler_version=capstone.__version__,binary_equivalence_proved=False,native_profile_admitted=False,
        abi_recovered=False,function_extent_proved=False,target_executed=False,production_admission=False,
        assumptions=['declared Windows x64 argument roles','valid nonoverflowing data addresses','declared language layout'],
        excluded_observables=['flags','non-return registers','RET stack and instruction pointer behavior',
            'exceptions and faults','concurrency','whole-function extent','lifetimes','ABI recovery'])
