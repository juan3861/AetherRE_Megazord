"""Finite, conditional composition of identity-bound observed direct calls.

No target bytes are executed. Argument correspondence is a declared model
hypothesis, never a claim of original parameter ABI or binary equivalence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import stat
from pathlib import Path

MODEL = 'bounded-direct-pure-calls.v1'
EFFECTS_MODEL = 'bounded-direct-effects-calls.v1'
STACK_MODEL = 'bounded-ms-x64-stack-values.v1'
MAX_OUTPUT_BYTES = 1048576
_TOKEN = object()


def validate_call_configuration(model,memory_model,selector):
    """Reject an explicit but unusable call model before starting a backend."""
    if model is None:return
    if type(model) is not str or model not in (MODEL,EFFECTS_MODEL,STACK_MODEL):raise ValueError('ghidra_call_model_invalid')
    if memory_model!='bounded-bytes.v2' or type(selector) is not str or not 1<=len(selector)<=4096 or not selector.strip():
        raise ValueError('ghidra_call_model_requires_sparse_reconstruction')


class _Refused(Exception):
    pass


def _bytes(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


@dataclass(frozen=True)
class _Function:
    identity: str
    address: str
    payload: bytes
    payload_sha256: str
    evidence_sha256: str
    label: str
    transport: tuple
    formal: tuple
    return_bits: int
    observation_sha256: str
    number: int = 0
    emitted_name: str = ''
    stack_slots: tuple = ()
    stack_reuse_proof: bytes = b''
    pointer_provenance_proof: bytes = b''
    stack_parameter_proof: bytes = b''


@dataclass(frozen=True)
class _Site:
    caller: str
    operation: str
    operation_number: int
    callee: str
    slots: tuple


@dataclass(frozen=True)
class _CallContext:
    functions: tuple
    sites: tuple
    root_identity: str
    fingerprint: str
    token: object = field(repr=False,compare=False)
    profile: str = MODEL

    @property
    def effects(self):return self.profile in (EFFECTS_MODEL,STACK_MODEL)

    @property
    def words(self):
        return tuple(int(self.fingerprint[i:i+16],16) for i in range(0,64,16))

    def function(self,identity):
        item=next((item for item in self.functions if item.identity==identity),None)
        if item is None:raise ValueError('call_closure_context_changed')
        return item

    def verify(self,data,target,address,name):
        if self.token is not _TOKEN or self.profile not in (MODEL,EFFECTS_MODEL,STACK_MODEL):raise ValueError('call_closure_context_not_admitted')
        item=self.function(target+'!'+address)
        if item.emitted_name!=name or hashlib.sha256(_bytes(data)).hexdigest()!=item.payload_sha256:
            raise ValueError('call_closure_context_changed')
        return item

    def site(self,identity,operation):
        return next(item for item in self.sites if item.caller==identity and item.operation==operation)


def _image(export,context,*,required_ms_x64=False):
    from aether_re.native_memory import build_pe_memory,build_elf_memory,MAX_FILE_BYTES
    path=Path(export.binary_path)
    def ordinary(info):
        return stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not getattr(info,'st_file_attributes',0)&0x400
    try:before=path.lstat()
    except OSError as error:raise ValueError('call_closure_target_unavailable') from error
    if not ordinary(before) or before.st_size>MAX_FILE_BYTES:raise ValueError('call_closure_target_file_invalid')
    try:
        with path.open('rb') as handle:
            import os
            opened=os.fstat(handle.fileno());data=handle.read(MAX_FILE_BYTES+1);after=os.fstat(handle.fileno())
    except OSError as error:raise ValueError('call_closure_target_unavailable') from error
    if (not ordinary(opened) or not ordinary(after) or
        (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
        or len(data)>MAX_FILE_BYTES or hashlib.sha256(data).hexdigest()!=export.target_sha256):
        raise ValueError('call_closure_target_changed')
    space,base=context['image_base'].split(':',1)
    default=next(s for s in context['spaces'] if s['name']==space)
    try:
        if data[:2]==b'MZ':
            image=build_pe_memory(data,target_sha256=export.target_sha256,space_id=default['id']&0xffffffff)
            if required_ms_x64:
                header=int.from_bytes(data[60:64],'little')
                if int.from_bytes(data[header+4:header+6],'little')!=0x8664:raise _Refused('call_closure_stack_parameter_machine')
            if image['base']!=int(base,16):raise _Refused('call_closure_image_context')
        elif data[:4]==b'\x7fELF':
            if required_ms_x64:raise _Refused('call_closure_stack_parameter_image')
            image=build_elf_memory(data,target_sha256=export.target_sha256,space_id=default['id']&0xffffffff,sparse=True,analysis_base=int(base,16))
        else:raise _Refused('call_closure_image_format')
    except ValueError as error:raise _Refused('call_closure_image_unsupported:'+str(error)) from error
    if image['bits']!=context['address_bits'] or image['endian']!=context['endian']:
        raise _Refused('call_closure_image_context')
    return image


def _coverage(data,image):
    memories=image.get('regions',[image]);proof=[]
    for block in data['blocks']:
        space,lo=block['start'].split(':',1);end_space,hi=block['stop'].split(':',1)
        start,end=int(lo,16),int(hi,16)
        if space!=data['function_address'].split(':',1)[0] or end_space!=space or end<start:
            raise _Refused('call_closure_executable_mapping')
        found=None
        for memory in memories:
            for origin in memory['provenance']:
                if origin['address']<=start<=end<origin['address']+origin['file_size']:
                    first,last=start-memory['base'],end-memory['base']+1
                    permissions=memory['permissions'][first:last];initialized=memory['initialized'][first:last]
                    if len(permissions)==end-start+1 and permissions.count(5)+permissions.count(7)==len(permissions) and initialized.count(1)==len(initialized):
                        found=dict(block=block['id'],start=block['start'],stop=block['stop'],file_offset=origin['file_offset']+start-origin['address'],file_bytes=end-start+1)
        if found is None:raise _Refused('call_closure_executable_mapping')
        proof.append(found)
    address=int(data['function_address'].split(':',1)[1],16)
    if not any(int(b['start'].split(':',1)[1],16)<=address<=int(b['stop'].split(':',1)[1],16) for b in data['blocks']):
        raise _Refused('call_closure_executable_mapping')
    return proof


def _returns(data):
    variables={v['id']:v for v in data['varnodes']};widths=set()
    for operation in data['operations']:
        if operation['opcode']!='RETURN':continue
        marker=variables[operation['inputs'][0]]
        if marker['kind']!='constant' or int(marker['offset'],16)!=0:
            raise _Refused('pcode_c_unmodeled_return_target_or_halt')
        if len(operation['inputs'])>2:raise _Refused('pcode_c_multi_value_return')
        widths.add(variables[operation['inputs'][1]]['size']*8 if len(operation['inputs'])==2 else 0)
    if len(widths)!=1:raise _Refused('pcode_c_absent_or_inconsistent_returns')
    return next(iter(widths))


def _stack_ssa(data,*,allow_reuse=False,allow_pointer_proof=False,admitted_inputs=()):
    """Admit distinct definition-only slots as private values in this pure IR."""
    nodes=[v for v in data['varnodes'] if v['kind']=='stack']
    if not nodes:return ()
    if not allow_pointer_proof and any(o['opcode'] in ('PTRADD','PTRSUB') for o in data['operations']):
        raise _Refused('call_closure_stack_address_unmodeled')
    spaces={s['name']:s for s in data['context']['spaces']};slots=[]
    for node in nodes:
        if node['input'] and not node.get('definition') and node['id'] in admitted_inputs:continue
        if node['input'] or not node.get('definition'):raise _Refused('call_closure_stack_input_unmodeled')
        space=spaces[node['space']]
        if space['kind']!='stack' or space['word_size']!=1 or int(node['offset'],16)+node['size']>1<<space['bits']:
            raise _Refused('call_closure_stack_range')
        slots.append((node['id'],node['space'],node['offset'],node['size']))
    ordered=sorted(slots,key=lambda s:(s[1],int(s[2],16)))
    for first,second in zip(ordered,ordered[1:]):
        if not allow_reuse and first[1]==second[1] and int(first[2],16)+first[3]>int(second[2],16):
            raise _Refused('call_closure_stack_overlap')
    return tuple(slots)


def reconstruct_direct_call_closure(export,selector,*,max_functions=16,max_depth=4,function_name='aether_recovered',call_model=MODEL):
    """Emit bounded C for a finite pure-call model; never compile or execute it."""
    from dataclasses import replace
    from aether_re.ghidra_headless_bridge import GhidraDecompilationResult
    from aether_re.ghidra_pcode_c import reconstruct_high_pcode,_SPARSE_MEMORY_RUNTIME
    from aether_re.call_runtime import CALL_RUNTIME
    if call_model is None:raise ValueError('ghidra_call_model_invalid')
    validate_call_configuration(call_model,'bounded-bytes.v2',selector)
    effects=call_model in (EFFECTS_MODEL,STACK_MODEL)
    effect_runtime=''
    if effects:
        from aether_re.effect_trace import EFFECT_RUNTIME
        effect_runtime=EFFECT_RUNTIME
    if (type(max_functions) is not int or not 1<=max_functions<=32 or type(max_depth) is not int or not 1<=max_depth<=16):
        raise ValueError('call_closure_budget_invalid')
    if (not isinstance(function_name,str) or not re.fullmatch('aether_[A-Za-z0-9_]{1,80}',function_name)
        or function_name.startswith(('aether_call_','aether_callee_','aether_sparse_memory_','aether_memory_'))
        or effects and function_name.startswith('aether_effect_')):
        raise ValueError('call_closure_function_name_invalid')
    if type(export) is not GhidraDecompilationResult or type(selector) is not str or not 1<=len(selector)<=4096:
        raise ValueError('call_closure_export_or_selector_invalid')
    if not isinstance(export.target_sha256,str) or not re.fullmatch('[0-9a-f]{64}',export.target_sha256):
        raise ValueError('call_closure_target_invalid')
    if type(export.functions) is not dict or type(export.total_functions) is not int or export.total_functions!=len(export.functions) or len(export.functions)>50000:
        raise ValueError('call_closure_inventory_invalid')
    for identity,info in export.functions.items():
        match=re.fullmatch(r'([A-Za-z0-9_.-]{1,64}):([0-9a-f]{1,16})',info.address) if type(info.address) is str else None
        canonical=match[1]+':'+format(int(match[2],16),'x') if match else None
        if info.address!=canonical or identity!=export.target_sha256+'!'+info.address or info.function_id!=identity:
            raise ValueError('call_closure_inventory_identity')
    root=export.functions.get(selector) or export.get_unique_function(selector)
    if root is None:raise ValueError('call_closure_selector_unavailable_or_ambiguous')
    report=dict(schema='ghidra-direct-call-closure.v1',status='unsupported',structured_c_source=None,errors=[],
        target_sha256=export.target_sha256,function_address=root.address,original_source_recovered=False,
        abi_recovered=False,source_parameter_count_proved=False,binary_equivalence_proved=False,call_semantics_proved=False,
        target_executed=False,limitations=['conditional composition of observed High P-Code; not original ABI or binary equivalence',
        'formal ordinal to call slot is an explicit model hypothesis, not source arity proof',
        'this profile refuses memory effects, indirect/user calls and recursive call graphs; broader profiles remain unproved'])
    if effects:
        report['limitations'][-1]='explicit abstract-byte effects only; indirect/user calls, recursion and original machine ABI remain unproved'
    snapshots={};sites=[];visiting=set();order=[];proofs={};image=None;reference=None
    total_operations=total_variables=total_coverage=0
    try:
        def visit(identity,depth):
            nonlocal image,reference,total_operations,total_variables,total_coverage
            if depth>max_depth:raise _Refused('call_closure_depth_budget')
            if identity in visiting:raise _Refused('call_closure_cycle')
            if identity in snapshots:return
            if len(snapshots)>=max_functions:raise _Refused('call_closure_function_budget')
            info=export.functions.get(identity)
            if info is None or not info.success:raise _Refused('call_closure_callee_unavailable')
            observed=export.select_reconstruction(identity,memory_model='bounded-bytes.v2')
            if observed['status']!='complete' and observed['errors'] not in (['pcode_c_unsupported_opcodes:CALL'],['pcode_c_external_storage']):
                raise _Refused('call_closure_function_untranslatable:'+','.join(observed['errors']))
            binding=observed.get('high_parameter_input_associations')
            if not binding or not binding['complete']:raise _Refused('call_closure_parameter_association_incomplete')
            data=json.loads(_bytes(info.pcode_ir));payload=_bytes(data)
            if hashlib.sha256(payload).hexdigest()!=info.pcode_payload_sha256:raise ValueError('ghidra_reconstruction_ir_changed')
            context=data['context'];space=context['image_base'].split(':',1)[0]
            current=(context['language_id'],context['compiler_spec_id'],context['endian'],context['address_bits'],context['image_base'],
                next(s for s in context['spaces'] if s['name']==space))
            if call_model==STACK_MODEL and (context['language_id']!='x86:LE:64:default' or context['compiler_spec_id']!='windows' or context['address_bits']!=64 or context['endian']!='little'):
                raise _Refused('call_closure_stack_parameter_context')
            if reference is None:
                reference=current
                image=_image(export,context,required_ms_x64=True) if call_model==STACK_MODEL else _image(export,context)
            elif reference!=current:raise _Refused('call_closure_context_mismatch')
            proofs[identity]=_coverage(data,image);total_coverage+=sum(b['file_bytes'] for b in proofs[identity])
            total_operations+=len(data['operations']);total_variables+=len(data['varnodes'])
            if total_operations>7200 or total_variables>6400 or total_coverage>4194304:raise _Refused('call_closure_translation_budget')
            forbidden={'CALLIND','CALLOTHER','INDIRECT'}| (set() if effects else {'LOAD','STORE'})
            if any(o['opcode'] in forbidden for o in data['operations']):raise _Refused('call_closure_effects_profile')
            if effects:
                variables={v['id']:v for v in data['varnodes']}
                for operation in data['operations']:
                    if operation['opcode'] in ('LOAD','STORE') and int(variables[operation['inputs'][0]]['offset'],16)!=(current[-1]['id']&0xffffffff):
                        raise _Refused('call_closure_memory_space')
            if any(v.get('persistent') for v in data['varnodes']):raise _Refused('call_closure_external_storage')
            stack_parameter_proof=None;admitted_inputs=()
            if call_model==STACK_MODEL and any(v['kind']=='stack' and v['input'] for v in data['varnodes']):
                from aether_re.stack_parameters import prove_ms_x64_stack_values
                try:stack_parameter_proof=prove_ms_x64_stack_values(data,info.high_parameter_observation,evidence_sha256=info.ir_analysis['source_ir_sha256'])
                except ValueError as error:raise _Refused(str(error)) from error
                admitted_inputs=tuple(v['varnode'] for v in stack_parameter_proof['stack_inputs'])
            stack_slots=_stack_ssa(data,allow_reuse=effects,allow_pointer_proof=effects,admitted_inputs=admitted_inputs);stack_reuse=None
            if effects and len(stack_slots)>1:
                from aether_re.stack_liveness import prove_stack_slot_reuse
                try:stack_reuse=prove_stack_slot_reuse(data,stack_slots)
                except ValueError as error:raise _Refused(str(error)) from error
            if observed['errors']==['pcode_c_external_storage'] and not stack_slots:
                raise _Refused('call_closure_function_untranslatable:pcode_c_external_storage')
            parameters=binding['parameters']
            if any(len(p['input_varnodes'])!=1 for p in parameters):raise _Refused('call_closure_parameter_shape')
            high_observation=json.loads(_bytes(info.high_parameter_observation))
            high_digest=hashlib.sha256(_bytes(high_observation)).hexdigest()
            if high_digest!=binding['source_observation_sha256'] or high_digest!=info._high_parameter_observation_sha256:
                raise ValueError('high_parameter_observation_changed')
            transport=tuple((v['id'],v['size']) for v in data['varnodes'] if v['input'])
            formal=tuple(p['input_varnodes'][0] for p in parameters)
            if len(set(formal))!=len(formal) or set(formal)!={v for v,_ in transport}:raise _Refused('call_closure_parameter_shape')
            widths=dict(transport)
            if any(p['size']!=widths[varnode] for p,varnode in zip(high_observation['parameters'],formal)):
                raise _Refused('call_closure_parameter_width')
            snapshot=_Function(identity,info.address,payload,hashlib.sha256(payload).hexdigest(),info.ir_analysis['source_ir_sha256'],
                info.name,transport,formal,_returns(data),binding['source_observation_sha256'],stack_slots=stack_slots,
                stack_reuse_proof=_bytes(stack_reuse) if stack_reuse else b'',
                stack_parameter_proof=_bytes(stack_parameter_proof) if stack_parameter_proof else b'')
            snapshots[identity]=snapshot;visiting.add(identity)
            variables={v['id']:v for v in data['varnodes']}
            pointer_sinks=[]
            for index,operation in enumerate(data['operations']):
                if operation['opcode']!='CALL':continue
                target=variables[operation['inputs'][0]]
                if target['kind']!='memory':raise _Refused('call_closure_direct_target_required')
                callee_id=export.target_sha256+'!'+target['space']+':'+format(int(target['offset'],16),'x')
                visit(callee_id,depth+1);callee=snapshots[callee_id]
                arguments=[variables[v] for v in operation['inputs'][1:]]
                if len(arguments)!=len(callee.formal):raise _Refused('call_closure_argument_arity')
                widths=dict(callee.transport)
                if any(v['size']!=widths[formal] for v,formal in zip(arguments,callee.formal)):raise _Refused('call_closure_argument_width')
                output=variables[operation['output']]['size']*8 if operation.get('output') is not None else 0
                if output!=callee.return_bits:raise _Refused('call_closure_return_width')
                if callee.pointer_provenance_proof:
                    required=json.loads(callee.pointer_provenance_proof)['used_address_formals']
                    pointer_sinks.extend(operation['inputs'][1+callee.formal.index(p)] for p in required)
                slots=tuple(callee.formal.index(v) for v,_ in callee.transport)
                sites.append(_Site(identity,operation['id'],index,callee_id,slots))
                if len(sites)>128:raise _Refused('call_closure_edge_budget')
            if effects and (pointer_sinks or stack_slots and any(o['opcode'] in ('PTRADD','PTRSUB') for o in data['operations'])):
                from aether_re.pointer_provenance import prove_pointer_provenance
                declared=set()
                for parameter,association in zip(high_observation['parameters'],parameters):
                    # Observed type text selects a caller hypothesis, never proves ABI.
                    if '*' in parameter.get('type_name','') and parameter['size']==context['address_bits']//8:
                        declared.update(association['input_varnodes'])
                try:pointer_proof=prove_pointer_provenance(data,declared,observation_sha256=high_digest,extra_sinks=pointer_sinks)
                except ValueError as error:raise _Refused(str(error)) from error
                snapshots[identity]=replace(snapshot,pointer_provenance_proof=_bytes(pointer_proof))
            visiting.remove(identity);order.append(identity)
        visit(root.function_id,0)
        heights={}
        for identity in order:
            heights[identity]=max((1+heights[s.callee] for s in sites if s.caller==identity),default=0)
        if heights[root.function_id]>max_depth:raise _Refused('call_closure_depth_budget')
        functions=tuple(replace(snapshots[identity],number=index,
            emitted_name=function_name if identity==root.function_id else 'aether_callee_'+str(index))
            for index,identity in enumerate(sorted(snapshots)))
        fingerprint_data=dict(model=call_model,root=root.function_id,
            functions=[(f.identity,f.payload_sha256,f.observation_sha256,f.emitted_name) for f in functions],
            sites=[(s.caller,s.operation,s.callee,s.slots) for s in sites],
            memory_runtime_sha256=hashlib.sha256(_SPARSE_MEMORY_RUNTIME.encode()).hexdigest(),
            call_runtime_sha256=hashlib.sha256(CALL_RUNTIME.encode()).hexdigest())
        if effects:
            fingerprint_data['effect_runtime_sha256']=hashlib.sha256(effect_runtime.encode()).hexdigest()
            fingerprint_data['ctree_node_budget']=512
        reuse_digests={f.identity:hashlib.sha256(f.stack_reuse_proof).hexdigest() for f in functions if f.stack_reuse_proof}
        if reuse_digests:fingerprint_data['stack_reuse_proofs']=reuse_digests
        pointer_digests={f.identity:hashlib.sha256(f.pointer_provenance_proof).hexdigest() for f in functions if f.pointer_provenance_proof}
        if pointer_digests:fingerprint_data['pointer_provenance_proofs']=pointer_digests
        stack_parameter_digests={f.identity:hashlib.sha256(f.stack_parameter_proof).hexdigest() for f in functions if f.stack_parameter_proof}
        if stack_parameter_digests:fingerprint_data['stack_parameter_proofs']=stack_parameter_digests
        fingerprint=hashlib.sha256(_bytes(fingerprint_data)).hexdigest()
        context=_CallContext(functions,tuple(sites),root.function_id,fingerprint,_TOKEN,call_model);translations={}
        for identity in order:
            item=context.function(identity)
            translated=reconstruct_high_pcode(json.loads(item.payload),expected_target=export.target_sha256,
                expected_address=item.address,evidence_sha256=item.evidence_sha256,function_name=item.emitted_name,
                memory_model='bounded-bytes.v2',_call_context=context)
            if translated['status']!='complete':raise _Refused('call_closure_function_untranslatable:'+','.join(translated['errors']))
            translations[identity]=translated
        source=_SPARSE_MEMORY_RUNTIME+'\n'+CALL_RUNTIME+'\n'+(effect_runtime+'\n' if effects else '')+'\n'.join(translations[i]['ctree']['structured_c_source'] for i in order)
        if len(source.encode('utf-8'))>MAX_OUTPUT_BYTES:raise _Refused('call_closure_output_budget')
        translated=translations[root.function_id]
        report.update(status='complete',structured_c_source=source,ctree=translated['ctree'],input_bindings=translated['input_bindings'],
            runtime_parameters=translated['runtime_parameters'],return_bits=translated['return_bits'],function_name=function_name,
            source_ir_sha256=root.ir_analysis['source_ir_sha256'],memory_model=translated['memory_model'],
            call_model=dict(schema=call_model,context_sha256=fingerprint,context_words=[format(word,'016x') for word in context.words],
                functions=[dict(identity=f.identity,index=f.number,label=f.label,function_name=f.emitted_name,
                source_ir_sha256=f.evidence_sha256,payload_sha256=f.payload_sha256,observation_sha256=f.observation_sha256,
                return_bits=f.return_bits,executable_file_blocks=proofs[f.identity],
                private_stack_slots=[dict(varnode=s[0],space=s[1],offset=s[2],bytes=s[3]) for s in f.stack_slots],
                **(dict(stack_reuse_proof=json.loads(f.stack_reuse_proof)) if f.stack_reuse_proof else {}),
                **(dict(pointer_provenance_proof=json.loads(f.pointer_provenance_proof)) if f.pointer_provenance_proof else {}),
                **(dict(stack_parameter_proof=json.loads(f.stack_parameter_proof)) if f.stack_parameter_proof else {})) for f in functions],
                call_sites=[dict(caller=s.caller,operation=s.operation,operation_index=s.operation_number,callee=s.callee,
                    transport_argument_slots=list(s.slots)) for s in sites],max_functions=max_functions,max_depth=max_depth,
                observed_call_depth=heights[root.function_id],
                runtime_status_codes={0:'ok',1:'invalid_state',2:'depth_budget',3:'trace_budget',4:'call_budget',5:'cancelled',6:'deadline_observed'},
                runtime_limits=dict(events=4096,depth=16,calls=1000000,arguments=64),
                hypotheses=['each observed formal ordinal corresponds to the same call operand slot',
                    'valid nonaliasing memory state, call state and trace buffers supplied by trusted caller',
                    'optional poll callback is bounded trusted infrastructure and does not mutate runtime state',
                    'definition-only disjoint stack SSA slots are function-private values in this closed pure IR model, not recovered machine stack ABI',
                    'failed states and partial traces are preserved; resetting status does not establish a valid replay',
                    'without a poll callback there is no wall-clock deadline proof; shared step budget still applies',
                    'return value invalid when either runtime status is nonzero; null state is an invalid precondition'],
                abi_recovered=False,call_semantics_proved=False))
        if effects:
            memory_operations=[];empty_blocks=[]
            for function in functions:
                data=json.loads(function.payload)
                variables={v['id']:v for v in data['varnodes']}
                for index,operation in enumerate(data['operations']):
                    if operation['opcode'] in ('LOAD','STORE'):
                        width=variables[operation['output']]['size'] if operation['opcode']=='LOAD' else variables[operation['inputs'][2]]['size']
                        memory_operations.append(dict(function=function.identity,function_index=function.number,
                            operation=operation['id'],operation_index=index,token=function.number*1024+index,
                            pc=operation['sequence']['pc'],block=next(b['id'] for b in data['blocks'] if operation['id'] in b['operations']),
                            kind=operation['opcode'],width=width))
                empty_blocks.extend(dict(function=function.identity,function_index=function.number,block=b['id'],block_index=index)
                    for index,b in enumerate(data['blocks']) if not b['operations'])
            report['memory_model']['count_scope']='selected_root_static_operations'
            report['call_model']['hypotheses'][3]='definition-only stack SSA values are private in this closed IR model; reused byte ranges require disjoint liveness proof, not original stack ABI'
            report['call_model']['hypotheses'][-1]='return value invalid when any of three runtime statuses is nonzero; null state is an invalid precondition'
            if pointer_digests:
                report['call_model']['hypotheses'].append('observed pointer formals conditionally designate caller-supplied abstract external addresses; private SSA storage is not a frame pointer or recovered RAM/ABI')
            report['effect_model']=dict(schema='bounded-operation-start-trace.v1',event_limit=1000000,
                event_kinds={1:'operation_start',2:'empty_block_start'},status_codes={0:'ok',1:'invalid_state',2:'trace_budget'},
                memory_operations=memory_operations,empty_blocks=empty_blocks,
                static_memory_reads=sum(o['kind']=='LOAD' for o in memory_operations),
                static_memory_writes=sum(o['kind']=='STORE' for o in memory_operations),
                count_scope='entire_closure_static_operations',
                hypotheses=['fresh zero-count runtime history at root; shared history across callees',
                    'events record starts after tick/trace admission, not successful operation completion',
                    'pre-event counters and final states join operation, memory and call streams',
                    'caller-owned valid nonaliasing buffers and initial abstract bytes; not authenticated process memory'])
        if call_model==STACK_MODEL:
            report['call_model']['hypotheses'].append('observed stack formals are immutable supplied 64-bit values in the explicit Microsoft x64 layout, not frame addresses or recovered original arity')
        if len(_bytes(report))>MAX_OUTPUT_BYTES:raise _Refused('call_closure_output_budget')
    except _Refused as error:
        report={key:value for key,value in report.items() if key in
            {'schema','target_sha256','function_address','original_source_recovered','abi_recovered',
             'source_parameter_count_proved','binary_equivalence_proved','call_semantics_proved','target_executed','limitations'}}
        report.update(status='unsupported',structured_c_source=None,errors=[str(error)])
    return report
