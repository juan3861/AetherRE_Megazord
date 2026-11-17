"""Conditional observed integer stack-value transport, not recovered ABI."""
import hashlib
import json
from aether_re.high_parameters import bind_high_parameters

def prove_ms_x64_stack_values(data,observation,*,evidence_sha256):
    """Bind immutable formal values under an explicit Windows x64 hypothesis.

    Only validated High IR/HighSymbol identity is used. Stack offsets do not
    become memory addresses, and source arity/calling-convention recovery is
    never inferred from association completeness.
    """
    def require(condition,reason):
        if not condition:raise ValueError('stack_parameter_'+reason)
    binding=bind_high_parameters(data,observation,expected_target=data['target_sha256'],
        expected_address=data['function_address'],evidence_sha256=evidence_sha256)
    require(binding['complete'],'association_incomplete')
    context=data['context']
    require(context['language_id']=='x86:LE:64:default' and context['compiler_spec_id']=='windows'
        and context['address_bits']==64 and context['endian']=='little','context')
    require(len(data['varnodes'])<=800 and len(data['operations'])<=900,'budget')
    require(not any(o['opcode'] in ('LOAD','STORE','PTRADD','PTRSUB','CALLIND','CALLOTHER','INDIRECT') for o in data['operations']),'address_or_indirect_effect')
    nodes={v['id']:v for v in data['varnodes']};spaces={s['name']:s for s in context['spaces']}
    parameters=binding['parameters'];require(1<=len(parameters)<=16,'formal_count')
    require(len(parameters)==len(observation['parameters']),'formal_count')
    inputs=[];stack_inputs=[];used=set()
    for ordinal,(association,parameter) in enumerate(zip(parameters,observation['parameters'])):
        require(association['ordinal']==parameter['ordinal']==ordinal,'ordinal')
        require(not parameter['hidden_return'] and not parameter['this_pointer'] and '*' not in parameter['type_name'],'special_parameter')
        require(parameter['size']==8 and len(association['input_varnodes'])==1,'shape')
        identity=association['input_varnodes'][0];node=nodes[identity]
        require(identity not in used,'duplicate');used.add(identity)
        require(node['input'] and not node.get('definition') and node['size']==8
            and not node.get('persistent') and not node.get('unaffected'),'input')
        expected_kind='register' if ordinal<4 else 'stack'
        offset=(8,16,128,136)[ordinal] if ordinal<4 else 40+8*(ordinal-4)
        require(node['kind']==expected_kind and int(node['offset'],16)==offset,'location')
        space=spaces[node['space']]
        require(space['kind']==expected_kind and space['word_size']==1
            and offset+8<=1<<space['bits'],'space')
        item=dict(ordinal=ordinal,varnode=identity,space=node['space'],offset=offset,bytes=8)
        inputs.append(item)
        if ordinal>=4:stack_inputs.append(item)
    require(used=={n['id'] for n in nodes.values() if n['input']},'unassociated_input')
    for node in nodes.values():
        if node['kind']!='stack':continue
        if node['input']:require(node['id'] in used,'unassociated_stack_input');continue
        require(bool(node.get('definition')) and not node.get('persistent'),'private_storage')
        start=int(node['offset'],16)
        require(all(node['space']!=item['space'] or start+node['size']<=item['offset'] or item['offset']+8<=start for item in stack_inputs),'private_overlap')
    payload=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
    return dict(schema='conditional-ms-x64-stack-values.v1',status='observed_value_transport',
        target_sha256=data['target_sha256'],function_address=data['function_address'],source_ir_sha256=evidence_sha256,
        ir_payload_sha256=hashlib.sha256(payload).hexdigest(),source_observation_sha256=binding['source_observation_sha256'],
        formal_count=len(inputs),input_layout=inputs,stack_inputs=stack_inputs,
        hypothesis='observed 64-bit integer formals use the explicit Microsoft x64 value layout; stack inputs are immutable supplied values, not frame addresses',
        abi_recovered=False,source_parameter_count_proved=False,binary_equivalence_proved=False,
        original_stack_frame_recovered=False)
