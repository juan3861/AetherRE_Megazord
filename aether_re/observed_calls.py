"""Observed call edges from identity-bound High P-Code, without ABI invention."""
from __future__ import annotations
import json
import re

def validate_function_storage(value,*,address,parameter_count,signature_source):
    """Strict observed storage envelope; does not adjudicate ABI correctness."""
    def require(ok):
        if not ok:raise ValueError('ghidra_storage_observation_invalid')
    def text(v,limit=4096):return isinstance(v,str) and 1<=len(v)<=limit
    def integer(v,low,high):return type(v) is int and low<=v<=high
    def canonical(v):
        m=re.fullmatch(r'([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{1,16})',v or '')
        require(m is not None);return m[1]+':'+format(int(m[2],16),'x')
    fields={'schema','function_address','signature_source','convention','custom_storage','variadic','parameters','return_value','abi_recovered'}
    require(type(value) is dict and set(value)==fields)
    require(value['schema']=='observed-function-storage.v1' and canonical(value['function_address'])==canonical(address))
    require(value['signature_source'] in ('DEFAULT','ANALYSIS','IMPORTED','USER_DEFINED')
        and value['signature_source']==signature_source and text(value['convention'],256))
    require(type(value['custom_storage']) is bool and type(value['variadic']) is bool and value['abi_recovered'] is False)
    parameters=value['parameters'];require(type(parameters) is list and len(parameters)==parameter_count and len(parameters)<=128)
    variable_fields={'name','type_name','type_size','source','auto_parameter','forced_indirect','storage'}
    for ordinal,variable in [(i,p) for i,p in enumerate(parameters)]+[(None,value['return_value'])]:
        require(type(variable) is dict and set(variable)==variable_fields|({'ordinal'} if ordinal is not None else set()))
        if ordinal is not None:require(type(variable['ordinal']) is int and variable['ordinal']==ordinal)
        require(text(variable['name']) and text(variable['type_name']) and integer(variable['type_size'],-1,1048576))
        require(variable['source'] in ('DEFAULT','ANALYSIS','IMPORTED','USER_DEFINED'))
        require(type(variable['auto_parameter']) is bool and type(variable['forced_indirect']) is bool)
        storage=variable['storage'];require(type(storage) is dict and set(storage)=={'size','unassigned','void','bad','pieces'})
        require(integer(storage['size'],0,1048576) and all(type(storage[k]) is bool for k in ('unassigned','void','bad')))
        pieces=storage['pieces'];require(type(pieces) is list and len(pieces)<=16)
        unavailable=storage['unassigned'] or storage['void'] or storage['bad']
        require(sum(int(storage[k]) for k in ('unassigned','void','bad'))<=1)
        require(not pieces and storage['size']==0 if unavailable else bool(pieces))
        total=0;seen=[]
        for piece in pieces:
            require(type(piece) is dict and set(piece)=={'space','offset','size'})
            require(text(piece['space'],64) and re.fullmatch('[A-Za-z0-9_.-]{1,64}',piece['space']) is not None)
            require(isinstance(piece['offset'],str) and re.fullmatch('[0-9a-fA-F]{1,16}',piece['offset']) is not None and integer(piece['size'],1,1048576))
            offset=int(piece['offset'],16);require(offset+piece['size']<=1<<64)
            require(not any(space==piece['space'] and offset<end and start<offset+piece['size'] for space,start,end in seen))
            seen.append((piece['space'],offset,offset+piece['size']));total+=piece['size']
        require(total==storage['size'])
    require(len(json.dumps(value,ensure_ascii=False).encode())<=256*1024)
    return value

def inventory_observed_calls(export,*,max_functions=256,max_calls=1024):
    """Report operands and address matches; never resolve indirect targets by guessing."""
    if type(max_functions) is not int or not 1<=max_functions<=1024 or type(max_calls) is not int or not 0<=max_calls<=4096:
        raise ValueError('observed_calls_budget_invalid')
    digest=export.target_sha256
    if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('observed_calls_target_invalid')
    if len(export.functions)>4096 or export.total_functions!=len(export.functions):raise ValueError('observed_calls_inventory_invalid')
    addresses={}
    for identity,info in export.functions.items():
        match=re.fullmatch(r'([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{1,16})',info.address or '')
        if not match:raise ValueError('observed_calls_address_invalid')
        address=match[1]+':'+format(int(match[2],16),'x')
        if identity!=digest+'!'+address or address in addresses:raise ValueError('observed_calls_identity_invalid')
        if not isinstance(info.name,str) or not 1<=len(info.name)<=4096:raise ValueError('observed_calls_name_invalid')
        addresses[address]=info
    result=dict(schema='observed-call-inventory.v1',target_sha256=digest,total_functions=len(export.functions),
        functions_examined=0,functions_with_verified_ir=0,functions_without_ir=0,calls=[],truncated=False,complete=False,
        call_semantics_proved=False,abi_recovered=False,target_executed=False,
        limitations=['IR operands are observations, not recovered source parameter/register ABI',
          'an inventory address match does not prove callee behavior, imports or runtime target',
          'indirect and user operations are not resolved as direct addresses'])
    for identity,info in sorted(export.functions.items()):
        if result['functions_examined']>=max_functions:result['truncated']=True;break
        result['functions_examined']+=1
        if info.pcode_ir is None or not info.ir_analysis or not info.normalized_ir:
            result['functions_without_ir']+=1;continue
        # Reuse the bridge's identity/digest/graph consistency boundary. A legitimate
        # unsupported lowering still has verified IR; a changed payload raises.
        export.select_reconstruction(identity)
        result['functions_with_verified_ir']+=1
        variables={v['id']:v for v in info.pcode_ir['varnodes']}
        for operation in info.pcode_ir['operations']:
            opcode=operation['opcode']
            if opcode not in ('CALL','CALLIND','CALLOTHER'):continue
            if len(result['calls'])>=max_calls:result['truncated']=True;break
            operand=variables[operation['inputs'][0]];kind={'CALL':'direct','CALLIND':'indirect','CALLOTHER':'user_operation'}[opcode]
            target_id=None;callee_name=None;resolution='unresolved'
            if opcode=='CALL' and operand['kind']=='memory':
                address=operand['space']+':'+format(int(operand['offset'],16),'x')
                target_id=digest+'!'+address
                if address in addresses:resolution='inventory_address_match';callee_name=addresses[address].name
                else:resolution='observed_address_outside_inventory'
            output=variables[operation['output']] if operation.get('output') is not None else None
            row=dict(caller_id=identity,operation_id=operation['id'],pc=operation['sequence']['pc'],kind=kind,
                target_id=target_id,callee_name=callee_name,resolution=resolution,target_varnode=operand['id'],
                arguments=[dict(slot=i,varnode=name,bits=variables[name]['size']*8) for i,name in enumerate(operation['inputs'][1:])],
                return_varnode=output['id'] if output else None,return_bits=output['size']*8 if output else None,
                source_ir_sha256=info.ir_analysis['source_ir_sha256'],abi_recovered=False,call_executed=False)
            if opcode=='CALLOTHER' and operand['kind']=='constant':row['user_operation_index']=int(operand['offset'],16)
            result['calls'].append(row)
        if result['truncated']:break
    result['complete']=not result['truncated'] and result['functions_with_verified_ir']==result['total_functions']
    result['status']='complete' if result['complete'] else 'partial'
    result['direct_calls']=sum(row['kind']=='direct' for row in result['calls'])
    result['indirect_calls']=sum(row['kind']=='indirect' for row in result['calls'])
    result['user_operations']=sum(row['kind']=='user_operation' for row in result['calls'])
    if len(json.dumps(result,ensure_ascii=False).encode())>1024*1024:raise ValueError('observed_calls_output_budget')
    return result

def bind_observed_storage(data,observation,*,expected_target,expected_address,evidence_sha256):
    """Compare exact byte storage, retaining gaps; no parameter/ABI guessing."""
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    checked=analyze_high_pcode(data,expected_target=expected_target,expected_address=expected_address,evidence_sha256=evidence_sha256)
    if type(observation) is not dict or type(observation.get('parameters')) is not list:
        raise ValueError('ghidra_storage_observation_invalid')
    validate_function_storage(observation,address=expected_address,parameter_count=len(observation['parameters']),signature_source=observation.get('signature_source'))
    inputs=[v for v in data['varnodes'] if v['input']];parameters=[];owners={}
    for parameter in observation['parameters']:
        matches=[]
        for piece in parameter['storage']['pieces']:
            candidates=[v['id'] for v in inputs if v['space']==piece['space'] and int(v['offset'],16)==int(piece['offset'],16) and v['size']==piece['size']]
            identity=candidates[0] if len(candidates)==1 else None
            matches.append(dict(space=piece['space'],offset=piece['offset'],size=piece['size'],varnode=identity,candidates=candidates))
            for candidate in candidates:owners.setdefault(candidate,set()).add(parameter['ordinal'])
        parameters.append(dict(ordinal=parameter['ordinal'],name=parameter['name'],auto_parameter=parameter['auto_parameter'],
            forced_indirect=parameter['forced_indirect'],pieces=matches,
            status='exact_storage_match' if matches and all(m['varnode'] is not None for m in matches) else 'unresolved'))
    used=set()
    for parameter in parameters:
        if any(len(m['candidates'])>1 or any(len(owners[c])>1 for c in m['candidates']) for m in parameter['pieces']):
            parameter['status']='ambiguous_storage'
        if parameter['status']=='exact_storage_match':used.update(m['varnode'] for m in parameter['pieces'])
    unbound=[v['id'] for v in inputs if v['id'] not in used]
    complete=(checked['summary']['status']=='structurally_valid' and not checked['summary']['unresolved_liveins']
        and not unbound and all(p['status']=='exact_storage_match' for p in parameters))
    return dict(schema='observed-storage-input-binding.v1',target_sha256=expected_target,function_address=expected_address,
        source_ir_sha256=evidence_sha256,parameters=parameters,unbound_inputs=unbound,
        unbound_input_observations=[dict(varnode=v['id'],space=v['space'],offset=v['offset'],bits=v['size']*8,
            unaffected=bool(v.get('unaffected')),persistent=bool(v.get('persistent'))) for v in inputs if v['id'] not in used],
        complete=complete,abi_recovered=False,call_semantics_proved=False,
        limitations=['exact byte storage equality between two Ghidra observations, not recovered original parameter ABI',
            'no widening, register alias synthesis, argument reordering or implicit input creation',
            'return storage and clobbers require separate validation; complete covers input storage inventory only'])
