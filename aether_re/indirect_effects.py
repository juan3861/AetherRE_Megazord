"""Observed Ghidra internal INDIRECT references, never alias/effect semantics."""
import re
from aether_re.high_parameters import _budget_bytes
from aether_re.ghidra_pcode_ir import analyze_high_pcode


def validate_indirect_effects(value,*,data,expected_target,expected_address,evidence_sha256):
    """Validate an optional producer sidecar against its verified raw IR bytes."""
    def require(condition):
        if not condition:raise ValueError('indirect_effect_observation_invalid')
    fields={'schema','stage','target_sha256','function_address','source_ir_sha256',
        'total','resolved','unresolved','complete','entries','alias_semantics_proved','call_semantics_proved'}
    require(type(value) is dict and set(value)==fields)
    require(value['schema']=='observed-indirect-effects.v1' and value['stage']=='high_function_after_decompilation')
    require(type(expected_target) is str and re.fullmatch('[0-9a-f]{64}',expected_target) is not None)
    require(type(evidence_sha256) is str and re.fullmatch('[0-9a-f]{64}',evidence_sha256) is not None)
    require(value['target_sha256']==expected_target and value['function_address']==expected_address
        and value['source_ir_sha256']==evidence_sha256)
    require(value['alias_semantics_proved'] is False and value['call_semantics_proved'] is False)
    require(all(type(value[key]) is int and 0<=value[key]<=8192 for key in ('total','resolved','unresolved')))
    require(type(value['complete']) is bool and type(value['entries']) is list and len(value['entries'])<=8192)
    analyze_high_pcode(data,expected_target=expected_target,expected_address=expected_address,evidence_sha256=evidence_sha256)
    operations={o['id']:o for o in data['operations']};nodes={n['id']:n for n in data['varnodes']}
    expected=[o for o in data['operations'] if o['opcode']=='INDIRECT']
    require(len(value['entries'])==len(expected)==value['total'])
    resolved=0
    for row,operation in zip(value['entries'],expected):
        require(type(row) is dict and set(row)=={'operation','reference_varnode','reference_id','status','effect'})
        require(row['operation']==operation['id'] and len(operation['inputs'])==2 and row['reference_varnode']==operation['inputs'][1])
        reference=nodes[operation['inputs'][1]]
        require(type(row['reference_id']) is int and 0<=row['reference_id']<(1<<64)
            and row['reference_id']==int(reference['offset'],16))
        status=row['status'];require(type(status) is str and status in ('resolved','unavailable','outside_inventory','reference_out_of_range'))
        if status=='resolved':
            effect=row['effect'];require(type(effect) is dict and set(effect)=={'operation','opcode','sequence'})
            require(type(effect['operation']) is str and effect['operation'] in operations and effect['operation']!=operation['id'])
            actual=operations[effect['operation']];sequence=effect['sequence']
            require(type(sequence) is dict and set(sequence)=={'pc','time','order'}
                and type(sequence['pc']) is str and type(sequence['time']) is int and type(sequence['order']) is int)
            require(effect['opcode']==actual['opcode'] and sequence==actual['sequence']
                and row['reference_id']<=0xffffffff and sequence['time']==row['reference_id'])
            resolved+=1
        else:
            require(row['effect'] is None)
            require((row['reference_id']>0xffffffff)==(status=='reference_out_of_range'))
    require(value['resolved']==resolved and value['unresolved']==len(expected)-resolved
        and value['complete']==(resolved==len(expected)))
    require(len(_budget_bytes(value))<=256*1024)
    return value
