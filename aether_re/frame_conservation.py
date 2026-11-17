"""Check SSA transport independently of a derived program's claimed provenance."""
from __future__ import annotations
import copy
from aether_re.frame_derivation import _binding, _digest, _formal_return_identity


def check_frame_transport(root, callee, frame_fact, packet, usage, *, object_base):
    """Return effect links, or refuse changed operations/operands/metadata."""
    try:
        return _check(root, callee, frame_fact, packet, usage, object_base)
    except (KeyError, TypeError, IndexError, AttributeError, StopIteration) as error:
        raise ValueError('frame_transport_envelope') from error


def _check(root, callee, fact, packet, usage, base):
    def require(value, reason):
        if not value:
            raise ValueError('frame_transport_' + reason)
    caller = root['pcode_ir']; child = callee['pcode_ir']
    ir = packet['derived_ir']; proof = packet['provenance']
    require(usage['root_ir_sha256'] == _digest(caller) and usage['frame_fact_sha256'] == _digest(fact)
            and usage['callee_ir_sha256'] == {child['function_address']: _digest(child)}, 'usage_identity')
    require(proof['caller_sha256'] == _digest(caller) and proof['callee_sha256'] == _digest(child)
            and proof['frame_fact_sha256'] == _digest(fact) and proof['derived_sha256'] == _digest(ir), 'digest')
    call = next(op for op in caller['operations'] if op['opcode'] == 'CALL')
    bound = _binding(child, callee['high_parameter_observation'], callee['ir_analysis']['source_ir_sha256'])
    formals = [p['input_varnodes'][0] for p in bound['parameters']]
    require(len(call['inputs']) == len(formals) + 1, 'arity')
    mapping = dict(zip(formals, call['inputs'][1:]))
    require(proof['formal_mapping'] == mapping, 'formal_mapping')
    rename = proof['callee_varnode_renaming']; opnames = proof['callee_operation_renaming']
    require(set(rename) == {node['id'] for node in child['varnodes']} and
            set(opnames) == {op['id'] for op in child['operations']}, 'renaming_inventory')
    caller_ids = {node['id'] for node in caller['varnodes']}
    nonformal = [rename[node['id']] for node in child['varnodes'] if node['id'] not in mapping]
    require(all(rename[name] == value for name, value in mapping.items()) and len(set(nonformal)) == len(nonformal)
            and not set(nonformal) & caller_ids, 'node_collision')
    require(len(set(opnames.values())) == len(opnames) and not set(opnames.values()) & {op['id'] for op in caller['operations']}, 'operation_collision')
    returned = _formal_return_identity(child, callee['high_parameter_observation'], callee['ir_analysis']['source_ir_sha256'])
    require(proof['return_identity'] == returned, 'return_identity')
    expected_ops = []; expected_provenance = {}
    def append(op, source, role, mode):
        op = copy.deepcopy(op); op['sequence']['order'] = len(expected_ops); expected_ops.append(op)
        expected_provenance[op['id']] = dict(origin=role, original_operation=source['id'],
            original_sequence=copy.deepcopy(source['sequence']), role=mode)
    for operation in caller['operations']:
        if operation['id'] != call['id']:
            append(operation, operation, 'caller', 'retained'); continue
        for source in child['operations'][:-1]:
            op = copy.deepcopy(source); op['id'] = opnames[source['id']]
            op['inputs'] = [rename[arg] for arg in source['inputs']]
            if 'output' in source:
                op['output'] = rename[source['output']]
            append(op, source, 'callee', 'alpha_renamed')
        op = copy.deepcopy(call); op.update(opcode='COPY', inputs=[mapping[returned['return_input_varnode']]])
        append(op, call, 'caller', 'call_result_alias_transport')
        expected_provenance[call['id']]['inlined_return'] = child['operations'][-1]['id']
    require(ir['operations'] == expected_ops, 'operation_transport')
    require(proof['operations'] == expected_provenance, 'provenance_transport')
    extent = fact['requested_object_bytes']; entry = base - fact['entry_rsp_offset']
    require(proof['frame'] == dict(object_base=base, object_bytes=extent, abstract_entry=entry,
                                  entry_offset=fact['entry_rsp_offset']), 'frame_relocation')
    expected = copy.deepcopy(caller)
    for node in expected['varnodes']:
        if node['id'] == fact['ambient_varnode']:
            node.update(space='const', kind='constant', offset=format(entry, 'x'), input=False, free=True, unaffected=False)
    for source in child['varnodes']:
        if source['id'] in mapping:
            continue
        node = copy.deepcopy(source); node['id'] = rename[source['id']]
        if 'definition' in node:
            node['definition'] = opnames[node['definition']]
        expected['varnodes'].append(node)
    expected['operations'] = expected_ops
    expected['blocks'][0]['operations'] = [op['id'] for op in expected_ops]
    used = {arg for op in expected_ops for arg in op['inputs']} | {op['output'] for op in expected_ops if 'output' in op}
    expected['varnodes'] = [node for node in expected['varnodes'] if node['id'] in used]
    require(ir == expected, 'node_or_metadata_transport')
    effects = [(index, op) for index, op in enumerate(ir['operations']) if op['opcode'] in ('STORE', 'LOAD')]
    require(len(effects) == len(usage['memory_events']), 'effect_count')
    links = []
    for (index, operation), event in zip(effects, usage['memory_events']):
        origin = proof['operations'][operation['id']]
        source = caller if origin['origin'] == 'caller' else child
        require(event['function'] == source['function_address'] and event['operation'] == origin['original_operation']
                and event['kind'] == operation['opcode'], 'effect_origin')
        links.append(dict(derived_operation=operation['id'], derived_operation_index=index,
                          source_function=event['function'], source_operation=event['operation'],
                          kind=event['kind'], offset=event['offset'], bytes=event['bytes']))
    return links
