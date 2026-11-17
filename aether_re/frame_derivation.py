"""Derive a distinct conditional frame program from observed High P-Code.

This module does not verify native frame facts, admit callees, recover ABI or
construct a production call context. Source IR and caller-supplied hypotheses
are preserved in provenance; the output is a different explicitly derived IR.
"""
from __future__ import annotations

import copy
import hashlib
import json

from aether_re.ghidra_pcode_ir import analyze_high_pcode
from aether_re.high_parameters import bind_high_parameters


def _require(condition, reason):
    if not condition:
        raise ValueError('frame_derivation_' + reason)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _checked_ir(data, evidence_sha256):
    _require(isinstance(data, dict) and isinstance(data.get('varnodes'), list)
             and isinstance(data.get('operations'), list) and 'target_sha256' in data
             and 'function_address' in data, 'ir_envelope')
    _require(len(data['varnodes']) <= 800 and len(data['operations']) <= 900, 'ir_budget')
    checked = analyze_high_pcode(data, expected_target=data['target_sha256'],
                                expected_address=data['function_address'], evidence_sha256=evidence_sha256)
    _require(checked['summary']['status'] == 'structurally_valid'
             and not checked['summary']['unresolved_liveins']
             and not checked['summary']['unreachable_blocks'], 'structural')
    _require(all(node['size'] in (1, 2, 4, 8) for node in data['varnodes']), 'word_width')
    return checked


def _binding(data, observation, evidence_sha256):
    bound = bind_high_parameters(data, observation, expected_target=data['target_sha256'],
                                 expected_address=data['function_address'], evidence_sha256=evidence_sha256)
    _require(len(bound['parameters']) <= 64, 'formal_budget')
    _require(all(p['status'] == 'observed_input_association'
                 and p['instance_enumeration_available'] and not p['omitted_instances']
                 and len(p['input_varnodes']) == 1 for p in bound['parameters']), 'formal_association')
    identities = [p['input_varnodes'][0] for p in bound['parameters']]
    _require(len(set(identities)) == len(identities), 'formal_identity')
    nodes = {n['id']: n for n in data['varnodes']}
    _require(all(nodes[identity]['size'] == parameter['size'] in (1, 2, 4, 8)
                 for identity, parameter in zip(identities, observation['parameters'])), 'formal_width')
    return bound


def _formal_return_identity(data, observation, evidence_sha256):
    """Find one observed pointer formal reached by COPY/CAST at every RETURN.

    PHI, constants, arithmetic, cycles, width changes and disagreement across
    returns are refused. The fixed IR/dependency budgets are refusal limits.
    This proves conditional value identity, not source pointer type or ABI.
    """
    _checked_ir(data, evidence_sha256)
    binding = _binding(data, observation, evidence_sha256)
    nodes = {n['id']: n for n in data['varnodes']}
    operations = {o['id']: o for o in data['operations']}
    formal = {p['input_varnodes'][0]: p['ordinal'] for p in binding['parameters']}
    returns = [op for op in data['operations'] if op['opcode'] == 'RETURN']
    _require(bool(returns), 'return_missing')
    dependencies = {}; roots = set(); visits = 0
    for returned in returns:
        _require(len(returned['inputs']) == 2, 'return_shape')
        marker = nodes[returned['inputs'][0]]
        _require(marker['kind'] == 'constant' and int(marker['offset'], 16) == 0, 'return_target')
        identity = returned['inputs'][1]; seen = set()
        while True:
            visits += 1
            _require(visits <= 1800 and identity not in seen, 'return_dependency_budget_or_cycle')
            seen.add(identity); node = nodes[identity]
            _require(node['size'] == 8, 'return_pointer_width')
            if node['input']:
                _require(identity in formal, 'return_nonformal_root')
                roots.add(identity); dependencies[identity] = []; break
            definition = operations.get(node.get('definition'))
            _require(definition is not None and definition['opcode'] in ('COPY', 'CAST')
                     and len(definition['inputs']) == 1, 'return_identity')
            dependencies[identity] = list(definition['inputs'])
            identity = definition['inputs'][0]
    _require(len(roots) == 1, 'return_formal_disagreement')
    root = next(iter(roots))
    return dict(schema='observed-formal-return-identity.v1', return_input_varnode=root,
                return_formal_ordinal=formal[root], value_bytes=8, dependencies=dependencies,
                return_operations=[o['id'] for o in returns], ir_payload_sha256=_digest(data),
                observation_sha256=binding['source_observation_sha256'],
                source_ir_sha256=evidence_sha256, callee_admitted=False,
                abi_recovered=False, original_source_recovered=False)


def _single_block(data):
    _require(len(data['blocks']) == 1, 'single_block_scope')
    block = data['blocks'][0]
    _require(data['entry_block'] == block['id'] and not block['predecessors']
             and not block['successors'] and block['operations'] == [o['id'] for o in data['operations']],
             'single_block_order')


def _fresh(prefix, identity, reserved):
    base = prefix + identity; candidate = base; suffix = 0
    while candidate in reserved:
        suffix += 1; candidate = base + '_' + str(suffix)
    reserved.add(candidate)
    return candidate


def derive_frame_program(caller, callee_info, frame_fact, *, object_base=0x100000):
    """Return a conditional derived IR, without mutating any supplied object.

    Supported scope: Windows x64, one acyclic single-block caller/callee and one
    direct CALL. The supplied address fact is a dependency hypothesis only.
    Native prefix correspondence and memory usage/escape need separate proofs.
    """
    _require(type(object_base) is int and 0 <= object_base < 1 << 64
             and object_base % 16 == 0, 'object_base')
    _require(isinstance(callee_info, dict) and all(key in callee_info for key in
             ('pcode_ir', 'high_parameter_observation', 'ir_analysis'))
             and isinstance(callee_info['ir_analysis'], dict)
             and 'source_ir_sha256' in callee_info['ir_analysis'], 'callee_envelope')
    _require(isinstance(frame_fact, dict) and all(key in frame_fact for key in
             ('target_sha256', 'function_address', 'ir_payload_sha256', 'requested_object_bytes',
              'entry_rsp_offset', 'call_operation', 'call_pc', 'ambient_varnode',
              'pointer_operation', 'pointer_pc')), 'frame_fact_envelope')
    child = callee_info['pcode_ir']; observation = callee_info['high_parameter_observation']
    source_evidence = callee_info['ir_analysis']['source_ir_sha256']
    _checked_ir(caller, _digest(caller)); _checked_ir(child, source_evidence)
    for data in (caller, child):
        context = data['context']
        _require(context['language_id'] == 'x86:LE:64:default' and context['compiler_spec_id'] == 'windows'
                 and context['endian'] == 'little' and context['address_bits'] == 64, 'context_scope')
        _single_block(data)
        for operation in data['operations']:
            if operation['opcode'] in ('PTRADD', 'PTRSUB'):
                nodes = {n['id']: n for n in data['varnodes']}
                _require(nodes[operation['output']]['size'] == 8
                         and all(nodes[arg]['size'] == 8 for arg in operation['inputs']), 'pointer_delta_width')
    _require(caller['target_sha256'] == child['target_sha256']
             and caller['context'] == child['context'], 'context_identity')
    _require(frame_fact['target_sha256'] == caller['target_sha256']
             and frame_fact['function_address'] == caller['function_address']
             and frame_fact['ir_payload_sha256'] == _digest(caller), 'frame_fact_identity')
    extent = frame_fact['requested_object_bytes']; delta = frame_fact['entry_rsp_offset']
    _require(type(extent) is int and 1 <= extent <= 4096, 'object_extent')
    _require(type(delta) is int and -(1 << 63) <= delta < 1 << 63, 'frame_offset')
    entry = object_base - delta
    _require(0 <= entry < 1 << 64 and extent - 1 <= ((1 << 64) - 1) - object_base,
             'frame_relocation_overflow')
    calls = [op for op in caller['operations'] if op['opcode'] == 'CALL']
    _require(len(calls) == 1, 'one_call_scope'); call = calls[0]
    _require(call['id'] == frame_fact['call_operation'] and call['sequence']['pc'] == frame_fact['call_pc'], 'call_site')
    _require(not any(op['opcode'] in ('CALL', 'CALLIND', 'BRANCH', 'CBRANCH', 'MULTIEQUAL') for op in child['operations']), 'callee_control_scope')
    _require(not any(op['opcode'] in ('CALLIND', 'BRANCH', 'CBRANCH', 'MULTIEQUAL') for op in caller['operations']), 'caller_control_scope')
    _require(caller['operations'][-1]['opcode'] == 'RETURN' and sum(o['opcode'] == 'RETURN' for o in caller['operations']) == 1
             and child['operations'][-1]['opcode'] == 'RETURN' and sum(o['opcode'] == 'RETURN' for o in child['operations']) == 1, 'terminal_return_scope')
    nodes = {n['id']: n for n in caller['varnodes']}; child_nodes = {n['id']: n for n in child['varnodes']}
    target = nodes[call['inputs'][0]]
    _require(target['kind'] == 'memory' and target['space'] + ':' + format(int(target['offset'], 16), 'x') == child['function_address'], 'direct_call_target')
    bound = _binding(child, observation, source_evidence)
    _require(bound['complete'] and len(call['inputs']) == 1 + len(bound['parameters']), 'call_arity_or_unbound')
    mapping = {}
    for ordinal, parameter in enumerate(bound['parameters']):
        identity = parameter['input_varnodes'][0]; actual = call['inputs'][1 + ordinal]
        _require(child_nodes[identity]['size'] == nodes[actual]['size'], 'call_width')
        mapping[identity] = actual
    returned = _formal_return_identity(child, observation, source_evidence)
    _require(call.get('output') in nodes and nodes[call['output']]['size'] == 8, 'call_return_width')
    ambient = frame_fact['ambient_varnode']; seed_id = frame_fact['pointer_operation']
    _require(ambient in nodes and nodes[ambient]['input'] and nodes[ambient]['kind'] == 'register'
             and nodes[ambient]['size'] == 8, 'ambient_seed')
    seed = next((o for o in caller['operations'] if o['id'] == seed_id), None)
    _require(seed is not None and seed['opcode'] == 'PTRSUB' and seed['inputs'][0] == ambient
             and seed['sequence']['pc'] == frame_fact['pointer_pc'], 'seed_operation')
    constant = nodes[seed['inputs'][1]]
    _require(constant['kind'] == 'constant' and constant['size'] == 8, 'seed_delta')
    raw = int(constant['offset'], 16); signed = raw - (1 << 64) if raw & (1 << 63) else raw
    _require(signed == delta, 'seed_offset')
    _require(all(op['id'] == seed_id or ambient not in op['inputs'] for op in caller['operations']), 'ambient_other_use')
    _require(caller['operations'].index(seed) < caller['operations'].index(call), 'seed_order')
    result = copy.deepcopy(caller)
    reserved_nodes = set(nodes); reserved_ops = {op['id'] for op in caller['operations']}
    renaming = {n['id']: mapping[n['id']] if n['id'] in mapping else _fresh('cal_', n['id'], reserved_nodes) for n in child['varnodes']}
    op_renaming = {op['id']: _fresh('cal_', op['id'], reserved_ops) for op in child['operations']}
    for node in result['varnodes']:
        if node['id'] == ambient:
            node.update(space='const', kind='constant', offset=format(entry, 'x'), input=False, free=True, unaffected=False)
    for node in child['varnodes']:
        if node['id'] in mapping: continue
        new = copy.deepcopy(node); new['id'] = renaming[node['id']]
        if 'definition' in new: new['definition'] = op_renaming[new['definition']]
        result['varnodes'].append(new)
    operations = []; provenance = {}
    def append(operation, role, original, mode):
        new = copy.deepcopy(operation); new['sequence']['order'] = len(operations); operations.append(new)
        provenance[new['id']] = dict(origin=role, original_operation=original['id'], original_sequence=copy.deepcopy(original['sequence']), role=mode)
    for operation in caller['operations']:
        if operation['id'] != call['id']:
            append(operation, 'caller', operation, 'retained'); continue
        for inner in child['operations'][:-1]:
            new = copy.deepcopy(inner); new['id'] = op_renaming[inner['id']]; new['inputs'] = [renaming[arg] for arg in inner['inputs']]
            if 'output' in new: new['output'] = renaming[inner['output']]
            append(new, 'callee', inner, 'alpha_renamed')
        new = copy.deepcopy(call); new['opcode'] = 'COPY'; new['inputs'] = [mapping[returned['return_input_varnode']]]
        append(new, 'caller', call, 'call_result_alias_transport')
        provenance[new['id']]['inlined_return'] = child['operations'][-1]['id']
    result['operations'] = operations; result['blocks'][0]['operations'] = [op['id'] for op in operations]
    used = {arg for op in operations for arg in op['inputs']} | {op['output'] for op in operations if 'output' in op}
    result['varnodes'] = [node for node in result['varnodes'] if node['id'] in used]
    _checked_ir(result, _digest(result))
    evidence = dict(schema='frame-derivation-provenance.v1', caller_sha256=_digest(caller), callee_sha256=_digest(child),
                    frame_fact_sha256=_digest(frame_fact), derived_sha256=_digest(result), operations=provenance,
                    formal_mapping=mapping, callee_varnode_renaming=renaming, callee_operation_renaming=op_renaming,
                    return_identity=returned, source_blocks=dict(caller=copy.deepcopy(caller['blocks']), callee=copy.deepcopy(child['blocks'])),
                    frame=dict(object_base=object_base, object_bytes=extent, abstract_entry=entry, entry_offset=delta),
                    binary_equivalence_proved=False, production_admission=False, native_frame_fact_verified=False,
                    abi_recovered=False, original_source_recovered=False)
    return dict(schema='derived-frame-program.v1', status='conditional_model', derived_ir=result, provenance=evidence,
                production_admission=False, binary_equivalence_proved=False, native_frame_fact_verified=False,
                abi_recovered=False, original_source_recovered=False,
                limitations=['derived IR is a distinct program under supplied frame hypothesis',
                             'native prefix, memory extent, aliases, escape, lifetime and ABI require separate qualification'])
