"""Conditional private-address usage; supplied native facts are hypotheses.

No file or target execution occurs. The proof covers one caller-owned abstract
object and bounded single-block direct callees, not original ABI or native IR
fidelity. A distinct derived program still requires checked lowering.
"""
from __future__ import annotations
import hashlib
import json
from aether_re.frame_derivation import _checked_ir, _binding, _formal_return_identity

def prove_frame_usage(*, root, callees, frame_fact, extent=None, max_operations=256):
    """Check definedness/escape without mutating inputs or granting admission."""
    try:
        return _prove_frame_usage(root=root, callees=callees, frame_fact=frame_fact,
                                  extent=extent, max_operations=max_operations)
    except (KeyError, TypeError, IndexError, StopIteration, AttributeError, RecursionError) as error:
        raise ValueError('frame_usage_envelope') from error

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()

def _prove_frame_usage(*, root, callees, frame_fact, extent=None, max_operations=256):
    def require(condition, reason):
        if not condition:
            raise ValueError('frame_usage_' + reason)
    require(isinstance(root, dict) and isinstance(frame_fact, dict), 'envelope')
    if extent is None:
        extent = frame_fact.get('requested_object_bytes')
    require(type(extent) is int and 1 <= extent <= 4096, 'extent')
    require(type(max_operations) is int and 1 <= max_operations <= 7200, 'budget')
    require(type(callees) is list and len(callees) <= 15, 'function_budget')
    data = root['pcode_ir']
    target = data['target_sha256']
    require(frame_fact['target_sha256'] == target and frame_fact['function_address'] == data['function_address']
            and frame_fact['ir_payload_sha256'] == digest(data)
            and frame_fact['requested_object_bytes'] == extent, 'frame_fact')
    inventory = {}
    for info in [root] + callees:
        item = info['pcode_ir']
        require(item['target_sha256'] == target and item['context'] == data['context'], 'context')
        key = item['function_address']
        require(key not in inventory, 'function_identity')
        inventory[key] = info
    initialized = [False] * extent
    events = []; borrowed = []; visited = []; active = set(); operation_count = 0
    scalar = set('INT_ADD INT_SUB INT_MULT INT_XOR INT_AND INT_OR INT_NEGATE INT_2COMP INT_SLESS INT_SLESSEQUAL INT_LESS INT_LESSEQUAL INT_EQUAL INT_NOTEQUAL INT_CARRY INT_SCARRY INT_SBORROW BOOL_NEGATE BOOL_XOR BOOL_AND BOOL_OR INT_ZEXT INT_SEXT INT_LEFT INT_RIGHT INT_SRIGHT PIECE SUBPIECE POPCOUNT LZCOUNT'.split())

    def analyze(info, supplied=None, depth=0):
        nonlocal operation_count
        ir = info['pcode_ir']; identity = ir['function_address']; is_root = supplied is None
        require(depth <= 4 and identity not in active, 'recursion_or_depth')
        checked = _checked_ir(ir, info['ir_analysis']['source_ir_sha256'])
        require(checked['summary']['status'] == 'structurally_valid' and not checked['summary']['unresolved_liveins'], 'structural')
        require(len(ir['blocks']) == 1 and not ir['blocks'][0]['predecessors'] and not ir['blocks'][0]['successors'], 'single_block_scope')
        nodes = {node['id']: node for node in ir['varnodes']}
        require(all(not node.get('persistent') and not (node.get('definition') and node['kind'] in ('memory', 'other', 'stack')) for node in ir['varnodes']), 'external_storage')
        operations = {op['id']: op for op in ir['operations']}
        binding = _binding(ir, info['high_parameter_observation'], info['ir_analysis']['source_ir_sha256'])
        if is_root:
            require(binding['source_observation_sha256'] == frame_fact.get('high_observation_sha256'), 'frame_fact')
        parameters = binding['parameters']
        require(all(p['status'] == 'observed_input_association' and p['instance_enumeration_available']
                    and not p['omitted_instances'] and len(p['input_varnodes']) == 1 for p in parameters), 'formal_association')
        formal = [p['input_varnodes'][0] for p in parameters]
        require(len(formal) == len(set(formal)), 'formal_identity')
        ambient = frame_fact['ambient_varnode'] if is_root else None
        require(set(binding['unbound_inputs']) == ({ambient} if is_root else set()), 'ambient_input')
        pointers = {}
        if not is_root:
            require(len(supplied) == len(formal), 'call_arity')
            for parameter, (width, pointer) in zip(formal, supplied):
                require(nodes[parameter]['size'] == width, 'call_width')
                if pointer is not None:
                    require(width == 8, 'pointer_width')
                    pointers[parameter] = pointer
        active.add(identity); visited.append(identity)
        returned = None; did_return = False
        for op_id in ir['blocks'][0]['operations']:
            require(not did_return, 'operation_after_return')
            operation_count += 1; require(operation_count <= max_operations, 'operation_budget')
            op = operations[op_id]; opcode = op['opcode']; args = op['inputs']; output = op.get('output')
            def constant(node_id):
                node = nodes[node_id]
                require(node['kind'] == 'constant', 'pointer_constant')
                return int(node['offset'], 16)
            def pointer_bounds(offset):
                require(0 <= offset <= extent, 'pointer_bounds')
                return offset
            if is_root and op_id == frame_fact['pointer_operation']:
                require(opcode == 'PTRSUB' and len(args) == 2 and args[0] == ambient
                        and op['sequence']['pc'] == frame_fact['pointer_pc'] and nodes[output]['size'] == 8, 'seed')
                require(nodes[args[0]]['size'] == nodes[args[1]]['size'] == 8, 'pointer_width')
                raw = constant(args[1]); width = 8 * nodes[args[1]]['size']
                offset = raw - (1 << width) if raw & (1 << (width - 1)) else raw
                require(offset == frame_fact['entry_rsp_offset'], 'seed_offset')
                pointers[output] = 0
            else:
                require(not is_root or ambient not in args, 'ambient_use')
                if opcode in ('COPY', 'CAST'):
                    if args[0] in pointers:
                        require(nodes[args[0]]['size'] == nodes[output]['size'] == 8, 'pointer_width')
                        pointers[output] = pointers[args[0]]
                elif opcode in ('PTRADD', 'PTRSUB'):
                    require(args[0] in pointers and nodes[output]['size'] == 8, 'address_unknown')
                    delta = constant(args[1])
                    if opcode == 'PTRADD':
                        delta *= constant(args[2])
                    else:
                        require(nodes[args[1]]['size'] == 8, 'pointer_width')
                        bits = nodes[args[1]]['size'] * 8
                        delta = delta - (1 << bits) if delta & (1 << (bits - 1)) else delta
                    pointers[output] = pointer_bounds(pointers[args[0]] + delta)
                elif opcode in ('LOAD', 'STORE'):
                    require(args[1] in pointers, 'address_unknown')
                    address = pointers[args[1]]
                    width = nodes[output]['size'] if opcode == 'LOAD' else nodes[args[2]]['size']
                    require(0 <= address and address + width <= extent, 'memory_bounds')
                    space = next(s for s in ir['context']['spaces'] if s['name'] == ir['context']['image_base'].split(':')[0])
                    require(constant(args[0]) == (space['id'] & 0xffffffff), 'memory_space')
                    if opcode == 'STORE':
                        require(args[2] not in pointers, 'store_escape')
                        initialized[address:address + width] = [True] * width
                    else:
                        require(all(initialized[address:address + width]), 'uninitialized')
                    events.append(dict(function=identity, operation=op_id, pc=op['sequence']['pc'],
                                       kind=opcode, offset=address, bytes=width))
                elif opcode == 'CALL':
                    target_node = nodes[args[0]]
                    require(target_node['kind'] == 'memory', 'indirect_call')
                    destination = target_node['space'] + ':' + format(int(target_node['offset'], 16), 'x')
                    require(destination in inventory, 'callee_missing')
                    if is_root:
                        require(op_id == frame_fact['call_operation'] and op['sequence']['pc'] == frame_fact['call_pc'], 'call_site')
                    actual = [(nodes[arg]['size'], pointers.get(arg)) for arg in args[1:]]
                    result = analyze(inventory[destination], actual, depth + 1)
                    if result is not None:
                        require(output is not None and nodes[output]['size'] == 8, 'call_return_width')
                        pointers[output] = result
                elif opcode == 'RETURN':
                    require(len(args) in (1, 2) and constant(args[0]) == 0, 'return_shape')
                    returned = pointers.get(args[1]) if len(args) == 2 else None; did_return = True
                    if returned is not None:
                        require(not is_root, 'root_escape')
                        proof = _formal_return_identity(ir, info['high_parameter_observation'], info['ir_analysis']['source_ir_sha256'])
                        require(proof['return_input_varnode'] in pointers and pointers[proof['return_input_varnode']] == returned, 'return_identity')
                        borrowed.append(dict(function=identity, formal_ordinal=proof['return_formal_ordinal'], offset=returned))
                elif opcode in scalar:
                    require(not any(arg in pointers for arg in args), 'pointer_use')
                else:
                    raise ValueError('frame_usage_unsupported_opcode:' + opcode)
        require(did_return, 'return_missing')
        active.remove(identity)
        return returned

    analyze(root)
    return dict(schema='conditional-private-frame-usage.v1', target_sha256=target,
                root_ir_sha256=digest(data), frame_fact_sha256=digest(frame_fact),
                callee_ir_sha256={info['pcode_ir']['function_address']: digest(info['pcode_ir']) for info in callees},
                memory_events=events, defined_bytes=[i for i, value in enumerate(initialized) if value],
                borrowed_returns=borrowed, visited_functions=visited, operation_count=operation_count,
                production_admission=False, native_ir_fidelity_proved=False, abi_recovered=False,
                scope='conditional single private object, acyclic single-block callees, no derived address stores/root return; native fact is a dependency hypothesis')
