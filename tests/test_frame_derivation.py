import copy
import hashlib
import json
from pathlib import Path

import pytest

from aether_re.frame_derivation import derive_frame_program, _formal_return_identity
from aether_re.ghidra_pcode_c import reconstruct_high_pcode


def fixture():
    return json.loads((Path(__file__).parent / 'fixtures/frame_program_ir.json').read_text())


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def derive(value, **options):
    return derive_frame_program(value['root']['pcode_ir'], value['callee'], value['frame_fact'], **options)


def refit(value):
    value['frame_fact']['ir_payload_sha256'] = digest(value['root']['pcode_ir'])


def test_real_ir_immutable_and_existing_emitter():
    value = fixture(); before = copy.deepcopy(value); result = derive(value)
    assert value == before
    assert result['schema'] == 'derived-frame-program.v1'
    assert result['status'] == 'conditional_model'
    assert not result['production_admission'] and not result['binary_equivalence_proved']
    data = result['derived_ir']
    assert len(data['operations']) == 14
    assert [op['opcode'] for op in data['operations'] if op['opcode'] in ('STORE', 'LOAD')] == ['STORE', 'STORE', 'LOAD', 'LOAD']
    assert set(result['provenance']['operations']) == {op['id'] for op in data['operations']}
    report = reconstruct_high_pcode(data, expected_target=data['target_sha256'], expected_address=data['function_address'], evidence_sha256=digest(data), function_name='aether_frame_body', memory_model='bounded-bytes.v2')
    assert report['status'] == 'complete', report['errors']
    assert len(report['input_bindings']) == 2


def test_different_offset_extent_and_relocation():
    value = fixture(); caller = value['root']['pcode_ir']
    next(v for v in caller['varnodes'] if v['id'] == 'v181')['offset'] = 'ffffffffffffffe0'
    value['frame_fact'].update(entry_rsp_offset=-32, requested_object_bytes=32)
    refit(value); result = derive(value, object_base=0x200000)
    assert result['provenance']['frame'] == dict(object_base=0x200000, object_bytes=32, abstract_entry=0x200020, entry_offset=-32)


def test_alpha_renamed_inputs_do_not_require_fixture_ids():
    value = fixture()
    for info in (value['root'], value['callee']):
        ir = info['pcode_ir']; nodes = {v['id']: 'renamed_' + v['id'] for v in ir['varnodes']}; ops = {o['id']: 'renamed_' + o['id'] for o in ir['operations']}
        for v in ir['varnodes']:
            v['id'] = nodes[v['id']]
            if 'definition' in v: v['definition'] = ops[v['definition']]
        for op in ir['operations']:
            op['id'] = ops[op['id']]; op['inputs'] = [nodes[x] for x in op['inputs']]
            if 'output' in op: op['output'] = nodes[op['output']]
        for block in ir['blocks']: block['operations'] = [ops[x] for x in block['operations']]
        for parameter in info['high_parameter_observation']['parameters']:
            parameter['instances']['observed'] = [nodes[x] for x in parameter['instances']['observed']]
    value['frame_fact'].update(ambient_varnode='renamed_v160', pointer_operation='renamed_o0', call_operation='renamed_o1')
    refit(value); result = derive(value)
    assert result['provenance']['return_identity']['return_input_varnode'] == 'renamed_v57'


def test_four_formals_and_nonzero_return_ordinal():
    value = fixture(); child = value['callee']; ir = child['pcode_ir']
    new = copy.deepcopy(ir['varnodes'][0]); new.update(id='fourth', offset='90'); ir['varnodes'].append(new)
    parameter = copy.deepcopy(child['high_parameter_observation']['parameters'][1]); parameter.update(ordinal=3, category_index=3, name='fourth'); parameter['instances']['observed'] = ['fourth']
    params = child['high_parameter_observation']['parameters']; params.append(parameter)
    root = value['root']['pcode_ir']; arg = copy.deepcopy(next(v for v in root['varnodes'] if v['id'] == 'v123')); arg.update(id='extra', offset='80'); root['varnodes'].append(arg)
    call = next(op for op in root['operations'] if op['opcode'] == 'CALL'); call['inputs'].append('extra')
    params[0], params[1] = params[1], params[0]
    for ordinal, p in enumerate(params): p['ordinal'] = ordinal; p['category_index'] = ordinal
    call['inputs'][1], call['inputs'][2] = call['inputs'][2], call['inputs'][1]
    refit(value); result = derive(value)
    assert len(result['provenance']['formal_mapping']) == 4
    assert result['provenance']['return_identity']['return_formal_ordinal'] == 1


def test_scalar_width_four_preserved():
    value = fixture(); ir = value['callee']['pcode_ir']
    for node in ir['varnodes']:
        if node['id'] in ('v59', 'v11', 'v9'): node['size'] = 4
    value['callee']['high_parameter_observation']['parameters'][2]['size'] = 4
    next(v for v in value['root']['pcode_ir']['varnodes'] if v['id'] == 'v123')['size'] = 4
    refit(value); result = derive(value)
    renamed = result['provenance']['callee_varnode_renaming']['v9']
    assert next(v for v in result['derived_ir']['varnodes'] if v['id'] == renamed)['size'] == 4


def test_alpha_collision_is_deterministic():
    value = fixture(); ir = value['root']['pcode_ir']
    extra = copy.deepcopy(ir['varnodes'][1]); extra['id'] = 'cal_v2'; ir['varnodes'].append(extra)
    refit(value); first = derive(value); second = derive(value)
    assert first == second
    assert first['provenance']['callee_varnode_renaming']['v2'] != 'cal_v2'
    ids = [v['id'] for v in first['derived_ir']['varnodes']]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize('base', [True, -16, 1, 1 << 64, (1 << 64) - 16])
def test_invalid_base_refused(base):
    with pytest.raises(ValueError): derive(fixture(), object_base=base)


@pytest.mark.parametrize('field,value', [('requested_object_bytes', 0), ('requested_object_bytes', 4097), ('entry_rsp_offset', True), ('ir_payload_sha256', '0' * 64), ('call_pc', 'ram:1')])
def test_invalid_fact_refused(field, value):
    data = fixture(); data['frame_fact'][field] = value
    with pytest.raises(ValueError): derive(data)


def test_pointer_delta_width_refused():
    value = fixture(); next(v for v in value['root']['pcode_ir']['varnodes'] if v['id'] == 'v181').update(size=4, offset='ffffffe8'); refit(value)
    with pytest.raises(ValueError): derive(value)


def test_context_arity_and_nested_calls_refused():
    for kind in ('context', 'arity', 'nested'):
        value = fixture()
        if kind == 'context':
            for info in (value['root'], value['callee']): info['pcode_ir']['context']['compiler_spec_id'] = 'gcc'
            refit(value)
        elif kind == 'arity': value['root']['pcode_ir']['operations'][1]['inputs'].pop(); refit(value)
        else: value['callee']['pcode_ir']['operations'][0]['opcode'] = 'CALL'
        with pytest.raises(ValueError): derive(value)


def test_return_helper_unique_formal_and_no_arithmetic():
    value = fixture()['callee']; ir = value['pcode_ir']
    proof = _formal_return_identity(ir, value['high_parameter_observation'], value['ir_analysis']['source_ir_sha256'])
    assert proof['return_formal_ordinal'] == 0 and proof['return_input_varnode'] == 'v57'
    next(o for o in ir['operations'] if o['id'] == 'o3').update(opcode='INT_ADD', inputs=['v57', 'v2'])
    with pytest.raises(ValueError): _formal_return_identity(ir, value['high_parameter_observation'], value['ir_analysis']['source_ir_sha256'])


def test_return_helper_checks_every_return():
    value = fixture()['callee']; ir = value['pcode_ir']; original = {n['id']: n for n in ir['varnodes']}
    address = int(ir['function_address'].split(':')[1], 16)
    pc = lambda offset: 'ram:' + format(address + offset, 'x')
    target = copy.deepcopy(original['v57']); target.update(id='branch_target', kind='memory', space='ram', offset=format(address + 16, 'x'), input=False)
    condition = copy.deepcopy(original['v2']); condition.update(id='condition', size=1, offset='1')
    ir['varnodes'] = [copy.deepcopy(original[n]) for n in ('v57', 'v58', 'v59', 'v55')] + [target, condition]
    ir['operations'] = [
        dict(id='branch', opcode='CBRANCH', inputs=['branch_target', 'condition'], sequence=dict(pc=pc(0), time=0, order=0)),
        dict(id='left', opcode='RETURN', inputs=['v55', 'v57'], sequence=dict(pc=pc(16), time=0, order=1)),
        dict(id='right', opcode='RETURN', inputs=['v55', 'v57'], sequence=dict(pc=pc(32), time=0, order=2)),
    ]
    ir['blocks'] = [
        dict(id='b0', start=pc(0), stop=pc(7), predecessors=[], successors=[dict(block='b2', target_slot=0), dict(block='b1', target_slot=0)], operations=['branch'], true_out='b1', false_out='b2'),
        dict(id='b1', start=pc(16), stop=pc(23), predecessors=[dict(block='b0', source_slot=1)], successors=[], operations=['left']),
        dict(id='b2', start=pc(32), stop=pc(39), predecessors=[dict(block='b0', source_slot=0)], successors=[], operations=['right']),
    ]
    proof = _formal_return_identity(ir, value['high_parameter_observation'], value['ir_analysis']['source_ir_sha256'])
    assert proof['return_operations'] == ['left', 'right']
    ir['operations'][-1]['inputs'][1] = 'v58'
    with pytest.raises(ValueError, match='return_formal_disagreement'):
        _formal_return_identity(ir, value['high_parameter_observation'], value['ir_analysis']['source_ir_sha256'])


def test_source_block_metadata_and_pc_time_are_preserved():
    value = fixture(); result = derive(value)
    block = copy.deepcopy(result['derived_ir']['blocks'][0]); original = copy.deepcopy(value['root']['pcode_ir']['blocks'][0])
    block.pop('operations'); original.pop('operations')
    assert block == original
    for op in result['derived_ir']['operations']:
        source = result['provenance']['operations'][op['id']]['original_sequence']
        assert (op['sequence']['pc'], op['sequence']['time']) == (source['pc'], source['time'])


def test_positive_offset_underflow_is_refused():
    value = fixture(); next(n for n in value['root']['pcode_ir']['varnodes'] if n['id'] == 'v181')['offset'] = '20'
    value['frame_fact']['entry_rsp_offset'] = 32; refit(value)
    with pytest.raises(ValueError, match='relocation_overflow'): derive(value, object_base=16)


@pytest.mark.parametrize('part', ['caller', 'callee', 'fact'])
def test_missing_envelope_is_explicit_value_error(part):
    value = fixture()
    with pytest.raises(ValueError):
        derive_frame_program({} if part == 'caller' else value['root']['pcode_ir'],
                             {} if part == 'callee' else value['callee'],
                             {} if part == 'fact' else value['frame_fact'])


def test_dependency_inventory_budget_refused():
    value = fixture()['callee']; value['pcode_ir']['varnodes'] *= 100
    with pytest.raises(ValueError, match='ir_budget'):
        _formal_return_identity(value['pcode_ir'], value['high_parameter_observation'], value['ir_analysis']['source_ir_sha256'])


@pytest.mark.parametrize('count', [64, 65])
def test_formal_count_boundary(count):
    value = fixture(); child = value['callee']; root = value['root']['pcode_ir']
    call = next(op for op in root['operations'] if op['opcode'] == 'CALL')
    for ordinal in range(3, count):
        node = copy.deepcopy(child['pcode_ir']['varnodes'][0]); node.update(id=f'extra{ordinal}', offset=format(256 + ordinal * 8, 'x'))
        child['pcode_ir']['varnodes'].append(node)
        argument = copy.deepcopy(node); argument['id'] = f'actual{ordinal}'; root['varnodes'].append(argument)
        call['inputs'].append(argument['id'])
        parameter = copy.deepcopy(child['high_parameter_observation']['parameters'][1])
        parameter.update(ordinal=ordinal, category_index=ordinal, name=f'p{ordinal}')
        parameter['instances']['observed'] = [node['id']]
        child['high_parameter_observation']['parameters'].append(parameter)
    refit(value)
    if count == 65:
        with pytest.raises(ValueError, match='formal_budget'): derive(value)
    else:
        assert len(derive(value)['provenance']['formal_mapping']) == 64


@pytest.mark.parametrize('size', [1, 2])
def test_small_scalar_widths_preserved(size):
    value = fixture(); child = value['callee']
    for node in child['pcode_ir']['varnodes']:
        if node['id'] in ('v59', 'v11', 'v9'): node['size'] = size
    child['high_parameter_observation']['parameters'][2]['size'] = size
    next(node for node in value['root']['pcode_ir']['varnodes'] if node['id'] == 'v123')['size'] = size
    refit(value)
    result = derive(value); renamed = result['provenance']['callee_varnode_renaming']['v9']
    assert next(n for n in result['derived_ir']['varnodes'] if n['id'] == renamed)['size'] == size


def test_operation_name_collision_is_avoided():
    value = fixture(); caller = value['root']['pcode_ir']; previous = value['frame_fact']['pointer_operation']
    new = 'cal_o0'
    next(op for op in caller['operations'] if op['id'] == previous)['id'] = new
    for block in caller['blocks']: block['operations'] = [new if item == previous else item for item in block['operations']]
    for node in caller['varnodes']:
        if node.get('definition') == previous: node['definition'] = new
    value['frame_fact']['pointer_operation'] = new; refit(value)
    result = derive(value)
    assert result['provenance']['callee_operation_renaming']['o0'] != new
    operations = [op['id'] for op in result['derived_ir']['operations']]
    assert len(operations) == len(set(operations))
