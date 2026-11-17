import copy
import json
from pathlib import Path
import pytest
from aether_re.frame_derivation import derive_frame_program, _digest
from aether_re.frame_usage import prove_frame_usage
from aether_re.frame_conservation import check_frame_transport


def inputs():
    fixture = json.loads((Path(__file__).parent / 'fixtures/frame_program_ir.json').read_text())
    root, child, fact = fixture['root'], fixture['callee'], fixture['frame_fact']
    packet = derive_frame_program(root['pcode_ir'], child, fact)
    usage = prove_frame_usage(root=root, callees=[child], frame_fact=fact)
    return root, child, fact, packet, usage


def test_conserves_real_ops_constants_and_effect_indices_without_mutation():
    value = inputs(); before = copy.deepcopy(value)
    links = check_frame_transport(*value, object_base=0x100000)
    assert value == before
    assert [item['derived_operation_index'] for item in links] == [3, 6, 9, 11]


@pytest.mark.parametrize('change', ['constant', 'scalar', 'block', 'effect_order', 'origin', 'usage_identity', 'collision'])
def test_changed_transport_refuses_even_if_derived_digest_is_refitted(change):
    root, child, fact, packet, usage = inputs()
    ir = packet['derived_ir']; provenance = packet['provenance']
    if change == 'constant':
        name = provenance['callee_varnode_renaming']['v65']
        next(node for node in ir['varnodes'] if node['id'] == name)['offset'] = '10'
    elif change == 'scalar':
        next(op for op in ir['operations'] if op['opcode'] == 'INT_ADD')['opcode'] = 'INT_SUB'
    elif change == 'block':
        ir['blocks'][0]['start'] = 'ram:180001270'
    elif change == 'effect_order':
        ir['operations'][3], ir['operations'][6] = ir['operations'][6], ir['operations'][3]
    elif change == 'origin':
        provenance['operations'][provenance['callee_operation_renaming']['o2']]['original_operation'] = 'o5'
    elif change == 'usage_identity':
        usage['root_ir_sha256'] = '0' * 64
    elif change == 'collision':
        provenance['callee_varnode_renaming']['v65'] = 'v160'
    provenance['derived_sha256'] = _digest(ir)
    with pytest.raises(ValueError, match='frame_transport_'):
        check_frame_transport(root, child, fact, packet, usage, object_base=0x100000)


def test_malformed_transport_is_value_error():
    with pytest.raises(ValueError, match='frame_transport_envelope'):
        check_frame_transport(None, None, None, None, None, object_base=0x100000)
