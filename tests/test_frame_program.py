import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
import pytest
import aether_re.frame_program as module


def inputs():
    packet = json.loads((Path(__file__).parent / 'fixtures/frame_program_ir.json').read_text(encoding='utf-8'))
    return packet['root'], packet['callee'], packet['frame_fact']


def refit(root, fact):
    fact['ir_payload_sha256'] = hashlib.sha256(json.dumps(root['pcode_ir'], sort_keys=True, separators=(',', ':'),
                                                        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def test_builds_private_storage_and_literal_internal_body():
    packet = inputs(); before = copy.deepcopy(packet)
    report = module.build_frame_program(*packet)
    assert packet == before
    assert report['status'] == 'complete', report
    assert report['program_kind'] == 'derived_model'
    assert report['native_frame_fact_verified'] is False
    assert report['production_frame_profile_admitted'] is False
    assert report['abi_recovered'] is False
    assert report['binary_equivalence_proved'] is False
    assert report['emitted']['linkage'] == 'internal'
    assert report['structured_c_source'].startswith(report['emitted']['structured_c_source'])
    assert 'static unsigned long long aether_frame_body(' in report['structured_c_source']
    assert 'unsigned long long aether_frame_entry(' in report['structured_c_source']
    assert 'aether_frame_leave(&aether_scope)' in report['structured_c_source']
    assert len(report['input_bindings']) == 2
    assert [item['offset'] for item in report['memory_links']] == [0, 8, 0, 8]


def test_extent_and_base_are_not_fixture_constants():
    root, callee, fact = inputs(); fact['requested_object_bytes'] = 24
    report = module.build_frame_program(root, callee, fact, object_base=0x300000, function_name='aether_other_entry')
    assert report['status'] == 'complete', report
    assert report['frame']['object_bytes'] == 24 and report['frame']['object_base'] == 0x300000
    assert 'aether_bytes[24]' in report['structured_c_source']
    assert '3145728ULL' in report['structured_c_source']
    assert 'unsigned long long aether_other_entry(' in report['structured_c_source']


def test_void_root_has_void_wrapper_and_cleanup():
    root, callee, fact = inputs()
    root['pcode_ir']['operations'][-1]['inputs'] = root['pcode_ir']['operations'][-1]['inputs'][:1]
    refit(root, fact)
    report = module.build_frame_program(root, callee, fact)
    assert report['status'] == 'complete', report
    assert report['return_bits'] == 0
    assert 'void aether_frame_entry(' in report['structured_c_source']
    assert 'aether_result =' not in report['structured_c_source']
    assert 'aether_frame_leave(&aether_scope)' in report['structured_c_source']


@pytest.mark.parametrize('name', ['bad name', 'aether_frame_body', 'aether_frame_enter', 'aether_sparse_memory_store', None])
def test_invalid_or_reserved_name_refuses_without_source(name):
    report = module.build_frame_program(*inputs(), function_name=name)
    assert report['status'] != 'complete' and report['structured_c_source'] is None
    assert report['errors']


@pytest.mark.parametrize('base', [True, -16, 17, 1 << 64])
def test_invalid_relocation_refuses_without_source(base):
    report = module.build_frame_program(*inputs(), object_base=base)
    assert report['status'] != 'complete' and report['structured_c_source'] is None


def test_private_pointer_escape_refuses_before_emission():
    root, callee, fact = inputs()
    root['pcode_ir']['operations'][-1]['inputs'][1] = 'v132'; refit(root, fact)
    report = module.build_frame_program(root, callee, fact)
    assert report['status'] != 'complete' and report['structured_c_source'] is None
    assert 'root_escape' in ','.join(report['errors'])


def test_unexpected_derived_constant_cannot_inherit_proof():
    original = module._derive
    def changed(*args, **kwargs):
        packet = original(*args, **kwargs)
        target = packet['provenance']['callee_varnode_renaming']['v65']
        next(node for node in packet['derived_ir']['varnodes'] if node['id'] == target)['offset'] = '10'
        return packet
    with patch.object(module, '_derive', changed):
        report = module.build_frame_program(*inputs())
    assert report['status'] != 'complete' and report['structured_c_source'] is None
    assert 'transport' in ','.join(report['errors'])


def test_lost_effect_cannot_inherit_proof():
    original = module._derive
    def changed(*args, **kwargs):
        packet = original(*args, **kwargs)
        ir = packet['derived_ir']
        lost = next(op['id'] for op in ir['operations'] if op['opcode'] == 'STORE')
        ir['operations'] = [op for op in ir['operations'] if op['id'] != lost]
        ir['blocks'][0]['operations'].remove(lost)
        return packet
    with patch.object(module, '_derive', changed):
        report = module.build_frame_program(*inputs())
    assert report['status'] != 'complete' and report['structured_c_source'] is None


def test_bad_envelopes_are_reported_without_publishing_c():
    report = module.build_frame_program(None, None, None)
    assert report['status'] != 'complete' and report['structured_c_source'] is None and report['errors']


def test_frame_modules_are_assigned_to_binary_reconstruction_phase():
    from tools.phase_test_map import MODULE_PHASE
    for name in ('frame_derivation', 'frame_usage', 'frame_conservation', 'frame_runtime', 'frame_program'):
        assert MODULE_PHASE.get(name) == 'F05', name
