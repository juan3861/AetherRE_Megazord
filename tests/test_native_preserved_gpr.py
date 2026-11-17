"""Owned-byte/IR mutations exercise derived preservation, without target execution."""
import copy
import struct

import pytest
from test_native_leaf_data import inputs, bind, BODY, observe as observe_leaf
from test_native_caller_data import observe


def use_rbx_object_after_call():
    raw, root, callee, language = inputs()
    raw = bytearray(raw)
    at = 512 + 0x290
    old = bytes(raw[at:at + 35])
    # Save the actual object pointer in RBX before CALL, then load through RBX.
    code = bytearray(old[:15] + bytes.fromhex('488bd9') + old[15:])
    struct.pack_into('<i', code, 19, struct.unpack_from('<i', old, 16)[0] - 3)
    code[25] = 0x13
    raw[at:at + len(code)] = code
    struct.pack_into('<I', raw, 512 + 0x704, 0x12b6)
    ir = root['pcode_ir']
    for operation in ir['operations'][1:]:
        operation['sequence']['pc'] = 'ram:' + format(int(operation['sequence']['pc'][4:], 16) + 3, 'x')
    ir['blocks'][0]['stop'] = 'ram:1800012b5'
    next(op for op in ir['operations'] if op['id'] == 'o3')['inputs'][1] = 'v30'
    bind(raw, root, callee)
    return bytes(raw), root, callee, language


def add_leaf_copies(args, *, restored=False):
    raw, root, callee, language = args
    raw = bytearray(raw)
    ir = callee['pcode_ir']
    # Either clobber RBX from an argument, or save and explicitly restore R8.
    prefix = bytes.fromhex('4d8bd0' if restored else '488bda')
    suffix = bytes.fromhex('4d8bc2') if restored else b''
    code = prefix + BODY[:-1] + suffix + BODY[-1:]
    raw[512 + 0x270:512 + 0x290] = code + b'\xcc' * (32 - len(code))
    for operation in ir['operations']:
        operation['sequence']['pc'] = 'ram:' + format(int(operation['sequence']['pc'][4:], 16) + 3, 'x')
    template = copy.deepcopy(next(node for node in ir['varnodes'] if node['id'] == 'v34'))
    template.update(id='saved_or_clobbered', offset='90' if restored else '18', definition='copy_prefix')
    ir['varnodes'].append(template)
    ir['operations'].insert(0, dict(id='copy_prefix', opcode='COPY',
        sequence=dict(pc='ram:180001270', time=0, order=0),
        inputs=['v59' if restored else 'v58'], output='saved_or_clobbered'))
    if restored:
        node = copy.deepcopy(template)
        node.update(id='restored_r8', offset='80', definition='copy_restore')
        ir['varnodes'].append(node)
        ir['operations'].insert(-1, dict(id='copy_restore', opcode='COPY',
            sequence=dict(pc='ram:180001285', time=0, order=0),
            inputs=['saved_or_clobbered'], output='restored_r8'))
        ir['operations'][-1]['sequence']['pc'] = 'ram:180001288'
    for index, operation in enumerate(ir['operations']):
        operation['sequence']['order'] = index
    ir['blocks'][0]['operations'] = [op['id'] for op in ir['operations']]
    ir['blocks'][0]['stop'] = ir['operations'][-1]['sequence']['pc']
    bind(raw, root, callee)
    return bytes(raw), root, callee, language


def test_preserved_rbx_uses_actual_pre_call_object_pointer():
    report = observe(use_rbx_object_after_call())
    assert report['ordered_data_events_equal'] and report['return_data_equal']
    assert 'rbx' in report['leaf_witness']['native_preserved_gprs']
    assert report['preserved_call_bindings']['rbx'] == report['events'][0]['address']
    assert report['preserved_call_bindings']['rbx'] != ('input', 'rbx')


def test_clobbered_rbx_is_not_available_after_call():
    args = add_leaf_copies(use_rbx_object_after_call())
    leaf = observe_leaf(args)
    assert 'rbx' not in leaf['native_preserved_gprs']
    with pytest.raises(ValueError, match='unproved_call_clobber_use'):
        observe(args)


def test_explicitly_restored_argument_register_is_preserved():
    args = add_leaf_copies(inputs(), restored=True)
    report = observe(args)
    assert 'r8' in report['leaf_witness']['native_preserved_gprs']
    assert 'r10' not in report['leaf_witness']['native_preserved_gprs']
    assert report['preserved_call_bindings']['r8'] == ('input', 'rdx')


def test_preservation_summary_is_bound_to_leaf_bytes_and_ir():
    original = observe_leaf(inputs())
    changed = observe_leaf(add_leaf_copies(inputs()))
    assert 'rbx' in original['native_preserved_gprs']
    assert 'rbx' not in changed['native_preserved_gprs']
    assert original['native_code_sha256'] != changed['native_code_sha256']
    assert original['ir_payload_sha256'] != changed['ir_payload_sha256']


def test_explicitly_restored_r8_can_feed_caller_return_expression():
    raw, root, callee, language = add_leaf_copies(inputs(), restored=True)
    raw = bytearray(raw)
    raw[512 + 0x290 + 27:512 + 0x290 + 30] = bytes.fromhex('4933c0')
    operation = next(op for op in root['pcode_ir']['operations'] if op['opcode'] == 'INT_XOR')
    operation['inputs'][1] = 'v123'
    bind(raw, root, callee)
    report = observe((bytes(raw), root, callee, language))
    assert report['return_data_equal']
    assert report['preserved_call_bindings']['r8'] == ('input', 'rdx')


def test_proven_preserved_volatile_rcx_can_supply_load_address():
    raw, root, callee, language = inputs()
    raw = bytearray(raw)
    raw[512 + 0x290 + 22] = 0x11  # mov rdx,[rcx]
    next(op for op in root['pcode_ir']['operations'] if op['id'] == 'o3')['inputs'][1] = 'v30'
    bind(raw, root, callee)
    report = observe((bytes(raw), root, callee, language))
    assert 'rcx' in report['leaf_witness']['native_preserved_gprs']
    assert report['ordered_data_events_equal']
