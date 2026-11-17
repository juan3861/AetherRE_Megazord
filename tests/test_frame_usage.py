import copy
import hashlib
import json
from pathlib import Path
import unittest
from aether_re.frame_usage import prove_frame_usage as prove_usage

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()

def inputs():
    data = json.loads((Path(__file__).parent / 'fixtures/frame_program_ir.json').read_text(encoding='utf-8'))
    return dict(root=data['root'], callees=[data['callee']], frame_fact=data['frame_fact'])

def refit_prefix_hypothesis(value):
    # A controlled model mutation, never claimed as fresh Ghidra/native evidence.
    value['frame_fact']['ir_payload_sha256'] = digest(value['root']['pcode_ir'])

class Usage(unittest.TestCase):
    def test_actual_ir_has_borrowed_return_and_defined_frame_reads(self):
        value = inputs(); before = copy.deepcopy(value)
        result = prove_usage(**value)
        self.assertEqual(value, before)
        self.assertEqual([(row['kind'], row['offset'], row['bytes']) for row in result['memory_events']],
                         [('STORE', 0, 8), ('STORE', 8, 8), ('LOAD', 0, 8), ('LOAD', 8, 8)])
        self.assertEqual(result['defined_bytes'], list(range(16)))
        self.assertEqual(len(result['borrowed_returns']), 1)
        self.assertFalse(result['production_admission'])

    def test_root_cannot_return_private_address(self):
        value = inputs()
        value['root']['pcode_ir']['operations'][-1]['inputs'][1] = 'v132'
        refit_prefix_hypothesis(value)
        with self.assertRaisesRegex(ValueError, 'root_escape'):
            prove_usage(**value)

    def test_callee_cannot_store_borrowed_private_address(self):
        value = inputs()
        store = next(op for op in value['callees'][0]['pcode_ir']['operations'] if op['opcode'] == 'STORE')
        store['inputs'][2] = 'v57'
        with self.assertRaisesRegex(ValueError, 'store_escape'):
            prove_usage(**value)

    def test_pointer_arithmetic_must_stay_in_object(self):
        value = inputs()
        next(node for node in value['root']['pcode_ir']['varnodes'] if node['id'] == 'v183')['offset'] = '3'
        refit_prefix_hypothesis(value)
        with self.assertRaisesRegex(ValueError, 'pointer_bounds'):
            prove_usage(**value)

    def test_callee_store_cannot_use_scalar_formal_as_address(self):
        value = inputs()
        next(op for op in value['callees'][0]['pcode_ir']['operations'] if op['opcode'] == 'STORE')['inputs'][1] = 'v58'
        with self.assertRaisesRegex(ValueError, 'address_unknown'):
            prove_usage(**value)

    def test_pointer_cannot_disappear_through_integer_arithmetic(self):
        value = inputs()
        next(op for op in value['callees'][0]['pcode_ir']['operations'] if op['opcode'] == 'INT_ADD')['inputs'][0] = 'v57'
        with self.assertRaisesRegex(ValueError, 'pointer_use'):
            prove_usage(**value)

    def test_undefined_read_refuses(self):
        value = inputs()
        ir = value['callees'][0]['pcode_ir']
        first = next(op for op in ir['operations'] if op['opcode'] == 'STORE')['id']
        ir['operations'] = [op for op in ir['operations'] if op['id'] != first]
        ir['blocks'][0]['operations'].remove(first)
        with self.assertRaisesRegex(ValueError, 'uninitialized'):
            prove_usage(**value)

    def test_short_seed_constant_cannot_be_sign_extended(self):
        value = inputs()
        node = next(node for node in value['root']['pcode_ir']['varnodes'] if node['id'] == 'v181')
        node.update(size=4, offset='ffffffe8')
        refit_prefix_hypothesis(value)
        with self.assertRaisesRegex(ValueError, 'pointer_width'):
            prove_usage(**value)

    def test_short_ptrsub_delta_cannot_be_sign_extended(self):
        value = inputs(); ir = value['root']['pcode_ir']
        ir['varnodes'].extend([
            dict(id='short_delta', space='const', kind='constant', offset='fffffff8', size=4, input=False, free=True, persistent=False, unaffected=False, addr_tied=False),
            dict(id='back_to_zero', space='unique', kind='unique', offset='a000', size=8, input=False, free=False, persistent=False, unaffected=False, addr_tied=False, definition='extra')])
        ir['operations'].insert(5, dict(id='extra', opcode='PTRSUB', inputs=['v48', 'short_delta'], output='back_to_zero',
                                      sequence=dict(pc='ram:1800012a7', time=999, order=5)))
        ir['blocks'][0]['operations'].insert(5, 'extra')
        next(op for op in ir['operations'] if op['id'] == 'o5')['inputs'][1] = 'back_to_zero'
        refit_prefix_hypothesis(value)
        with self.assertRaisesRegex(ValueError, 'pointer_width'):
            prove_usage(**value)

    def test_missing_callee_and_budget_refuse(self):
        for options in ({'callees': []}, {'max_operations': 1}, {'extent': True}):
            value = inputs(); value.update(options)
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    prove_usage(**value)

    def test_native_fact_digest_is_bound(self):
        value = inputs(); value['frame_fact']['ir_payload_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'frame_fact'):
            prove_usage(**value)

    def test_unknown_call_arity_refuses(self):
        value = inputs()
        next(op for op in value['root']['pcode_ir']['operations'] if op['opcode'] == 'CALL')['inputs'].pop()
        refit_prefix_hypothesis(value)
        with self.assertRaisesRegex(ValueError, 'call_arity'):
            prove_usage(**value)

    def test_void_root_still_checks_memory_and_cleanup_model(self):
        value = inputs()
        value['root']['pcode_ir']['operations'][-1]['inputs'] = value['root']['pcode_ir']['operations'][-1]['inputs'][:1]
        refit_prefix_hypothesis(value)
        self.assertEqual(len(prove_usage(**value)['memory_events']), 4)

    def test_changed_high_observation_requires_new_frame_hypothesis(self):
        value = inputs()
        value['root']['high_parameter_observation']['parameters'][0]['name'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'frame_fact'):
            prove_usage(**value)

    def test_invalid_envelopes_are_value_errors(self):
        for options in ({'root': None}, {'callees': [None]}, {'frame_fact': None}):
            value = inputs(); value.update(options)
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    prove_usage(**value)

    def test_external_storage_is_not_private_ssa(self):
        value = inputs()
        node = next(node for node in value['callees'][0]['pcode_ir']['varnodes'] if node.get('definition'))
        node['persistent'] = True
        with self.assertRaises(ValueError):
            prove_usage(**value)

if __name__ == '__main__':
    unittest.main()
