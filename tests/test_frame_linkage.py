import hashlib
import json
from pathlib import Path

import pytest

from aether_re.ghidra_pcode_c import reconstruct_high_pcode


def emit(**options):
    data = json.loads((Path(__file__).parent / 'fixtures/frame_program_ir.json').read_text())['callee']['pcode_ir']
    evidence = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return reconstruct_high_pcode(data, expected_target=data['target_sha256'],
                                 expected_address=data['function_address'], evidence_sha256=evidence,
                                 function_name='aether_private_frame_body', memory_model='bounded-bytes.v2', **options)


def test_internal_linkage_is_formed_before_ctree():
    result = emit(internal_linkage=True)
    assert result['status'] == 'complete', result['errors']
    assert result['linkage'] == 'internal'
    signature = 'static unsigned long long aether_private_frame_body('
    assert signature in result['structured_c_source']
    assert signature in result['ctree']['structured_c_source']
    assert 'static static' not in result['structured_c_source']


def test_default_and_explicit_false_preserve_complete_report():
    default = emit(); explicit = emit(internal_linkage=False)
    assert default == explicit
    assert default['status'] == 'complete'
    assert 'linkage' not in default
    assert '\nunsigned long long aether_private_frame_body(' in default['structured_c_source']
    assert '\nstatic unsigned long long aether_private_frame_body(' not in default['structured_c_source']


@pytest.mark.parametrize('value', [None, 0, 1, '', 'false', [], {}])
def test_linkage_rejects_non_boolean_without_throwing(value):
    result = emit(internal_linkage=value)
    assert result['status'] == 'invalid'
    assert result['errors'] == ['pcode_c_linkage_invalid']
    assert result['structured_c_source'] is None
    assert 'linkage' not in result
