import copy
import hashlib
import json
from types import SimpleNamespace

import pytest


def api():
    from aether_re import universal_frame
    return universal_frame


def test_snapshot_preserves_original_bytes_and_receipt(tmp_path):
    raw = '{ "target_sha256": "abc", "note": "ação" }\n'.encode()
    source = tmp_path / 'fact.json'
    source.write_bytes(raw)
    dest = tmp_path / 'snapshot.json'
    fact, receipt = api().snapshot_frame_fact(source, dest, target_sha256='abc')
    assert dest.read_bytes() == raw
    assert fact['note'] == 'ação'
    assert receipt['sha256'] == hashlib.sha256(raw).hexdigest()
    assert receipt['snapshot_path'] == str(dest)
    assert receipt['native_fact_verified'] is False
    with pytest.raises((ValueError, FileExistsError)):
        api().snapshot_frame_fact(source, dest, target_sha256='abc')
    assert dest.read_bytes() == raw


def test_snapshot_refuses_binding_and_preflight_mutation(tmp_path):
    from aether_re.frame_request import read_frame_fact
    source = tmp_path / 'fact.json'
    source.write_text('{"target_sha256":"abc"}', encoding='utf-8')
    dest = tmp_path / 'snapshot.json'
    with pytest.raises(ValueError):
        api().snapshot_frame_fact(source, dest, target_sha256='other')
    assert not dest.exists()
    preflight = read_frame_fact(source)
    source.write_text('{"target_sha256":"abc", "changed":true}', encoding='utf-8')
    with pytest.raises(ValueError):
        api().snapshot_frame_fact(source, dest, target_sha256='abc', preflight=preflight)
    assert not dest.exists()


def exported(program=None, **overrides):
    values = dict(success=True, target_sha256='abc', status='complete', total_functions=7,
                  worker_execution={'status': 'fixture'}, artifact_dir=None, error_message=None)
    values.update(overrides)
    obj = SimpleNamespace(**values)
    obj.calls = []
    def select(selector, fact):
        obj.calls.append((selector, fact))
        if isinstance(program, Exception):
            raise program
        return program
    obj.select_frame_program = select
    return obj


def build(obj, profile='native-pe'):
    return api().build_frame_case(obj, target_sha256='abc', selector='root',
                                  fact={'target_sha256': 'abc'}, intake={'sha256':'raw'}, profile=profile)


def test_case_counts_one_requested_model_and_preserves_refusal():
    program = {'status':'refused', 'report':None, 'c_source':None, 'reason':'unsupported'}
    obj = exported(program)
    result = build(obj)
    assert result['status'] == 'refused'
    assert result['program'] == program
    assert result['requested_programs'] == result['attempted_programs'] == result['refused_programs'] == 1
    assert result['derived_programs'] == 0
    assert result['exported_total_functions'] == 7
    assert len(obj.calls) == 1
    assert result['target_executed'] is False
    assert result['binary_equivalence'] is False
    assert result['original_source'] is False


@pytest.mark.parametrize('status,profile,success', [('unsupported_profile','other',True), ('backend_failed','native-elf',False)])
def test_case_does_not_select_when_unavailable(status, profile, success):
    obj = exported(success=success)
    result = build(obj, profile)
    assert result['status'] == status
    assert result['attempted_programs'] == 0
    assert not obj.calls


def test_case_complete_unavailable_binding_and_selector_error():
    assert build(None)['status'] == 'backend_unavailable'
    obj = exported({'status':'complete', 'c_source':'conditional model'})
    result = build(obj)
    assert result['derived_programs'] == 1
    assert result['status'] == 'complete'
    bad = exported(target_sha256='other')
    with pytest.raises(ValueError):
        build(bad)
    assert not bad.calls
    result = build(exported(ValueError('selector_invalid')))
    assert result['status'] == 'refused'
    assert result['refused_programs'] == 1
    assert result['error_code'] == 400
    assert result['program'] is None


def test_publication_is_create_only_hashed_body_and_does_not_mutate(tmp_path):
    result = {'schema':'derived-frame-case.v1', 'note':'ação'}
    original = copy.deepcopy(result)
    dest = tmp_path / 'case.json'
    published = api().publish_frame_case(result, dest)
    raw = dest.read_bytes()
    assert json.loads(raw) == result == original
    assert raw.endswith(b'\n')
    assert published['publication'] == dict(path=str(dest), sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
    with pytest.raises((ValueError, FileExistsError)):
        api().publish_frame_case(result, dest)
    assert dest.read_bytes() == raw


def test_publication_budget_includes_newline_and_utf8_bytes(tmp_path):
    dest = tmp_path / 'case.json'
    with pytest.raises(ValueError):
        api().publish_frame_case({'value':'é' * (4 * 1024 * 1024)}, dest)
    assert not dest.exists()
