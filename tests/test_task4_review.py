from pathlib import Path
import hashlib
import pytest
from aether_re.adapters._static_base import doc
from aether_re.profile_certification import certify_static_profile
from aether_re.static_profiles import select_static_profile
from aether_re.static_worker import StaticWorkerSpec, probe_static_worker


def test_jvm_class_header_is_never_macho(tmp_path):
    target = tmp_path / 'C.class'
    target.write_bytes(bytes.fromhex('cafebabe0000003d'))
    assert select_static_profile(target).profile_id == 'jvm'


def test_worker_probe_rejects_missing_or_mismatched_expected_version(monkeypatch, tmp_path):
    exe = tmp_path / 'tool.exe'; exe.write_bytes(b'tool')
    digest = hashlib.sha256(b'tool').hexdigest()
    spec = StaticWorkerSpec('tool', exe, digest, 'tool 2.0', 'MIT', 1, 64, 1, 1024)
    monkeypatch.setattr('aether_re.static_worker._run_bounded', lambda *a, **k: {'returncode': 0, 'stdout': 'tool 1.0', 'stderr': ''})
    assert 'worker_version_mismatch' in probe_static_worker(spec).errors
    bad = StaticWorkerSpec('tool', exe, digest, '', '', 1, 64, 1, 1024)
    assert {'worker_expected_version_missing', 'worker_license_missing'} <= set(probe_static_worker(bad).errors)


def test_certification_requires_workers_measured_values_and_evidence():
    result = certify_static_profile({'schema':'profile-scope.v1','profile_id':'wasm'},
        {'development_hash':'d','calibration_hash':'c','blind_hash':'b'}, {'workers': []},
        {'oracle_independent': True}, {'regressions': []})
    codes = {x['code'] for x in result['errors']}
    assert result['status'] == 'NAO_COMPROVADA'
    assert {'workers_missing', 'entities_unmeasured', 'evaluation_evidence_missing'} <= codes


def test_hostile_adapter_output_rejected_before_publication():
    with pytest.raises(ValueError, match='adapter_payload_invalid'):
        doc('wasm', 'sha256:x', ('ev:x',), {'functions': [{'name':'f', 'confidence':'not-number'}]}, 'wasm', {'functions':'function'})


def test_thin_macho_32_magic_is_classified(tmp_path):
    target = tmp_path / 'thin32.bin'
    target.write_bytes(bytes.fromhex('cefaedfe'))
    assert select_static_profile(target).profile_id == 'macho'


def test_adapter_rejects_supplied_edge_with_unknown_endpoint():
    payload = {'functions': [{'name':'known'}], 'edges': [{'source':'known','target':'missing','kind':'calls'}]}
    with pytest.raises(ValueError, match='adapter_payload_invalid'):
        doc('wasm', 'sha256:x', ('ev:x',), payload, 'wasm', {'functions':'function'})
