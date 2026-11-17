import hashlib
import json
from pathlib import Path

import pytest

from aether_re.behavioral_runner import run_behavioral_cases, validate_candidate
from megazord import main


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_bundle(root: Path, *, status: str = "candidate"):
    original_source = b"int main(void){return 0;}\n"
    candidate_source = b"int main(void){return 0;}\n"
    original_binary = b"original-bin"
    candidate_binary = b"candidate-bin"
    toolchain = b"compiler identity and version"
    reconstruction_evidence = b'{"schema":"reconstruction-evidence.v1","analysis":"synthetic test evidence"}'
    for name, data in (("original.c", original_source), ("candidate.c", candidate_source),
                       ("original.bin", original_binary), ("candidate.bin", candidate_binary),
                       ("toolchain.lock", toolchain), ("reconstruction.json", reconstruction_evidence)):
        (root / name).write_bytes(data)
    cases = {"schema": "behavior-cases.v1", "cases": [{"case_id": "zero", "input": {"argv": ["0"]}}]}
    (root / "cases.json").write_text(json.dumps(cases, sort_keys=True), encoding="utf-8")
    candidate = {
        "schema": "reconstruction-candidate.v1", "status": status,
        "original": {"source": {"path": "original.c", "sha256": _sha(original_source)},
                     "binary": {"path": "original.bin", "sha256": _sha(original_binary)}},
        "candidate": {"source": {"path": "candidate.c", "sha256": _sha(candidate_source)},
                      "binary": {"path": "candidate.bin", "sha256": _sha(candidate_binary)}},
        "toolchain": {"path": "toolchain.lock", "sha256": _sha(toolchain)},
        "reconstruction_evidence": {"path": "reconstruction.json", "sha256": _sha(reconstruction_evidence)},
        "input_manifest": {"path": "cases.json", "sha256": _sha((root / "cases.json").read_bytes())},
    }
    lease = {
        "schema": "dynamic-lab-handoff.v1",
        "run_lease": {"schema": "run-lease.v1", "run_id": "r1", "authorization_id": "owned-test", "vm_provider": "hyper-v", "guest_id": "guest-1", "snapshot_id": "clean-1", "nonce": "nonce-1", "signed_evidence_id": "sig-lease"},
        "vm_qualification": {"schema": "vm-qualification.v1", "vm_provider": "hyper-v", "guest_id": "guest-1", "snapshot_id": "clean-1", "network_isolated": True, "disposable_disk": True, "heartbeat_id": "hb-1", "nonce": "nonce-1", "signed_evidence_id": "sig-vm", "execution_environment": "vm"},
        "dynamic_trace": {"schema": "dynamic-trace.v1", "run_id": "r1", "vm_provider": "hyper-v", "guest_id": "guest-1", "snapshot_id": "clean-1", "nonce": "nonce-1", "signed_evidence_id": "sig-trace", "events": ["trace:1"]},
        "rollback_attestation": {"schema": "rollback-attestation.v1", "run_id": "r1", "guest_id": "guest-1", "snapshot_id": "clean-1", "nonce": "nonce-1", "signed_evidence_id": "sig-rollback", "rollback_evidence": ["rollback:1"]},
    }
    signed_handoff = {"payload": lease, "signature": {"key_id": "test-key", "algorithm": "test", "value": "valid"}}
    return candidate, signed_handoff, cases


def _signed_result(request, *, guest="guest-1", original=None, candidate=None, case_id=None):
    payload = {
        "schema": "guest-pair-result.v1", "run_id": "r1", "guest_id": guest, "nonce": "nonce-1",
        "case_id": case_id or request["case"]["case_id"],
        "case_index": request["case_index"], "case_total": request["case_total"],
        "input": request["case"]["input"], "input_sha256": request["input_sha256"],
        "input_manifest_sha256": request["input_manifest_sha256"],
        "candidate_manifest_sha256": request["candidate_manifest_sha256"], "timeout_s": request["timeout_s"],
        "max_output_bytes": request["max_output_bytes"],
        "original_binary_sha256": request["original_binary_sha256"],
        "candidate_binary_sha256": request["candidate_binary_sha256"],
        "original": original or {"stdout": "ok\n", "stderr": "", "exit_code": 0, "exception": None, "timeout": False, "effects": {"status": "unknown", "events": []}},
        "candidate": candidate or {"stdout": "ok\n", "stderr": "", "exit_code": 0, "exception": None, "timeout": False, "effects": {"status": "unknown", "events": []}},
    }
    return {"payload": payload, "signature": {"key_id": "test-key", "algorithm": "test", "value": "valid"}}


def _verify(envelope, trust_map=None):
    return isinstance(envelope, dict) and envelope.get("signature", {}).get("value") == "valid"


def _run(root, *, executor=None, verifier=_verify, status="candidate"):
    candidate, handoff, _ = _write_bundle(root, status=status)
    executor = executor or (lambda request: _signed_result(request))
    return run_behavioral_cases(
        candidate=candidate, artifact_root=root, case_manifest_path=root / "cases.json",
        signed_handoff=handoff, guest_executor=executor, verify_attestation=verifier,
        timeout_s=5, max_output_bytes=4096,
    )


def test_valid_matching_guest_run_preserves_unknown_effects_and_hashes(tmp_path):
    report = _run(tmp_path)
    assert report["schema"] == "behavioral-run.v1"
    assert report["status"] == "complete"
    assert report["summary"] == {"cases": 1, "observed": 1, "failed": 0}
    assert report["original"][0]["effects"] == {"status": "unknown", "events": []}
    assert report["candidate"][0]["effects"] == {"status": "unknown", "events": []}
    assert report["guest_id"] == "guest-1"
    assert report["candidate_hashes"]["original_binary_sha256"] == _sha(b"original-bin")


def test_output_mismatch_is_retained_as_counterexample(tmp_path):
    def executor(request):
        return _signed_result(request, candidate={"stdout": "different\n", "stderr": "", "exit_code": 0, "exception": None, "timeout": False, "effects": {"status": "unknown", "events": []}})
    report = _run(tmp_path, executor=executor)
    assert report["status"] == "complete"
    assert report["comparison"]["status"] == "counterexamples_found"
    assert report["comparison"]["mismatches"][0]["fields"] == ["output"]


def test_exception_mismatch_is_retained(tmp_path):
    def executor(request):
        return _signed_result(request, candidate={"stdout": "", "stderr": "", "exit_code": 1, "exception": {"type": "Abort"}, "timeout": False, "effects": {"status": "unknown", "events": []}})
    report = _run(tmp_path, executor=executor)
    assert report["comparison"]["mismatches"][0]["fields"] == ["output", "exception"]


def test_timeout_is_recorded_and_not_called_a_match(tmp_path):
    def executor(request):
        return _signed_result(request, candidate={"stdout": "", "stderr": "", "exit_code": None, "exception": None, "timeout": True, "effects": {"status": "unknown", "events": []}})
    report = _run(tmp_path, executor=executor)
    assert report["candidate"][0]["output"]["timeout"] is True
    assert report["comparison"]["summary"]["matched"] == 0


def test_refuses_guest_when_handoff_signature_is_invalid(tmp_path):
    called = False
    def executor(_request):
        nonlocal called
        called = True
        return {}
    report = _run(tmp_path, executor=executor, verifier=lambda _envelope: False)
    assert report["status"] == "refused"
    assert {e["code"] for e in report["errors"]} == {"handoff_attestation_invalid"}
    assert not called


def test_tampered_target_hash_fails_before_guest_execution(tmp_path):
    candidate, handoff, _ = _write_bundle(tmp_path)
    candidate["candidate"]["binary"]["sha256"] = "0" * 64
    called = False
    def executor(_request):
        nonlocal called
        called = True
        return {}
    report = run_behavioral_cases(candidate=candidate, artifact_root=tmp_path, case_manifest_path=tmp_path / "cases.json", signed_handoff={"payload": handoff["payload"], "signature": handoff["signature"]}, guest_executor=executor, verify_attestation=_verify, timeout_s=5, max_output_bytes=4096)
    assert report["status"] == "invalid"
    assert any(e["code"] == "artifact_hash_mismatch" for e in report["errors"])
    assert not called


@pytest.mark.parametrize("artifact_name", ["original.bin", "candidate.bin"])
def test_execution_binary_changed_after_validation_is_rejected_before_guest_execution(tmp_path, monkeypatch, artifact_name):
    from aether_re import behavioral_runner

    candidate, handoff, _ = _write_bundle(tmp_path)
    validate = behavioral_runner.validate_candidate

    def validate_then_mutate(*args, **kwargs):
        result = validate(*args, **kwargs)
        (tmp_path / artifact_name).write_bytes(b"changed after the evidence hash was checked")
        return result

    monkeypatch.setattr(behavioral_runner, "validate_candidate", validate_then_mutate)
    calls = []

    def executor(request):
        calls.append(request)
        return _signed_result(request)

    report = run_behavioral_cases(
        candidate=candidate,
        artifact_root=tmp_path,
        case_manifest_path=tmp_path / "cases.json",
        signed_handoff=handoff,
        guest_executor=executor,
        verify_attestation=_verify,
        timeout_s=5,
        max_output_bytes=4096,
    )

    assert report["status"] == "invalid"
    assert any(error["code"] == "execution_artifact_hash_changed" for error in report["errors"])
    assert calls == []


def test_missing_guest_observation_fails_closed(tmp_path):
    def executor(request):
        return _signed_result(request, case_id="wrong-case")
    report = _run(tmp_path, executor=executor)
    assert report["status"] == "invalid"
    assert any(e["code"] == "guest_case_identity_mismatch" for e in report["errors"])
    assert report["original"] == [] and report["candidate"] == []


def test_duplicate_input_cases_fail_before_guest_execution(tmp_path):
    candidate, handoff, cases = _write_bundle(tmp_path)
    cases["cases"].append({"case_id": "duplicate", "input": {"argv": ["0"]}})
    (tmp_path / "cases.json").write_text(json.dumps(cases, sort_keys=True), encoding="utf-8")
    candidate["input_manifest"]["sha256"] = _sha((tmp_path / "cases.json").read_bytes())
    called = False
    def executor(_request):
        nonlocal called
        called = True
        return {}
    report = run_behavioral_cases(candidate=candidate, artifact_root=tmp_path, case_manifest_path=tmp_path / "cases.json", signed_handoff=handoff, guest_executor=executor, verify_attestation=_verify, timeout_s=5, max_output_bytes=4096)
    assert report["status"] == "invalid"
    assert any(e["code"] == "duplicate_input" for e in report["errors"])
    assert not called


def test_pseudo_source_only_candidate_is_not_executable(tmp_path):
    report = _run(tmp_path, status="pseudo_source_only")
    assert report["status"] == "refused"
    assert any(e["code"] == "candidate_not_executable" for e in report["errors"])


def test_behavior_compare_cli_rejects_unvalidated_observation_file(tmp_path, monkeypatch):
    inp = tmp_path / "observations.json"
    out = tmp_path / "comparison.json"
    inp.write_text(json.dumps({"schema": "behavioral-run.v1", "status": "partial", "original": [], "candidate": []}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord.py", "behavior-compare", "--input", str(inp), "--out", str(out)])
    assert main() == 2
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "observations_not_verified"


def test_candidate_validation_rejects_path_escape(tmp_path):
    candidate, _, _ = _write_bundle(tmp_path)
    candidate["candidate"]["binary"]["path"] = "../../outside.bin"
    result = validate_candidate(candidate, tmp_path, case_manifest_path=tmp_path / "cases.json")
    assert result["status"] == "invalid"
    assert any(e["code"] == "artifact_path_escape" for e in result["errors"])


def test_signed_behavior_compare_rejects_truncated_denominator(tmp_path, monkeypatch):
    from aether_re import behavioral_runner
    report = _run(tmp_path)
    monkeypatch.setattr(behavioral_runner, "verify_signed_document", _verify)
    trust = {"schema": "aetherre-trust-map.v1", "keys": []}
    complete = behavioral_runner.compare_signed_behavioral_run(report, trust)
    assert complete["status"] == "equivalent_on_observations"
    report["guest_result_envelopes"].clear()
    truncated = behavioral_runner.compare_signed_behavioral_run(report, trust)
    assert truncated["status"] == "invalid"
    assert any(e["code"] == "guest_observation_denominator_mismatch" for e in truncated["errors"])


def test_behavior_compare_cli_recomputes_verified_counterexamples(tmp_path, monkeypatch):
    from aether_re import behavioral_runner
    from aether_re.behavioral_runner import compare_signed_behavioral_run
    def executor(request):
        return _signed_result(request, candidate={"stdout": "different\n", "stderr": "", "exit_code": 0, "exception": None, "timeout": False, "effects": {"status": "unknown", "events": []}})
    run = _run(tmp_path, executor=executor)
    monkeypatch.setattr(behavioral_runner, "verify_signed_document", _verify)
    source = tmp_path / "run.json"
    trust = tmp_path / "trust.json"
    output = tmp_path / "comparison.json"
    source.write_text(json.dumps(run), encoding="utf-8")
    trust.write_text(json.dumps({"schema": "aetherre-trust-map.v1", "keys": []}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord.py", "behavior-compare", "--input", str(source), "--trust-map", str(trust), "--out", str(output)])
    assert main() == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "counterexamples_found"
    assert result["summary"]["mismatches"] == 1


def test_candidate_cannot_mislabel_pseudo_source_as_executable(tmp_path):
    candidate, _, _ = _write_bundle(tmp_path)
    pseudo = b"/* PSEUDO_SOURCE_ONLY: generated decompiler sketch */\n"
    (tmp_path / "candidate.c").write_bytes(pseudo)
    candidate["candidate"]["source"]["sha256"] = _sha(pseudo)
    result = validate_candidate(candidate, tmp_path, case_manifest_path=tmp_path / "cases.json")
    assert result["status"] == "invalid"
    assert any(e["code"] == "candidate_pseudo_source_marked" for e in result["errors"])
