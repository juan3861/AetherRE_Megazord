import json
from argparse import Namespace

from aether_re.lab_policy import LabPolicy, preflight_dynamic_lab, validate_runtime_proof
from megazord import cmd_lab_preflight


def test_lab_policy_refuses_host_and_accepts_minimal_vm_profile():
    refused = preflight_dynamic_lab(LabPolicy(authorized=True, isolation="host", host_execution=True))
    assert refused["status"] == "refused"
    assert "host_execution_forbidden" in refused["errors"]
    ready = preflight_dynamic_lab(LabPolicy(authorized=True, isolation="vm"))
    assert ready["status"] == "ready"
    assert ready["errors"] == []


def test_lab_policy_runtime_gate_requires_snapshot_rollback_collector_and_budgets():
    refused = preflight_dynamic_lab(LabPolicy(authorized=True, isolation="vm"), require_runtime_proof=True)
    assert refused["status"] == "refused"
    assert {
        "disposable_snapshot_required",
        "rollback_required",
        "collector_configuration_required",
        "timeout_budget_required",
        "memory_budget_required",
    } <= set(refused["errors"])
    ready = preflight_dynamic_lab(
        LabPolicy(
            authorized=True,
            isolation="vm",
            snapshot_id="vm-snapshot-001",
            rollback_enabled=True,
            collector_configured=True,
            timeout_s=60,
            memory_limit_mb=1024,
        ),
        require_runtime_proof=True,
    )
    assert ready["status"] == "ready"
    assert ready["runtime_proof_required"] is True


def test_lab_policy_rejects_malformed_types_without_crashing():
    malformed = preflight_dynamic_lab(
        LabPolicy(
            authorized="yes",  # type: ignore[arg-type]
            isolation=[],  # type: ignore[arg-type]
            network_enabled="off",  # type: ignore[arg-type]
            timeout_s=-1,
        ),
        require_runtime_proof="yes",  # type: ignore[arg-type]
    )
    assert malformed["status"] == "refused"
    assert {
        "authorized_invalid",
        "isolation_invalid",
        "network_enabled_invalid",
        "timeout_s_invalid",
        "runtime_proof_flag_invalid",
    } <= set(malformed["errors"])
    assert preflight_dynamic_lab(None)["errors"] == ["policy_type_invalid"]  # type: ignore[arg-type]


def _runtime_proof():
    return {
        "schema": "dynamic-lab-runtime-proof.v1",
        "run_id": "run-001",
        "snapshot_id": "vm-snapshot-001",
        "snapshot_sha256": "a" * 64,
        "target_sha256": "b" * 64,
        "rollback_verified": True,
        "network_isolated": True,
        "collector_heartbeat": True,
        "started_at": "2026-09-16T00:00:00Z",
        "ended_at": "2026-09-16T00:00:05Z",
        "timeout_s": 60,
        "memory_limit_mb": 1024,
        "target_identity": {"name": "owned-fixture", "arch": "x86_64"},
        "events": [{"seq": 0, "kind": "heartbeat"}, {"seq": 1, "kind": "exit"}],
    }


def test_runtime_proof_validates_materialized_guest_evidence():
    policy = LabPolicy(authorized=True, isolation="vm", snapshot_id="vm-snapshot-001", timeout_s=60, memory_limit_mb=1024)
    report = validate_runtime_proof(_runtime_proof(), policy=policy)
    assert report["status"] == "verified"
    assert report["summary"]["events"] == 2
    assert report["errors"] == []


def test_runtime_proof_cannot_override_unsafe_policy_flags():
    report = validate_runtime_proof(
        _runtime_proof(),
        policy=LabPolicy(authorized=False, isolation="vm", network_enabled=True, writable_project_mount=True, host_execution=True),
    )
    assert report["status"] == "refused"
    codes = {item["code"] for item in report["errors"]}
    assert {"policy_authorization_required", "policy_network_must_be_blocked", "policy_writable_mount_forbidden", "policy_host_execution_forbidden"} <= codes


def test_runtime_proof_rejects_tampering_and_policy_mismatch():
    proof = _runtime_proof()
    proof["snapshot_sha256"] = "bad"
    proof["events"].append({"seq": 1, "kind": "duplicate"})
    proof["network_isolated"] = False
    report = validate_runtime_proof(
        proof,
        policy=LabPolicy(authorized=True, isolation="vm", snapshot_id="other", timeout_s=10, memory_limit_mb=64),
    )
    assert report["status"] == "invalid"
    codes = {item["code"] for item in report["errors"]}
    assert {"sha256_invalid", "event_sequence_duplicate", "network_not_isolated", "snapshot_id_mismatch", "timeout_exceeds_policy", "memory_exceeds_policy"} <= codes


def test_runtime_proof_rejects_missing_fields_and_non_object():
    missing = _runtime_proof()
    missing.pop("events")
    report = validate_runtime_proof(missing)
    assert report["status"] == "invalid"
    assert report["errors"] == [{"code": "required_field_missing", "field": "events"}]
    assert validate_runtime_proof(None)["errors"] == [{"code": "proof_must_be_object"}]  # type: ignore[arg-type]


def test_runtime_proof_requires_schema_and_temporal_continuity():
    proof = _runtime_proof()
    proof.pop("schema")
    report = validate_runtime_proof(proof)
    assert report["status"] == "invalid"
    assert report["errors"][0] == {"code": "required_field_missing", "field": "schema"}
    proof = _runtime_proof()
    proof["started_at"] = "2026-09-16T00:00:06Z"
    proof["events"] = [{"seq": 1, "kind": "heartbeat"}, {"seq": 2, "kind": "exit"}]
    report = validate_runtime_proof(proof)
    codes = {item["code"] for item in report["errors"]}
    assert {"timestamp_order_invalid", "event_sequence_not_contiguous"} <= codes


def test_runtime_proof_bounds_hostile_event_count_and_error_size():
    proof = _runtime_proof()
    proof["events"] = [{"seq": 0, "kind": "heartbeat"}, {"seq": 1, "kind": "exit"}, {"seq": 2, "kind": "late"}]
    report = validate_runtime_proof(proof, max_events=2)
    assert report["status"] == "invalid"
    assert report["summary"]["events"] == 3
    assert report["summary"]["events_checked"] == 2
    assert {item["code"] for item in report["errors"]} >= {"event_budget_exceeded"}
    assert len(json.dumps(report)) < 2000
    assert validate_runtime_proof(proof, max_events=True)["errors"] == [{"code": "max_events_invalid"}]


def test_runtime_proof_sequence_diagnostic_is_compact():
    proof = _runtime_proof()
    proof["events"] = [{"seq": 1_000_000, "kind": "heartbeat"}]
    report = validate_runtime_proof(proof)
    issue = next(item for item in report["errors"] if item["code"] == "event_sequence_not_contiguous")
    assert issue == {"code": "event_sequence_not_contiguous", "index": 0, "expected": 0, "observed": 1_000_000}
    assert len(json.dumps(report)) < 2000
    assert report["summary"]["isolation_attested"] is False


def test_lab_preflight_cli_binds_materialized_runtime_proof(tmp_path, capsys):
    proof_path = tmp_path / "runtime-proof.json"
    proof_path.write_text(json.dumps(_runtime_proof()), encoding="utf-8")
    code = cmd_lab_preflight(
        Namespace(
            authorized=True,
            isolation="vm",
            network=False,
            writable_mount=False,
            host_execution=False,
            snapshot_id="vm-snapshot-001",
            rollback=True,
            collector_configured=True,
            timeout_s=60,
            memory_mb=1024,
            runtime_proof=True,
            proof=str(proof_path),
        )
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["status"] == "ready"
    assert report["runtime_proof"]["status"] == "verified"


def test_lab_preflight_cli_fails_closed_for_unreadable_runtime_proof(tmp_path, capsys):
    code = cmd_lab_preflight(
        Namespace(
            authorized=True,
            isolation="vm",
            network=False,
            writable_mount=False,
            host_execution=False,
            snapshot_id="vm-snapshot-001",
            rollback=True,
            collector_configured=True,
            timeout_s=60,
            memory_mb=1024,
            runtime_proof=True,
            proof=str(tmp_path / "missing.json"),
        )
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == "refused"
    assert report["runtime_proof"]["status"] == "invalid"
    assert report["runtime_proof"]["errors"][0]["code"] == "proof_unreadable"
