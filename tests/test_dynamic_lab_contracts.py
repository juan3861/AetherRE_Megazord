import json

import pytest

from aether_re.dynamic_lab_contracts import (
    DynamicLabHandoff,
    DynamicTrace,
    RollbackAttestation,
    RunLease,
    VMQualification,
)
from aether_re.kernel_contracts import ContractError
from megazord import main


def _lease():
    return RunLease(
        schema="run-lease.v1", run_id="run-001", authorization_id="auth-001",
        vm_provider="hyper-v", guest_id="guest-001", snapshot_id="clean-001",
        nonce="nonce-001", signed_evidence_id="sig:lease-001",
    )


def _qualification():
    return VMQualification(
        schema="vm-qualification.v1", vm_provider="hyper-v", guest_id="guest-001",
        snapshot_id="clean-001", network_isolated=True, disposable_disk=True,
        heartbeat_id="heartbeat-001", nonce="nonce-001", signed_evidence_id="sig:vm-001",
    )


def _trace():
    return DynamicTrace(
        schema="dynamic-trace.v1", run_id="run-001", vm_provider="hyper-v",
        guest_id="guest-001", snapshot_id="clean-001", nonce="nonce-001",
        signed_evidence_id="sig:trace-001", events=("evidence:trace-chunk-001",),
    )


def _rollback():
    return RollbackAttestation(
        schema="rollback-attestation.v1", run_id="run-001", guest_id="guest-001",
        snapshot_id="clean-001", nonce="nonce-001", signed_evidence_id="sig:rollback-001",
        rollback_evidence=("evidence:rollback-001",),
    )


def test_valid_contracts_round_trip_and_aggregate_handoff_is_verified():
    handoff = DynamicLabHandoff(
        schema="dynamic-lab-handoff.v1", run_lease=_lease(),
        vm_qualification=_qualification(), dynamic_trace=_trace(),
        rollback_attestation=_rollback(),
    )
    assert DynamicLabHandoff.from_dict(handoff.to_dict()) == handoff
    assert handoff.to_dict()["dynamic_trace"]["events"] == ["evidence:trace-chunk-001"]


@pytest.mark.parametrize("field,value", [
    ("vm_provider", "wsl"), ("vm_provider", "docker"), ("execution_environment", "host-direct"),
])
def test_vm_qualification_rejects_non_vm_substitutes(field, value):
    payload = _qualification().to_dict()
    payload[field] = value
    with pytest.raises(ContractError):
        VMQualification.from_dict(payload)


@pytest.mark.parametrize("factory,field,bad", [
    (_lease, "nonce", ""),
    (_lease, "signed_evidence_id", ""),
    (_qualification, "network_isolated", False),
    (_qualification, "disposable_disk", False),
    (_qualification, "heartbeat_id", ""),
    (_trace, "events", ()),
    (_rollback, "rollback_evidence", ()),
])
def test_contracts_fail_closed_for_required_dynamic_evidence(factory, field, bad):
    payload = factory().to_dict()
    payload[field] = list(bad) if isinstance(bad, tuple) else bad
    cls = {"run-lease.v1": RunLease, "vm-qualification.v1": VMQualification,
           "dynamic-trace.v1": DynamicTrace, "rollback-attestation.v1": RollbackAttestation}[payload["schema"]]
    with pytest.raises(ContractError):
        cls.from_dict(payload)


def test_contracts_require_exact_schema_and_no_unknown_fields():
    payload = _lease().to_dict()
    payload["unexpected"] = True
    with pytest.raises(ContractError):
        RunLease.from_dict(payload)
    payload = _lease().to_dict()
    payload["schema"] = "run-lease.v2"
    with pytest.raises(ContractError):
        RunLease.from_dict(payload)


def test_aggregate_handoff_rejects_linkage_mismatch_or_duplicate_signed_evidence():
    payload = DynamicLabHandoff(
        schema="dynamic-lab-handoff.v1", run_lease=_lease(), vm_qualification=_qualification(),
        dynamic_trace=_trace(), rollback_attestation=_rollback(),
    ).to_dict()
    payload["dynamic_trace"]["nonce"] = "different"
    with pytest.raises(ContractError):
        DynamicLabHandoff.from_dict(payload)
    payload = DynamicLabHandoff(
        schema="dynamic-lab-handoff.v1", run_lease=_lease(), vm_qualification=_qualification(),
        dynamic_trace=_trace(), rollback_attestation=_rollback(),
    ).to_dict()
    payload["rollback_attestation"]["signed_evidence_id"] = "sig:trace-001"
    with pytest.raises(ContractError):
        DynamicLabHandoff.from_dict(payload)


def test_lab_qualify_cli_validates_but_does_not_execute_a_guest(tmp_path, monkeypatch):
    document = DynamicLabHandoff(
        schema="dynamic-lab-handoff.v1", run_lease=_lease(), vm_qualification=_qualification(),
        dynamic_trace=_trace(), rollback_attestation=_rollback(),
    ).to_dict()
    source = tmp_path / "handoff.json"
    output = tmp_path / "qualification.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord.py", "lab-qualify", "--input", str(source), "--out", str(output)])
    assert main() == 3
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["qualified"] is False
    assert report["structurally_valid"] is True
    assert report["execution"] is False
