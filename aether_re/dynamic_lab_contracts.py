"""Fail-closed, data-only contracts for a qualified disposable-VM lab.

These contracts validate handoff evidence only.  They never start a guest, a
hypervisor, a container, WSL, or an analysis sample.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from aether_re.kernel_contracts import ContractError


_FORBIDDEN_VM_SUBSTITUTES = ("wsl", "container", "docker", "podman", "host", "direct")


def _text(value: Any, error: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(error)
    return value.strip()


def _vm_provider(value: Any) -> str:
    provider = _text(value, "vm_provider_invalid")
    normalized = provider.casefold()
    if any(token in normalized for token in _FORBIDDEN_VM_SUBSTITUTES):
        raise ContractError("vm_provider_not_real_vm")
    return provider


def _true(value: Any, error: str) -> bool:
    if value is not True:
        raise ContractError(error)
    return True


def _evidence_list(value: Any, error: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ContractError(error)
    items = tuple(_text(item, error) for item in value)
    if len(items) != len(set(items)):
        raise ContractError(error)
    return items


def _exact(value: Any, fields: set[str], error: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ContractError(error)
    return value


@dataclass(frozen=True)
class RunLease:
    schema: str
    run_id: str
    authorization_id: str
    vm_provider: str
    guest_id: str
    snapshot_id: str
    nonce: str
    signed_evidence_id: str

    def __post_init__(self) -> None:
        if self.schema != "run-lease.v1":
            raise ContractError("run_lease_schema_invalid")
        for field in ("run_id", "authorization_id", "guest_id", "snapshot_id", "nonce", "signed_evidence_id"):
            object.__setattr__(self, field, _text(getattr(self, field), f"run_lease_{field}_invalid"))
        object.__setattr__(self, "vm_provider", _vm_provider(self.vm_provider))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RunLease":
        fields = {"schema", "run_id", "authorization_id", "vm_provider", "guest_id", "snapshot_id", "nonce", "signed_evidence_id"}
        data = _exact(value, fields, "run_lease_schema_invalid")
        return cls(**dict(data))

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in ("schema", "run_id", "authorization_id", "vm_provider", "guest_id", "snapshot_id", "nonce", "signed_evidence_id")}


@dataclass(frozen=True)
class VMQualification:
    schema: str
    vm_provider: str
    guest_id: str
    snapshot_id: str
    network_isolated: bool
    disposable_disk: bool
    heartbeat_id: str
    nonce: str
    signed_evidence_id: str
    execution_environment: str = "vm"

    def __post_init__(self) -> None:
        if self.schema != "vm-qualification.v1":
            raise ContractError("vm_qualification_schema_invalid")
        if self.execution_environment != "vm":
            raise ContractError("execution_environment_not_real_vm")
        object.__setattr__(self, "vm_provider", _vm_provider(self.vm_provider))
        for field in ("guest_id", "snapshot_id", "heartbeat_id", "nonce", "signed_evidence_id"):
            object.__setattr__(self, field, _text(getattr(self, field), f"vm_qualification_{field}_invalid"))
        _true(self.network_isolated, "network_isolation_required")
        _true(self.disposable_disk, "disposable_disk_required")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VMQualification":
        fields = {"schema", "vm_provider", "guest_id", "snapshot_id", "network_isolated", "disposable_disk", "heartbeat_id", "nonce", "signed_evidence_id", "execution_environment"}
        data = _exact(value, fields, "vm_qualification_schema_invalid")
        return cls(**dict(data))

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in ("schema", "vm_provider", "guest_id", "snapshot_id", "network_isolated", "disposable_disk", "heartbeat_id", "nonce", "signed_evidence_id", "execution_environment")}


@dataclass(frozen=True)
class DynamicTrace:
    schema: str
    run_id: str
    vm_provider: str
    guest_id: str
    snapshot_id: str
    nonce: str
    signed_evidence_id: str
    events: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema != "dynamic-trace.v1":
            raise ContractError("dynamic_trace_schema_invalid")
        object.__setattr__(self, "vm_provider", _vm_provider(self.vm_provider))
        for field in ("run_id", "guest_id", "snapshot_id", "nonce", "signed_evidence_id"):
            object.__setattr__(self, field, _text(getattr(self, field), f"dynamic_trace_{field}_invalid"))
        object.__setattr__(self, "events", _evidence_list(self.events, "dynamic_trace_events_required"))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DynamicTrace":
        fields = {"schema", "run_id", "vm_provider", "guest_id", "snapshot_id", "nonce", "signed_evidence_id", "events"}
        data = _exact(value, fields, "dynamic_trace_schema_invalid")
        return cls(**dict(data))

    def to_dict(self) -> dict[str, Any]:
        result = {field: getattr(self, field) for field in ("schema", "run_id", "vm_provider", "guest_id", "snapshot_id", "nonce", "signed_evidence_id")}
        result["events"] = list(self.events)
        return result


@dataclass(frozen=True)
class RollbackAttestation:
    schema: str
    run_id: str
    guest_id: str
    snapshot_id: str
    nonce: str
    signed_evidence_id: str
    rollback_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema != "rollback-attestation.v1":
            raise ContractError("rollback_attestation_schema_invalid")
        for field in ("run_id", "guest_id", "snapshot_id", "nonce", "signed_evidence_id"):
            object.__setattr__(self, field, _text(getattr(self, field), f"rollback_attestation_{field}_invalid"))
        object.__setattr__(self, "rollback_evidence", _evidence_list(self.rollback_evidence, "rollback_evidence_required"))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RollbackAttestation":
        fields = {"schema", "run_id", "guest_id", "snapshot_id", "nonce", "signed_evidence_id", "rollback_evidence"}
        data = _exact(value, fields, "rollback_attestation_schema_invalid")
        return cls(**dict(data))

    def to_dict(self) -> dict[str, Any]:
        result = {field: getattr(self, field) for field in ("schema", "run_id", "guest_id", "snapshot_id", "nonce", "signed_evidence_id")}
        result["rollback_evidence"] = list(self.rollback_evidence)
        return result


@dataclass(frozen=True)
class DynamicLabHandoff:
    """Aggregate all linked evidence required for an offline VM-lab handoff."""
    schema: str
    run_lease: RunLease
    vm_qualification: VMQualification
    dynamic_trace: DynamicTrace
    rollback_attestation: RollbackAttestation

    def __post_init__(self) -> None:
        if self.schema != "dynamic-lab-handoff.v1":
            raise ContractError("dynamic_lab_handoff_schema_invalid")
        if not all(isinstance(item, expected) for item, expected in (
            (self.run_lease, RunLease), (self.vm_qualification, VMQualification),
            (self.dynamic_trace, DynamicTrace), (self.rollback_attestation, RollbackAttestation),
        )):
            raise ContractError("dynamic_lab_handoff_component_invalid")
        lease, vm, trace, rollback = self.run_lease, self.vm_qualification, self.dynamic_trace, self.rollback_attestation
        if (lease.vm_provider, lease.guest_id, lease.snapshot_id, lease.nonce) != (vm.vm_provider, vm.guest_id, vm.snapshot_id, vm.nonce):
            raise ContractError("dynamic_lab_handoff_vm_linkage_invalid")
        if (lease.run_id, lease.vm_provider, lease.guest_id, lease.snapshot_id, lease.nonce) != (trace.run_id, trace.vm_provider, trace.guest_id, trace.snapshot_id, trace.nonce):
            raise ContractError("dynamic_lab_handoff_trace_linkage_invalid")
        if (lease.run_id, lease.guest_id, lease.snapshot_id, lease.nonce) != (rollback.run_id, rollback.guest_id, rollback.snapshot_id, rollback.nonce):
            raise ContractError("dynamic_lab_handoff_rollback_linkage_invalid")
        signed_ids = (lease.signed_evidence_id, vm.signed_evidence_id, trace.signed_evidence_id, rollback.signed_evidence_id)
        if len(set(signed_ids)) != len(signed_ids):
            raise ContractError("dynamic_lab_handoff_signed_evidence_duplicate")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DynamicLabHandoff":
        fields = {"schema", "run_lease", "vm_qualification", "dynamic_trace", "rollback_attestation"}
        data = _exact(value, fields, "dynamic_lab_handoff_schema_invalid")
        return cls(
            schema=data["schema"], run_lease=RunLease.from_dict(data["run_lease"]),
            vm_qualification=VMQualification.from_dict(data["vm_qualification"]),
            dynamic_trace=DynamicTrace.from_dict(data["dynamic_trace"]),
            rollback_attestation=RollbackAttestation.from_dict(data["rollback_attestation"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"schema": self.schema, "run_lease": self.run_lease.to_dict(), "vm_qualification": self.vm_qualification.to_dict(), "dynamic_trace": self.dynamic_trace.to_dict(), "rollback_attestation": self.rollback_attestation.to_dict()}


DynamicLabHandoffManifest = DynamicLabHandoff

__all__ = ["RunLease", "VMQualification", "DynamicTrace", "RollbackAttestation", "DynamicLabHandoff", "DynamicLabHandoffManifest"]
