"""Política de preflight para laboratório dinâmico; não inicia alvos."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
import re
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class LabPolicy:
    authorized: bool = False
    isolation: str = "none"
    network_enabled: bool = False
    writable_project_mount: bool = False
    host_execution: bool = False
    snapshot_id: str | None = None
    rollback_enabled: bool = False
    collector_configured: bool = False
    timeout_s: int = 0
    memory_limit_mb: int = 0


_RUNTIME_REQUIRED = (
    "schema",
    "run_id",
    "snapshot_id",
    "snapshot_sha256",
    "target_sha256",
    "rollback_verified",
    "network_isolated",
    "collector_heartbeat",
    "started_at",
    "ended_at",
    "timeout_s",
    "memory_limit_mb",
    "target_identity",
    "events",
)


def validate_runtime_proof(
    proof: dict[str, Any], *, policy: LabPolicy | None = None, max_events: int = 100_000
) -> dict[str, Any]:
    """Validate a materialized guest-run proof without executing anything.

    This is intentionally a contract gate, not a sandbox attestation.  The
    collector/VM must produce the document; this function only checks shape,
    hashes, sequencing, and consistency with an optional declared policy.
    """
    schema = "dynamic-lab-runtime-proof.v1"
    limitations = [
        "validação não prova isolamento efetivo nem autenticidade da VM",
        "hashes e flags dependem da custódia/atestado do coletor",
        "nenhum alvo é executado durante a validação",
    ]
    if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1 <= max_events <= 1_000_000:
        return {"schema": schema, "status": "invalid", "summary": {}, "errors": [{"code": "max_events_invalid"}], "limitations": limitations}
    if not isinstance(proof, dict):
        return {"schema": schema, "status": "invalid", "summary": {}, "errors": [{"code": "proof_must_be_object"}], "limitations": limitations}
    errors: list[dict[str, Any]] = []
    if "schema" in proof and proof.get("schema") != schema:
        errors.append({"code": "schema_invalid", "expected": schema})
    missing = [field for field in _RUNTIME_REQUIRED if field not in proof]
    errors.extend({"code": "required_field_missing", "field": field} for field in missing)
    if missing:
        return {"schema": schema, "status": "invalid", "summary": {"events": 0}, "errors": errors, "limitations": limitations}

    for field in ("run_id", "snapshot_id", "started_at", "ended_at"):
        if not isinstance(proof[field], str) or not proof[field].strip():
            errors.append({"code": "string_field_invalid", "field": field})
    timestamps: dict[str, datetime] = {}
    for field in ("started_at", "ended_at"):
        value = proof[field]
        if isinstance(value, str) and value.strip():
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                errors.append({"code": "timestamp_invalid", "field": field})
            else:
                if parsed.tzinfo is None:
                    errors.append({"code": "timestamp_timezone_required", "field": field})
                else:
                    timestamps[field] = parsed
    if "started_at" in timestamps and "ended_at" in timestamps and timestamps["ended_at"] < timestamps["started_at"]:
        errors.append({"code": "timestamp_order_invalid"})
    for field in ("snapshot_sha256", "target_sha256"):
        if not isinstance(proof[field], str) or not _SHA256_RE.fullmatch(proof[field]):
            errors.append({"code": "sha256_invalid", "field": field})
    for field in ("rollback_verified", "network_isolated", "collector_heartbeat"):
        if not isinstance(proof[field], bool):
            errors.append({"code": "boolean_field_invalid", "field": field})
    for field in ("timeout_s", "memory_limit_mb"):
        if isinstance(proof[field], bool) or not isinstance(proof[field], int) or proof[field] < 1:
            errors.append({"code": "positive_budget_invalid", "field": field})
    identity = proof["target_identity"]
    if not isinstance(identity, dict) or not identity or not any(isinstance(identity.get(key), str) and identity[key].strip() for key in ("name", "id", "path")):
        errors.append({"code": "target_identity_invalid"})

    events = proof["events"]
    if not isinstance(events, list) or not events:
        errors.append({"code": "events_must_be_nonempty_list"})
        event_count = 0
    else:
        event_count = len(events)
        if event_count > max_events:
            errors.append({"code": "event_budget_exceeded", "received": event_count, "max_events": max_events})
        seen_sequences: set[int] = set()
        first_sequence_mismatch: dict[str, int] | None = None
        for index, event in enumerate(events[:max_events]):
            if not isinstance(event, dict):
                errors.append({"index": index, "code": "event_not_object"})
                continue
            sequence = event.get("seq")
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
                errors.append({"index": index, "code": "event_sequence_invalid"})
            elif sequence in seen_sequences:
                errors.append({"index": index, "code": "event_sequence_duplicate", "seq": sequence})
            else:
                seen_sequences.add(sequence)
                if sequence != index and first_sequence_mismatch is None:
                    first_sequence_mismatch = {"index": index, "expected": index, "observed": sequence}
            if not isinstance(event.get("kind"), str) or not event["kind"].strip():
                errors.append({"index": index, "code": "event_kind_invalid"})
        if first_sequence_mismatch is not None:
            errors.append({"code": "event_sequence_not_contiguous", **first_sequence_mismatch})

    gate_errors: list[dict[str, Any]] = []
    for field, code in (("rollback_verified", "rollback_not_verified"), ("network_isolated", "network_not_isolated"), ("collector_heartbeat", "collector_heartbeat_missing")):
        if proof[field] is not True:
            gate_errors.append({"code": code})
    if policy is not None:
        if not isinstance(policy, LabPolicy):
            gate_errors.append({"code": "policy_type_invalid"})
        else:
            if policy.authorized is not True:
                gate_errors.append({"code": "policy_authorization_required"})
            if policy.isolation != "vm":
                gate_errors.append({"code": "policy_requires_vm"})
            if policy.network_enabled is True:
                gate_errors.append({"code": "policy_network_must_be_blocked"})
            if policy.writable_project_mount is True:
                gate_errors.append({"code": "policy_writable_mount_forbidden"})
            if policy.host_execution is True:
                gate_errors.append({"code": "policy_host_execution_forbidden"})
            if isinstance(policy.snapshot_id, str) and policy.snapshot_id and proof["snapshot_id"] != policy.snapshot_id:
                gate_errors.append({"code": "snapshot_id_mismatch"})
            if isinstance(policy.timeout_s, int) and not isinstance(policy.timeout_s, bool) and policy.timeout_s > 0 and proof["timeout_s"] > policy.timeout_s:
                gate_errors.append({"code": "timeout_exceeds_policy"})
            if isinstance(policy.memory_limit_mb, int) and not isinstance(policy.memory_limit_mb, bool) and policy.memory_limit_mb > 0 and proof["memory_limit_mb"] > policy.memory_limit_mb:
                gate_errors.append({"code": "memory_exceeds_policy"})
    errors.extend(gate_errors)
    shape_codes = {"schema_invalid", "required_field_missing", "string_field_invalid", "timestamp_invalid", "timestamp_timezone_required", "timestamp_order_invalid", "sha256_invalid", "boolean_field_invalid", "positive_budget_invalid", "target_identity_invalid", "events_must_be_nonempty_list", "event_budget_exceeded", "event_not_object", "event_sequence_invalid", "event_sequence_duplicate", "event_sequence_not_contiguous", "event_kind_invalid"}
    status = "invalid" if any(item.get("code") in shape_codes for item in errors) else "refused" if errors else "verified"
    return {
        "schema": schema,
        "status": status,
        "summary": {"run_id": proof.get("run_id"), "events": event_count, "events_checked": min(event_count, max_events), "snapshot_id": proof.get("snapshot_id"), "timeout_s": proof.get("timeout_s"), "memory_limit_mb": proof.get("memory_limit_mb"), "contract_only": True, "isolation_attested": False},
        "errors": errors,
        "limitations": limitations,
    }


def preflight_dynamic_lab(policy: LabPolicy, *, require_runtime_proof: bool = False) -> dict[str, Any]:
    limitations = ["preflight não prova isolamento efetivo", "snapshot/rollback/collector declarados precisam de verificação operacional", "nenhum alvo foi executado"]
    if not isinstance(policy, LabPolicy):
        return {
            "schema": "dynamic-lab-policy.v1",
            "policy": None,
            "runtime_proof_required": require_runtime_proof if isinstance(require_runtime_proof, bool) else False,
            "status": "refused",
            "errors": ["policy_type_invalid"],
            "limitations": limitations,
        }
    errors: list[str] = []
    bool_fields = ("authorized", "network_enabled", "writable_project_mount", "host_execution", "rollback_enabled", "collector_configured")
    for field in bool_fields:
        if not isinstance(getattr(policy, field), bool):
            errors.append(f"{field}_invalid")
    if not isinstance(policy.isolation, str):
        errors.append("isolation_invalid")
    if policy.snapshot_id is not None and not isinstance(policy.snapshot_id, str):
        errors.append("snapshot_id_invalid")
    for field in ("timeout_s", "memory_limit_mb"):
        value = getattr(policy, field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{field}_invalid")
    if isinstance(policy.authorized, bool) and not policy.authorized:
        errors.append("authorization_required")
    if isinstance(policy.isolation, str) and policy.isolation not in {"vm", "container", "host", "none"}:
        errors.append("isolation_invalid")
    if isinstance(policy.isolation, str) and policy.isolation != "vm":
        errors.append("disposable_vm_required")
    if isinstance(policy.network_enabled, bool) and policy.network_enabled:
        errors.append("network_must_be_blocked_by_default")
    if isinstance(policy.writable_project_mount, bool) and policy.writable_project_mount:
        errors.append("writable_project_mount_forbidden")
    if isinstance(policy.host_execution, bool) and policy.host_execution:
        errors.append("host_execution_forbidden")
    if not isinstance(require_runtime_proof, bool):
        errors.append("runtime_proof_flag_invalid")
    if require_runtime_proof is True:
        if not isinstance(policy.snapshot_id, str) or not policy.snapshot_id.strip():
            errors.append("disposable_snapshot_required")
        if isinstance(policy.rollback_enabled, bool) and policy.rollback_enabled is not True:
            errors.append("rollback_required")
        if isinstance(policy.collector_configured, bool) and policy.collector_configured is not True:
            errors.append("collector_configuration_required")
        if isinstance(policy.timeout_s, int) and not isinstance(policy.timeout_s, bool) and policy.timeout_s < 1:
            errors.append("timeout_budget_required")
        if isinstance(policy.memory_limit_mb, int) and not isinstance(policy.memory_limit_mb, bool) and policy.memory_limit_mb < 1:
            errors.append("memory_budget_required")
    return {
        "schema": "dynamic-lab-policy.v1",
        "policy": asdict(policy),
        "runtime_proof_required": require_runtime_proof,
        "status": "ready" if not errors else "refused",
        "errors": errors,
        "limitations": limitations,
    }
