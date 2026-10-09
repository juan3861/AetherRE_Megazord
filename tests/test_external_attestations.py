from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aether_re.external_attestations import (
    verify_vm_attestation,
    verify_worm_attestation,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _setup(tmp_path: Path) -> tuple[Path, Path, Path, Ed25519PrivateKey, datetime]:
    repository = tmp_path / "repository"
    evidence = tmp_path / "evidence"
    external = tmp_path / "external-trust"
    repository.mkdir()
    evidence.mkdir()
    external.mkdir()
    now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    _json(
        external / "trust-map.json",
        {
            "schema": "external-trust-map.v1",
            "keys": [
                {
                    "key_id": "independent-auditor-01",
                    "algorithm": "Ed25519",
                    "public_key_b64": base64.b64encode(public).decode("ascii"),
                    "identity": "independent-auditor",
                    "independent": True,
                    "roles": ["vm-attestation", "worm-attestation"],
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2027-01-01T00:00:00Z",
                }
            ],
        },
    )
    _json(evidence / "release-manifest.json", {"schema": "release-manifest.v1", "commit": "abc123"})
    return repository, evidence, external / "trust-map.json", private, now


def _signed(
    evidence: Path,
    private: Ed25519PrivateKey,
    *,
    schema: str,
    payload: dict,
    now: datetime,
    name: str,
) -> tuple[Path, Path]:
    doc = {
        "schema": schema,
        "key_id": "independent-auditor-01",
        "issuer_identity": "independent-auditor",
        "producer_identity": "megazord-release-team",
        "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
        "payload": payload,
    }
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    attestation = evidence / f"{name}.json"
    signature = evidence / f"{name}.sig"
    _json(attestation, doc)
    signature.write_bytes(private.sign(canonical))
    return attestation, signature


def _artifact(evidence: Path, name: str, data: bytes) -> dict[str, str]:
    path = evidence / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": name, "sha256": _sha(path)}


def _vm_payload(evidence: Path) -> dict:
    manifest_sha = _sha(evidence / "release-manifest.json")
    trace = _artifact(evidence, "traces/trace.jsonl", b'{"event":"process_start"}\n')
    rollback = _artifact(evidence, "rollback/restore.json", b'{"restored":true}\n')
    checkpoint_sha = hashlib.sha256(b"clean checkpoint bytes").hexdigest()
    nonce = "n-" + "a" * 32
    return {
        "release_manifest_sha256": manifest_sha,
        "producer_identity": "megazord-release-team",
        "lease": {"id": "lease-001", "vm_id": "hyperv-vm-001", "nonce": nonce},
        "checkpoint": {"id": "checkpoint-clean-001", "sha256": checkpoint_sha},
        "hypervisor_provider": "Microsoft Hyper-V",
        "network_isolation": {"isolated": True, "policy_sha256": hashlib.sha256(b"isolated switch").hexdigest()},
        "disposable_disk": {"disposable": True, "disk_id": "diff-disk-001", "image_sha256": hashlib.sha256(b"guest image").hexdigest()},
        "trace_artifacts": [trace],
        "rollback": {
            "verified": True,
            "lease_id": "lease-001",
            "nonce": nonce,
            "checkpoint_id": "checkpoint-clean-001",
            "restored_checkpoint_sha256": checkpoint_sha,
            "artifact": rollback,
        },
    }


def _worm_payload(evidence: Path) -> dict:
    bundle = _artifact(evidence, "release-bundle.tar", b"sealed release bundle")
    manifest_sha = _sha(evidence / "release-manifest.json")
    digest = bundle["sha256"]
    return {
        "release_manifest_sha256": manifest_sha,
        "producer_identity": "megazord-release-team",
        "bundle_artifact": bundle,
        "object_uri": "s3://forensic-evidence/releases/megazord-abc123.tar",
        "retention": {"mode": "COMPLIANCE", "period_days": 365, "retain_until": "2027-09-30T12:00:00Z"},
        "write_once_lock": True,
        "put": {"sha256": digest, "version_id": "version-001"},
        "readback": {"sha256": digest, "version_id": "version-001"},
        "independent_credentials_identity": "external-audit-account:123456789012",
    }


def test_valid_signed_vm_attestation_verifies_material_but_never_promotes_gate(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    payload = _vm_payload(evidence)
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=payload, now=now, name="vm-attestation")

    result = verify_vm_attestation(
        attestation, signature, trust,
        repository_root=repository,
        evidence_root=evidence,
        release_manifest_path=evidence / "release-manifest.json",
        now=now,
    )

    assert result.verified is True
    assert result.issuer_identity == "independent-auditor"
    assert result.gate_status == "NOT_PROMOTED"
    assert result.verification_scope == "signature_and_material_binding_only"


def test_valid_signed_worm_attestation_verifies_storage_claim_binding_but_never_promotes_gate(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    attestation, signature = _signed(evidence, private, schema="external-worm-attestation.v1", payload=_worm_payload(evidence), now=now, name="worm-attestation")

    result = verify_worm_attestation(
        attestation, signature, trust,
        repository_root=repository,
        evidence_root=evidence,
        release_manifest_path=evidence / "release-manifest.json",
        now=now,
    )

    assert result.verified is True
    assert result.gate_status == "NOT_PROMOTED"


def test_vm_rejects_detached_signature_tampering(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=_vm_payload(evidence), now=now, name="vm-attestation")
    signature.write_bytes(bytes([signature.read_bytes()[0] ^ 1]) + signature.read_bytes()[1:])

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "signature_invalid" in result.errors


def test_vm_rejects_changed_trace_hash_even_with_valid_signed_claim(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    payload = _vm_payload(evidence)
    (evidence / payload["trace_artifacts"][0]["path"]).write_bytes(b"tampered")
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=payload, now=now, name="vm-attestation")

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "artifact_hash_mismatch" in result.errors


def test_worm_rejects_mismatched_readback_and_non_compliance_retention(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    payload = _worm_payload(evidence)
    payload["readback"]["sha256"] = "0" * 64
    payload["retention"]["mode"] = "GOVERNANCE"
    attestation, signature = _signed(evidence, private, schema="external-worm-attestation.v1", payload=payload, now=now, name="worm-attestation")

    result = verify_worm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert {"worm_put_readback_mismatch", "worm_retention_mode_invalid"} <= set(result.errors)


def test_worm_rejects_uri_without_an_object_key(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    payload = _worm_payload(evidence)
    payload["object_uri"] = "s3://bucket-only"
    attestation, signature = _signed(evidence, private, schema="external-worm-attestation.v1", payload=payload, now=now, name="worm-attestation")

    result = verify_worm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "worm_object_uri_invalid" in result.errors


@pytest.mark.parametrize("bad_ref", ["../outside.bin", "C:/outside.bin", "/outside.bin", "traces/../outside.bin"])
def test_vm_rejects_unsafe_artifact_paths(tmp_path: Path, bad_ref: str) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    payload = _vm_payload(evidence)
    payload["trace_artifacts"][0]["path"] = bad_ref
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=payload, now=now, name="vm-attestation")

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "artifact_path_unsafe" in result.errors


@pytest.mark.parametrize("location", ["repository", "evidence"])
def test_trust_map_inside_repository_or_evidence_is_rejected(tmp_path: Path, location: str) -> None:
    repository, evidence, _trust, private, now = _setup(tmp_path)
    trust_inside = (repository if location == "repository" else evidence) / "trust-map.json"
    _json(trust_inside, {})
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=_vm_payload(evidence), now=now, name="vm-attestation")

    result = verify_vm_attestation(attestation, signature, trust_inside, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "trust_map_not_external" in result.errors


def test_vm_rejects_symlinked_trace_artifact(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    payload = _vm_payload(evidence)
    trace = evidence / payload["trace_artifacts"][0]["path"]
    outside = tmp_path / "outside-trace.jsonl"
    outside.write_bytes(trace.read_bytes())
    trace.unlink()
    try:
        trace.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink privilege unavailable: {exc}")
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=payload, now=now, name="vm-attestation")

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "artifact_path_unsafe" in result.errors


def test_vm_rejects_timezone_naive_signed_timestamps(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=_vm_payload(evidence), now=now, name="vm-attestation")
    doc = json.loads(attestation.read_text(encoding="utf-8"))
    doc["issued_at"] = "2026-09-30T11:59:00"
    _json(attestation, doc)
    signature.write_bytes(private.sign(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()))

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "attestation_timestamp_invalid" in result.errors


def test_vm_rejects_input_path_with_parent_traversal_even_when_it_resolves_inside_evidence(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=_vm_payload(evidence), now=now, name="vm-attestation")
    traversal_path = str(evidence / "nested" / ".." / attestation.name)

    result = verify_vm_attestation(traversal_path, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "attestation_path_unsafe" in result.errors


def test_vm_rejects_naive_verification_clock(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=_vm_payload(evidence), now=now, name="vm-attestation")

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=datetime(2026, 9, 30, 12, 0))

    assert result.verified is False
    assert "verification_time_invalid" in result.errors


def test_vm_rejects_unencodable_unicode_without_raising(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=_vm_payload(evidence), now=now, name="vm-attestation")
    doc = json.loads(attestation.read_text(encoding="utf-8"))
    doc["producer_identity"] = "bad-\ud800"
    _json(attestation, doc)

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "attestation_canonicalization_invalid" in result.errors


def test_vm_rejects_expired_attestation_and_self_identity(tmp_path: Path) -> None:
    repository, evidence, trust, private, now = _setup(tmp_path)
    attestation, signature = _signed(evidence, private, schema="external-vm-attestation.v1", payload=_vm_payload(evidence), now=now - timedelta(days=2), name="vm-attestation")
    expired = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)
    assert expired.verified is False
    assert "attestation_expired" in expired.errors

    payload = _vm_payload(evidence)
    doc = json.loads(attestation.read_text(encoding="utf-8"))
    doc["producer_identity"] = "independent-auditor"
    _json(attestation, doc)
    signature.write_bytes(private.sign(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()))
    self_signed = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)
    assert self_signed.verified is False
    assert "issuer_not_independent" in self_signed.errors


def test_status_text_only_is_not_a_signed_attestation(tmp_path: Path) -> None:
    repository, evidence, trust, _private, now = _setup(tmp_path)
    attestation = evidence / "status.json"
    signature = evidence / "status.sig"
    _json(attestation, {"status": "pass", "gate": "F08"})
    signature.write_bytes(b"pass")

    result = verify_vm_attestation(attestation, signature, trust, repository_root=repository, evidence_root=evidence, release_manifest_path=evidence / "release-manifest.json", now=now)

    assert result.verified is False
    assert "attestation_schema_invalid" in result.errors
