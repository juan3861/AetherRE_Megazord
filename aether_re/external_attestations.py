"""Fail-closed verification of externally signed VM and WORM assertions.

This module verifies signatures, schema, freshness, path safety, and local
material bindings. It does not prove that a signer told the truth, query a VM
or object store, or promote release gates. Gate promotion remains a separate
review decision.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VM_SCHEMA = "external-vm-attestation.v1"
_WORM_SCHEMA = "external-worm-attestation.v1"
_TRUST_SCHEMA = "external-trust-map.v1"
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_ATTESTATION_LIFETIME = timedelta(days=30)
_FUTURE_SKEW = timedelta(minutes=5)


@dataclass(frozen=True)
class AttestationVerification:
    """Verification outcome; ``verified`` never means a gate is promoted."""

    schema: str
    verified: bool
    gate_status: str
    verification_scope: str
    issuer_identity: str | None
    attestation_sha256: str | None
    trust_map_sha256: str | None
    errors: tuple[str, ...]


def verify_vm_attestation(
    attestation_path: Path,
    signature_path: Path,
    trust_map_path: Path,
    *,
    repository_root: Path,
    evidence_root: Path,
    release_manifest_path: Path,
    now: datetime | None = None,
) -> AttestationVerification:
    """Verify a detached Ed25519 VM/rollback attestation and its local files.

    The signed payload must bind the release manifest, run lease/nonce, clean
    checkpoint, isolation policy, disposable disk, trace files, and rollback
    evidence. Trust-map roots must be explicitly supplied by the caller from
    outside both the repository and evidence bundle.
    """
    return _verify(
        attestation_path, signature_path, trust_map_path,
        repository_root=repository_root,
        evidence_root=evidence_root,
        release_manifest_path=release_manifest_path,
        now=now,
        expected_schema=_VM_SCHEMA,
        role="vm-attestation",
        validator=_validate_vm_payload,
    )


def verify_worm_attestation(
    attestation_path: Path,
    signature_path: Path,
    trust_map_path: Path,
    *,
    repository_root: Path,
    evidence_root: Path,
    release_manifest_path: Path,
    now: datetime | None = None,
) -> AttestationVerification:
    """Verify a detached Ed25519 WORM claim and bind it to local bundle bytes.

    Object existence, retention settings, and credential identity are signed
    claims; this verifier does not make remote provider API calls to re-query
    them. Consequently a valid result is not a release-gate approval.
    """
    return _verify(
        attestation_path, signature_path, trust_map_path,
        repository_root=repository_root,
        evidence_root=evidence_root,
        release_manifest_path=release_manifest_path,
        now=now,
        expected_schema=_WORM_SCHEMA,
        role="worm-attestation",
        validator=_validate_worm_payload,
    )


def _verify(
    attestation_path: Path,
    signature_path: Path,
    trust_map_path: Path,
    *,
    repository_root: Path,
    evidence_root: Path,
    release_manifest_path: Path,
    now: datetime | None,
    expected_schema: str,
    role: str,
    validator: Any,
) -> AttestationVerification:
    errors: list[str] = []
    observed_now = now or datetime.now(timezone.utc)
    if observed_now.tzinfo is None or observed_now.utcoffset() is None:
        if now is not None:
            errors.append("verification_time_invalid")
        observed_now = observed_now.replace(tzinfo=timezone.utc)
    observed_now = observed_now.astimezone(timezone.utc)
    repository = _resolve_root(repository_root, "repository_root_invalid", errors)
    evidence = _resolve_root(evidence_root, "evidence_root_invalid", errors)

    attestation = _admit_file(attestation_path, evidence, "attestation_path_unsafe", errors)
    signature = _admit_file(signature_path, evidence, "signature_path_unsafe", errors)
    manifest = _admit_file(release_manifest_path, evidence, "release_manifest_path_unsafe", errors)
    trust = _admit_file(trust_map_path, None, "trust_map_path_unsafe", errors)
    if trust is not None:
        if repository is None or evidence is None or _inside(trust, repository) or _inside(trust, evidence):
            errors.append("trust_map_not_external")
            trust = None
        else:
            try:
                if trust.stat().st_nlink != 1:
                    errors.append("trust_map_path_unsafe")
                    trust = None
            except OSError:
                errors.append("trust_map_path_unsafe")
                trust = None

    doc: dict[str, Any] | None = None
    trust_doc: dict[str, Any] | None = None
    attestation_bytes: bytes | None = None
    signature_bytes: bytes | None = None
    trust_bytes: bytes | None = None
    try:
        if attestation is not None:
            attestation_bytes, doc = _read_json(attestation, "attestation_json_invalid")
    except _DocumentError as exc:
        errors.append(exc.code)
    try:
        if trust is not None:
            trust_bytes, trust_doc = _read_json(trust, "trust_map_json_invalid")
    except _DocumentError as exc:
        errors.append(exc.code)
    try:
        if signature is not None:
            signature_bytes = _read_bytes(signature, max_bytes=4096)
    except _DocumentError as exc:
        errors.append(exc.code)

    issuer: str | None = None
    signer_key = None
    if doc is not None:
        required = {"schema", "key_id", "issuer_identity", "producer_identity", "issued_at", "expires_at", "payload"}
        if set(doc) != required or doc.get("schema") != expected_schema:
            errors.append("attestation_schema_invalid")
        else:
            issuer = _text(doc.get("issuer_identity"))
            key_id = _text(doc.get("key_id"))
            producer = _text(doc.get("producer_identity"))
            payload = doc.get("payload")
            if issuer is None or key_id is None or producer is None or not isinstance(payload, dict):
                errors.append("attestation_fields_invalid")
            else:
                if issuer.casefold() == producer.casefold():
                    errors.append("issuer_not_independent")
                _validate_times(doc, observed_now, errors)
                signer_key = _find_trusted_key(trust_doc, key_id, issuer, role, doc, observed_now, errors)
                validator(payload, doc, evidence, manifest, errors)
                if manifest is not None:
                    try:
                        manifest_sha = _hash_file(manifest)
                        if payload.get("release_manifest_sha256") != manifest_sha:
                            errors.append("release_manifest_hash_mismatch")
                    except OSError:
                        errors.append("release_manifest_unreadable")
                if signer_key is not None and signature_bytes is not None:
                    signed_doc = {k: v for k, v in doc.items()}
                    try:
                        canonical = _canonical_json(signed_doc)
                        Ed25519PublicKey.from_public_bytes(signer_key).verify(signature_bytes, canonical)
                    except (InvalidSignature, ValueError, UnicodeError):
                        errors.append("signature_invalid")
                        if _contains_unencodable_unicode(signed_doc):
                            errors.append("attestation_canonicalization_invalid")
                    if len(signature_bytes) != 64:
                        errors.append("signature_format_invalid")

    unique_errors = tuple(dict.fromkeys(errors))
    return AttestationVerification(
        schema=expected_schema,
        verified=not unique_errors,
        gate_status="NOT_PROMOTED",
        verification_scope="signature_and_material_binding_only",
        issuer_identity=issuer,
        attestation_sha256=hashlib.sha256(attestation_bytes).hexdigest() if attestation_bytes is not None else None,
        trust_map_sha256=hashlib.sha256(trust_bytes).hexdigest() if trust_bytes is not None else None,
        errors=unique_errors,
    )


def _validate_vm_payload(payload: dict[str, Any], doc: dict[str, Any], evidence: Path | None, manifest: Path | None, errors: list[str]) -> None:
    required = {"release_manifest_sha256", "producer_identity", "lease", "checkpoint", "hypervisor_provider", "network_isolation", "disposable_disk", "trace_artifacts", "rollback"}
    if set(payload) != required:
        errors.append("vm_payload_schema_invalid")
        return
    _bind_producer(payload, doc, errors)
    if not _valid_sha(payload.get("release_manifest_sha256")):
        errors.append("release_manifest_hash_invalid")
    lease = payload.get("lease")
    checkpoint = payload.get("checkpoint")
    network = payload.get("network_isolation")
    disk = payload.get("disposable_disk")
    rollback = payload.get("rollback")
    if not _exact(lease, {"id", "vm_id", "nonce"}):
        errors.append("vm_lease_invalid")
        lease = {}
    if not _exact(checkpoint, {"id", "sha256"}):
        errors.append("vm_checkpoint_invalid")
        checkpoint = {}
    if not _exact(network, {"isolated", "policy_sha256"}) or network.get("isolated") is not True or not _valid_sha(network.get("policy_sha256")):
        errors.append("vm_network_isolation_invalid")
        network = {}
    if not _exact(disk, {"disposable", "disk_id", "image_sha256"}) or disk.get("disposable") is not True or not _valid_sha(disk.get("image_sha256")):
        errors.append("vm_disposable_disk_invalid")
        disk = {}
    for name, item in (("lease_id", lease.get("id")), ("vm_id", lease.get("vm_id")), ("nonce", lease.get("nonce")), ("checkpoint_id", checkpoint.get("id"))):
        if _text(item) is None:
            errors.append(f"vm_{name}_invalid")
    nonce = lease.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < 32:
        errors.append("vm_nonce_too_short")
    if not _valid_sha(checkpoint.get("sha256")):
        errors.append("vm_checkpoint_hash_invalid")
    provider = _text(payload.get("hypervisor_provider"))
    if provider is None or any(token in provider.casefold() for token in ("wsl", "container", "docker", "podman", "host", "direct")):
        errors.append("vm_provider_not_qualified")
    if not _exact(rollback, {"verified", "lease_id", "nonce", "checkpoint_id", "restored_checkpoint_sha256", "artifact"}):
        errors.append("vm_rollback_invalid")
        rollback = {}
    if rollback.get("verified") is not True:
        errors.append("vm_rollback_not_verified")
    if (rollback.get("lease_id"), rollback.get("nonce"), rollback.get("checkpoint_id")) != (lease.get("id"), lease.get("nonce"), checkpoint.get("id")):
        errors.append("vm_rollback_binding_mismatch")
    if rollback.get("restored_checkpoint_sha256") != checkpoint.get("sha256"):
        errors.append("vm_rollback_checkpoint_mismatch")
    trace_artifacts = payload.get("trace_artifacts")
    if not isinstance(trace_artifacts, list) or not trace_artifacts:
        errors.append("vm_trace_artifacts_required")
    else:
        for artifact in trace_artifacts:
            _verify_artifact(artifact, evidence, errors)
    _verify_artifact(rollback.get("artifact"), evidence, errors)


def _validate_worm_payload(payload: dict[str, Any], doc: dict[str, Any], evidence: Path | None, manifest: Path | None, errors: list[str]) -> None:
    required = {"release_manifest_sha256", "producer_identity", "bundle_artifact", "object_uri", "retention", "write_once_lock", "put", "readback", "independent_credentials_identity"}
    if set(payload) != required:
        errors.append("worm_payload_schema_invalid")
        return
    _bind_producer(payload, doc, errors)
    if not _valid_sha(payload.get("release_manifest_sha256")):
        errors.append("release_manifest_hash_invalid")
    _verify_artifact(payload.get("bundle_artifact"), evidence, errors)
    object_uri = _text(payload.get("object_uri"))
    parsed = urlparse(object_uri or "")
    if parsed.scheme not in {"s3", "https"} or not parsed.netloc or not parsed.path.strip("/") or parsed.username or parsed.password or parsed.fragment or ".." in parsed.path.split("/"):
        errors.append("worm_object_uri_invalid")
    retention = payload.get("retention")
    if not _exact(retention, {"mode", "period_days", "retain_until"}):
        errors.append("worm_retention_invalid")
        retention = {}
    if retention.get("mode") != "COMPLIANCE":
        errors.append("worm_retention_mode_invalid")
    period = retention.get("period_days")
    if isinstance(period, bool) or not isinstance(period, int) or period < 1 or period > 36500:
        errors.append("worm_retention_period_invalid")
        period = 0
    retain_until = _parse_time(retention.get("retain_until"))
    issued_at = _parse_time(doc.get("issued_at"))
    if retain_until is None or issued_at is None or period and retain_until < issued_at + timedelta(days=period):
        errors.append("worm_retention_expiry_invalid")
    if payload.get("write_once_lock") is not True:
        errors.append("worm_write_once_lock_missing")
    put = payload.get("put")
    readback = payload.get("readback")
    if not _exact(put, {"sha256", "version_id"}) or not _exact(readback, {"sha256", "version_id"}):
        errors.append("worm_put_readback_invalid")
        put, readback = {}, {}
    if (put.get("sha256"), put.get("version_id")) != (readback.get("sha256"), readback.get("version_id")):
        errors.append("worm_put_readback_mismatch")
    bundle = payload.get("bundle_artifact")
    if isinstance(bundle, dict) and (put.get("sha256") != bundle.get("sha256") or readback.get("sha256") != bundle.get("sha256")):
        errors.append("worm_bundle_hash_mismatch")
    credentials = _text(payload.get("independent_credentials_identity"))
    producer = _text(payload.get("producer_identity"))
    if credentials is None or producer is None or credentials.casefold() == producer.casefold():
        errors.append("worm_credentials_not_independent")


def _bind_producer(payload: Mapping[str, Any], doc: Mapping[str, Any], errors: list[str]) -> None:
    if _text(payload.get("producer_identity")) is None or payload.get("producer_identity", "").casefold() != doc.get("producer_identity", "").casefold():
        errors.append("producer_identity_binding_mismatch")


def _verify_artifact(value: Any, evidence: Path | None, errors: list[str]) -> None:
    if not _exact(value, {"path", "sha256"}):
        errors.append("artifact_ref_invalid")
        return
    rel = value.get("path")
    expected = value.get("sha256")
    if not _safe_relative_path(rel):
        errors.append("artifact_path_unsafe")
        return
    if not _valid_sha(expected):
        errors.append("artifact_hash_invalid")
        return
    if evidence is None:
        errors.append("evidence_root_invalid")
        return
    try:
        path = _admit_file(evidence.joinpath(*PurePosixPath(rel).parts), evidence, "artifact_path_unsafe", errors)
        if path is None:
            return
        if _hash_file(path) != expected:
            errors.append("artifact_hash_mismatch")
    except OSError:
        errors.append("artifact_missing")


def _find_trusted_key(trust_doc: dict[str, Any] | None, key_id: str, issuer: str, role: str, doc: Mapping[str, Any], now: datetime, errors: list[str]) -> bytes | None:
    if trust_doc is None or set(trust_doc) != {"schema", "keys"} or trust_doc.get("schema") != _TRUST_SCHEMA or not isinstance(trust_doc.get("keys"), list):
        errors.append("trust_map_schema_invalid")
        return None
    matching = [item for item in trust_doc["keys"] if isinstance(item, dict) and item.get("key_id") == key_id]
    if len(matching) != 1:
        errors.append("trust_key_missing_or_duplicate")
        return None
    key = matching[0]
    required = {"key_id", "algorithm", "public_key_b64", "identity", "independent", "roles", "not_before", "not_after"}
    if set(key) != required or key.get("algorithm") != "Ed25519":
        errors.append("trust_key_schema_invalid")
        return None
    identity = _text(key.get("identity"))
    roles = key.get("roles")
    if identity is None or identity.casefold() != issuer.casefold() or key.get("independent") is not True or not isinstance(roles, list) or role not in roles:
        errors.append("trust_key_not_independent_or_wrong_role")
        return None
    not_before, not_after = _parse_time(key.get("not_before")), _parse_time(key.get("not_after"))
    issued_at = _parse_time(doc.get("issued_at"))
    if not_before is None or not_after is None or issued_at is None or not_before > issued_at or issued_at >= not_after or not_before > now or now >= not_after:
        errors.append("trust_key_outside_validity")
        return None
    try:
        public_key = base64.b64decode(key["public_key_b64"], validate=True)
        if len(public_key) != 32:
            raise ValueError("invalid Ed25519 public key length")
        return public_key
    except (ValueError, TypeError):
        errors.append("trust_key_encoding_invalid")
        return None


def _validate_times(doc: Mapping[str, Any], now: datetime, errors: list[str]) -> None:
    issued = _parse_time(doc.get("issued_at"))
    expires = _parse_time(doc.get("expires_at"))
    if issued is None or expires is None:
        errors.append("attestation_timestamp_invalid")
        return
    if issued > now + _FUTURE_SKEW:
        errors.append("attestation_issued_in_future")
    if expires <= now:
        errors.append("attestation_expired")
    if expires <= issued or expires - issued > _MAX_ATTESTATION_LIFETIME:
        errors.append("attestation_lifetime_invalid")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or value.startswith("/"):
        return False
    if any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in value):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and bool(path.parts) and all(part not in {"", ".", ".."} for part in value.split("/"))


def _exact(value: Any, fields: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == fields


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


class _DocumentError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _read_json(path: Path, invalid_code: str) -> tuple[bytes, dict[str, Any]]:
    raw = _read_bytes(path, max_bytes=_MAX_JSON_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _DocumentError(invalid_code) from exc
    if not isinstance(value, dict):
        raise _DocumentError(invalid_code)
    return raw, value


def _no_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_bytes(path: Path, *, max_bytes: int) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise _DocumentError("file_type_or_size_invalid")
        data = path.read_bytes()
        after = path.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise _DocumentError("file_changed_during_read")
        return data
    except OSError as exc:
        raise _DocumentError("file_unreadable") from exc


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _contains_unencodable_unicode(value: Any) -> bool:
    try:
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        return False
    except (TypeError, ValueError, UnicodeError):
        return True


def _resolve_root(path: Path, error_code: str, errors: list[str]) -> Path | None:
    try:
        if _has_parent_segment(path):
            errors.append(error_code)
            return None
        candidate = Path(path).absolute()
        if _has_reparse_component(candidate):
            errors.append(error_code)
            return None
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir():
            errors.append(error_code)
            return None
        return resolved
    except (OSError, RuntimeError, TypeError):
        errors.append(error_code)
        return None


def _admit_file(path: Path, required_root: Path | None, error_code: str, errors: list[str]) -> Path | None:
    try:
        if _has_parent_segment(path):
            errors.append(error_code)
            return None
        candidate = Path(path).absolute()
        if _has_reparse_component(candidate):
            errors.append(error_code)
            return None
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file() or required_root is not None and not _inside(resolved, required_root):
            errors.append(error_code)
            return None
        return resolved
    except (OSError, RuntimeError, TypeError):
        errors.append(error_code)
        return None


def _has_parent_segment(path: Path) -> bool:
    try:
        raw = os.fspath(path)
    except TypeError:
        return True
    return ".." in raw.replace("\\", "/").split("/")


def _has_reparse_component(path: Path) -> bool:
    """Reject symlink/junction/reparse points in every existing path component."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for component in parts:
        current = current / component
        try:
            info = current.lstat()
        except FileNotFoundError:
            return True
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag:
            return True
    return False


def _inside(path: Path, root: Path | None) -> bool:
    if root is None:
        return False
    try:
        Path(path).relative_to(Path(root))
        return True
    except ValueError:
        return False


def _hash_file(path: Path) -> str:
    if _has_reparse_component(path):
        raise OSError("evidence path contains a reparse point")
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("evidence path is not a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    after = path.stat(follow_symlinks=False)
    if _has_reparse_component(path) or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise OSError("evidence changed while hashing")
    return digest.hexdigest()


__all__ = ["AttestationVerification", "verify_vm_attestation", "verify_worm_attestation"]
