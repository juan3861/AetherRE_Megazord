"""Fail-closed release certification with external Ed25519 reviewer trust."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "release-certification.v1"
MANIFEST_SCHEMA = "release-manifest.v1"
REVIEW_SCHEMA = "independent-review.v1"
TRUST_SCHEMA = "review-trust-map.v1"
REQUIRED_GATES = tuple(f"F{index:02d}" for index in range(13))
_HEX = frozenset("0123456789abcdef")
GATE_EVIDENCE_SCHEMA = "gate-evidence.v1"
_GATE_EVIDENCE_FIELDS = {
    "schema", "gate", "status", "gate_passed", "integrity_errors",
    "blocking_gates", "artifacts",
}


class _DuplicateJsonKey(ValueError):
    """Reject ambiguous JSON objects at the release-evidence boundary."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(key)
        value[key] = item
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    return normalized or None


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(character in _HEX for character in value.lower())


def _is_symlink_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _file_hash(root: Path, relative: Any) -> str | None:
    if not isinstance(relative, str) or not relative:
        return None
    try:
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or relative_path.drive
            or relative_path.root
            or ".." in relative_path.parts
            or _is_symlink_or_junction(root)
        ):
            return None
        raw = root
        for part in relative_path.parts:
            raw = raw / part
            if _is_symlink_or_junction(raw):
                return None
        path = raw.resolve(strict=True)
        path.relative_to(root.resolve())
        if not path.is_file():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def _validate_gate_evidence(document: Any, *, gate: str, release_root: Path) -> list[dict[str, str]]:
    """Validate machine-verifiable gate evidence instead of trusting status text."""
    if (
        not isinstance(document, dict)
        or set(document) != _GATE_EVIDENCE_FIELDS
        or document.get("schema") != GATE_EVIDENCE_SCHEMA
        or document.get("gate") != gate
        or document.get("status") != "QUITADA"
        or document.get("gate_passed") is not True
        or document.get("integrity_errors") != []
        or document.get("blocking_gates") != []
        or not isinstance(document.get("artifacts"), list)
        or not document["artifacts"]
    ):
        return [{"code": "manifest_gate_evidence_contract_invalid"}]
    errors: list[dict[str, str]] = []
    seen: set[str] = set()
    for artifact in document["artifacts"]:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            errors.append({"code": "manifest_gate_artifact_contract_invalid"})
            continue
        path, expected = artifact.get("path"), artifact.get("sha256")
        if not isinstance(path, str) or not path or path in seen or not _hex(expected, 64):
            errors.append({"code": "manifest_gate_artifact_contract_invalid"})
            continue
        seen.add(path)
        if _file_hash(release_root, path) != expected:
            errors.append({"code": "manifest_gate_artifact_hash_mismatch"})
    return errors


def validate_release_manifest(manifest: Any, *, release_root: Path) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "commit", "toolchain_lock_sha256", "corpus_lock_sha256", "gates"} or manifest.get("schema") != MANIFEST_SCHEMA:
        return [{"code": "manifest_schema_invalid"}]
    if not _hex(manifest.get("commit"), 40): errors.append({"code": "manifest_commit_invalid"})
    for field in ("toolchain_lock_sha256", "corpus_lock_sha256"):
        if not _hex(manifest.get(field), 64): errors.append({"code": f"manifest_{field}_invalid"})
    gates = manifest["gates"]
    if not isinstance(gates, list) or len(gates) != len(REQUIRED_GATES): return errors + [{"code": "manifest_gates_invalid"}]
    seen: set[str] = set()
    for item in gates:
        if not isinstance(item, dict) or set(item) != {"gate", "status", "evidence_path", "evidence_sha256"} or item.get("gate") not in REQUIRED_GATES or item["gate"] in seen:
            errors.append({"code": "manifest_gate_identity_invalid"}); continue
        seen.add(item["gate"])
        if item.get("status") != "QUITADA": errors.append({"code": "manifest_gate_not_quitada"})
        if not _hex(item.get("evidence_sha256"), 64): errors.append({"code": "manifest_gate_evidence_invalid"}); continue
        if _file_hash(release_root, item.get("evidence_path")) != item["evidence_sha256"]:
            errors.append({"code": "manifest_gate_evidence_hash_mismatch"})
            continue
        evidence_path = release_root / item["evidence_path"]
        try:
            if evidence_path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("gate_evidence_too_large")
            evidence_document = json.loads(
                evidence_path.read_text(encoding="utf-8"),
                object_pairs_hook=_strict_object,
            )
        except (OSError, UnicodeError, ValueError, TypeError):
            errors.append({"code": "manifest_gate_evidence_contract_invalid"})
            continue
        errors.extend(_validate_gate_evidence(evidence_document, gate=item["gate"], release_root=release_root))
    if seen != set(REQUIRED_GATES): errors.append({"code": "manifest_gate_set_invalid"})
    return errors


def sign_review(manifest: Mapping[str, Any], *, reviewer: str, producer: str, private_key: Ed25519PrivateKey) -> dict[str, str]:
    reviewer_id, producer_id = _identity(reviewer), _identity(producer)
    if reviewer_id is None or producer_id is None or not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("review_identity_or_key_invalid")
    manifest_hash = _hash(manifest)
    message = f"{REVIEW_SCHEMA}|{reviewer_id}|{producer_id}|{manifest_hash}".encode("utf-8")
    return {"schema": REVIEW_SCHEMA, "reviewer": reviewer_id, "producer": producer_id, "manifest_sha256": manifest_hash,
            "algorithm": "ed25519", "signature": base64.b64encode(private_key.sign(message)).decode("ascii")}


def _trusted_key(trust_map: Any, reviewer: str | None) -> Ed25519PublicKey | None:
    if not isinstance(trust_map, dict) or set(trust_map) != {"schema", "reviewers"} or trust_map.get("schema") != TRUST_SCHEMA or not isinstance(trust_map["reviewers"], dict) or reviewer is None:
        return None
    item = trust_map["reviewers"].get(reviewer)
    if not isinstance(item, dict) or set(item) != {"ed25519_public_key"} or not isinstance(item["ed25519_public_key"], str): return None
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(item["ed25519_public_key"]))
    except ValueError:
        return None


def certify_release(manifest: Any, review: Any, trust_map: Any, *, release_root: Path) -> dict[str, Any]:
    """Rehash gate evidence and verify an Ed25519 review from an external trust map."""
    errors: list[dict[str, str]] = []
    try:
        root = Path(release_root).resolve(strict=True)
        if not root.is_dir() or _is_symlink_or_junction(Path(release_root)): raise OSError("invalid_root")
    except (OSError, ValueError):
        root = Path("."); errors.append({"code": "release_root_invalid"})
    errors.extend(validate_release_manifest(manifest, release_root=root))
    # A generic hashed file is never sufficient to establish the dynamic
    # laboratory gates.  Their real-VM attestation is deliberately external
    # to this repository and therefore cannot be promoted by this local
    # universal certifier.
    errors.append({"code": "external_vm_attestation_required_for_f08_f09"})
    # A local path (even a read-only one) cannot establish retention lock,
    # separation of credentials, or a later independent recovery from WORM.
    # Until a separately governed attestation verifier is integrated, keep
    # the external-custody gate closed rather than trusting a status field.
    errors.append({"code": "external_worm_attestation_required"})
    if not isinstance(review, dict) or set(review) != {"schema", "reviewer", "producer", "manifest_sha256", "algorithm", "signature"} or review.get("schema") != REVIEW_SCHEMA:
        errors.append({"code": "review_schema_invalid"}); review = {}
    reviewer, producer = _identity(review.get("reviewer")), _identity(review.get("producer"))
    if reviewer is None or producer is None: errors.append({"code": "review_identity_invalid"})
    elif reviewer == producer: errors.append({"code": "self_review_forbidden"})
    try: manifest_hash = _hash(manifest)
    except (TypeError, ValueError): manifest_hash = None; errors.append({"code": "manifest_canonicalization_invalid"})
    if review.get("manifest_sha256") != manifest_hash: errors.append({"code": "review_manifest_hash_mismatch"})
    key = _trusted_key(trust_map, reviewer)
    if key is None: errors.append({"code": "reviewer_untrusted"})
    if review.get("algorithm") != "ed25519": errors.append({"code": "review_algorithm_invalid"})
    try:
        signature = base64.b64decode(review.get("signature", ""), validate=True)
        message = f"{REVIEW_SCHEMA}|{reviewer}|{producer}|{review.get('manifest_sha256', '')}".encode("utf-8")
        if key is None: raise InvalidSignature
        key.verify(signature, message)
    except (ValueError, TypeError, InvalidSignature): errors.append({"code": "review_signature_invalid"})
    certified = not errors
    return {"schema": SCHEMA, "status": "QUITADA" if certified else "PARCIALMENTE_QUITADA", "certified": certified,
            "manifest_sha256": manifest_hash, "reviewer": reviewer, "errors": errors,
            "limitations": ["trust-map provenance must be governed outside this repository", "no dynamic VM qualification is inferred by release certification", "no WORM immutability or recovery is inferred from local files"]}
