"""Material, fail-closed builder for ``release-manifest.v1``.

The builder does not infer gate success.  It accepts exactly one material
``gate-evidence.v1`` document for every F00--F12 gate, rehashes every
referenced artifact, then emits the small manifest consumed by the release
certifier.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

from .release_certification import REQUIRED_GATES, validate_release_manifest


_GATE_FIELDS = {
    "schema",
    "gate",
    "status",
    "gate_passed",
    "integrity_errors",
    "blocking_gates",
    "artifacts",
}
_HEX = frozenset("0123456789abcdef")
_MAX_GATE_EVIDENCE_BYTES = 4 * 1024 * 1024
_MAX_GATE_ARTIFACT_JSON_BYTES = 4 * 1024 * 1024


class ReleaseManifestBuildError(ValueError):
    """Raised with a stable machine-readable reason when building is unsafe."""


class _DuplicateJsonKey(ValueError):
    pass


def _fail(code: str) -> None:
    raise ReleaseManifestBuildError(code)


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in _HEX for character in value.casefold())
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(key)
        value[key] = item
    return value


def _is_symlink_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _material_file(root: Path, relative_value: Any, *, kind: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value:
        _fail(f"{kind}_path_invalid")
    relative = Path(relative_value)
    if relative.is_absolute() or relative == Path(".") or ".." in relative.parts:
        _fail(f"{kind}_path_invalid")

    current = root
    try:
        for part in relative.parts:
            current = current / part
            if _is_symlink_or_junction(current):
                _fail(f"{kind}_path_invalid")
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file():
            _fail(f"{kind}_path_invalid")
    except ReleaseManifestBuildError:
        raise
    except (OSError, RuntimeError, ValueError):
        _fail(f"{kind}_path_invalid")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        _fail("material_file_unreadable")
    return digest.hexdigest()


def _reject_release_inventory_artifact(path: Path) -> None:
    """Reject the non-certifying inventory schema as gate-proof material.

    JSON-looking artifacts are inspected by content, not filename extension,
    because renaming an inventory must not make it eligible evidence. The
    bounded inspection is deliberately fail-closed for oversized JSON-like
    files; unrelated binary artifacts remain opaque and are only hashed.
    """
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            content = handle.read(_MAX_GATE_ARTIFACT_JSON_BYTES + 1)
    except OSError:
        _fail("gate_artifact_unreadable")

    prefix = content.lstrip(b" \t\r\n")
    if prefix.startswith(b"\xef\xbb\xbf"):
        prefix = prefix[3:].lstrip(b" \t\r\n")
    json_object_candidate = prefix.startswith(b"{") or not prefix
    if size > _MAX_GATE_ARTIFACT_JSON_BYTES or len(content) > _MAX_GATE_ARTIFACT_JSON_BYTES:
        if path.suffix.casefold() == ".json" or json_object_candidate:
            _fail("gate_artifact_json_size_limit_exceeded")
        return
    if not prefix.startswith(b"{"):
        return
    try:
        document = json.loads(content.decode("utf-8-sig"), object_pairs_hook=_strict_object)
    except _DuplicateJsonKey:
        _fail("gate_artifact_json_ambiguous")
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail("gate_artifact_json_invalid")
    if isinstance(document, dict) and document.get("schema") == "release-inventory.v1":
        _fail("gate_artifact_release_inventory_forbidden")


def _load_gate_evidence(path: Path) -> Any:
    try:
        if path.stat().st_size > _MAX_GATE_EVIDENCE_BYTES:
            _fail("gate_evidence_contract_invalid")
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except ReleaseManifestBuildError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJsonKey):
        _fail("gate_evidence_contract_invalid")


def _verify_gate_document(document: Any, *, root: Path) -> str:
    if (
        not isinstance(document, dict)
        or set(document) != _GATE_FIELDS
        or document.get("schema") != "gate-evidence.v1"
        or document.get("gate") not in REQUIRED_GATES
        or document.get("status") != "QUITADA"
        or document.get("gate_passed") is not True
        or document.get("integrity_errors") != []
        or document.get("blocking_gates") != []
        or not isinstance(document.get("artifacts"), list)
        or not document["artifacts"]
    ):
        _fail("gate_evidence_contract_invalid")

    seen_artifacts: set[str] = set()
    for artifact in document["artifacts"]:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"path", "sha256"}
            or not isinstance(artifact.get("path"), str)
            or not artifact["path"]
            or not _is_hex(artifact.get("sha256"), 64)
        ):
            _fail("gate_artifact_contract_invalid")
        if artifact["path"] in seen_artifacts:
            _fail("gate_artifact_duplicate")
        seen_artifacts.add(artifact["path"])
        path = _material_file(root, artifact["path"], kind="gate_artifact")
        _reject_release_inventory_artifact(path)
        if _sha256_file(path) != artifact["sha256"]:
            _fail("gate_artifact_hash_mismatch")
    return document["gate"]


def build_release_manifest(
    release_root: Path | str,
    *,
    commit: str,
    toolchain_lock_sha256: str,
    corpus_lock_sha256: str,
    gate_evidence_paths: Sequence[str],
) -> dict[str, Any]:
    """Build a validator-compatible manifest from 13 verified gate documents.

    Nothing is written.  Callers may serialize the returned document only
    after this function succeeds.
    """
    raw_root = Path(release_root)
    try:
        if _is_symlink_or_junction(raw_root):
            _fail("release_root_invalid")
        root = raw_root.resolve(strict=True)
        if not root.is_dir():
            _fail("release_root_invalid")
    except ReleaseManifestBuildError:
        raise
    except (OSError, RuntimeError, ValueError):
        _fail("release_root_invalid")

    for field, value, length in (
        ("commit", commit, 40),
        ("toolchain_lock_sha256", toolchain_lock_sha256, 64),
        ("corpus_lock_sha256", corpus_lock_sha256, 64),
    ):
        if not _is_hex(value, length):
            _fail(f"{field}_invalid")

    if (
        isinstance(gate_evidence_paths, (str, bytes))
        or not isinstance(gate_evidence_paths, Sequence)
        or len(gate_evidence_paths) != len(REQUIRED_GATES)
    ):
        _fail("gate_evidence_count_invalid")

    seen_paths: set[str] = set()
    gates: dict[str, dict[str, str]] = {}
    for relative in gate_evidence_paths:
        if not isinstance(relative, str):
            _fail("gate_evidence_path_invalid")
        if relative in seen_paths:
            _fail("gate_evidence_path_duplicate")
        seen_paths.add(relative)
        evidence_path = _material_file(root, relative, kind="gate_evidence")
        document = _load_gate_evidence(evidence_path)
        gate = _verify_gate_document(document, root=root)
        if gate in gates:
            _fail("gate_identity_duplicate")
        gates[gate] = {
            "gate": gate,
            "status": "QUITADA",
            "evidence_path": relative,
            "evidence_sha256": _sha256_file(evidence_path),
        }

    if set(gates) != set(REQUIRED_GATES):
        _fail("gate_set_invalid")

    manifest: dict[str, Any] = {
        "schema": "release-manifest.v1",
        "commit": commit,
        "toolchain_lock_sha256": toolchain_lock_sha256,
        "corpus_lock_sha256": corpus_lock_sha256,
        "gates": [gates[gate] for gate in REQUIRED_GATES],
    }
    if validate_release_manifest(manifest, release_root=root):
        _fail("release_manifest_validation_failed")
    return manifest


__all__ = ["ReleaseManifestBuildError", "build_release_manifest"]
