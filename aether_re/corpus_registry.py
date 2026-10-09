"""Material, fail-closed validation for a versioned forensic corpus registry."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from base64 import b64decode
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import CANONICAL_PROFILE_IDS


REGISTRY_SCHEMA = "corpus-registry.v1"
ORACLE_SCHEMA = "blind-oracle.v1"
REPORT_SCHEMA = "corpus-validation-report.v1"
ATTESTATION_SCHEMA = "blind-oracle-attestation.v1"
TRUST_MAP_SCHEMA = "oracle-trust-map.v1"
SPLITS = ("development", "calibration", "blind")
_ORACLE_FIELDS = frozenset({"oracle", "expected", "ground_truth", "labels", "truth"})


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _load_object(path: Path, code: str, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append({"code": code, "detail": type(exc).__name__})
        return None
    if not isinstance(value, dict):
        errors.append({"code": code, "detail": "object_required"})
        return None
    return value


def _error(errors: list[dict[str, Any]], code: str, artifact_id: str | None = None) -> None:
    item: dict[str, Any] = {"code": code}
    if artifact_id:
        item["artifact_id"] = artifact_id
    errors.append(item)


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_material_path(root: Path, relative: Any, artifact_id: str, errors: list[dict[str, Any]]) -> Path | None:
    if not _nonempty_string(relative):
        _error(errors, "path_invalid", artifact_id)
        return None
    candidate_relative = Path(relative)
    if candidate_relative.is_absolute() or ".." in candidate_relative.parts:
        _error(errors, "path_outside_root", artifact_id)
        return None
    candidate = root / candidate_relative
    current = root
    try:
        if root.is_symlink():
            _error(errors, "symlink_forbidden", artifact_id)
            return None
        for part in candidate_relative.parts:
            current = current / part
            if current.is_symlink():
                _error(errors, "symlink_forbidden", artifact_id)
                return None
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, RuntimeError):
        _error(errors, "material_unreadable", artifact_id)
        return None
    except ValueError:
        _error(errors, "path_outside_root", artifact_id)
        return None
    if not resolved.is_file():
        _error(errors, "material_not_file", artifact_id)
        return None
    return resolved


def _validate_oracle(
    oracle: dict[str, Any] | None,
    oracle_provided: bool,
    blind_ids: set[str],
    nonblind_ids: set[str],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    if not oracle_provided:
        if blind_ids:
            _error(errors, "blind_oracle_required")
        return {"status": "missing", "entry_count": 0}
    if oracle is None:
        return {"status": "invalid", "entry_count": 0}
    if oracle.get("schema") != ORACLE_SCHEMA:
        _error(errors, "blind_oracle_schema_mismatch")
    rows = oracle.get("entries")
    if not isinstance(rows, list):
        _error(errors, "blind_oracle_entries_invalid")
        return {"status": "invalid", "entry_count": 0}
    oracle_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not _nonempty_string(row.get("artifact_id")):
            _error(errors, "blind_oracle_entry_invalid")
            continue
        artifact_id = row["artifact_id"].strip()
        if artifact_id in oracle_ids:
            _error(errors, "blind_oracle_duplicate_entry", artifact_id)
        oracle_ids.add(artifact_id)
        if artifact_id in nonblind_ids:
            _error(errors, "blind_oracle_nonblind_entry", artifact_id)
        elif artifact_id not in blind_ids:
            _error(errors, "blind_oracle_unknown_entry", artifact_id)
        if "expected" not in row or row["expected"] in (None, "", {}, []):
            _error(errors, "blind_oracle_expected_missing", artifact_id)
    for artifact_id in sorted(blind_ids - oracle_ids):
        _error(errors, "blind_oracle_missing_entry", artifact_id)
    oracle_errors = [item for item in errors if item["code"].startswith("blind_oracle")]
    return {
        "status": "invalid" if oracle_errors else "verified",
        "entry_count": len(oracle_ids),
    }


def _valid_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _outside_execution_root(path: Path, root: Path) -> bool:
    try:
        if path.is_symlink():
            return False
        resolved = path.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
        try:
            resolved.relative_to(resolved_root)
        except ValueError:
            return True
        return False
    except (OSError, RuntimeError):
        return False


def _discover_repository_root() -> Path | None:
    """Locate the checkout containing this module, never from the process CWD.

    Installed copies without the repository sentinels deliberately return None;
    callers then fail closed instead of guessing from an arbitrary working
    directory or trusting a caller-controlled boundary.
    """

    try:
        source = Path(__file__).resolve(strict=True)
        root = source.parent.parent
        git_marker = root / ".git"
        if (
            not root.is_dir()
            or not (root / "megazord.py").is_file()
            or not (root / "aether_re" / "corpus_registry.py").is_file()
            or not git_marker.exists()
            or _is_reparse_point(git_marker)
        ):
            return None
        return root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None


def _is_reparse_point(path: Path) -> bool:
    """Treat symlinks, junctions, and other Windows reparse points as links."""

    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except OSError:
        return True


def _has_linked_path_component(path: Path) -> bool:
    """Reject a trust-map path whose own name or any parent traverses a link."""

    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
        return any(_is_reparse_point(component) for component in (absolute, *absolute.parents))
    except (OSError, RuntimeError, ValueError):
        return True


def _is_within(path: Path, root: Path) -> bool:
    try:
        normalized_path = os.path.normcase(os.path.abspath(os.fspath(path)))
        normalized_root = os.path.normcase(os.path.abspath(os.fspath(root)))
        return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
    except (OSError, ValueError):
        return False


def _outside_trust_map_roots(
    path: Path,
    *,
    corpus_root: Path,
    repository_root: Path | None,
) -> bool:
    """Prove a trust map is a standalone regular file outside both local roots.

    Path containment is checked both before and after resolving links. Hard links
    have no distinct resolved target path, so files with multiple links are
    rejected as well. This is only a location boundary; it does not establish
    trust-map identity, governance, or reviewer independence.
    """

    if repository_root is None or _has_linked_path_component(path):
        return False
    try:
        candidate = Path(os.path.abspath(os.fspath(path)))
        resolved_candidate = candidate.resolve(strict=True)
        resolved_corpus = corpus_root.resolve(strict=True)
        resolved_repository = repository_root.resolve(strict=True)
        file_stat = candidate.stat(follow_symlinks=False)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
            return False
        if any(
            _is_within(candidate, root) or _is_within(resolved_candidate, root)
            for root in (corpus_root, repository_root, resolved_corpus, resolved_repository)
        ):
            return False
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _validate_independent_attestation(
    *,
    attestation_path: Path | None,
    trust_map_path: Path | None,
    trust_map_allowed: bool,
    oracle: dict[str, Any] | None,
    oracle_summary: dict[str, Any],
    corpus_lock_sha256: str | None,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    if attestation_path is None:
        _error(errors, "oracle_attestation_required")
        return {"status": "not_verified", "owner": None}
    attestation = _load_object(attestation_path, "oracle_attestation_unreadable", errors)
    if attestation is None:
        return {"status": "invalid", "owner": None}
    expected_fields = {
        "schema", "owner", "issued_at", "oracle_schema", "oracle_sha256",
        "corpus_lock_sha256", "algorithm", "signature",
    }
    if set(attestation) != expected_fields or attestation.get("schema") != ATTESTATION_SCHEMA:
        _error(errors, "oracle_attestation_schema_invalid")
    owner = attestation.get("owner")
    if not _nonempty_string(owner):
        _error(errors, "oracle_attestation_owner_invalid")
        owner = None
    else:
        owner = owner.strip()
    issued_at = attestation.get("issued_at")
    try:
        if not isinstance(issued_at, str) or not issued_at.endswith("Z"):
            raise ValueError("UTC RFC3339 required")
        parsed_date = datetime.fromisoformat(issued_at[:-1] + "+00:00")
        if parsed_date.tzinfo is None:
            raise ValueError("timezone required")
    except (TypeError, ValueError):
        _error(errors, "oracle_attestation_date_invalid")
    if attestation.get("oracle_schema") != ORACLE_SCHEMA:
        _error(errors, "oracle_attestation_oracle_schema_mismatch")
    try:
        oracle_sha256 = hashlib.sha256(_canonical_bytes(oracle)).hexdigest() if oracle is not None else None
    except (TypeError, ValueError):
        oracle_sha256 = None
    if not _valid_sha256(attestation.get("oracle_sha256")) or attestation.get("oracle_sha256") != oracle_sha256:
        _error(errors, "oracle_attestation_oracle_hash_mismatch")
    if not _valid_sha256(attestation.get("corpus_lock_sha256")) or attestation.get("corpus_lock_sha256") != corpus_lock_sha256:
        _error(errors, "oracle_attestation_corpus_lock_mismatch")
    if attestation.get("algorithm") != "ed25519":
        _error(errors, "oracle_attestation_algorithm_invalid")

    trust_map = None
    if trust_map_path is None:
        _error(errors, "oracle_trust_map_required")
    elif trust_map_allowed:
        trust_map = _load_object(trust_map_path, "oracle_trust_map_unreadable", errors)
    trusted_key: Ed25519PublicKey | None = None
    if (
        not isinstance(trust_map, dict)
        or set(trust_map) != {"schema", "owners"}
        or trust_map.get("schema") != TRUST_MAP_SCHEMA
        or not isinstance(trust_map.get("owners"), dict)
    ):
        if trust_map is not None:
            _error(errors, "oracle_trust_map_invalid")
    elif owner is not None:
        owner_record = trust_map["owners"].get(owner)
        if not isinstance(owner_record, dict) or set(owner_record) != {"ed25519_public_key"}:
            _error(errors, "oracle_attestation_owner_untrusted")
        else:
            try:
                key_bytes = bytes.fromhex(owner_record["ed25519_public_key"])
                trusted_key = Ed25519PublicKey.from_public_bytes(key_bytes)
            except (KeyError, TypeError, ValueError):
                _error(errors, "oracle_attestation_owner_untrusted")

    signed_document = {key: attestation.get(key) for key in expected_fields - {"signature"}}
    try:
        signature = b64decode(attestation.get("signature", ""), validate=True)
        if trusted_key is None:
            raise InvalidSignature
        trusted_key.verify(signature, _canonical_bytes(signed_document))
    except (TypeError, ValueError, InvalidSignature):
        _error(errors, "oracle_attestation_signature_invalid")

    attestation_codes = {
        item["code"] for item in errors
        if item["code"].startswith("oracle_attestation") or item["code"].startswith("oracle_trust_map")
    }
    valid = not attestation_codes and oracle_summary.get("status") == "verified" and corpus_lock_sha256 is not None
    return {"status": "verified" if valid else "invalid", "owner": owner}


def validate_corpus_registry(
    registry_path: str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    blind_oracle_path: str | os.PathLike[str] | None = None,
    blind_attestation_path: str | os.PathLike[str] | None = None,
    trust_map_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate registry declarations against bytes on disk and seal a canonical lock.

    Oracle contents and its filesystem location are deliberately never included in
    the returned report or canonical lock.
    """

    errors: list[dict[str, Any]] = []
    counts = {split: 0 for split in SPLITS}
    corpus_root = Path(root)
    registry = _load_object(Path(registry_path), "registry_unreadable", errors)
    if registry is None:
        return _report(
            counts, errors, [], {"status": "not_checked", "entry_count": 0},
            {"status": "not_verified", "owner": None}, material_error_count=len(errors),
        )
    if registry.get("schema") != REGISTRY_SCHEMA:
        _error(errors, "schema_mismatch")
    rows = registry.get("entries")
    if not isinstance(rows, list):
        _error(errors, "entries_invalid")
        rows = []

    normalized: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    ids: set[str] = set()
    family_splits: dict[str, set[str]] = {}
    project_splits: dict[str, set[str]] = {}
    blind_ids: set[str] = set()
    nonblind_ids: set[str] = set()

    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            _error(errors, "entry_invalid")
            continue
        artifact_id_value = row.get("artifact_id")
        artifact_id = artifact_id_value.strip() if _nonempty_string(artifact_id_value) else f"entry:{index}"
        if not _nonempty_string(artifact_id_value):
            _error(errors, "artifact_id_invalid", artifact_id)
        elif artifact_id in ids:
            _error(errors, "duplicate_artifact_id", artifact_id)
        ids.add(artifact_id)

        if _ORACLE_FIELDS.intersection(row):
            _error(errors, "oracle_exposed_in_registry", artifact_id)
        for field, code in (
            ("origin", "origin_invalid"),
            ("license", "license_invalid"),
            ("authorization", "authorization_invalid"),
            ("family", "family_invalid"),
            ("project", "project_invalid"),
        ):
            if not _nonempty_string(row.get(field)):
                _error(errors, code, artifact_id)

        profile_id = row.get("profile_id")
        if profile_id not in CANONICAL_PROFILE_IDS:
            _error(errors, "profile_id_invalid", artifact_id)
        split = row.get("split")
        if split not in SPLITS:
            _error(errors, "split_invalid", artifact_id)
        else:
            counts[split] += 1
            if split == "blind":
                blind_ids.add(artifact_id)
            else:
                nonblind_ids.add(artifact_id)
            if _nonempty_string(row.get("family")):
                family_splits.setdefault(row["family"].strip(), set()).add(split)
            if _nonempty_string(row.get("project")):
                project_splits.setdefault(row["project"].strip(), set()).add(split)

        declared_hash = row.get("sha256")
        if not isinstance(declared_hash, str) or len(declared_hash) != 64:
            _error(errors, "sha256_invalid", artifact_id)
        else:
            try:
                int(declared_hash, 16)
            except ValueError:
                _error(errors, "sha256_invalid", artifact_id)
            else:
                declared_hash = declared_hash.lower()
                if declared_hash in hashes:
                    _error(errors, "duplicate_sha256", artifact_id)
                hashes[declared_hash] = artifact_id
        declared_size = row.get("size")
        if isinstance(declared_size, bool) or not isinstance(declared_size, int) or declared_size < 0:
            _error(errors, "size_invalid", artifact_id)

        material = _safe_material_path(corpus_root, row.get("path"), artifact_id, errors)
        observed_hash: str | None = None
        observed_size: int | None = None
        if material is not None:
            try:
                observed_hash, observed_size = _sha256_file(material)
            except OSError:
                _error(errors, "material_unreadable", artifact_id)
            else:
                if isinstance(declared_hash, str) and observed_hash != declared_hash.lower():
                    _error(errors, "sha256_mismatch", artifact_id)
                if isinstance(declared_size, int) and not isinstance(declared_size, bool) and observed_size != declared_size:
                    _error(errors, "size_mismatch", artifact_id)

        normalized.append(
            {
                "artifact_id": artifact_id,
                "path": row.get("path"),
                "sha256": observed_hash,
                "size": observed_size,
                "origin": row.get("origin"),
                "license": row.get("license"),
                "authorization": row.get("authorization"),
                "profile_id": profile_id,
                "split": split,
                "family": row.get("family"),
                "project": row.get("project"),
            }
        )

    for split, count in counts.items():
        if count == 0:
            _error(errors, "split_missing", split)
    for family, assigned in sorted(family_splits.items()):
        if len(assigned) > 1:
            _error(errors, "family_split_overlap", family)
    for project, assigned in sorted(project_splits.items()):
        if len(assigned) > 1:
            _error(errors, "project_split_overlap", project)

    material_error_count = len(errors)
    lock_sha256 = _lock_hash(normalized) if material_error_count == 0 else None
    oracle_path = Path(blind_oracle_path) if blind_oracle_path is not None else None
    if oracle_path is not None and not _outside_execution_root(oracle_path, corpus_root):
        _error(errors, "blind_oracle_not_separate")
    oracle_document = _load_object(oracle_path, "blind_oracle_unreadable", errors) if oracle_path is not None else None
    oracle_summary = _validate_oracle(
        oracle_document,
        oracle_path is not None,
        blind_ids,
        nonblind_ids,
        errors,
    )
    trust_path = Path(trust_map_path) if trust_map_path is not None else None
    trust_map_allowed = False
    if trust_path is not None:
        repository_root = _discover_repository_root()
        if repository_root is None:
            _error(errors, "oracle_trust_map_repository_root_unavailable")
            _error(errors, "oracle_trust_map_not_external")
        else:
            trust_map_allowed = _outside_trust_map_roots(
                trust_path,
                corpus_root=corpus_root,
                repository_root=repository_root,
            )
            if not trust_map_allowed:
                _error(errors, "oracle_trust_map_not_external")
    attestation_summary = _validate_independent_attestation(
        attestation_path=Path(blind_attestation_path) if blind_attestation_path is not None else None,
        trust_map_path=trust_path,
        trust_map_allowed=trust_map_allowed,
        oracle=oracle_document,
        oracle_summary=oracle_summary,
        corpus_lock_sha256=lock_sha256,
        errors=errors,
    )
    return _report(
        counts, errors, normalized, oracle_summary, attestation_summary,
        material_error_count=material_error_count,
    )


def _lock_hash(normalized: list[dict[str, Any]]) -> str:
    lock_document = {
        "schema": REGISTRY_SCHEMA,
        "entries": sorted(normalized, key=lambda item: item["artifact_id"]),
    }
    return hashlib.sha256(_canonical_bytes(lock_document)).hexdigest()


def _report(
    counts: dict[str, int],
    errors: list[dict[str, Any]],
    normalized: list[dict[str, Any]],
    oracle_summary: dict[str, Any],
    attestation_summary: dict[str, Any],
    *,
    material_error_count: int,
) -> dict[str, Any]:
    lock_sha256 = _lock_hash(normalized) if material_error_count == 0 else None
    return {
        "schema": REPORT_SCHEMA,
        "status": "QUITADA" if not errors else "NAO_COMPROVADA",
        "counts": counts,
        "entry_count": len(normalized),
        "lock_sha256": lock_sha256,
        "material_integrity": {
            "status": "verified" if material_error_count == 0 else "invalid",
            "entry_count": len(normalized),
        },
        "blind_oracle": oracle_summary,
        "independent_attestation": attestation_summary,
        "errors": errors,
        "limitations": [
            "trust-map governance is external and cannot be self-proven by this report",
            "trust-map path location does not prove signer identity, governance, or reviewer independence",
        ],
    }

