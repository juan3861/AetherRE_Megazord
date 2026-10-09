"""Auditoria independente de um pacote de execução já materializado.

Esta camada verifica integridade e completude do pacote; não reexecuta o alvo e
não transforma um pacote íntegro em prova de correção sem ground truth.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from aether_re.evidence import (
    FileSizeLimitExceeded,
    MAX_MANIFEST_JSON_BYTES,
    _has_link_or_reparse_component,
    _is_hardlinked_regular_file,
    read_bounded_bytes,
    sha256_file,
)
from aether_re.lock import RunLock


SCHEMA = "homologation-report.v1"
_LIMITATIONS = [
    "não reexecuta o alvo",
    "integridade do pacote não prova equivalência semântica",
    "homologação exige ground truth e revisão independente",
    "path checks não são race-proof contra alteração local concorrente",
]
REQUIRED_ARTIFACTS = (
    "manifest.json",
    "report.json",
    "checkpoint.json",
    "input.snapshot",
    "pseudo_source.c",
    "findings.md",
    "strings.txt",
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class _DuplicateJSONKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _load_json(
    path: Path,
    issues: list[dict[str, str]],
    *,
    max_bytes: int | None = None,
    size_limit_code: str = "json_size_limit_exceeded",
) -> dict[str, Any] | None:
    if _has_link_or_reparse_component(path):
        issues.append({"code": "json_file_link", "path": path.name, "detail": "linked_or_reparse_file_not_accepted"})
        return None
    if _is_hardlinked_regular_file(path):
        issues.append({"code": "artifact_hardlink", "path": path.name, "detail": "hardlinked_files_not_accepted"})
        return None
    try:
        content = (
            read_bounded_bytes(path, max_bytes=max_bytes)
            if max_bytes is not None
            else path.read_bytes()
        )
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
    except _DuplicateJSONKey as exc:
        issues.append({"code": "json_duplicate_key", "path": path.name, "detail": str(exc)})
        return None
    except FileSizeLimitExceeded:
        issues.append({"code": size_limit_code, "path": path.name, "detail": f"limit={max_bytes}"})
        return None
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        issues.append({"code": "json_invalid", "path": path.name, "detail": type(exc).__name__})
        return None
    if not isinstance(value, dict):
        issues.append({"code": "json_not_object", "path": path.name, "detail": "object_required"})
        return None
    return value


def audit_run_package(
    run_dir: Path,
    *,
    target: Path | None = None,
    active_lock: RunLock | None = None,
) -> dict[str, Any]:
    """Validate a materialized run package.

    ``active_lock`` must be the live lock object owned by the caller. The audit
    compares its path and token to the current lock file. Path checks are
    point-in-time checks, not race-proof protection against a concurrent local
    writer replacing a checked path before it is opened.
    """
    run_dir = Path(run_dir)
    issues: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    checks: list[dict[str, Any]] = []
    if _has_link_or_reparse_component(run_dir):
        issues.append({"code": "run_dir_link", "path": str(run_dir), "detail": "linked_or_reparse_directory_not_accepted"})
        return {"schema": SCHEMA, "status": "fail", "run_dir": str(run_dir), "checks": checks, "issues": issues, "warnings": warnings, "limitations": list(_LIMITATIONS)}
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        issues.append({"code": "run_dir_missing", "path": str(run_dir), "detail": "directory_required"})
        return {"schema": SCHEMA, "status": "fail", "run_dir": str(run_dir), "checks": checks, "issues": issues, "warnings": warnings, "limitations": list(_LIMITATIONS)}

    manifest_path = run_dir / "manifest.json"
    manifest = _load_json(
        manifest_path,
        issues,
        max_bytes=MAX_MANIFEST_JSON_BYTES,
        size_limit_code="manifest_size_limit_exceeded",
    )
    if manifest is not None:
        if manifest.get("schema") != "evidence-manifest.v1":
            issues.append({"code": "manifest_schema_invalid", "path": "manifest.json", "detail": str(manifest.get("schema"))})
        entries = manifest.get("files", [])
        if not isinstance(entries, list):
            issues.append({"code": "manifest_files_invalid", "path": "manifest.json", "detail": "list_required"})
            entries = []
        target_digest = manifest.get("target_sha256")
        snapshot_entries = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == "input.snapshot"]
        manifest_paths: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not isinstance(entry.get("sha256"), str):
                issues.append({"code": "manifest_entry_invalid", "path": "manifest.json", "detail": "path_sha256_required"})
                continue
            rel = Path(entry["path"])
            relative_name = rel.as_posix()
            if relative_name in manifest_paths:
                issues.append({"code": "manifest_duplicate_path", "path": entry["path"], "detail": "manifest_paths_must_be_unique"})
            manifest_paths.add(relative_name)
            if rel.is_absolute() or ".." in rel.parts:
                issues.append({"code": "path_escape", "path": entry["path"], "detail": "manifest_path_outside_run"})
                continue
            if not _SHA256_RE.fullmatch(entry["sha256"]):
                issues.append({"code": "manifest_hash_invalid", "path": entry["path"], "detail": "sha256_required"})
                continue
            is_input_snapshot = entry["path"] == "input.snapshot"
            if is_input_snapshot and entry["sha256"] != target_digest:
                issues.append({"code": "snapshot_target_hash_mismatch", "path": "input.snapshot", "detail": "manifest_entry_digest_differs_from_target_digest"})
            if is_input_snapshot and (isinstance(entry.get("size"), bool) or not isinstance(entry.get("size"), int)):
                issues.append({"code": "snapshot_size_invalid", "path": "input.snapshot", "detail": "integer_size_required"})
            raw_artifact = run_dir / rel
            if _has_link_or_reparse_component(raw_artifact):
                issues.append({"code": "artifact_symlink", "path": entry["path"], "detail": "symlinks_not_accepted"})
                continue
            if _is_hardlinked_regular_file(raw_artifact):
                issues.append({"code": "artifact_hardlink", "path": entry["path"], "detail": "hardlinked_files_not_accepted"})
                continue
            artifact = raw_artifact.resolve()
            try:
                artifact.relative_to(run_dir)
            except ValueError:
                issues.append({"code": "path_escape", "path": entry["path"], "detail": "manifest_path_outside_run"})
                continue
            if not artifact.is_file():
                issues.append({"code": "artifact_missing", "path": entry["path"], "detail": "file_required"})
                continue
            observed = sha256_file(artifact)
            if observed != entry["sha256"]:
                issues.append({"code": "hash_mismatch", "path": entry["path"], "detail": f"expected={entry['sha256']} observed={observed}"})
            if is_input_snapshot and observed != target_digest:
                issues.append({"code": "snapshot_target_hash_mismatch", "path": "input.snapshot", "detail": "snapshot_bytes_differ_from_target_digest"})
            if is_input_snapshot and isinstance(entry.get("size"), int) and not isinstance(entry.get("size"), bool) and entry["size"] != artifact.stat().st_size:
                issues.append({"code": "snapshot_size_mismatch", "path": "input.snapshot", "detail": "manifest_size_differs_from_snapshot"})
            if "size" in entry and entry["size"] != artifact.stat().st_size:
                issues.append({"code": "size_mismatch", "path": entry["path"], "detail": "manifest_size_differs"})
        if len(snapshot_entries) > 1:
            issues.append({"code": "manifest_duplicate_path", "path": "input.snapshot", "detail": "input_snapshot_must_be_unique"})
        # Only root manifest.json is the container itself and intentionally excluded.
        required_missing_from_manifest = [name for name in REQUIRED_ARTIFACTS if name != "manifest.json" and name not in manifest_paths]
        for name in required_missing_from_manifest:
            issues.append({"code": "manifest_required_artifact_missing", "path": name, "detail": "required_artifact_not_listed"})
        listed_files = {name for name in manifest_paths if name not in {"manifest.json", "run.lock"}}
        for path in run_dir.rglob("*"):
            relative_name = path.relative_to(run_dir).as_posix()
            if relative_name in {"manifest.json", "run.lock"}:
                continue
            if _has_link_or_reparse_component(path):
                issues.append({"code": "artifact_symlink", "path": relative_name, "detail": "linked_or_reparse_artifact_not_accepted"})
                continue
            if not path.is_file():
                continue
            if _is_hardlinked_regular_file(path):
                issues.append({"code": "artifact_hardlink", "path": relative_name, "detail": "hardlinked_files_not_accepted"})
            if relative_name not in listed_files:
                issues.append({"code": "manifest_unlisted_artifact", "path": relative_name, "detail": "regular_file_not_in_manifest"})
        checks.append({"name": "manifest_entries", "count": len(entries), "verified": not any(i["code"] in {"path_escape", "artifact_symlink", "artifact_hardlink", "artifact_missing", "hash_mismatch", "size_mismatch", "snapshot_target_hash_mismatch", "snapshot_size_invalid", "snapshot_size_mismatch", "manifest_entry_invalid", "manifest_duplicate_path", "manifest_hash_invalid", "manifest_required_artifact_missing", "manifest_unlisted_artifact", "manifest_metadata_invalid", "json_duplicate_key", "json_file_link", "json_invalid"} for i in issues)})

    for name in REQUIRED_ARTIFACTS:
        required_path = run_dir / name
        if _has_link_or_reparse_component(required_path):
            issues.append({"code": "artifact_symlink", "path": name, "detail": "symlinks_not_accepted"})
        elif _is_hardlinked_regular_file(required_path):
            issues.append({"code": "artifact_hardlink", "path": name, "detail": "hardlinked_files_not_accepted"})
        elif not required_path.is_file():
            issues.append({"code": "required_artifact_missing", "path": name, "detail": "required_by_pipeline"})

    report = _load_json(run_dir / "report.json", issues)
    checkpoint = _load_json(run_dir / "checkpoint.json", issues)
    if manifest and report:
        if report.get("target_sha256") != manifest.get("target_sha256"):
            issues.append({"code": "target_hash_mismatch", "path": "report.json", "detail": "report_manifest"})
    if target is not None:
        target = Path(target)
        if _has_link_or_reparse_component(target):
            issues.append({"code": "target_link", "path": str(target), "detail": "linked_or_reparse_target_not_accepted"})
        elif _is_hardlinked_regular_file(target):
            issues.append({"code": "target_hardlink", "path": str(target), "detail": "hardlinked_target_not_accepted"})
        else:
            try:
                observed = sha256_file(target.resolve())
                if manifest and observed != manifest.get("target_sha256"):
                    issues.append({"code": "target_hash_mismatch", "path": str(target), "detail": "target_manifest"})
            except (FileNotFoundError, OSError) as exc:
                issues.append({"code": "target_missing", "path": str(target), "detail": type(exc).__name__})
    if checkpoint:
        if checkpoint.get("schema") != "analysis-checkpoint.v1":
            issues.append({"code": "checkpoint_schema_invalid", "path": "checkpoint.json", "detail": str(checkpoint.get("schema"))})
        if checkpoint.get("status") != "succeeded" or checkpoint.get("stage") != "persisted":
            issues.append({"code": "checkpoint_incomplete", "path": "checkpoint.json", "detail": f"{checkpoint.get('status')}:{checkpoint.get('stage')}"})
    run_lock_path = run_dir / "run.lock"
    run_lock_present = run_lock_path.exists()
    run_lock_path_safe = True
    if _has_link_or_reparse_component(run_lock_path):
        issues.append({"code": "run_lock_link", "path": "run.lock", "detail": "linked_or_reparse_lock_not_accepted"})
        run_lock_path_safe = False
    elif _is_hardlinked_regular_file(run_lock_path):
        issues.append({"code": "run_lock_hardlink", "path": "run.lock", "detail": "hardlinked_lock_not_accepted"})
        run_lock_path_safe = False
    if active_lock is not None:
        if not run_lock_present:
            issues.append({"code": "run_lock_expected_but_missing", "path": "run.lock", "detail": "active_lock_mode_requires_existing_lock_file"})
            run_lock_state = "expected_but_missing"
        else:
            try:
                same_path = (
                    isinstance(active_lock, RunLock)
                    and Path(active_lock.path).resolve() == run_lock_path.resolve()
                )
                owner_matches = same_path and active_lock.verify_owner()
            except (OSError, RuntimeError, TypeError, ValueError):
                owner_matches = False
            if not run_lock_path_safe or not owner_matches:
                issues.append({"code": "run_lock_owner_mismatch", "path": "run.lock", "detail": "active_lock_does_not_own_current_lock_file"})
                run_lock_state = "active_rejected"
            else:
                run_lock_state = "expected_active"
        checks.append({"name": "active_lock_expected", "verified": run_lock_present and run_lock_path_safe and run_lock_state == "expected_active"})
    else:
        if run_lock_present:
            issues.append({"code": "run_lock_present", "path": "run.lock", "detail": "run_may_still_be_active"})
            run_lock_state = "active_rejected"
        else:
            run_lock_state = "released"
        checks.append({"name": "lock_released", "verified": not run_lock_present})
    metadata: dict[str, Any] = {}
    if manifest is not None:
        candidate_metadata = manifest.get("metadata", {})
        if not isinstance(candidate_metadata, dict):
            issues.append({"code": "manifest_metadata_invalid", "path": "manifest.json", "detail": "object_required"})
        else:
            metadata = candidate_metadata
        if not metadata.get("cache_key") and isinstance(candidate_metadata, dict):
            warnings.append({"code": "cache_key_missing", "path": "manifest.json", "detail": "older_package_or_non_pipeline_run"})
    checks.extend([
        {"name": "required_artifacts", "count": len(REQUIRED_ARTIFACTS), "verified": not any(i["code"] == "required_artifact_missing" for i in issues)},
        {"name": "checkpoint_terminal", "verified": bool(checkpoint and checkpoint.get("status") == "succeeded" and checkpoint.get("stage") == "persisted")},
    ])
    return {
        "schema": SCHEMA,
        "status": "pass" if not issues else "fail",
        "run_dir": str(run_dir),
        "checks": checks,
        "issues": issues,
        "warnings": warnings,
        "run_lock_state": run_lock_state,
        "limitations": list(_LIMITATIONS),
    }


def write_homologation_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
