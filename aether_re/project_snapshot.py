"""Create-only, content-verified snapshots of an explicitly bounded project scope.

This preserves the files admitted by the inventory policy. Excluded files are
listed but not copied; a local snapshot is not WORM or external custody.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from aether_re.evidence import SnapshotCancelled, _path_has_link, _sha256_bounded, create_verified_snapshot, sha256_file, write_manifest_atomic
from aether_re.lock import RunLock
from aether_re.project_inventory import inventory_project


SCHEMA = "project-snapshot.v1"


def _relative_file(value: Any) -> Path:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("snapshot_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or ":" in path.parts[0]:
        raise ValueError("snapshot_path_invalid")
    return Path(*path.parts)


def _validate_destination(source: Path, destination: Path) -> None:
    if _path_has_link(source) or not source.is_dir():
        raise ValueError("snapshot_source_invalid")
    if _path_has_link(destination.parent) or destination.exists() or destination.is_symlink():
        raise ValueError("snapshot_destination_not_create_only")
    if destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("snapshot_destination_inside_source")


def _cleanup_stale_stages(parent: Path, destination: Path) -> list[str]:
    """Remove only orphan stages for this destination after the run lock is held."""
    prefix = f".{destination.name}."
    removed: list[str] = []
    try:
        candidates = list(parent.iterdir())
    except OSError:
        return removed
    for candidate in candidates:
        if not candidate.name.startswith(prefix) or not candidate.name.endswith(".stage"):
            continue
        if candidate.is_symlink() or _path_has_link(candidate) or not candidate.is_dir():
            continue
        try:
            shutil.rmtree(candidate)
        except OSError:
            continue
        removed.append(candidate.name)
    return removed


def _apply_local_seal(destination: Path) -> None:
    """Mark every regular snapshot file read-only as a local seal.

    This is deliberately not advertised as WORM or external custody: a local
    owner can still change ACLs or directory entries.  Verification therefore
    checks both the content hashes and the read-only file state.
    """
    for current, dirs, files in os.walk(destination, topdown=True, followlinks=False):
        parent = Path(current)
        for name in files:
            path = parent / name
            if _path_has_link(path) or not path.is_file():
                raise ValueError("snapshot_seal_link_or_nonfile")
            try:
                mode = path.stat().st_mode
                os.chmod(path, mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            except OSError as exc:
                raise OSError("snapshot_seal_failed") from exc


def create_project_snapshot(
    source: Path, destination: Path, *, max_files: int = 5000,
    max_bytes: int = 512 * 1024 * 1024,
    max_file_bytes: int = 16 * 1024 * 1024,
    cancel_check: Callable[[], bool] | None = None,
    immutable: bool = False,
) -> dict[str, Any]:
    """Copy the inventory's included files, re-inventory source, publish once."""
    source, destination = Path(source).absolute(), Path(destination).absolute()
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_files, max_bytes, max_file_bytes)):
        raise ValueError("snapshot_limits_invalid")
    if cancel_check is not None and not callable(cancel_check):
        raise ValueError("snapshot_cancel_check_invalid")
    if not isinstance(immutable, bool):
        raise ValueError("snapshot_immutability_invalid")
    if cancel_check is not None and cancel_check():
        raise SnapshotCancelled("snapshot_cancelled")
    _validate_destination(source, destination)
    inventory = inventory_project(source, max_files=max_files, max_bytes=max_bytes, max_file_bytes=max_file_bytes)
    if inventory.get("status") == "invalid":
        raise ValueError("snapshot_inventory_invalid")
    if not inventory.get("files"):
        raise ValueError("snapshot_empty_scope")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if _path_has_link(destination.parent):
        raise ValueError("snapshot_destination_not_create_only")
    lock = RunLock(destination.parent / f".{destination.name}.snapshot.lock")
    lock.acquire()
    stage: Path | None = None
    try:
        _validate_destination(source, destination)
        _cleanup_stale_stages(destination.parent, destination)
        stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", suffix=".stage", dir=str(destination.parent)))
        for entry in inventory["files"]:
            if cancel_check is not None and cancel_check():
                raise SnapshotCancelled("snapshot_cancelled")
            relative = _relative_file(entry["path"])
            create_verified_snapshot(
                source / relative, stage / "files" / relative,
                expected_sha256=entry["sha256"], max_bytes=max_file_bytes,
                cancel_check=cancel_check,
            )
        if cancel_check is not None and cancel_check():
            raise SnapshotCancelled("snapshot_cancelled")
        after = inventory_project(source, max_files=max_files, max_bytes=max_bytes, max_file_bytes=max_file_bytes)
        if after.get("root_digest") != inventory.get("root_digest") or after.get("skipped") != inventory.get("skipped"):
            raise ValueError("source_changed_during_project_snapshot")
        manifest = {
            "schema": SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_root": str(source.resolve()),
            "source_root_digest": inventory["root_digest"],
            "inventory_status": inventory["status"],
            "scope": "partial" if inventory.get("skipped") or inventory["status"] != "complete" else "complete",
            "files": inventory["files"],
            "skipped": inventory.get("skipped", []),
            "limits": inventory["limits"],
            "immutability": {
                "sealed": immutable,
                "mode": "local_read_only_files" if immutable else "mutable_local",
                "enforcement": "regular_files_only",
            },
            "limitations": ["somente arquivos incluídos no inventário foram copiados", "hash local não é custódia externa ou armazenamento WORM", "mudança e reversão entre leituras pode não ser detectada", "o selo local não impede um administrador de alterar ACLs ou diretórios"],
        }
        write_manifest_atomic(manifest, stage / "manifest.json")
        verification = verify_project_snapshot(stage, max_total_bytes=max_bytes)
        if verification["status"] != "pass":
            raise ValueError("snapshot_verification_failed")
        if destination.exists():
            raise ValueError("snapshot_destination_not_create_only")
        os.rename(stage, destination)
        stage = None
        if immutable:
            _apply_local_seal(destination)
        final_verification = verify_project_snapshot(destination, max_total_bytes=max_bytes, require_sealed=immutable)
        return {"schema": SCHEMA, "status": "created" if final_verification["status"] == "pass" else "invalid", "destination": str(destination), "scope": manifest["scope"], "file_count": len(manifest["files"]), "root_digest": manifest["source_root_digest"], "manifest_sha256": sha256_file(destination / "manifest.json"), "sealed": immutable, "verification": final_verification}
    finally:
        if stage is not None:
            # A stage is created directly under the named destination parent;
            # never recursively remove an unverified/computed outside path.
            resolved_stage = stage.resolve()
            if resolved_stage.parent == destination.parent.resolve() and resolved_stage.name.startswith(f".{destination.name}."):
                shutil.rmtree(resolved_stage)
        lock.release()


def verify_project_snapshot(destination: Path, *, max_total_bytes: int = 512 * 1024 * 1024, expected_manifest_sha256: str | None = None, require_sealed: bool = False) -> dict[str, Any]:
    """Verify manifest, exact file set and hashes without executing content."""
    destination = Path(destination)
    issues: list[dict[str, str]] = []
    if isinstance(max_total_bytes, bool) or not isinstance(max_total_bytes, int) or max_total_bytes < 1:
        return {"schema": SCHEMA, "status": "fail", "issues": [{"code": "limit_invalid"}]}
    if not isinstance(require_sealed, bool):
        return {"schema": SCHEMA, "status": "fail", "issues": [{"code": "seal_requirement_invalid"}]}
    if _path_has_link(destination) or not destination.is_dir():
        return {"schema": SCHEMA, "status": "fail", "issues": [{"code": "snapshot_directory_invalid"}]}
    try:
        manifest_path = destination / "manifest.json"
        if _path_has_link(manifest_path):
            raise ValueError("manifest_link_not_allowed")
        if manifest_path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("manifest_too_large")
        manifest_bytes = manifest_path.read_bytes()
        if expected_manifest_sha256 is not None and hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256:
            issues.append({"code": "manifest_hash_mismatch"})
        manifest = json.loads(manifest_bytes)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {"schema": SCHEMA, "status": "fail", "issues": [{"code": "manifest_invalid", "detail": type(exc).__name__}]}
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA or not isinstance(manifest.get("files"), list):
        return {"schema": SCHEMA, "status": "fail", "issues": [{"code": "manifest_schema_invalid"}]}
    if require_sealed:
        seal = manifest.get("immutability")
        if not isinstance(seal, dict) or seal.get("sealed") is not True or seal.get("mode") != "local_read_only_files":
            issues.append({"code": "snapshot_not_sealed"})
    entries = manifest["files"]
    if {path.name for path in destination.iterdir()} != {"manifest.json", "files"}:
        issues.append({"code": "snapshot_top_level_mismatch"})
    if len(entries) > 5000:
        issues.append({"code": "manifest_file_budget_exceeded"})
    expected: set[str] = set()
    total = 0
    for entry in entries[:5001]:
        if not isinstance(entry, dict):
            issues.append({"code": "manifest_entry_invalid"})
            continue
        try:
            relative = _relative_file(entry.get("path"))
        except ValueError:
            issues.append({"code": "manifest_path_invalid"})
            continue
        name = relative.as_posix()
        if name in expected:
            issues.append({"code": "manifest_duplicate_path", "path": name})
            continue
        expected.add(name)
        size, digest = entry.get("size"), entry.get("sha256")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            issues.append({"code": "manifest_entry_invalid", "path": name})
            continue
        total += size
        if total > max_total_bytes:
            issues.append({"code": "snapshot_byte_budget_exceeded"})
            break
        path = destination / "files" / relative
        if _path_has_link(path) or not path.is_file():
            issues.append({"code": "snapshot_file_missing_or_link", "path": name})
            continue
        try:
            if path.stat().st_size != size or _sha256_bounded(path, max_total_bytes) != digest:
                issues.append({"code": "snapshot_hash_mismatch", "path": name})
        except (OSError, ValueError):
            issues.append({"code": "snapshot_hash_mismatch", "path": name})
    if require_sealed:
        for sealed_file in (destination / "manifest.json",):
            try:
                if sealed_file.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                    issues.append({"code": "snapshot_not_read_only", "path": sealed_file.name})
            except OSError:
                issues.append({"code": "snapshot_file_unstatable", "path": sealed_file.name})
    actual: set[str] = set()
    files_root = destination / "files"
    if _path_has_link(files_root):
        issues.append({"code": "snapshot_files_link"})
        return {"schema": SCHEMA, "status": "fail", "destination": str(destination), "scope": manifest.get("scope"), "file_count": len(expected), "issues": issues}
    if files_root.is_dir():
        visited = 0
        for current, dirs, files in os.walk(files_root, topdown=True, followlinks=False):
            parent = Path(current)
            for dirname in dirs[:]:
                child = parent / dirname
                if _path_has_link(child):
                    issues.append({"code": "snapshot_directory_link", "path": child.relative_to(files_root).as_posix()})
                    dirs.remove(dirname)
            for filename in files:
                path = parent / filename
                actual.add(path.relative_to(files_root).as_posix())
                if require_sealed:
                    try:
                        if path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                            issues.append({"code": "snapshot_not_read_only", "path": path.relative_to(destination).as_posix()})
                    except OSError:
                        issues.append({"code": "snapshot_file_unstatable", "path": path.relative_to(destination).as_posix()})
                visited += 1
                if visited > 5000:
                    issues.append({"code": "snapshot_actual_file_budget_exceeded"})
                    break
            if visited > 5000:
                break
    elif expected:
        issues.append({"code": "snapshot_files_missing"})
    if actual != expected:
        issues.append({"code": "snapshot_file_set_mismatch", "detail": f"expected={len(expected)} actual={len(actual)}"})
    return {"schema": SCHEMA, "status": "pass" if not issues else "fail", "destination": str(destination), "scope": manifest.get("scope"), "file_count": len(expected), "issues": issues}
