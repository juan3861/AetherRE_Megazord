"""Custódia mínima de artefatos: hashes e manifesto atômico por execução."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = "evidence-manifest.v1"
MAX_MANIFEST_JSON_BYTES = 16 * 1024 * 1024


class FileSizeLimitExceeded(ValueError):
    """Raised when a bounded evidence read exceeds its configured byte limit."""


def read_bounded_bytes(path: Path, *, max_bytes: int) -> bytes:
    """Read at most ``max_bytes + 1`` so oversized files fail before parsing."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("read_size_limit_invalid")
    with Path(path).open("rb") as handle:
        content = handle.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise FileSizeLimitExceeded(f"file_size_limit_exceeded:{max_bytes}")
    return content


class SnapshotCancelled(RuntimeError):
    """The caller cancelled a bounded snapshot before publication."""


def _is_link_or_reparse_point(path: Path) -> bool:
    """Return true for links/reparse points; treat inspection errors as unsafe."""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _has_link_or_reparse_component(path: Path) -> bool:
    """Reject links in every existing component, including the supplied root."""
    absolute = Path(os.path.abspath(path))
    components = [absolute, *absolute.parents]
    return any(_is_link_or_reparse_point(component) for component in components)


def _has_symlink_component(path: Path, root: Path) -> bool:
    """Compatibility helper: reject linked/reparse components below a root."""
    try:
        path.relative_to(root)
    except ValueError:
        return True
    return _has_link_or_reparse_component(path)


def _is_hardlinked_regular_file(path: Path) -> bool:
    try:
        return path.is_file() and path.stat(follow_symlinks=False).st_nlink > 1
    except OSError:
        return True


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bounded(path: Path, max_bytes: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(min(1024 * 1024, max_bytes - total + 1)):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("source_size_budget_exceeded")
            digest.update(chunk)
    return digest.hexdigest()


def _path_has_link(path: Path) -> bool:
    # Use the same strict component check as manifest construction so generic
    # Windows reparse points cannot slip through snapshot source/destination paths.
    return _has_link_or_reparse_component(path)


def create_verified_snapshot(
    source: Path, destination: Path, *, expected_sha256: str | None = None,
    max_bytes: int = 512 * 1024 * 1024,
    cancel_check: Callable[[], bool] | None = None,
) -> str:
    """Publish a bounded, verified copy without overwriting an existing input.

    The copied bytes are stable for the run, but local hashes are not external
    custody and cannot defeat an adversary with write access to the run folder.
    """
    source, destination = Path(source), Path(destination)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("snapshot_limit_invalid")
    if cancel_check is not None and not callable(cancel_check):
        raise ValueError("snapshot_cancel_check_invalid")
    if cancel_check is not None and cancel_check():
        raise SnapshotCancelled("snapshot_cancelled")
    if _path_has_link(source) or not source.is_file():
        raise ValueError("source_must_be_regular_file")
    if _path_has_link(destination.parent) or destination.exists() or destination.is_symlink():
        raise ValueError("snapshot_destination_not_create_only")
    if source.stat().st_size > max_bytes:
        raise ValueError("source_size_budget_exceeded")
    expected = expected_sha256 or _sha256_bounded(source, max_bytes)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if _path_has_link(destination.parent):
        raise ValueError("snapshot_destination_not_create_only")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent))
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    copied = 0
    try:
        with os.fdopen(fd, "wb") as writer, source.open("rb") as reader:
            while chunk := reader.read(min(1024 * 1024, max_bytes - copied + 1)):
                if cancel_check is not None and cancel_check():
                    raise SnapshotCancelled("snapshot_cancelled")
                copied += len(chunk)
                if copied > max_bytes:
                    raise ValueError("source_size_budget_exceeded")
                writer.write(chunk)
                digest.update(chunk)
            if cancel_check is not None and cancel_check():
                raise SnapshotCancelled("snapshot_cancelled")
            writer.flush()
            os.fsync(writer.fileno())
        observed = digest.hexdigest()
        if observed != expected or _sha256_bounded(source, max_bytes) != expected:
            raise ValueError("source_changed_during_snapshot")
        if cancel_check is not None and cancel_check():
            raise SnapshotCancelled("snapshot_cancelled")
        try:
            os.link(temporary, destination)
        except FileExistsError:
            raise ValueError("snapshot_destination_not_create_only") from None
        return observed
    finally:
        temporary.unlink(missing_ok=True)


def build_manifest(target: Path, run_dir: Path, *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    target = Path(target)
    run_dir = Path(run_dir)
    if _has_link_or_reparse_component(target) or not target.is_file():
        raise ValueError("target_must_be_regular_file")
    if _is_hardlinked_regular_file(target):
        raise ValueError("target_hardlink_not_allowed")
    if _has_link_or_reparse_component(run_dir) or not run_dir.is_dir():
        raise ValueError("run_dir_must_be_regular_directory")
    if metadata is not None:
        try:
            json.dumps(metadata, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError):
            raise ValueError("metadata_not_serializable") from None
    resolved_run = run_dir.resolve()
    files: list[dict[str, Any]] = []
    for path in sorted(resolved_run.rglob("*")):
        # angr's per-input LMDB spill database is mutable analysis state. It is
        # removed during worker shutdown and is never an evidence artifact.
        if any("_angr_rtdb" in component.name for component in (path, *path.parents)):
            continue
        relative_name = path.relative_to(resolved_run).as_posix()
        if relative_name in {"manifest.json", "run.lock"}:
            if _has_link_or_reparse_component(path):
                raise ValueError("symlinked_control_file_not_allowed")
            if _is_hardlinked_regular_file(path):
                raise ValueError("hardlinked_control_file_not_allowed")
            continue
        if _has_link_or_reparse_component(path):
            raise ValueError("linked_artifact_not_allowed")
        if path.is_file():
            if _is_hardlinked_regular_file(path):
                raise ValueError("hardlinked_artifact_not_allowed")
            if relative_name in {"", "."} or relative_name.startswith("../") or "/../" in relative_name:
                raise ValueError("artifact_path_escape")
            files.append({"path": relative_name, "sha256": sha256_file(path), "size": path.stat().st_size})
    return {
        "schema": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "target_sha256": sha256_file(target),
        "files": files,
        "metadata": metadata or {},
    }


def write_manifest_atomic(manifest: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def sha256_file_bounded(path: Path, max_bytes: int) -> str:
    """Public bounded hash primitive used by the evidence kernel."""
    return _sha256_bounded(path, max_bytes)
