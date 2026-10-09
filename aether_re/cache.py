"""Identidade determinística de cache para análises reproduzíveis."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from aether_re.evidence import (
    FileSizeLimitExceeded,
    MAX_MANIFEST_JSON_BYTES,
    read_bounded_bytes,
    sha256_file,
)


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class _DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object contains an ambiguous repeated key."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKeyError(key)
        value[key] = item
    return value


def _path_components(path: Path) -> list[Path]:
    """Return absolute components without resolving links before inspection."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    result = [current]
    for part in absolute.parts[1:]:
        current = current / part
        result.append(current)
    return result


def _path_safety_issue(path: Path) -> str | None:
    """Reject link/reparse traversal and multiply-linked files in evidence paths.

    Inspect each component with lstat so that symlinks, Windows junctions, and
    other reparse points cannot be hidden by resolving only the final path.
    This is a path-integrity check, not an OS-level race-proof open operation.
    """
    components = _path_components(path)
    final = components[-1]
    final_stat = None
    for component in components:
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            continue
        except OSError:
            return "path_uninspectable"
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        is_junction = getattr(os.path, "isjunction", None)
        try:
            junction = bool(is_junction and is_junction(component))
        except OSError:
            return "path_uninspectable"
        if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag or junction:
            return "reparse"
        if component == final:
            final_stat = info
    if final_stat is not None and stat.S_ISREG(final_stat.st_mode) and getattr(final_stat, "st_nlink", 1) > 1:
        return "hardlink"
    return None


def analysis_cache_key(target: Path, *, config: dict[str, Any] | None = None, schema: str = "analysis.v1") -> str:
    """Deriva chave de conteúdo sem depender de caminho ou timestamp."""
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    payload = {"target_sha256": digest.hexdigest(), "config": config or {}, "schema": schema}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def verify_manifest(manifest_path: Path, target: Path, *, expected_cache_key: str | None = None) -> tuple[bool, list[str]]:
    """Verifica manifesto e artefatos sem executar conteúdo do run.

    Path checks reject static aliases but are not race-proof against a concurrent
    local writer replacing a checked path before it is opened.
    """
    errors: list[str] = []
    manifest_safety = _path_safety_issue(manifest_path)
    if manifest_safety is not None:
        return False, [f"manifest_{manifest_safety}"]
    try:
        manifest_bytes = read_bounded_bytes(
            manifest_path, max_bytes=MAX_MANIFEST_JSON_BYTES
        )
        manifest = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=_unique_object)
    except _DuplicateJSONKeyError:
        return False, ["manifest_invalid:DuplicateJSONKeyError"]
    except FileSizeLimitExceeded:
        return False, ["manifest_size_limit_exceeded"]
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        return False, [f"manifest_invalid:{exc.__class__.__name__}"]
    if not isinstance(manifest, dict):
        return False, ["manifest_not_object"]
    if manifest.get("schema") != "evidence-manifest.v1":
        errors.append("schema_mismatch")
    target_hash = manifest.get("target_sha256")
    if not isinstance(target_hash, str) or not _SHA256_RE.fullmatch(target_hash):
        errors.append("target_hash_invalid")
    target_size: int | None = None
    target_safety = _path_safety_issue(target)
    if target_safety is not None:
        errors.append(f"target_{target_safety}")
    elif not target.is_file():
        errors.append("target_hash_mismatch")
    else:
        target_size = target.stat().st_size
        if sha256_file(target) != target_hash:
            errors.append("target_hash_mismatch")
    metadata = manifest.get("metadata", {})
    if not isinstance(metadata, dict):
        errors.append("metadata_invalid")
        metadata = {}
    if expected_cache_key is not None and metadata.get("cache_key") != expected_cache_key:
        errors.append("cache_key_mismatch")
    files = manifest.get("files", [])
    if not isinstance(files, list):
        errors.append("files_invalid")
        files = []
    run_root = manifest_path.parent.resolve()
    seen_paths: set[str] = set()
    snapshot_entry: dict[str, Any] | None = None
    for item in files:
        if not isinstance(item, dict):
            errors.append("file_entry_invalid")
            continue
        rel_value = item.get("path")
        rel_name = rel_value if isinstance(rel_value, str) else ""
        if not rel_name:
            errors.append("file_entry_path_invalid")
            continue
        if rel_name == "input.snapshot":
            snapshot_entry = item
        if rel_name in seen_paths:
            errors.append(f"duplicate_path:{rel_name}")
            continue
        seen_paths.add(rel_name)
        expected_hash = item.get("sha256")
        if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
            errors.append(f"hash_invalid:{rel_name}")
            continue
        try:
            path = (run_root / rel_name).resolve()
        except (OSError, ValueError):
            errors.append(f"path_invalid:{rel_name}")
            continue
        try:
            path.relative_to(run_root)
        except ValueError:
            errors.append(f"path_escape:{rel_name}")
            continue
        raw_path = run_root / rel_name
        artifact_safety = _path_safety_issue(raw_path)
        if artifact_safety is not None:
            errors.append(f"artifact_{artifact_safety}:{rel_name}")
            continue
        if not path.is_file():
            errors.append(f"missing:{rel_name}")
            continue
        actual_sha = sha256_file(path)
        if actual_sha != expected_hash:
            errors.append(f"hash_mismatch:{rel_name}")
        if "size" in item and (isinstance(item.get("size"), bool) or not isinstance(item.get("size"), int) or item.get("size") != path.stat().st_size):
            errors.append(f"size_mismatch:{rel_name}")
        if rel_name == "input.snapshot":
            if expected_hash != target_hash:
                errors.append("input_snapshot_target_hash_mismatch")
            declared_size = item.get("size")
            if isinstance(declared_size, bool) or not isinstance(declared_size, int):
                errors.append("input_snapshot_size_invalid")
            elif declared_size != path.stat().st_size or (target_size is not None and path.stat().st_size != target_size):
                errors.append("input_snapshot_size_mismatch")
    if snapshot_entry is None:
        errors.append("input_snapshot_missing")
    return not errors, errors
