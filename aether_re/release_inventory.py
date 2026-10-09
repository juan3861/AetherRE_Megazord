"""Create-only, non-certifying inventory of explicitly named release files.

This module records point-in-time file presence, size, and SHA-256 values. It
does not evaluate gate truth, run tests, produce ``release-manifest.v1``, or
authorize promotion. Path checks reject static traversal/link aliases but are
not race-proof against a concurrent local writer.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PureWindowsPath
from typing import Any, Sequence


SCHEMA = "release-inventory.v1"
_GATE_STATUSES = frozenset(
    {"QUITADA", "PARCIALMENTE QUITADA", "NÃO QUITADA", "NÃO COMPROVADA"}
)
_GATE_IDS = frozenset(f"F{index:02d}" for index in range(13))


class ReleaseInventoryError(ValueError):
    """Stable fail-closed error for unsafe or invalid inventory input."""


def _fail(code: str) -> None:
    raise ReleaseInventoryError(code)


def _components(path: Path) -> list[Path]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    result = [current]
    for part in absolute.parts[1:]:
        current = current / part
        result.append(current)
    return result


def _check_path_components(path: Path, *, kind: str, reject_hardlink: bool = False) -> None:
    """Reject existing symlink, junction, reparse, and optionally hardlink components."""
    final = Path(os.path.abspath(os.fspath(path)))
    final_info: os.stat_result | None = None
    for component in _components(final):
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            continue
        except OSError:
            _fail(f"{kind}_path_uninspectable")

        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        is_junction = getattr(os.path, "isjunction", None)
        try:
            junction = bool(is_junction and is_junction(component))
        except OSError:
            _fail(f"{kind}_path_uninspectable")
        if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag or junction:
            _fail(f"{kind}_link_or_reparse")
        if component == final:
            final_info = info

    if (
        reject_hardlink
        and final_info is not None
        and stat.S_ISREG(final_info.st_mode)
        and getattr(final_info, "st_nlink", 1) > 1
    ):
        _fail(f"{kind}_hardlink")


def _relative_path(value: Any, *, kind: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail(f"{kind}_path_invalid")
    relative = Path(value)
    windows = PureWindowsPath(value)
    if (
        relative.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or relative == Path(".")
        or not relative.parts
        or ".." in relative.parts
        or any(":" in part for part in relative.parts)
    ):
        _fail(f"{kind}_path_invalid")
    return relative, relative.as_posix()


def _win32_alias_key(relative: Path) -> str:
    """Return a conservative Win32 name key without permitting ADS syntax.

    Win32 normally treats names case-insensitively and strips trailing spaces
    and dots from each component.  The stricter key is applied on every host so
    an inventory prepared elsewhere cannot acquire aliases when moved to
    Windows.  Colons have already been rejected by :func:`_relative_path`.
    """
    components = tuple(
        part.rstrip(" .").casefold()
        for part in PureWindowsPath(os.fspath(relative)).parts
    )
    if not components or any(not part for part in components):
        _fail("inventory_path_win32_alias_invalid")
    return "/".join(components)


def _safe_root(value: Path | str) -> Path:
    root_arg = Path(value)
    _check_path_components(root_arg, kind="root")
    try:
        root = root_arg.resolve(strict=True)
        info = root.stat(follow_symlinks=False)
    except (OSError, RuntimeError, ValueError):
        _fail("root_invalid")
    if not stat.S_ISDIR(info.st_mode):
        _fail("root_invalid")
    return root


def _confined_path(root: Path, relative: Path, *, kind: str, reject_hardlink: bool = False) -> Path:
    candidate = root / relative
    _check_path_components(candidate, kind=kind, reject_hardlink=reject_hardlink)
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        _fail(f"{kind}_root_escape")
    return candidate


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and getattr(left, "st_mtime_ns", None) == getattr(right, "st_mtime_ns", None)
        and getattr(left, "st_nlink", 1) == getattr(right, "st_nlink", 1)
    )


def _fingerprint(path: Path, *, relative_name: str) -> tuple[dict[str, Any], tuple[int, int]]:
    try:
        before_path = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before_path.st_mode):
            _fail("input_not_regular_file")
        if getattr(before_path, "st_nlink", 1) > 1:
            _fail("input_hardlink")

        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as handle:
            before_fd = os.fstat(handle.fileno())
            if not stat.S_ISREG(before_fd.st_mode) or getattr(before_fd, "st_nlink", 1) > 1:
                _fail("input_changed_during_hash")
            if not _same_file_state(before_path, before_fd):
                _fail("input_changed_during_hash")
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                total += len(chunk)
                digest.update(chunk)
            after_fd = os.fstat(handle.fileno())
        after_path = path.stat(follow_symlinks=False)
    except ReleaseInventoryError:
        raise
    except OSError:
        _fail("input_unreadable")

    if (
        not _same_file_state(before_fd, after_fd)
        or not _same_file_state(after_fd, after_path)
        or total != after_fd.st_size
    ):
        _fail("input_changed_during_hash")
    return (
        {"path": relative_name, "present": True, "size_bytes": total, "sha256": digest.hexdigest()},
        (after_fd.st_dev, after_fd.st_ino),
    )


def _gate_claims(values: Sequence[str] | None) -> list[dict[str, Any]]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail("gate_claims_invalid")
    claims: dict[str, str] = {}
    for raw in values:
        if not isinstance(raw, str) or "=" not in raw:
            _fail("gate_claim_invalid")
        gate, claimed_status = raw.split("=", 1)
        if gate not in _GATE_IDS or claimed_status not in _GATE_STATUSES or gate in claims:
            _fail("gate_claim_invalid")
        claims[gate] = claimed_status
    return [
        {"gate": gate, "claimed_status": claims[gate], "verified": False}
        for gate in sorted(claims)
    ]


def _write_create_only(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        _fail("inventory_output_exists")
    except OSError:
        _fail("inventory_output_create_failed")

    try:
        with os.fdopen(fd, "wb") as handle:
            remaining = memoryview(payload)
            while remaining:
                written = handle.write(remaining)
                if not written:
                    _fail("inventory_output_write_failed")
                remaining = remaining[written:]
            handle.flush()
            os.fsync(handle.fileno())
    except ReleaseInventoryError:
        raise
    except OSError:
        _fail("inventory_output_write_failed")


def create_release_inventory(
    root: Path | str,
    files: Sequence[str],
    *,
    output: str,
    gate_claims: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Hash explicitly named files and create a non-certifying inventory JSON.

    Missing listed files are recorded as absent. Existing inputs and the new
    output must resolve beneath ``root`` and may not traverse link/reparse
    components. The output is a new file only; existing destinations are never
    replaced. Gate status strings are retained solely as unverified claims.
    """
    resolved_root = _safe_root(root)
    if isinstance(files, (str, bytes)) or not isinstance(files, Sequence) or not files:
        _fail("inventory_files_required")

    output_relative, output_name = _relative_path(output, kind="output")
    output_alias_key = _win32_alias_key(output_relative)
    output_path = _confined_path(resolved_root, output_relative, kind="output", reject_hardlink=True)
    output_parent = output_path.parent
    try:
        parent_info = output_parent.stat(follow_symlinks=False)
    except OSError:
        _fail("output_parent_missing")
    if not stat.S_ISDIR(parent_info.st_mode):
        _fail("output_parent_invalid")
    _check_path_components(output_parent, kind="output")
    if output_path.exists():
        _fail("inventory_output_exists")
    requested: dict[str, Path] = {}
    requested_aliases: set[str] = set()
    for value in files:
        relative, canonical = _relative_path(value, kind="input")
        alias_key = _win32_alias_key(relative)
        if canonical in requested or alias_key in requested_aliases:
            _fail("inventory_input_duplicate")
        requested[canonical] = relative
        requested_aliases.add(alias_key)
    if output_name in requested or output_alias_key in requested_aliases:
        _fail("output_cannot_be_input")

    entries: list[dict[str, Any]] = []
    physical_inputs: set[tuple[int, int]] = set()
    for relative_name, relative in sorted(requested.items()):
        path = _confined_path(resolved_root, relative, kind="input", reject_hardlink=True)
        for ancestor in path.parents:
            if ancestor == resolved_root:
                break
            try:
                ancestor_info = ancestor.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                _fail("input_path_uninspectable")
            if not stat.S_ISDIR(ancestor_info.st_mode):
                _fail("input_parent_not_directory")
        try:
            path.stat(follow_symlinks=False)
        except FileNotFoundError:
            entries.append({"path": relative_name, "present": False, "size_bytes": None, "sha256": None})
            continue
        except OSError:
            _fail("input_uninspectable")
        entry, identity = _fingerprint(path, relative_name=relative_name)
        if identity in physical_inputs:
            _fail("inventory_input_duplicate")
        physical_inputs.add(identity)
        entries.append(entry)

    claims = _gate_claims(gate_claims)
    present_count = sum(entry["present"] is True for entry in entries)
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "inventory_status": "PARTIAL_INVENTORY",
        "root": str(resolved_root),
        "summary": {"listed": len(entries), "present": present_count, "missing": len(entries) - present_count},
        "files": entries,
        "gate_claims": claims,
        "certification_status": "NOT_CERTIFIED",
        "promoted_gates": [],
        "gate_truth_recalculated": False,
        "manifest_built": False,
        "release_manifest_generated": False,
        "limitations": [
            "inventaria apenas os caminhos explicitamente listados",
            "claims de gate são texto não verificado e não alteram nenhum gate",
            "presença, tamanho e SHA-256 não provam validade semântica nem truth de gate",
            "checagens de caminho são pontuais e não impedem TOCTOU por escritor local concorrente",
        ],
    }
    encoded = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_create_only(output_path, encoded)
    return report


__all__ = ["ReleaseInventoryError", "create_release_inventory"]
