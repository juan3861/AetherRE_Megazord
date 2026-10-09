"""Detached custody receipts for local evidence bundles.

A receipt commits to a sorted set of artifacts with a Merkle-like root and an
optional previous receipt hash. It is a local integrity witness, not a WORM or
external notarization service; the report says so explicitly.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

SCHEMA = "custody-receipt.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_link(path: Path) -> bool:
    current = path.absolute()
    while True:
        try:
            if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
                return True
        except OSError:
            return True
        if current.parent == current:
            return False
        current = current.parent


def _artifact_name(name: object) -> str | None:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        return None
    return name


def _root(entries: list[dict[str, Any]]) -> str:
    canonical = "".join(f"{entry['name']}\0{entry['size']}\0{entry['sha256']}\n" for entry in sorted(entries, key=lambda item: item["name"]))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _invalid(code: str, *, receipt: Path | None = None, issues: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "invalid", "receipt": str(receipt) if receipt else "", "issues": issues or [{"code": code}], "artifacts": [], "external_anchor": False}


def create_custody_receipt(
    artifacts: Mapping[str, Path],
    output: Path,
    *,
    metadata: Mapping[str, Any] | None = None,
    previous_receipt: Path | None = None,
    immutable: bool = False,
) -> dict[str, Any]:
    """Create one detached, hash-chained receipt without copying artifacts."""
    output = Path(output).resolve()
    if output.exists() or output.is_symlink() or _has_link(output.parent):
        return _invalid("receipt_destination_must_be_new", receipt=output)
    if not isinstance(artifacts, Mapping) or not artifacts:
        return _invalid("artifacts_required", receipt=output)
    if metadata is not None:
        try:
            json.dumps(dict(metadata), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError):
            return _invalid("metadata_invalid", receipt=output)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_name, raw_path in artifacts.items():
        name = _artifact_name(raw_name)
        if name is None or name in seen:
            return _invalid("artifact_name_invalid", receipt=output)
        seen.add(name)
        try:
            path = Path(raw_path).resolve()
        except (TypeError, ValueError, OSError, RuntimeError):
            return _invalid("artifact_path_invalid", receipt=output)
        if _has_link(path) or not path.is_file():
            return _invalid("artifact_must_be_regular_file", receipt=output)
        try:
            size = path.stat().st_size
        except OSError:
            return _invalid("artifact_stat_failed", receipt=output)
        entries.append({"name": name, "path": str(path), "size": size, "sha256": _sha256(path)})
    previous_hash = ""
    if previous_receipt is not None:
        previous = Path(previous_receipt).resolve()
        if _has_link(previous) or not previous.is_file():
            return _invalid("previous_receipt_invalid", receipt=output)
        previous_hash = _sha256(previous)
    receipt = {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": sorted(entries, key=lambda item: item["name"]),
        "artifact_root": _root(entries),
        "previous_receipt_sha256": previous_hash,
        "metadata": dict(metadata or {}),
        "custody": {
            "local_integrity": True,
            "external_anchor": False,
            "anchor_required_for_worm": True,
            "mode": "local_detached_hash_chain",
        },
        "limitations": [
            "hashes e cadeia são locais; não são WORM nem notariação externa",
            "um administrador com acesso ao diretório pode substituir recibo e artefatos",
            "integridade não prova verdade semântica ou equivalência do alvo",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
        if immutable:
            mode = output.stat().st_mode
            os.chmod(output, mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    finally:
        temporary.unlink(missing_ok=True)
    verification = verify_custody_receipt(output, require_sealed=immutable)
    return {"schema": SCHEMA, "status": "created" if verification["status"] == "pass" else "invalid", "receipt": str(output), "receipt_sha256": _sha256(output), "artifact_root": receipt["artifact_root"], "artifact_count": len(entries), "verification": verification, "custody": receipt["custody"]}


def verify_custody_receipt(receipt: Path, *, require_sealed: bool = False, expected_artifacts: Mapping[str, Path] | None = None) -> dict[str, Any]:
    receipt = Path(receipt)
    issues: list[dict[str, str]] = []
    if _has_link(receipt) or not receipt.is_file():
        return _invalid("receipt_missing_or_link", receipt=receipt)
    try:
        if receipt.stat().st_size > 32 * 1024 * 1024:
            return _invalid("receipt_too_large", receipt=receipt)
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _invalid("receipt_invalid", receipt=receipt, issues=[{"code": "receipt_invalid", "detail": type(exc).__name__}])
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("artifacts"), list):
        return _invalid("receipt_schema_invalid", receipt=receipt)
    entries = data["artifacts"]
    names: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or _artifact_name(entry.get("name")) is None or entry.get("name") in names:
            issues.append({"code": "artifact_entry_invalid"})
            continue
        names.add(entry["name"])
        path = Path(str(entry.get("path", "")))
        digest = entry.get("sha256")
        size = entry.get("size")
        if _has_link(path) or not path.is_file() or not isinstance(size, int) or isinstance(size, bool) or size < 0 or not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            issues.append({"code": "artifact_invalid", "name": entry["name"]})
            continue
        observed_size = path.stat().st_size
        observed_hash = _sha256(path)
        if observed_size != size or observed_hash != digest:
            issues.append({"code": "artifact_hash_mismatch", "name": entry["name"]})
        normalized.append({"name": entry["name"], "size": size, "sha256": digest})
        if expected_artifacts is not None:
            expected = expected_artifacts.get(entry["name"])
            if expected is None or Path(expected).resolve() != path.resolve():
                issues.append({"code": "artifact_path_mismatch", "name": entry["name"]})
    declared_root = data.get("artifact_root")
    if not isinstance(declared_root, str) or not _SHA256_RE.fullmatch(declared_root) or _root(normalized) != declared_root:
        issues.append({"code": "artifact_root_mismatch"})
    custody = data.get("custody")
    if not isinstance(custody, dict) or custody.get("external_anchor") is not False:
        issues.append({"code": "custody_declaration_invalid"})
    if require_sealed:
        try:
            if receipt.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                issues.append({"code": "receipt_not_read_only"})
        except OSError:
            issues.append({"code": "receipt_unstatable"})
    return {"schema": SCHEMA, "status": "pass" if not issues else "fail", "receipt": str(receipt.resolve()), "artifact_count": len(normalized), "artifact_root": declared_root if isinstance(declared_root, str) else "", "issues": issues, "external_anchor": False, "limitations": data.get("limitations", [])}


def write_custody_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
