"""Phase 0, non-destructive custody and reproducibility inventory.

The snapshot deliberately contains metadata and hashes only.  It never copies or
executes project content, and redacts secret candidates by policy rather than
trying to infer whether a value is actually sensitive.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = "custody-snapshot.v1"
MANIFEST_NAME = "custody-snapshot.v1.json"
CACHE_DIRECTORIES = frozenset({
    ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".venv",
    "venv", "__pycache__", "node_modules", "htmlcov", ".eggs",
})
BUILD_DIRECTORIES = frozenset({"build", "dist", "output", "artifacts", "coverage"})
# These roots can contain whole Git object databases, generated output, or raw corpora.
# They are recorded as excluded directory roots and never recursively traversed.
PRUNED_DIRECTORY_REASONS = {".git": "repository_metadata", "corpus": "corpus_material", "output": "build_artifact_directory", "build": "build_artifact_directory", "dist": "build_artifact_directory", "artifacts": "build_artifact_directory", "node_modules": "cache_directory"}
BUILD_ARTIFACT_EXTENSIONS = frozenset({
    ".obj", ".pdb", ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo",
    ".tmp", ".temp", ".dmp", ".dump",
})
SECRET_EXTENSIONS = frozenset({".pem", ".key", ".pfx", ".p12", ".kdbx"})
SECRET_NAME = re.compile(r"(?:^|[._-])(secret|credential|password|token|api[_-]?key)(?:[._-]|$)", re.IGNORECASE)


def _has_link(path: Path) -> bool:
    """Reject a symlink or junction at any point in a path."""
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


def _stable_sha256(path: Path) -> tuple[str, int]:
    before = path.stat()
    signature = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            count += len(chunk)
    after = path.stat()
    after_signature = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if signature != after_signature or count != before.st_size:
        raise ValueError(f"custody_file_changed_during_hash:{path}")
    return digest.hexdigest(), count


def _run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, check=False)
    except OSError:
        return None


def _git_metadata(root: Path) -> tuple[dict[str, Any], set[str], set[str]]:
    head = _run_git(root, "rev-parse", "HEAD")
    branch = _run_git(root, "branch", "--show-current")
    status = _run_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    tracked = _run_git(root, "ls-files", "-z")
    if head is None or head.returncode != 0:
        return ({"available": False, "head": None, "branch": None, "status_entries": [], "reason": "git_unavailable_or_not_repository"}, set(), set())
    status_entries: list[dict[str, str]] = []
    untracked: set[str] = set()
    raw = status.stdout.split(b"\0") if status and status.returncode == 0 else []
    for record in raw:
        if not record:
            continue
        text = record.decode("utf-8", "surrogateescape")
        if len(text) < 4:
            continue
        code, path = text[:2], text[3:]
        status_entries.append({"code": code, "path": path})
        if code == "??":
            untracked.add(path.replace("\\", "/"))
    tracked_paths = {
        item.decode("utf-8", "surrogateescape").replace("\\", "/")
        for item in (tracked.stdout.split(b"\0") if tracked and tracked.returncode == 0 else [])
        if item
    }
    return ({
        "available": True,
        "head": head.stdout.decode("ascii", "replace").strip(),
        "branch": branch.stdout.decode("utf-8", "surrogateescape").strip() if branch and branch.returncode == 0 else None,
        "status_entries": status_entries,
        "status_sha256": hashlib.sha256(status.stdout if status else b"").hexdigest(),
    }, tracked_paths, untracked)


def _exclusion_for(path: Path, relative: str) -> str | None:
    parts = [part.casefold() for part in Path(relative).parts]
    if any(part in CACHE_DIRECTORIES for part in parts[:-1]):
        return "cache_directory"
    if any(part in BUILD_DIRECTORIES for part in parts[:-1]):
        return "build_artifact_directory"
    if path.suffix.casefold() in BUILD_ARTIFACT_EXTENSIONS:
        return "build_artifact_extension"
    return None


def _secret_reasons(path: Path) -> list[str]:
    suffix = path.suffix.casefold()
    name = path.name.casefold()
    reasons: list[str] = []
    if suffix in SECRET_EXTENSIONS:
        reasons.append("sensitive_extension")
    if name == ".env" or name.startswith(".env."):
        reasons.append("environment_file")
    if SECRET_NAME.search(path.name):
        reasons.append("sensitive_filename")
    return reasons


def _walk_regular_files(root: Path) -> Iterator[Path]:
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        parent = Path(current)
        directories[:] = sorted(
            name for name in directories
            if not (parent / name).is_symlink() and name.casefold() not in PRUNED_DIRECTORY_REASONS
        )
        for name in sorted(names):
            path = parent / name
            if path.is_symlink():
                continue
            try:
                if path.is_file():
                    yield path
            except OSError:
                continue


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha512(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha512(payload).hexdigest()


def capture_custody_snapshot(
    root: Path,
    output_dir: Path,
    *,
    signing_key: bytes | None = None,
) -> dict[str, Any]:
    """Create a hash manifest in a new external directory without copying inputs.

    The caller must select a non-existent output directory outside ``root``.  This
    makes the result create-only and avoids the manifest contaminating its own
    inventory.
    """
    root = Path(root).absolute()
    output_dir = Path(output_dir).absolute()
    if _has_link(root) or not root.is_dir():
        raise ValueError("custody_snapshot_root_invalid")
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError("custody_snapshot_destination_exists")
    if output_dir.resolve().is_relative_to(root.resolve()):
        raise ValueError("custody_snapshot_destination_inside_source")
    if _has_link(output_dir.parent):
        raise ValueError("custody_snapshot_destination_parent_invalid")

    git, tracked, untracked = _git_metadata(root)
    files: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for child in sorted(root.iterdir(), key=lambda item: item.name.casefold()):
        reason = PRUNED_DIRECTORY_REASONS.get(child.name.casefold())
        if reason and child.is_dir() and not child.is_symlink():
            excluded.append({"path": child.name, "reason": reason, "action": "not_recursively_traversed"})
    for path in _walk_regular_files(root):
        relative = path.relative_to(root).as_posix()
        exclusion = _exclusion_for(path, relative)
        if exclusion:
            excluded.append({"path": relative, "reason": exclusion, "action": "not_copied_or_hashed"})
            continue
        digest, size = _stable_sha256(path)
        secret_reasons = _secret_reasons(path)
        files.append({
            "path": relative,
            "size": size,
            "sha256": digest,
            "git_classification": "tracked" if relative in tracked else "untracked" if relative in untracked else "untracked_or_ignored",
            "secret_candidate": bool(secret_reasons),
            "secret_reasons": secret_reasons,
            "content_copied": False,
        })
    files.sort(key=lambda item: item["path"])
    excluded.sort(key=lambda item: item["path"])
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(root.resolve()),
        "output": str((output_dir / MANIFEST_NAME).resolve()),
        "git": git,
        "files": files,
        "excluded": excluded,
        "policy": {
            "cache_directories": sorted(CACHE_DIRECTORIES),
            "build_directories": sorted(BUILD_DIRECTORIES),
            "build_artifact_extensions": sorted(BUILD_ARTIFACT_EXTENSIONS),
            "secret_extensions": sorted(SECRET_EXTENSIONS),
            "secret_filename_rule": SECRET_NAME.pattern,
            "destructive_actions": False,
            "content_copy": False,
        },
        "limitations": [
            "manifesto local de hashes; não é arquivo WORM nem atestação externa",
            "candidatos a segredo são identificados por nome/extensão, sem inspeção de conteúdo",
            "arquivos excluídos são apenas registrados; nenhum arquivo de origem é removido",
        ],
    }
    inventory_payload = {"files": files, "excluded": excluded, "git": git}
    report["inventory_sha256"] = _canonical_sha256(inventory_payload)
    report["inventory_sha512"] = _canonical_sha512(inventory_payload)
    if signing_key is not None:
        canonical = json.dumps(inventory_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        report["attestation"] = {
            "algorithm": "HMAC-SHA512",
            "signature_hex": hmac.new(signing_key, canonical, hashlib.sha512).hexdigest(),
        }
    output_dir.mkdir(parents=True, exist_ok=False)
    destination = output_dir / MANIFEST_NAME
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # The directory is newly owned by this failed operation; do not touch source.
        try:
            destination.unlink(missing_ok=True)
            output_dir.rmdir()
        except OSError:
            pass
        raise
    return report


def verify_custody_snapshot(
    manifest_path: Path | str,
    *,
    signing_key: bytes | None = None,
    verify_files_on_disk: bool = True,
) -> dict[str, Any]:
    """Verify integrity, SHA-256/SHA-512 canonical digests, and optional HMAC-SHA512 attestation."""
    mp = Path(manifest_path)
    if not mp.is_file():
        raise FileNotFoundError(f"Custody manifest not found: {mp}")
    data = json.loads(mp.read_text(encoding="utf-8"))
    inventory_payload = {
        "files": data.get("files", []),
        "excluded": data.get("excluded", []),
        "git": data.get("git", {}),
    }
    expected_256 = _canonical_sha256(inventory_payload)
    expected_512 = _canonical_sha512(inventory_payload)
    sha256_ok = data.get("inventory_sha256") == expected_256
    sha512_ok = (data.get("inventory_sha512") is None) or (data.get("inventory_sha512") == expected_512)

    hmac_ok: bool | None = None
    att = data.get("attestation")
    if signing_key is not None and isinstance(att, dict):
        canonical = json.dumps(inventory_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_sig = hmac.new(signing_key, canonical, hashlib.sha512).hexdigest()
        hmac_ok = hmac.compare_digest(expected_sig, str(att.get("signature_hex", "")))

    tampered_files: list[str] = []
    missing_files: list[str] = []
    if verify_files_on_disk and data.get("source_root"):
        root = Path(data["source_root"])
        for entry in data.get("files", []):
            fp = root / entry["path"]
            if not fp.is_file():
                missing_files.append(entry["path"])
                continue
            digest, size = _stable_sha256(fp)
            if digest != entry.get("sha256") or size != entry.get("size"):
                tampered_files.append(entry["path"])

    verified = bool(sha256_ok and sha512_ok and (hmac_ok is not False) and not tampered_files and not missing_files)
    return {
        "schema": "custody-verify.v1",
        "manifest_path": str(mp.resolve()),
        "verified": verified,
        "inventory_sha256_ok": sha256_ok,
        "inventory_sha512_ok": sha512_ok,
        "hmac_attestation_ok": hmac_ok,
        "file_count_checked": len(data.get("files", [])),
        "tampered_files": tampered_files,
        "missing_files": missing_files,
    }


