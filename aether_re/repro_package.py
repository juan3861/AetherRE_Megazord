"""Empacotamento e verificação de uma execução para reprodução offline.

O pacote contém somente artefatos já materializados. Não inclui o alvo por
conta própria, não executa conteúdo e usa timestamps fixos para replay
byte-a-byte quando os arquivos de entrada não mudam.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from aether_re.evidence import sha256_file
from aether_re.homologation import audit_run_package


SCHEMA = "repro-package.v1"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _has_symlink_component(path: Path) -> bool:
    """Check existing components before ``Path.resolve`` removes aliases."""
    current = path
    while True:
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
        if current.parent == current:
            return False
        current = current.parent


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    # Rejeita separadores Windows e drives mesmo quando a ZIP usa nomes POSIX;
    # isso evita interpretações diferentes durante extração em outro host.
    return (
        "\x00" not in name
        and "\\" not in name
        and "//" not in name
        and not name.startswith("/")
        and not name.endswith("/")
        and ":" not in (path.parts[0] if path.parts else "")
        and not path.is_absolute()
        and ".." not in path.parts
        and "" not in path.parts
    )


def _zip_bytes(zf: zipfile.ZipFile, name: str, payload: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    zf.writestr(info, payload)


def _manifest_entry(name: str, payload: bytes) -> dict[str, Any]:
    return {"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def create_repro_package(run_dir: Path, output_zip: Path, *, require_homologation: bool = True) -> dict[str, Any]:
    """Create a deterministic ZIP and return its verification report."""
    run_dir = run_dir.resolve()
    audit = audit_run_package(run_dir)
    if require_homologation and audit["status"] != "pass":
        return {"schema": SCHEMA, "status": "rejected", "output": str(output_zip.resolve()), "homologation": audit, "issues": [{"code": "homologation_failed", "detail": "package_not_created"}]}
    source_files: list[tuple[str, bytes]] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.name == "run.lock":
            continue
        relative = path.relative_to(run_dir).as_posix()
        name = f"run/{relative}"
        if not _safe_member(name):
            return {"schema": SCHEMA, "status": "rejected", "output": str(output_zip.resolve()), "issues": [{"code": "path_escape", "detail": relative}]}
        source_files.append((name, path.read_bytes()))
    if not source_files:
        return {"schema": SCHEMA, "status": "rejected", "output": str(output_zip.resolve()), "issues": [{"code": "empty_run", "detail": "no_files"}]}
    entries = [_manifest_entry(name, payload) for name, payload in source_files]
    source_digest = hashlib.sha256("".join(f"{item['path']}\0{item['size']}\0{item['sha256']}\n" for item in entries).encode("utf-8")).hexdigest()
    audit_payload = (json.dumps(audit, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    package_meta = {
        "schema": SCHEMA,
        "source_run_dir": str(run_dir),
        "source_digest": source_digest,
        "homologation_sha256": hashlib.sha256(audit_payload).hexdigest(),
        "files": entries,
        "limitations": ["pacote não executa alvo", "reprodução depende do ambiente e das ferramentas registradas", "integridade não prova equivalência semântica"],
    }
    meta_payload = (json.dumps(package_meta, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    output_zip = output_zip.resolve()
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_zip.with_suffix(output_zip.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            _zip_bytes(zf, "package.json", meta_payload)
            _zip_bytes(zf, "homologation.json", audit_payload)
            for name, payload in source_files:
                _zip_bytes(zf, name, payload)
        temporary.replace(output_zip)
    finally:
        if temporary.exists():
            temporary.unlink()
    verification = verify_repro_package(output_zip)
    return {"schema": SCHEMA, "status": "created" if verification["status"] == "pass" else "invalid", "output": str(output_zip), "source_digest": source_digest, "file_count": len(entries), "homologation": audit, "verification": verification}


def verify_repro_package(package: Path, *, max_total_bytes: int = 512 * 1024 * 1024) -> dict[str, Any]:
    """Verify ZIP member safety, package manifest and all content hashes."""
    if isinstance(max_total_bytes, bool) or not isinstance(max_total_bytes, int) or max_total_bytes < 1:
        return {"schema": SCHEMA, "status": "fail", "package": str(package), "issues": [{"code": "max_total_bytes_invalid"}]}
    try:
        raw_package = Path(package)
        if _has_symlink_component(raw_package):
            return {"schema": SCHEMA, "status": "fail", "package": str(raw_package), "issues": [{"code": "symlink_path_forbidden"}]}
        package = raw_package.resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return {"schema": SCHEMA, "status": "fail", "package": repr(package), "issues": [{"code": "package_path_invalid", "detail": type(exc).__name__}]}
    issues: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(package) as zf:
            names = zf.namelist()
            infos = zf.infolist()
            if any(((info.external_attr >> 16) & 0o170000) == 0o120000 for info in infos):
                issues.append({"code": "symlink_member", "detail": "zip_symlinks_not_accepted"})
            declared_total = sum(max(0, int(info.file_size)) for info in infos)
            if declared_total > max_total_bytes:
                issues.append({"code": "zip_uncompressed_budget_exceeded", "detail": f"declared={declared_total} max={max_total_bytes}"})
            if len(names) != len(set(names)):
                issues.append({"code": "duplicate_member", "detail": "zip_names_not_unique"})
            for name in names:
                if not _safe_member(name):
                    issues.append({"code": "path_escape", "detail": name})
            try:
                meta = json.loads(zf.read("package.json"))
            except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                meta = None
                issues.append({"code": "package_manifest_invalid", "detail": type(exc).__name__})
            if not isinstance(meta, dict) or meta.get("schema") != SCHEMA:
                issues.append({"code": "package_schema_invalid", "detail": "repro-package.v1 required"})
            entries = meta.get("files", []) if isinstance(meta, dict) else []
            if not isinstance(entries, list) or not entries:
                issues.append({"code": "package_files_invalid", "detail": "nonempty_list_required"})
                entries = []
            listed: set[str] = set()
            valid_entries: list[dict[str, Any]] = []
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    issues.append({"code": "package_entry_invalid", "detail": "path_required"})
                    continue
                name = entry["path"]
                if name in listed:
                    issues.append({"code": "duplicate_manifest_path", "detail": name})
                    continue
                if not _safe_member(name) or not name.startswith("run/") or name == "run/":
                    issues.append({"code": "manifest_path_invalid", "detail": name})
                    continue
                if not isinstance(entry.get("sha256"), str) or not _SHA256_RE.fullmatch(entry["sha256"]):
                    issues.append({"code": "manifest_hash_invalid", "detail": name})
                    continue
                if isinstance(entry.get("size"), bool) or not isinstance(entry.get("size"), int) or entry["size"] < 0:
                    issues.append({"code": "manifest_size_invalid", "detail": name})
                    continue
                listed.add(name)
                valid_entries.append(entry)
                if name not in names:
                    issues.append({"code": "member_missing", "detail": name})
                    continue
                payload = zf.read(name)
                if entry.get("sha256") != hashlib.sha256(payload).hexdigest() or entry.get("size") != len(payload):
                    issues.append({"code": "hash_mismatch", "detail": name})
            if isinstance(meta, dict):
                source_digest = meta.get("source_digest")
                if not isinstance(source_digest, str) or not _SHA256_RE.fullmatch(source_digest):
                    issues.append({"code": "source_digest_invalid", "detail": "sha256_required"})
                else:
                    canonical = "".join(f"{entry['path']}\0{entry['size']}\0{entry['sha256']}\n" for entry in sorted(valid_entries, key=lambda item: item["path"]))
                    observed_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                    if observed_digest != source_digest:
                        issues.append({"code": "source_digest_mismatch", "detail": f"expected={source_digest} observed={observed_digest}"})
                declared_homologation_hash = meta.get("homologation_sha256")
                if not isinstance(declared_homologation_hash, str) or not _SHA256_RE.fullmatch(declared_homologation_hash):
                    issues.append({"code": "homologation_hash_invalid", "detail": "sha256_required"})
            try:
                homologation_payload = zf.read("homologation.json")
                homologation = json.loads(homologation_payload)
                if not isinstance(homologation, dict) or homologation.get("schema") != "homologation-report.v1":
                    issues.append({"code": "homologation_invalid", "detail": "homologation-report.v1 required"})
                if isinstance(meta, dict) and meta.get("homologation_sha256") != hashlib.sha256(homologation_payload).hexdigest():
                    issues.append({"code": "homologation_hash_mismatch", "detail": "metadata_vs_member"})
            except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                issues.append({"code": "homologation_invalid", "detail": type(exc).__name__})
            actual_run = {name for name in names if name.startswith("run/")}
            if actual_run != listed:
                issues.append({"code": "manifest_members_mismatch", "detail": f"listed={len(listed)} actual={len(actual_run)}"})
            expected_members = {"package.json", "homologation.json"} | listed
            for name in sorted(set(names) - expected_members):
                issues.append({"code": "unexpected_member", "detail": name})
            for name in sorted(expected_members - set(names)):
                issues.append({"code": "member_missing", "detail": name})
    except (FileNotFoundError, OSError, zipfile.BadZipFile) as exc:
        issues.append({"code": "zip_invalid", "detail": type(exc).__name__})
    return {"schema": SCHEMA, "status": "pass" if not issues else "fail", "package": str(package), "issues": issues}


def restore_repro_package(package: Path, destination: Path, *, max_total_bytes: int = 512 * 1024 * 1024) -> dict[str, Any]:
    """Safely restore the verified ``run/`` tree without executing content.

    Restoration is intentionally create-only: an existing destination is
    refused, so a replay cannot silently overwrite analyst files.  The ZIP is
    verified before extraction, every payload is re-hashed, and the completed
    tree is published with one directory rename.
    """
    schema = "repro-restore.v1"
    if isinstance(max_total_bytes, bool) or not isinstance(max_total_bytes, int) or max_total_bytes < 1:
        return {"schema": schema, "status": "invalid", "package": str(package), "destination": str(destination), "files": [], "issues": [{"code": "max_total_bytes_invalid"}]}
    try:
        raw_package = Path(package)
        raw_destination = Path(destination)
        if _has_symlink_component(raw_package) or _has_symlink_component(raw_destination):
            return {"schema": schema, "status": "rejected", "package": str(raw_package), "destination": str(raw_destination), "files": [], "issues": [{"code": "symlink_path_forbidden"}]}
        package = raw_package.resolve()
        destination = raw_destination.resolve()
    except (TypeError, ValueError, OSError, RuntimeError) as exc:
        return {"schema": schema, "status": "invalid", "package": repr(package), "destination": repr(destination), "files": [], "issues": [{"code": "path_invalid", "detail": type(exc).__name__}]}
    if package.is_symlink() or not package.is_file():
        return {"schema": schema, "status": "rejected", "package": str(package), "destination": str(destination), "files": [], "issues": [{"code": "package_missing_or_symlink"}]}
    if destination.exists():
        return {"schema": schema, "status": "rejected", "package": str(package), "destination": str(destination), "files": [], "issues": [{"code": "destination_must_not_exist"}]}
    verification = verify_repro_package(package, max_total_bytes=max_total_bytes)
    if verification.get("status") != "pass":
        return {"schema": schema, "status": "rejected", "package": str(package), "destination": str(destination), "files": [], "verification": verification, "issues": [{"code": "package_verification_failed"}]}
    temporary: Path | None = None
    restored: list[dict[str, Any]] = []
    total_bytes = 0
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.restore-", dir=str(destination.parent)))
        with zipfile.ZipFile(package) as zf:
            meta = json.loads(zf.read("package.json"))
            for entry in sorted(meta["files"], key=lambda item: item["path"]):
                member = entry["path"]
                relative = PurePosixPath(member).relative_to("run")
                target = temporary.joinpath(*relative.parts)
                # The member was already checked by verify_repro_package; keep
                # the containment check at the extraction boundary as defense
                # in depth against future changes to that verifier.
                if target.parent.resolve() != temporary.resolve() and not str(target.parent.resolve()).startswith(str(temporary.resolve()) + os.sep):
                    raise ValueError("restore_path_escape")
                payload = zf.read(member)
                if len(payload) != entry["size"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
                    raise ValueError("restore_hash_mismatch")
                total_bytes += len(payload)
                if total_bytes > max_total_bytes:
                    raise ValueError("restore_budget_exceeded")
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() or target.is_symlink():
                    raise ValueError("restore_duplicate_path")
                target.write_bytes(payload)
                restored.append({"path": relative.as_posix(), "size": len(payload), "sha256": entry["sha256"]})
        temporary.replace(destination)
        temporary = None
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        if temporary is not None:
            import shutil

            shutil.rmtree(temporary, ignore_errors=True)
        return {"schema": schema, "status": "rejected", "package": str(package), "destination": str(destination), "files": [], "verification": verification, "issues": [{"code": "restore_failed", "detail": str(exc)}]}
    return {"schema": schema, "status": "restored", "package": str(package), "destination": str(destination), "files": restored, "total_bytes": total_bytes, "verification": verification, "limitations": ["restauração não executa artefatos", "ambiente/toolchain original não é recriado", "integridade do pacote não prova equivalência semântica"]}


def write_repro_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
