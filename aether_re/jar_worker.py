"""Hash-pinned Java archive workers used by static profile adapters.

The ordinary toolchain lock binds one executable. Java tools need two trust
anchors: the runtime and the JAR passed to it. This module preserves that
boundary and never invokes a command interpreter.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = re.compile(r"[|&;<>\x00\r\n]|(?:^|[\\/])\.\.(?:[\\/]|$)|^@")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class JarWorkerSpec:
    name: str
    java_executable: Path
    java_sha256: str
    archive: Path
    archive_sha256: str
    expected_version: str
    license_spdx: str
    version_args: tuple[str, ...] = ("--version",)
    timeout_s: float = 60.0
    max_output_bytes: int = 8 * 1024 * 1024


def probe_jar_worker(spec: JarWorkerSpec) -> dict[str, Any]:
    """Verify both immutable inputs and perform a bounded version probe."""
    errors: list[str] = []
    if not _SHA256.fullmatch(spec.java_sha256) or not _SHA256.fullmatch(spec.archive_sha256):
        errors.append("worker_hash_invalid")
    if not spec.expected_version or not spec.version_args or any(_FORBIDDEN.search(arg) for arg in spec.version_args):
        errors.append("worker_probe_arguments_invalid")
    try:
        java = spec.java_executable.resolve(strict=True)
        archive = spec.archive.resolve(strict=True)
        if not java.is_file() or _sha256(java) != spec.java_sha256:
            errors.append("java_hash_mismatch")
        if not archive.is_file() or _sha256(archive) != spec.archive_sha256:
            errors.append("archive_hash_mismatch")
        if errors:
            return {"schema": "jar-worker-probe.v1", "name": spec.name, "available": False, "errors": errors}
        result = subprocess.run(
            [str(java), "-jar", str(archive), *spec.version_args], shell=False,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=min(spec.timeout_s, 15), cwd=str(archive.parent), check=False,
        )
        text = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode != 0 or spec.expected_version not in text:
            errors.append("worker_version_mismatch")
        if len(text.encode("utf-8")) > spec.max_output_bytes:
            errors.append("worker_output_limit_exceeded")
        return {
            "schema": "jar-worker-probe.v1", "name": spec.name,
            "available": not errors, "version_output": text[:4096], "errors": errors,
        }
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"schema": "jar-worker-probe.v1", "name": spec.name, "available": False, "errors": [f"worker_probe_failed:{exc.__class__.__name__}"]}


def verify_jar_workers_lock(path: str | Path) -> dict[str, Any]:
    """Rehash Java runtimes and archives from a v1 lock without executing them."""
    required = {'name','version','license_spdx','profiles','official_url','java_executable','java_sha256','archive','archive_sha256','version_argv'}
    try:
        raw = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(raw, dict) or raw.get('schema') != 'jar-workers-lock.v1' or set(raw) != {'schema','policy','workers'} or not isinstance(raw['workers'], list) or not raw['workers']:
            raise ValueError('jar_workers_lock_schema_invalid')
        rows=[]; names=set()
        for item in raw['workers']:
            if not isinstance(item,dict) or set(item) != required or not isinstance(item['name'],str) or not item['name'] or item['name'] in names:
                raise ValueError('jar_workers_lock_schema_invalid')
            names.add(item['name'])
            java=Path(item['java_executable']); archive=Path(item['archive'])
            java_actual=_sha256(java) if java.is_file() else None; archive_actual=_sha256(archive) if archive.is_file() else None
            state='verified' if java_actual==item['java_sha256'] and archive_actual==item['archive_sha256'] else ('java_hash_mismatch' if java_actual is not None and java_actual!=item['java_sha256'] else ('archive_hash_mismatch' if archive_actual is not None and archive_actual!=item['archive_sha256'] else 'worker_file_missing'))
            rows.append({'name':item['name'],'state':state,'expected_java_sha256':item['java_sha256'],'observed_java_sha256':java_actual or '','expected_archive_sha256':item['archive_sha256'],'observed_archive_sha256':archive_actual or ''})
        return {'schema':'jar-workers-verification.v1','verified':all(x['state']=='verified' for x in rows),'workers':rows,'limitations':['verification rehashes runtime and archive bytes only; it does not execute tools or prove analysis quality']}
    except (OSError,UnicodeError,json.JSONDecodeError,ValueError) as exc:
        return {'schema':'jar-workers-verification.v1','verified':False,'workers':[],'errors':[str(exc) or 'jar_workers_lock_invalid']}


__all__ = ["JarWorkerSpec", "probe_jar_worker", "verify_jar_workers_lock"]
