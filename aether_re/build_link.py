"""Conservative source/build/binary provenance linkage by declared output and hashes.

This module never invokes a compiler or executes the target.  A ``linked``
result means that a compilation database declares the binary output and that
the declared source hashes and optional binary report hash match the files on
disk.  It is custody/provenance evidence, not semantic equivalence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "build-artifact-link.v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_declared(value: object, *, directory: Path, root: Path) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value.strip().strip('"'))
    if not candidate.is_absolute():
        candidate = directory / candidate
    try:
        return candidate.resolve()
    except OSError:
        return None


def link_build_artifact(
    build_report: dict[str, Any],
    binary_path: Path,
    *,
    binary_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify declared build-output linkage without executing any target."""
    base = {
        "schema": SCHEMA,
        "status": "invalid",
        "executed": False,
        "equivalence_proven": False,
        "binary": str(Path(binary_path)),
        "matches": [],
        "errors": [],
        "limitations": [
            "compile_commands é declaração de build, não prova de execução",
            "hashes provam identidade de arquivos, não equivalência semântica",
            "debug info, linker inputs transitivos e comportamento permanecem não comprovados",
        ],
    }
    if not isinstance(build_report, dict):
        base["errors"] = [{"code": "build_report_must_be_object"}]
        return base
    binary = Path(binary_path)
    if not binary.is_file() or binary.is_symlink():
        base["errors"] = [{"code": "binary_must_be_regular_file"}]
        return base
    root = Path(str(build_report.get("root") or binary.parent)).resolve()
    units = build_report.get("compile_commands", [])
    if not isinstance(units, list):
        base["errors"] = [{"code": "compile_commands_must_be_list"}]
        return base
    binary_resolved = binary.resolve()
    binary_sha256 = _sha256(binary)
    report_sha256 = None
    if isinstance(binary_report, dict):
        report_sha256 = binary_report.get("target_sha256") or (binary_report.get("target_identity") or {}).get("sha256")
        if report_sha256 is not None and (not isinstance(report_sha256, str) or len(report_sha256) != 64 or report_sha256.lower() != binary_sha256):
            base["errors"].append({"code": "binary_report_hash_mismatch", "observed": binary_sha256, "declared": report_sha256})
    candidates: list[dict[str, Any]] = []
    for index, raw in enumerate(units):
        if not isinstance(raw, dict):
            continue
        directory = _resolve_declared(raw.get("directory"), directory=root, root=root) or root
        output = _resolve_declared(raw.get("output"), directory=directory, root=root)
        if output is None or output != binary_resolved:
            continue
        source = _resolve_declared(raw.get("file"), directory=directory, root=root)
        source_observed = _sha256(source) if source is not None and source.is_file() and not source.is_symlink() else None
        declared = raw.get("source_sha256")
        candidates.append({
            "index": index,
            "file": raw.get("file"),
            "output": raw.get("output"),
            "source_sha256_declared": declared,
            "source_sha256_observed": source_observed,
            "source_hash_match": isinstance(declared, str) and declared == source_observed,
            "output_match": True,
            "compiler": raw.get("compiler"),
        })
    base.update({"binary_sha256": binary_sha256, "binary_report_sha256": report_sha256, "matches": candidates})
    if base["errors"]:
        base["status"] = "invalid"
        return base
    if not candidates:
        base["status"] = "unmatched"
        base["reason"] = "declared_output_not_found"
        return base
    source_ok = all(item["source_hash_match"] for item in candidates)
    base["status"] = "linked" if source_ok else "partial"
    base["proof"] = {
        "method": "declared_compile_commands_plus_content_hash",
        "output_declared": True,
        "source_hashes_match": source_ok,
        "binary_hash_observed": binary_sha256,
        "binary_hash_matches_report": report_sha256 is None or report_sha256 == binary_sha256,
    }
    return base


def write_build_link_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
