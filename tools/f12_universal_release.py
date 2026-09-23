"""Fail-closed F00--F12 release evidence aggregator.

This tool only aggregates materialized evidence.  It does not run a suite,
qualify a VM, perform a clean replay, or infer that an absent proof passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "universal-release.v1"
REQUIRED_GATES = tuple(f"F{i:02d}" for i in range(13))
ALLOWED_STATUSES = {"QUITADA", "PARCIALMENTE_QUITADA", "NAO_QUITADA", "NAO_COMPROVADA"}


def _normalized_status(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return {
        "PARCIALMENTE QUITADA": "PARCIALMENTE_QUITADA",
        "NÃO QUITADA": "NAO_QUITADA",
        "NÃO COMPROVADA": "NAO_COMPROVADA",
    }.get(value, value if value in ALLOWED_STATUSES else None)


def _phase_evidence_valid(row: dict[str, Any]) -> bool:
    evidence = row.get("evidence")
    return (
        isinstance(evidence, list)
        and bool(evidence)
        and all(isinstance(item, dict) and item.get("verified") is True for item in evidence)
        and not row.get("errors")
    )


def _rows_from_document(document: Any) -> list[Any] | None:
    if not isinstance(document, dict):
        return None
    if isinstance(document.get("gates"), list):
        return document["gates"]
    if isinstance(document.get("rows"), list):
        return document["rows"]
    if isinstance(document.get("phases"), list):
        converted = []
        for row in document["phases"]:
            if not isinstance(row, dict):
                converted.append(row)
                continue
            converted.append({
                "gate": row.get("phase_id", row.get("phase")),
                "status": _normalized_status(row.get("status")),
                "evidence_valid": _phase_evidence_valid(row),
            })
        return converted
    if "gate" in document:
        return [document]
    return None


def evaluate_universal_release_from_rows(
    rows: list[dict[str, Any]], *, source_errors: Sequence[dict[str, Any]] = (), sources: Sequence[dict[str, Any]] = ()
) -> dict[str, Any]:
    """Aggregate exactly F00--F12; ambiguity and missing proof remain debt."""
    parsed: list[dict[str, Any]] = []
    errors = [dict(item) for item in source_errors]
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append({"code": "gate_row_invalid", "index": index})
            continue
        gate = row.get("gate", row.get("gate_id", row.get("phase_id")))
        status = _normalized_status(row.get("status"))
        evidence_valid = row.get("evidence_valid")
        if gate not in REQUIRED_GATES:
            errors.append({"code": "gate_id_invalid", "index": index, "gate": gate})
            continue
        if status is None:
            errors.append({"code": "gate_status_invalid", "index": index, "gate": gate})
        if not isinstance(evidence_valid, bool):
            errors.append({"code": "evidence_valid_invalid", "index": index, "gate": gate})
            evidence_valid = False
        parsed.append({"gate": gate, "status": status, "evidence_valid": evidence_valid})

    counts = Counter(row["gate"] for row in parsed)
    by_gate = {row["gate"]: row for row in parsed if counts[row["gate"]] == 1}
    for gate, count in sorted(counts.items()):
        if count > 1:
            errors.append({"code": "duplicate_gate", "gate": gate, "count": count})

    # A document-level validator failure invalidates the evidence set even if
    # every copied row happens to look complete.  Do not allow row projection
    # to erase a contradictory parent report.
    blocked_by_integrity = bool(errors)
    gates: list[dict[str, Any]] = []
    debt: list[str] = []
    for gate in REQUIRED_GATES:
        row = by_gate.get(gate)
        if row is None:
            reason = "duplicate_gate" if counts[gate] else "gate_missing"
            result = {"gate": gate, "status": "NAO_COMPROVADA", "evidence_valid": False, "reason": reason}
        elif row["status"] != "QUITADA":
            result = {**row, "reason": "gate_not_quitada"}
        elif row["evidence_valid"] is not True:
            result = {**row, "reason": "evidence_invalid"}
        else:
            result = {**row, "reason": None}
        if blocked_by_integrity and result["reason"] is None:
            result["reason"] = "source_integrity_error"
        if result["reason"] is not None:
            debt.append(gate)
        gates.append(result)

    gate_passed = not debt and not errors
    codes = sorted({str(item.get("code", "integrity_error")) for item in errors})
    return {
        "schema": SCHEMA,
        "status": "QUITADA" if gate_passed else "PARCIALMENTE_QUITADA",
        "gate_passed": gate_passed,
        "gates": gates,
        "remaining_debt": debt,
        "integrity_errors": codes,
        "errors": errors,
        "sources": list(sources),
        "limitations": [
            "aggregation does not execute tests, targets, VM probes, or clean replay",
            "a valid hash proves the bytes observed locally, not semantic truth",
            "missing evidence is debt and is never inferred as success",
        ],
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_symlink_component(path: Path, root: Path) -> bool:
    try:
        current = root
        for part in path.relative_to(root).parts:
            current /= part
            if current.is_symlink():
                return True
    except (ValueError, OSError):
        return True
    return False


def evaluate_universal_release(root: Path, evidence: Sequence[Path]) -> dict[str, Any]:
    """Read evidence JSON files confined to ``root`` and aggregate their rows."""
    root = Path(root)
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    try:
        resolved_root = root.resolve(strict=True)
        if not resolved_root.is_dir() or root.is_symlink():
            raise OSError("regular directory required")
    except (OSError, RuntimeError):
        return evaluate_universal_release_from_rows([], source_errors=[{"code": "root_invalid"}])

    for supplied in evidence:
        raw_path = Path(supplied)
        candidate = raw_path if raw_path.is_absolute() else resolved_root / raw_path
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
            relative = resolved.relative_to(resolved_root).as_posix()
            if _has_symlink_component(candidate, resolved_root) or not resolved.is_file():
                raise OSError("regular file required")
        except ValueError:
            errors.append({"code": "evidence_path_escape", "path": str(raw_path)})
            continue
        except (OSError, RuntimeError):
            errors.append({"code": "evidence_file_invalid", "path": str(raw_path)})
            continue
        try:
            document = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append({"code": "evidence_json_invalid", "path": relative})
            continue
        extracted = _rows_from_document(document)
        if extracted is None:
            errors.append({"code": "evidence_schema_unsupported", "path": relative})
            continue
        # phase-gate-report.v1 has a parent verdict that must survive the
        # conversion to universal-release rows.  A partial/failed parent,
        # or any parent error, is not repaired by complete-looking children.
        if isinstance(document.get("phases"), list):
            if document.get("gate_passed") is not True:
                errors.append({"code": "source_gate_not_passed", "path": relative})
            if document.get("status") != "complete":
                errors.append({"code": "source_status_not_complete", "path": relative})
            parent_errors = document.get("errors")
            if not isinstance(parent_errors, list):
                errors.append({"code": "source_errors_invalid", "path": relative})
            elif parent_errors:
                errors.append({"code": "source_document_errors", "path": relative, "count": len(parent_errors)})
        rows.extend(extracted)
        sources.append({"path": relative, "sha256": _sha256(resolved), "rows": len(extracted)})
    sources.sort(key=lambda item: item["path"])
    return evaluate_universal_release_from_rows(rows, source_errors=errors, sources=sources)


def _write_json_atomic(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = evaluate_universal_release(args.root, args.evidence)
        _write_json_atomic(args.output, report)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"release aggregation failed: {exc}\n")
    print(json.dumps({"status": report["status"], "gate_passed": report["gate_passed"], "remaining_debt": report["remaining_debt"]}))
    return 0 if report["gate_passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
