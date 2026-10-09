"""Avaliação mecânica dos gates F00--F12 sem inflar homologação.

O plano mestre define treze fases, mas uma lista em Markdown não é um gate
executável. Este módulo transforma declarações de implementação, integração,
testes, revisão e evidências em um relatório conservador. Ele não executa
alvos, não roda testes por conta própria e não trata uma declaração de status
como prova.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "phase-gate-report.v1"
PHASE_IDS = tuple(f"F{index:02d}" for index in range(13))
GATE_IDS = tuple(f"G{index:02d}" for index in range(13))
PHASE_STATUSES = {"QUITADA", "PARCIALMENTE QUITADA", "NÃO QUITADA", "NÃO COMPROVADA"}
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_LIMITATIONS = [
    "o gate valida declarações e artefatos materializados; não executa testes nem alvos",
    "hash prova integridade relativa ao arquivo observado, não verdade semântica",
    "revisão independente e cobertura do plano precisam de evidência externa",
]


def _invalid(errors: list[dict[str, Any]], *, phases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = phases or []
    return {
        "schema": SCHEMA,
        "status": "invalid",
        "gate_passed": False,
        "phases": rows,
        "errors": errors,
        "summary": {
            "total": len(PHASE_IDS),
            "received": len(rows),
            "quitada": 0,
            "parcialmente_quitada": 0,
            "nao_quitada": 0,
            "nao_comprovada": len(PHASE_IDS),
            "gate_passed": False,
        },
        "limitations": list(_LIMITATIONS),
    }


def _hash_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (FileNotFoundError, OSError):
        return None


def _text(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _has_symlink_component(path: Path, root: Path) -> bool:
    """Return whether any existing component below ``root`` is a symlink."""
    try:
        current = root
        for component in path.relative_to(root).parts:
            current = current / component
            if current.is_symlink():
                return True
    except (ValueError, OSError):
        return True
    return False


def _phase_status(
    *,
    implementation: bool | None,
    integration: bool | None,
    review: bool | None,
    tests: dict[str, int] | None,
    evidence_ok: bool,
    evidence_complete: bool,
    structural_errors: bool,
) -> str:
    if structural_errors:
        return "NÃO COMPROVADA"
    if implementation is False or integration is False or (tests and tests["failed"] > 0):
        return "NÃO QUITADA"
    if (
        implementation is True
        and integration is True
        and review is True
        and tests is not None
        and tests["passed"] > 0
        and tests["failed"] == 0
        and tests["skipped"] == 0
        and evidence_ok
        and evidence_complete
    ):
        return "QUITADA"
    if any(value is True for value in (implementation, integration, review)) or (tests is not None and tests["passed"] > 0) or evidence_ok:
        return "PARCIALMENTE QUITADA"
    return "NÃO COMPROVADA"


def evaluate_phase_gates(document: Any, *, root: Path | None = None, max_evidence: int = 10_000) -> dict[str, Any]:
    """Evaluate a phase declaration and its on-disk evidence fail-closed.

    A complete phase must explicitly declare implementation, integration and
    independent review, report a non-empty passing test count with no failures
    or mandatory skips, and provide hashed regular files under ``root``. Missing
    information is *NÃO COMPROVADA* or *PARCIALMENTE QUITADA*, never inferred.
    """
    if isinstance(max_evidence, bool) or not isinstance(max_evidence, int) or not 1 <= max_evidence <= 1_000_000:
        return _invalid([{"code": "max_evidence_invalid", "detail": "integer_range=1..1000000"}])
    if isinstance(document, dict):
        raw_phases = document.get("phases")
    else:
        raw_phases = document
    if not isinstance(raw_phases, list):
        return _invalid([{"code": "phases_must_be_list"}])
    if len(raw_phases) > len(PHASE_IDS):
        return _invalid([{"code": "phase_budget_exceeded", "received": len(raw_phases), "max": len(PHASE_IDS)}])
    resolved_root: Path | None = None
    root_errors: list[dict[str, Any]] = []
    if root is not None:
        try:
            candidate = Path(root)
            if candidate.is_symlink() or not candidate.is_dir():
                root_errors.append({"code": "root_invalid", "detail": "regular_directory_required"})
            else:
                resolved_root = candidate.resolve()
        except (OSError, RuntimeError, TypeError):
            root_errors.append({"code": "root_invalid", "detail": "path_unreadable"})
    errors: list[dict[str, Any]] = list(root_errors)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_phases):
        row_errors: list[dict[str, Any]] = []
        if not isinstance(raw, dict):
            errors.append({"index": index, "code": "phase_not_object"})
            rows.append({"phase_id": None, "status": "NÃO COMPROVADA", "errors": [{"code": "phase_not_object"}]})
            continue
        phase_id = _text(raw.get("phase_id", raw.get("phase")))
        declared_gate_id = _text(raw.get("gate_id"))
        if phase_id in GATE_IDS and declared_gate_id is None:
            declared_gate_id = phase_id
            phase_id = PHASE_IDS[GATE_IDS.index(declared_gate_id)]
        elif phase_id is None and declared_gate_id in GATE_IDS:
            phase_id = PHASE_IDS[GATE_IDS.index(declared_gate_id)]
        if phase_id not in PHASE_IDS:
            row_errors.append({"code": "phase_id_invalid", "phase_id": phase_id})
        elif phase_id in seen:
            row_errors.append({"code": "duplicate_phase_id", "phase_id": phase_id})
        else:
            seen.add(phase_id)
        computed_gate_id = GATE_IDS[PHASE_IDS.index(phase_id)] if phase_id in PHASE_IDS else None
        if declared_gate_id is not None and declared_gate_id != computed_gate_id:
            row_errors.append({"code": "gate_id_mismatch", "gate_id": declared_gate_id, "phase_id": phase_id})
        bools: dict[str, bool | None] = {}
        for field in ("implementation", "integration", "reviewed"):
            value = raw.get(field)
            if not isinstance(value, bool):
                if field in raw:
                    row_errors.append({"code": "phase_boolean_invalid", "field": field})
                bools[field] = None
            else:
                bools[field] = value
        test_raw = raw.get("tests")
        tests: dict[str, int] | None = None
        if test_raw is not None:
            if not isinstance(test_raw, dict):
                row_errors.append({"code": "tests_must_be_object"})
            else:
                parsed: dict[str, int] = {}
                for field in ("passed", "failed", "skipped"):
                    value = test_raw.get(field)
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        row_errors.append({"code": "test_count_invalid", "field": field})
                    else:
                        parsed[field] = value
                if len(parsed) == 3:
                    tests = parsed
        evidence_raw = raw.get("evidence")
        evidence = evidence_raw if isinstance(evidence_raw, list) else []
        if evidence_raw is None:
            row_errors.append({"code": "evidence_missing"})
        elif not isinstance(evidence_raw, list):
            row_errors.append({"code": "evidence_must_be_list"})
        elif not evidence_raw:
            row_errors.append({"code": "evidence_empty"})
        if len(evidence) > max_evidence:
            row_errors.append({"code": "evidence_budget_exceeded", "received": len(evidence), "max": max_evidence})
        evidence_results: list[dict[str, Any]] = []
        evidence_ok = False
        evidence_complete = bool(evidence)
        for evidence_index, item in enumerate(evidence[:max_evidence]):
            if not isinstance(item, dict):
                row_errors.append({"code": "evidence_not_object", "index": evidence_index})
                evidence_complete = False
                continue
            rel_name = _text(item.get("path"))
            expected_hash = item.get("sha256")
            result: dict[str, Any] = {"path": rel_name, "verified": False}
            if rel_name is None:
                row_errors.append({"code": "evidence_path_invalid", "index": evidence_index})
                evidence_complete = False
                evidence_results.append(result)
                continue
            relative = Path(rel_name)
            if relative.is_absolute() or ".." in relative.parts or any(part == "" for part in relative.parts):
                row_errors.append({"code": "evidence_path_escape", "index": evidence_index, "path": rel_name})
                evidence_complete = False
                evidence_results.append(result)
                continue
            if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
                row_errors.append({"code": "evidence_hash_invalid", "index": evidence_index, "path": rel_name})
                evidence_complete = False
                evidence_results.append(result)
                continue
            if resolved_root is None:
                row_errors.append({"code": "evidence_root_required", "index": evidence_index, "path": rel_name})
                evidence_complete = False
                evidence_results.append(result)
                continue
            artifact = (resolved_root / relative).resolve()
            try:
                artifact.relative_to(resolved_root)
            except ValueError:
                row_errors.append({"code": "evidence_path_escape", "index": evidence_index, "path": rel_name})
                evidence_complete = False
                evidence_results.append(result)
                continue
            raw_artifact = resolved_root / relative
            if _has_symlink_component(raw_artifact, resolved_root) or not artifact.is_file():
                row_errors.append({"code": "evidence_file_invalid", "index": evidence_index, "path": rel_name})
                evidence_complete = False
                evidence_results.append(result)
                continue
            observed_hash = _hash_file(artifact)
            result["observed_sha256"] = observed_hash
            result["verified"] = observed_hash == expected_hash
            if not result["verified"]:
                row_errors.append({"code": "evidence_hash_mismatch", "index": evidence_index, "path": rel_name})
                evidence_complete = False
            else:
                evidence_ok = True
            evidence_results.append(result)
        if not evidence:
            evidence_complete = False
        status = _phase_status(
            implementation=bools["implementation"],
            integration=bools["integration"],
            review=bools["reviewed"],
            tests=tests,
            evidence_ok=evidence_ok,
            evidence_complete=evidence_complete,
            structural_errors=bool(row_errors),
        )
        declared = raw.get("status")
        if declared is not None and declared not in PHASE_STATUSES:
            row_errors.append({"code": "declared_status_invalid"})
            status = "NÃO COMPROVADA"
        elif declared is not None and declared != status:
            code = "declared_status_overclaim" if declared == "QUITADA" else "declared_status_mismatch"
            row_errors.append({"code": code, "declared": declared, "computed": status})
            # Preserve the computed status; a declaration must never override
            # the checks or downgrade an explicit test failure.
        if row_errors:
            errors.extend({"index": index, **item} for item in row_errors)
        rows.append({
            "phase_id": phase_id,
            "gate_id": computed_gate_id,
            "status": status,
            "implementation": bools["implementation"],
            "integration": bools["integration"],
            "reviewed": bools["reviewed"],
            "tests": tests,
            "evidence": evidence_results,
            "errors": row_errors,
        })
    missing = [phase_id for phase_id in PHASE_IDS if phase_id not in seen]
    for phase_id in missing:
        rows.append({"phase_id": phase_id, "gate_id": GATE_IDS[PHASE_IDS.index(phase_id)], "status": "NÃO COMPROVADA", "errors": [{"code": "phase_missing"}]})
        errors.append({"code": "phase_missing", "phase_id": phase_id})
    rows.sort(key=lambda item: PHASE_IDS.index(item["phase_id"]) if item["phase_id"] in PHASE_IDS else len(PHASE_IDS))
    counts = {
        "quitada": sum(row["status"] == "QUITADA" for row in rows),
        "parcialmente_quitada": sum(row["status"] == "PARCIALMENTE QUITADA" for row in rows),
        "nao_quitada": sum(row["status"] == "NÃO QUITADA" for row in rows),
        "nao_comprovada": sum(row["status"] == "NÃO COMPROVADA" for row in rows),
    }
    gate_passed = not errors and len(rows) == len(PHASE_IDS) and counts["quitada"] == len(PHASE_IDS)
    return {
        "schema": SCHEMA,
        "status": "complete" if gate_passed else "partial",
        "gate_passed": gate_passed,
        "phases": rows,
        "errors": errors,
        "summary": {"total": len(PHASE_IDS), "received": len(raw_phases), **counts, "gate_passed": gate_passed},
        "limitations": list(_LIMITATIONS),
    }


def write_phase_gate_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
