"""Contrato para resultados de exploração simbólica produzidos externamente.

O Megazord não inicia solver nem executa o alvo neste validador.  O objetivo é
dar uma fronteira verificável para um worker isolado: budgets, identidade,
paths e conclusão são conferidos, e ``UNSAT`` nunca é convertido em prova de
segurança ou equivalência universal.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SCHEMA = "symbolic-exploration.v1"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RUN_STATUSES = {"sat", "unsat", "unknown", "timeout", "failed"}
_PATH_STATUSES = {"sat", "unsat", "unknown", "error"}
_LIMITATIONS = [
    "validação não inicia solver nem executa alvo",
    "UNSAT é conclusão do modelo/budget, não prova universal de segurança ou equivalência",
    "resultado depende da custódia do worker e do atestado de laboratório",
]


def _invalid(errors: list[dict[str, Any]], *, received: int = 0) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "invalid",
        "conclusion": "not_proven",
        "paths": [],
        "errors": errors,
        "summary": {"received_paths": received, "accepted_paths": 0, "states_explored": 0, "review_required": True},
        "limitations": list(_LIMITATIONS),
    }


def validate_symbolic_result(document: dict[str, Any], *, max_paths: int = 10_000) -> dict[str, Any]:
    """Validate a bounded symbolic-run artifact without trusting its claims."""
    if not isinstance(max_paths, int) or isinstance(max_paths, bool) or not 1 <= max_paths <= 1_000_000:
        return _invalid([{"code": "max_paths_invalid", "detail": "integer_range=1..1000000"}])
    if not isinstance(document, dict):
        return _invalid([{"code": "result_must_be_object"}])
    errors: list[dict[str, Any]] = []
    required = ("schema", "run_id", "target_sha256", "engine", "objective", "status", "states_explored", "paths", "timeout_s", "memory_limit_mb", "executed_in_lab")
    errors.extend({"code": "required_field_missing", "field": field} for field in required if field not in document)
    if errors:
        return _invalid(errors)
    if document.get("schema") != SCHEMA:
        errors.append({"code": "schema_invalid", "expected": SCHEMA})
    for field in ("run_id", "engine", "objective"):
        if not isinstance(document[field], str) or not document[field].strip():
            errors.append({"code": "string_field_invalid", "field": field})
    if not isinstance(document["target_sha256"], str) or not _SHA256_RE.fullmatch(document["target_sha256"]):
        errors.append({"code": "target_hash_invalid"})
    status = document["status"]
    if not isinstance(status, str) or status not in _RUN_STATUSES:
        errors.append({"code": "run_status_invalid", "status": status})
        status = "failed"
    states = document["states_explored"]
    if isinstance(states, bool) or not isinstance(states, int) or states < 0:
        errors.append({"code": "states_explored_invalid"})
        states = 0
    for field in ("timeout_s", "memory_limit_mb"):
        value = document[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            errors.append({"code": "positive_budget_invalid", "field": field})
    lab_proof_id = document.get("lab_proof_id")
    if "lab_proof_id" in document and (not isinstance(lab_proof_id, str) or not lab_proof_id.strip()):
        errors.append({"code": "lab_proof_id_invalid"})
    if not isinstance(document["executed_in_lab"], bool):
        errors.append({"code": "executed_in_lab_invalid"})
    elif document["executed_in_lab"]:
        if not isinstance(lab_proof_id, str) or not lab_proof_id.strip():
            errors.append({"code": "lab_proof_id_required"})
    paths = document["paths"]
    if not isinstance(paths, list):
        errors.append({"code": "paths_must_be_list"})
        paths = []
    if len(paths) > max_paths:
        errors.append({"code": "path_budget_exceeded", "received": len(paths), "max_paths": max_paths})
    accepted: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, path in enumerate(paths[:max_paths]):
        if not isinstance(path, dict):
            errors.append({"index": index, "code": "path_not_object"})
            continue
        path_id = path.get("path_id")
        if not isinstance(path_id, str) or not path_id.strip():
            errors.append({"index": index, "code": "path_id_invalid"})
            continue
        if path_id in seen_ids:
            errors.append({"index": index, "code": "path_id_duplicate", "path_id": path_id})
            continue
        seen_ids.add(path_id)
        path_status = path.get("status")
        if not isinstance(path_status, str) or path_status not in _PATH_STATUSES:
            errors.append({"index": index, "code": "path_status_invalid", "path_id": path_id})
            continue
        row: dict[str, Any] = {"path_id": path_id, "status": path_status}
        if "input_sha256" in path:
            if not isinstance(path["input_sha256"], str) or not _SHA256_RE.fullmatch(path["input_sha256"]):
                errors.append({"index": index, "code": "path_input_hash_invalid", "path_id": path_id})
            else:
                row["input_sha256"] = path["input_sha256"]
        # Preserve only bounded metadata; arbitrary solver payload remains
        # untrusted data and is not interpreted or executed.
        if "note" in path:
            if isinstance(path["note"], str):
                row["note"] = path["note"][:4096]
            else:
                errors.append({"index": index, "code": "path_note_invalid", "path_id": path_id})
        accepted.append(row)
    if errors:
        conclusion = "not_proven"
    elif status == "sat" or any(path.get("status") == "sat" for path in accepted):
        conclusion = "counterexample_found"
    elif status == "unsat":
        conclusion = "not_proven"
    elif status == "timeout":
        conclusion = "timeout"
    else:
        conclusion = "unknown"
    return {
        "schema": SCHEMA,
        "status": "invalid" if errors else "complete",
        "conclusion": conclusion,
        "run_id": document.get("run_id"),
        "target_sha256": document.get("target_sha256"),
        "engine": document.get("engine"),
        "objective": document.get("objective"),
        "paths": accepted,
        "errors": errors,
        "summary": {"received_paths": len(paths), "accepted_paths": len(accepted), "states_explored": states, "run_status": status, "review_required": True, "universal_proof": False},
        "limits": {"max_paths": max_paths, "timeout_s": document.get("timeout_s"), "memory_limit_mb": document.get("memory_limit_mb")},
        "lab_proof_id": document.get("lab_proof_id"),
        "executed_in_lab": document.get("executed_in_lab"),
        "limitations": list(_LIMITATIONS),
    }


def write_symbolic_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
