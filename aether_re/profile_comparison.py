"""Compare two already-evaluated binary profiles without executing targets.

This measures changes on exactly the same manifest/projects. A complete
comparison means the *comparison* was valid, not that either profile is good.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any


SCHEMA = "binary-profile-comparison.v1"
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_SCORES = ("symbols", "symbol_candidates")
_METRICS = ("precision", "recall", "f1")


def _invalid(errors: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "invalid", "projects": [], "summary": {}, "errors": errors,
            "limitations": ["comparação exige avaliações completas do mesmo manifesto e projetos", "nenhum binário foi executado"]}


def _index(document: dict[str, Any], label: str, errors: list[dict[str, Any]], max_projects: int) -> dict[str, dict[str, Any]]:
    projects = document.get("projects")
    if not isinstance(projects, list) or not 1 <= len(projects) <= max_projects:
        errors.append({"code": "projects_invalid", "profile": label})
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(projects):
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"].strip():
            errors.append({"code": "project_invalid", "profile": label, "index": index})
            continue
        project_id = row["id"]
        if project_id in indexed:
            errors.append({"code": "project_duplicate", "profile": label, "id": project_id})
        else:
            indexed[project_id] = row
    return indexed


def _score(row: dict[str, Any], field: str, label: str, project_id: str, errors: list[dict[str, Any]]) -> dict[str, float] | None:
    value = row.get(field)
    if not isinstance(value, dict):
        errors.append({"code": "score_missing", "profile": label, "id": project_id, "field": field})
        return None
    result: dict[str, float] = {}
    for metric in _METRICS:
        score = value.get(metric)
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
            errors.append({"code": "score_invalid", "profile": label, "id": project_id, "field": field, "metric": metric})
            return None
        result[metric] = float(score)
    counts: dict[str, int] = {}
    for count_field in ("expected", "observed", "true_positive", "false_positive", "false_negative"):
        count = value.get(count_field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            errors.append({"code": "score_count_invalid", "profile": label, "id": project_id, "field": field, "count": count_field})
            return None
        counts[count_field] = count
    tp, fp, fn = counts["true_positive"], counts["false_positive"], counts["false_negative"]
    if counts["expected"] != tp + fn or counts["observed"] != tp + fp:
        errors.append({"code": "score_counts_inconsistent", "profile": label, "id": project_id, "field": field})
        return None
    if counts["expected"] == counts["observed"] == 0:
        precision = recall = 1.0
    else:
        precision = tp / counts["observed"] if counts["observed"] else 0.0
        recall = tp / counts["expected"] if counts["expected"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    if any(abs(result[metric] - expected_value) > 1e-9 for metric, expected_value in (("precision", precision), ("recall", recall), ("f1", f1))):
        errors.append({"code": "score_metrics_inconsistent", "profile": label, "id": project_id, "field": field})
        return None
    result["expected"] = counts["expected"]
    return result


def compare_binary_profiles(baseline: Any, candidate: Any, *, max_projects: int = 10_000) -> dict[str, Any]:
    if isinstance(max_projects, bool) or not isinstance(max_projects, int) or not 1 <= max_projects <= 100_000:
        return _invalid([{"code": "max_projects_invalid"}])
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        return _invalid([{"code": "input_must_be_object"}])
    errors: list[dict[str, Any]] = []
    for label, document in (("baseline", baseline), ("candidate", candidate)):
        if document.get("schema") != "corpus-binary-evaluation.v1" or document.get("status") != "complete":
            errors.append({"code": "evaluation_not_complete", "profile": label})
        digest = document.get("manifest_sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            errors.append({"code": "manifest_hash_invalid", "profile": label})
        if document.get("executed_targets") is not False:
            errors.append({"code": "execution_state_invalid", "profile": label})
    if errors:
        return _invalid(errors)
    if baseline["manifest_sha256"].lower() != candidate["manifest_sha256"].lower():
        return _invalid([{"code": "manifest_hash_mismatch"}])
    baseline_rows = _index(baseline, "baseline", errors, max_projects)
    candidate_rows = _index(candidate, "candidate", errors, max_projects)
    if set(baseline_rows) != set(candidate_rows):
        errors.append({"code": "project_set_mismatch", "baseline_only": sorted(set(baseline_rows) - set(candidate_rows)), "candidate_only": sorted(set(candidate_rows) - set(baseline_rows))})
    if errors:
        return _invalid(errors)
    rows: list[dict[str, Any]] = []
    for project_id in sorted(baseline_rows):
        before, after = baseline_rows[project_id], candidate_rows[project_id]
        for field in ("family", "language", "split", "build_kind"):
            if before.get(field) != after.get(field):
                errors.append({"code": "project_identity_mismatch", "id": project_id, "field": field})
        for label, item in (("baseline", before), ("candidate", after)):
            digest = item.get("binary_sha256")
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                errors.append({"code": "binary_hash_invalid", "profile": label, "id": project_id})
        comparisons: dict[str, Any] = {}
        for field in _SCORES:
            left = _score(before, field, "baseline", project_id, errors)
            right = _score(after, field, "candidate", project_id, errors)
            if left is not None and right is not None:
                if left["expected"] != right["expected"]:
                    errors.append({"code": "expected_count_mismatch", "id": project_id, "field": field})
                comparisons[field] = {metric: {"baseline": left[metric], "candidate": right[metric], "delta": right[metric] - left[metric]} for metric in _METRICS}
        left_rel, right_rel = before.get("relations"), after.get("relations")
        if not isinstance(left_rel, dict) or not isinstance(right_rel, dict):
            errors.append({"code": "relations_invalid", "id": project_id})
            relation = {"status": "not_measured"}
        elif left_rel.get("status") not in {"measured", "not_measured"} or right_rel.get("status") not in {"measured", "not_measured"}:
            errors.append({"code": "relation_status_invalid", "id": project_id})
            relation = {"status": "invalid"}
        elif left_rel.get("status") == right_rel.get("status") == "measured":
            left = _score(before, "relations", "baseline", project_id, errors)
            right = _score(after, "relations", "candidate", project_id, errors)
            if left is not None and right is not None:
                if left["expected"] != right["expected"]:
                    errors.append({"code": "expected_count_mismatch", "id": project_id, "field": "relations"})
                relation = {"status": "measured", **{metric: {"baseline": left[metric], "candidate": right[metric], "delta": right[metric] - left[metric]} for metric in _METRICS}}
            else:
                relation = {"status": "invalid"}
        else:
            relation = {"status": "not_comparable", "baseline": left_rel.get("status"), "candidate": right_rel.get("status")}
        rows.append({"id": project_id, "family": before.get("family"), "split": before.get("split"), "build_kind": before.get("build_kind"), "baseline_sha256": before.get("binary_sha256"), "candidate_sha256": after.get("binary_sha256"), "scores": comparisons, "relations": relation})
    if errors:
        return _invalid(errors)
    def aggregate(field: str, metric: str) -> dict[str, Any]:
        values = [row["scores"][field][metric]["delta"] for row in rows]
        return {"compared": len(values), "mean_delta": sum(values) / len(values), "regressed": sum(value < 0 for value in values), "improved": sum(value > 0 for value in values), "unchanged": sum(value == 0 for value in values)}
    relation_values = [row["relations"]["recall"]["delta"] for row in rows if row["relations"]["status"] == "measured"]
    summary = {"projects": len(rows), "symbol_recall": aggregate("symbols", "recall"), "symbol_precision": aggregate("symbols", "precision"), "candidate_recall": aggregate("symbol_candidates", "recall"), "relations_compared": len(relation_values), "relations_not_comparable": len(rows) - len(relation_values), "relation_recall_mean_delta": sum(relation_values) / len(relation_values) if relation_values else None}
    return {"schema": SCHEMA, "status": "complete", "manifest_sha256": baseline["manifest_sha256"], "projects": rows, "summary": summary, "errors": [], "executed_targets": False, "limitations": ["comparação válida não implica qualidade suficiente de qualquer perfil", "mesmo corpus e oracle; não é validação externa independente", "diferenças de símbolos/calls não provam equivalência comportamental", "nenhum binário foi executado"]}


def write_profile_comparison(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
