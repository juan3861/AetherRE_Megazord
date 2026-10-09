"""Métricas e calibração para previsões com ground truth explícito."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _text(value: object) -> str:
    return "" if value is None else str(value).strip()


def _wilson(successes: int, trials: int, *, z: float = 1.96) -> dict[str, Any] | None:
    """Intervalo Wilson 95%; evita vender contagem pequena como certeza."""
    if trials <= 0:
        return None
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (proportion + z * z / (2.0 * trials)) / denominator
    radius = z * math.sqrt((proportion * (1.0 - proportion) + z * z / (4.0 * trials)) / trials) / denominator
    return {"level": 0.95, "low": max(0.0, centre - radius), "high": min(1.0, centre + radius), "successes": successes, "trials": trials}


def calibration_metrics(rows: list[dict[str, Any]], *, bins: int = 10, group_by: str | None = None) -> dict[str, Any]:
    if isinstance(bins, bool) or not isinstance(bins, int) or bins <= 0 or bins > 1000:
        raise ValueError("bins_must_be_positive")
    if not isinstance(rows, list):
        raise ValueError("rows_must_be_list")
    if group_by is not None and (not isinstance(group_by, str) or not group_by.strip()):
        raise ValueError("group_by_invalid")
    if not rows:
        return {"schema": "calibration-report.v1", "sample_count": 0, "metrics": {}, "bins": [], "status": "insufficient_data"}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"row_must_be_object:{index}")
    split_validation = validate_split_integrity(rows)
    if not split_validation["valid"]:
        return {"schema": "calibration-report.v1", "sample_count": 0, "metrics": {}, "bins": [], "status": "invalid_split", "split_validation": split_validation}
    labels: list[int] = []
    scores: list[float] = []
    for row in rows:
        label = row.get("label")
        score = row.get("score")
        if label not in (0, 1, False, True):
            raise ValueError("label_must_be_binary")
        if isinstance(score, bool):
            raise ValueError("score_must_be_numeric")
        try:
            value = float(score)
        except (TypeError, ValueError):
            raise ValueError("score_must_be_numeric") from None
        if not 0.0 <= value <= 1.0:
            raise ValueError("score_out_of_range")
        labels.append(int(bool(label)))
        scores.append(value)
    predicted = [int(score >= 0.5) for score in scores]
    tp = sum(p == 1 and y == 1 for p, y in zip(predicted, labels))
    fp = sum(p == 1 and y == 0 for p, y in zip(predicted, labels))
    fn = sum(p == 0 and y == 1 for p, y in zip(predicted, labels))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    bucket_rows: list[dict[str, Any]] = []
    ece = 0.0
    for bucket in range(bins):
        selected = [i for i, score in enumerate(scores) if (bucket / bins <= score < (bucket + 1) / bins) or (bucket == bins - 1 and score == 1.0)]
        if not selected:
            continue
        confidence = sum(scores[i] for i in selected) / len(selected)
        accuracy = sum(predicted[i] == labels[i] for i in selected) / len(selected)
        gap = abs(confidence - accuracy)
        ece += len(selected) / len(rows) * gap
        bucket_rows.append({"bin": bucket, "count": len(selected), "confidence": confidence, "accuracy": accuracy, "gap": gap})
    ordered = sorted(range(len(rows)), key=lambda i: scores[i], reverse=True)
    selective = []
    for coverage in (0.25, 0.5, 0.75, 1.0):
        count = max(1, round(len(rows) * coverage))
        errors = sum(predicted[i] != labels[i] for i in ordered[:count])
        selective.append({"coverage": count / len(rows), "risk": errors / count})
    report = {
        "schema": "calibration-report.v1",
        "sample_count": len(rows),
        "metrics": {"precision": precision, "recall": recall, "f1": f1, "accuracy": sum(predicted[i] == labels[i] for i in range(len(rows))) / len(rows), "brier": sum((score - label) ** 2 for score, label in zip(scores, labels)) / len(rows), "ece": ece},
        "confidence_intervals": {
            "precision": _wilson(tp, tp + fp),
            "recall": _wilson(tp, tp + fn),
            "accuracy": _wilson(sum(predicted[i] == labels[i] for i in range(len(rows))), len(rows)),
        },
        "bins": bucket_rows,
        "selective_risk": selective,
        "status": "measured",
        "split_validation": split_validation,
        "limitations": ["métricas dependem da qualidade/independência do ground truth", "ECE/Brier não provam generalização", "calibração deve ser congelada antes do holdout"],
    }
    if group_by:
        groups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            key = row.get(group_by)
            groups.setdefault("<missing>" if key is None else str(key), []).append(row)
        report["group_by"] = group_by
        report["groups"] = {key: calibration_metrics(value, bins=bins) for key, value in sorted(groups.items())}
    return report


def validate_split_integrity(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Impede que a mesma família apareça em calibração e holdout."""
    if not isinstance(rows, list):
        return {"valid": False, "leakage_families": [], "invalid_rows": ["<not-a-list>"]}
    families: dict[str, set[str]] = {}
    invalid_rows: list[int] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            invalid_rows.append(index)
            continue
        family, split = row.get("family"), row.get("split")
        if family is None or split is None:
            continue
        families.setdefault(str(family), set()).add(str(split))
    leakage = sorted(family for family, splits in families.items() if len(splits) > 1)
    result: dict[str, Any] = {"valid": not leakage and not invalid_rows, "leakage_families": leakage}
    if invalid_rows:
        result["invalid_rows"] = invalid_rows
    return result


def evaluate_blind_holdout(
    rows: list[dict[str, Any]],
    *,
    bins: int = 10,
    calibration_frozen: bool = False,
    calibration_split: str = "calibration",
    holdout_split: str = "holdout",
    minimum_samples: int = 0,
    minimum_families: int = 0,
) -> dict[str, Any]:
    """Evaluate a prediction set with a family-disjoint blind holdout.

    This is deliberately stricter than :func:`calibration_metrics`: every
    row needs a stable sample/evidence identity and producer so duplicated or
    correlated observations cannot silently inflate confidence.  The
    ``calibration_frozen`` argument is an explicit declaration by the caller;
    it does not prove the training history and is therefore published as a
    limitation instead of being inferred from the rows.
    """
    schema = "blind-holdout-report.v1"
    if not isinstance(rows, list):
        return {"schema": schema, "status": "invalid", "calibration": {}, "holdout": {}, "errors": [{"code": "predictions_not_list"}], "summary": {"received": 0, "accepted": 0}, "limitations": ["holdout exige famílias disjuntas e identidade de evidência", "calibration_frozen é declaração, não prova histórica"]}
    if not isinstance(calibration_frozen, bool):
        return {"schema": schema, "status": "invalid", "calibration": {}, "holdout": {}, "errors": [{"code": "calibration_frozen_invalid"}], "summary": {"received": len(rows), "accepted": 0}, "limitations": ["holdout exige famílias disjuntas e identidade de evidência", "calibration_frozen é declaração, não prova histórica"]}
    if isinstance(minimum_samples, bool) or not isinstance(minimum_samples, int) or minimum_samples < 0:
        return {"schema": schema, "status": "invalid", "calibration": {}, "holdout": {}, "errors": [{"code": "minimum_samples_invalid"}], "summary": {"received": len(rows), "accepted": 0}, "limitations": ["minimum_samples é uma política declarada", "amostra suficiente não prova independência sem ground truth"]}
    if isinstance(minimum_families, bool) or not isinstance(minimum_families, int) or minimum_families < 0:
        return {"schema": schema, "status": "invalid", "calibration": {}, "holdout": {}, "errors": [{"code": "minimum_families_invalid"}], "summary": {"received": len(rows), "accepted": 0}, "limitations": ["minimum_families é uma política declarada", "amostra suficiente não prova independência sem ground truth"]}
    if calibration_split == holdout_split or not isinstance(calibration_split, str) or not isinstance(holdout_split, str) or not calibration_split or not holdout_split:
        return {"schema": schema, "status": "invalid", "calibration": {}, "holdout": {}, "errors": [{"code": "split_names_invalid"}], "summary": {"received": len(rows), "accepted": 0}, "limitations": ["holdout exige famílias disjuntas e identidade de evidência", "calibration_frozen é declaração, não prova histórica"]}
    errors: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    seen_samples: set[str] = set()
    seen_evidence: dict[str, tuple[int, str]] = {}
    seen_samples_any: set[str] = set()
    seen_evidence_any: set[str] = set()
    declared_calibration_families: set[str] = set()
    declared_holdout_families: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            errors.append({"index": index, "code": "prediction_not_object"})
            continue
        sample_id = _text(raw.get("sample_id"))
        evidence_id = _text(raw.get("evidence_id"))
        family = _text(raw.get("family"))
        split = _text(raw.get("split"))
        producer = _text(raw.get("producer"))
        if family and split == calibration_split:
            declared_calibration_families.add(family)
        elif family and split == holdout_split:
            declared_holdout_families.add(family)
        # Register identities before checking the remaining fields.  A row
        # with a malformed score/family must not hide a repeated sample or
        # evidence ID from a later valid row; otherwise leakage could be
        # silently converted into a generic schema error.
        row_errors: list[str] = []
        if sample_id:
            if sample_id in seen_samples_any:
                row_errors.append("duplicate_sample_id")
            else:
                seen_samples_any.add(sample_id)
        if evidence_id:
            if evidence_id in seen_evidence_any:
                row_errors.append("duplicate_evidence_id")
            else:
                seen_evidence_any.add(evidence_id)
        required = ("sample_id", "evidence_id", "family", "split", "label", "score", "producer")
        missing = [field for field in required if field not in raw]
        if missing:
            errors.append({"index": index, "code": "prediction_fields_missing", "fields": missing})
            errors.extend({"index": index, "code": code} for code in row_errors)
            continue
        if not sample_id:
            row_errors.append("sample_id_empty")
        if not evidence_id:
            row_errors.append("evidence_id_empty")
        if not family:
            row_errors.append("family_empty")
        if split not in {calibration_split, holdout_split}:
            row_errors.append("split_invalid")
        if not producer:
            row_errors.append("producer_empty")
        label = raw.get("label")
        if label not in (0, 1, False, True):
            row_errors.append("label_must_be_binary")
        score = raw.get("score")
        if isinstance(score, bool):
            row_errors.append("score_must_be_numeric")
            numeric_score = None
        else:
            try:
                numeric_score = float(score)
            except (TypeError, ValueError, OverflowError):
                row_errors.append("score_must_be_numeric")
                numeric_score = None
        if numeric_score is not None and (not math.isfinite(numeric_score) or not 0.0 <= numeric_score <= 1.0):
            row_errors.append("score_out_of_range")
        abstain = raw.get("abstain", False)
        if not isinstance(abstain, bool):
            row_errors.append("abstain_must_be_boolean")
            abstain = False
        artifact_sha256 = raw.get("artifact_sha256")
        if artifact_sha256 is not None and (not isinstance(artifact_sha256, str) or not _SHA256_RE.fullmatch(artifact_sha256)):
            row_errors.append("artifact_hash_invalid")
        if row_errors:
            errors.extend({"index": index, "code": code} for code in row_errors)
            continue
        seen_samples.add(sample_id)
        seen_evidence[evidence_id] = (index, split)
        accepted.append({"sample_id": sample_id, "evidence_id": evidence_id, "family": family, "split": split, "label": int(bool(label)), "score": numeric_score, "producer": producer, "abstain": abstain, **({"artifact_sha256": artifact_sha256} if artifact_sha256 is not None else {})})
    calibration_rows = [row for row in accepted if row["split"] == calibration_split]
    holdout_rows = [row for row in accepted if row["split"] == holdout_split]
    calibration_families = declared_calibration_families | {row["family"] for row in calibration_rows}
    holdout_families = declared_holdout_families | {row["family"] for row in holdout_rows}
    overlap = sorted(calibration_families & holdout_families)
    if overlap:
        errors.append({"code": "family_leakage", "families": overlap})
    summary: dict[str, Any] = {
        "received": len(rows),
        "accepted": len(accepted),
        "calibration": len(calibration_rows),
        "holdout": len(holdout_rows),
        "calibration_families": sorted(calibration_families),
        "holdout_families": sorted(holdout_families),
        "family_overlap": overlap,
        "unique_samples": len(seen_samples),
        "unique_evidence": len(seen_evidence),
        "minimum_samples": minimum_samples,
        "minimum_families": minimum_families,
    }
    base = {"schema": schema, "calibration": {}, "holdout": {}, "errors": errors, "summary": summary, "split_validation": {"valid": not overlap and not errors, "family_overlap": overlap}, "calibration_frozen": calibration_frozen, "minimum_samples": minimum_samples, "minimum_families": minimum_families, "limitations": ["holdout exige famílias disjuntas e identidade de evidência", "calibration_frozen é declaração, não prova histórica", "métricas dependem do ground truth fornecido", "abstenção mede cobertura declarada, não segurança universal", "mínimos amostrais são política de suficiência, não prova de independência"]}
    if errors:
        base["status"] = "invalid_split" if overlap and not any(item.get("code") != "family_leakage" for item in errors) else "invalid"
        return base
    sufficiency_errors: list[dict[str, Any]] = []
    if minimum_samples:
        if len(calibration_rows) < minimum_samples:
            sufficiency_errors.append({"code": "calibration_samples_below_minimum", "observed": len(calibration_rows), "minimum": minimum_samples})
        if len(holdout_rows) < minimum_samples:
            sufficiency_errors.append({"code": "holdout_samples_below_minimum", "observed": len(holdout_rows), "minimum": minimum_samples})
    if minimum_families:
        if len(calibration_families) < minimum_families:
            sufficiency_errors.append({"code": "calibration_families_below_minimum", "observed": len(calibration_families), "minimum": minimum_families})
        if len(holdout_families) < minimum_families:
            sufficiency_errors.append({"code": "holdout_families_below_minimum", "observed": len(holdout_families), "minimum": minimum_families})
    if sufficiency_errors:
        base["errors"].extend(sufficiency_errors)
        base["status"] = "insufficient_data"
        return base
    if not calibration_rows or not holdout_rows:
        base["status"] = "insufficient_data"
        return base
    try:
        calibration_report = calibration_metrics(calibration_rows, bins=bins, group_by="producer")
        holdout_report = calibration_metrics(holdout_rows, bins=bins, group_by="producer")
    except ValueError as exc:
        base["errors"] = [{"code": str(exc)}]
        base["status"] = "invalid"
        return base
    base["calibration"] = calibration_report
    base["holdout"] = holdout_report
    for name, subset in (("calibration", calibration_rows), ("holdout", holdout_rows)):
        scored = [row for row in subset if not row["abstain"]]
        errors_count = sum((int(row["score"] >= 0.5) != row["label"]) for row in scored)
        base.setdefault("abstention", {})[name] = {"total": len(subset), "abstained": len(subset) - len(scored), "coverage": len(scored) / len(subset) if subset else 0.0, "selective_risk": errors_count / len(scored) if scored else None}
    base["status"] = "measured" if calibration_frozen else "not_proven"
    return base


def write_metrics_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
