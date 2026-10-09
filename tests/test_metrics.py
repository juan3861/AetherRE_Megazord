import hashlib
import json
from argparse import Namespace

import pytest

from aether_re.metrics import calibration_metrics, evaluate_blind_holdout, validate_split_integrity
from megazord import cmd_metrics, cmd_metrics_holdout


def test_calibration_metrics_are_explicit_and_reproducible():
    rows = [{"label": 1, "score": 0.9}, {"label": 0, "score": 0.1}, {"label": 1, "score": 0.6}, {"label": 0, "score": 0.4}]
    report = calibration_metrics(rows, bins=2)
    assert report["status"] == "measured"
    assert report["sample_count"] == 4
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["metrics"]["brier"] < 0.1


def test_calibration_metrics_fail_closed_on_bad_scores():
    with pytest.raises(ValueError, match="score_out_of_range"):
        calibration_metrics([{"label": 1, "score": 2.0}])


def test_calibration_metrics_rejects_scalar_rows_bool_bins_and_bool_scores():
    with pytest.raises(ValueError, match="rows_must_be_list"):
        calibration_metrics(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="bins_must_be_positive"):
        calibration_metrics([], bins=True)
    with pytest.raises(ValueError, match="score_must_be_numeric"):
        calibration_metrics([{"label": 1, "score": True}])
    with pytest.raises(ValueError, match="row_must_be_object"):
        calibration_metrics(["bad"])  # type: ignore[list-item]


def test_split_integrity_rejects_family_leakage():
    result = validate_split_integrity([
        {"family": "same", "split": "calibration"},
        {"family": "same", "split": "holdout"},
    ])
    assert result == {"valid": False, "leakage_families": ["same"]}


def test_split_integrity_rejects_malformed_row_without_traceback():
    result = validate_split_integrity(["bad"])  # type: ignore[list-item]
    assert result["valid"] is False
    assert result["invalid_rows"] == [0]


def test_metrics_publish_wilson_intervals_and_stratified_groups():
    rows = [
        {"label": 1, "score": 0.9, "language": "python"},
        {"label": 0, "score": 0.2, "language": "python"},
        {"label": 1, "score": 0.8, "language": "c"},
        {"label": 0, "score": 0.1, "language": "c"},
    ]
    report = calibration_metrics(rows, bins=2, group_by="language")
    interval = report["confidence_intervals"]["precision"]
    assert interval["level"] == 0.95
    assert 0.0 <= interval["low"] <= interval["high"] <= 1.0
    assert set(report["groups"]) == {"c", "python"}


def _holdout_rows():
    return [
        {"sample_id": "cal-1", "evidence_id": "ev-1", "family": "family-cal-a", "split": "calibration", "label": 1, "score": 0.9, "producer": "engine-a"},
        {"sample_id": "cal-2", "evidence_id": "ev-2", "family": "family-cal-b", "split": "calibration", "label": 0, "score": 0.1, "producer": "engine-a"},
        {"sample_id": "hold-1", "evidence_id": "ev-3", "family": "family-hold-a", "split": "holdout", "label": 1, "score": 0.8, "producer": "engine-b"},
        {"sample_id": "hold-2", "evidence_id": "ev-4", "family": "family-hold-b", "split": "holdout", "label": 0, "score": 0.2, "producer": "engine-b", "abstain": True},
    ]


def test_blind_holdout_requires_frozen_calibration_and_reports_abstention():
    report = evaluate_blind_holdout(_holdout_rows(), calibration_frozen=True, bins=2)
    assert report["status"] == "measured"
    assert report["summary"]["family_overlap"] == []
    assert report["calibration"]["sample_count"] == 2
    assert report["holdout"]["sample_count"] == 2
    assert report["abstention"]["holdout"] == {"total": 2, "abstained": 1, "coverage": 0.5, "selective_risk": 0.0}
    not_frozen = evaluate_blind_holdout(_holdout_rows())
    assert not_frozen["status"] == "not_proven"


def test_blind_holdout_rejects_family_and_evidence_leakage():
    rows = _holdout_rows()
    rows[2]["family"] = rows[0]["family"]
    rows[2]["evidence_id"] = rows[0]["evidence_id"]
    report = evaluate_blind_holdout(rows, calibration_frozen=True)
    assert report["status"] == "invalid"
    codes = {item["code"] for item in report["errors"]}
    assert {"duplicate_evidence_id", "family_leakage"} <= codes


def test_blind_holdout_rejects_missing_identity_and_out_of_range_scores():
    rows = _holdout_rows()
    rows[0].pop("evidence_id")
    rows[1]["score"] = float("inf")
    report = evaluate_blind_holdout(rows, calibration_frozen=True)
    assert report["status"] == "invalid"
    codes = {item["code"] for item in report["errors"]}
    assert {"prediction_fields_missing", "score_out_of_range"} <= codes


def test_blind_holdout_detects_duplicate_identity_hidden_by_malformed_row():
    rows = _holdout_rows()
    malformed = dict(rows[0])
    malformed.pop("score")
    rows.insert(1, malformed)
    report = evaluate_blind_holdout(rows, calibration_frozen=True)
    assert report["status"] == "invalid"
    codes = {item["code"] for item in report["errors"]}
    assert {"prediction_fields_missing", "duplicate_sample_id", "duplicate_evidence_id"} <= codes


def test_blind_holdout_cli_rejects_unreadable_input(tmp_path):
    source = tmp_path / "predictions.json"
    out = tmp_path / "holdout.json"
    source.write_text("{", encoding="utf-8")
    code = cmd_metrics_holdout(Namespace(input=str(source), out=str(out), bins=2, calibration_frozen=True))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"


def test_metrics_cli_rejects_scalar_and_unreadable_inputs(tmp_path):
    scalar = tmp_path / "scalar.json"
    scalar.write_text("42", encoding="utf-8")
    out_scalar = tmp_path / "scalar-report.json"
    code = cmd_metrics(Namespace(input=str(scalar), out=str(out_scalar), bins=2, group_by=None))
    report = json.loads(out_scalar.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "rows_must_be_list"
    out_missing = tmp_path / "missing-report.json"
    code = cmd_metrics(Namespace(input=str(tmp_path / "missing.json"), out=str(out_missing), bins=2, group_by=None))
    report = json.loads(out_missing.read_text(encoding="utf-8"))
    assert code == 2
    assert report["errors"][0]["code"] == "input_unreadable"


def test_blind_holdout_cli_binds_canonical_prediction_hash(tmp_path):
    rows = _holdout_rows()
    canonical = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    source = tmp_path / "predictions.json"
    out = tmp_path / "holdout.json"
    source.write_text(json.dumps({"predictions": rows, "predictions_sha256": digest}), encoding="utf-8")
    code = cmd_metrics_holdout(Namespace(input=str(source), out=str(out), bins=2, calibration_frozen=True))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0
    assert report["status"] == "measured"
    assert report["input_provenance"]["hash_match"] is True
    assert report["input_provenance"]["predictions_sha256"] == digest


def test_blind_holdout_rejects_declared_insufficient_sample_policy():
    report = evaluate_blind_holdout(_holdout_rows(), calibration_frozen=True, minimum_samples=3, minimum_families=3)
    assert report["status"] == "insufficient_data"
    codes = {item["code"] for item in report["errors"]}
    assert {"calibration_samples_below_minimum", "holdout_samples_below_minimum", "calibration_families_below_minimum", "holdout_families_below_minimum"} <= codes


def test_blind_holdout_accepts_zero_policy_without_changing_legacy_contract():
    report = evaluate_blind_holdout(_holdout_rows(), calibration_frozen=True, minimum_samples=0, minimum_families=0)
    assert report["status"] == "measured"
    assert report["summary"]["minimum_samples"] == 0


def test_blind_holdout_accepts_declared_sufficient_sample_policy():
    rows = []
    for split, prefix, producer in (("calibration", "cal", "engine-a"), ("holdout", "hold", "engine-b")):
        for family_index in range(5):
            for sample_index in range(6):
                label = int(sample_index % 2 == 0)
                rows.append({
                    "sample_id": f"{prefix}-{family_index}-{sample_index}",
                    "evidence_id": f"ev-{prefix}-{family_index}-{sample_index}",
                    "family": f"{prefix}-family-{family_index}",
                    "split": split, "label": label, "score": 0.9 if label else 0.1,
                    "producer": producer,
                })
    report = evaluate_blind_holdout(rows, calibration_frozen=True, minimum_samples=30, minimum_families=5)
    assert report["status"] == "measured"
    assert report["summary"]["calibration"] == 30
    assert report["summary"]["holdout"] == 30
    assert report["summary"]["calibration_families"] == [f"cal-family-{i}" for i in range(5)]
    assert report["summary"]["holdout_families"] == [f"hold-family-{i}" for i in range(5)]
