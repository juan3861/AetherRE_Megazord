from __future__ import annotations

import json
from pathlib import Path

from tools.tri_split_ci import compute_tri_split_ci


def _report(path: Path) -> None:
    path.write_text(json.dumps({
        "schema": "f03-tri-split-evaluation.v1",
        "projects": [
            {"id": "a", "split": "development", "language": "python", "scored": True, "scores": {"symbols": {"precision": 1.0, "recall": 0.5}, "relations": {"precision": 0.5, "recall": 1.0}}},
            {"id": "b", "split": "development", "language": "python", "scored": True, "scores": {"symbols": {"precision": 0.0, "recall": 1.0}, "relations": {"precision": 1.0, "recall": 0.0}}},
            {"id": "h", "split": "holdout", "language": "python", "scored": False, "scores": None},
        ],
    }), encoding="utf-8")


def test_tri_split_ci_is_deterministic_and_withholds(tmp_path: Path):
    path = tmp_path / "evaluation.json"
    _report(path)
    first = compute_tri_split_ci(path, resamples=300, seed=7)
    second = compute_tri_split_ci(path, resamples=300, seed=7)
    assert first == second
    assert first["status"] == "complete"
    assert first["groups"]["development:python"]["symbol_precision"]["n"] == 2
    assert first["groups"]["holdout:python"]["symbol_precision"] is None
    assert first["groups"]["holdout:python"]["withheld_or_unscored"] is True


def test_tri_split_ci_rejects_wrong_schema(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
    result = compute_tri_split_ci(path)
    assert result["status"] == "invalid"
    assert result["errors"][0]["code"] == "evaluation_schema_invalid"


def test_tri_split_ci_accepts_controlled_unblind_scores(tmp_path: Path):
    path = tmp_path / "unblind.json"
    path.write_text(json.dumps({
        "schema": "f03-tri-split-unblind.v1",
        "phase": "unblind_after_blind_lock",
        "projects": [
            {"id": "h1", "split": "holdout", "language": "c", "scored": True, "scores": {"symbols": {"precision": 0.25, "recall": 1.0}, "relations": {"precision": 0.5, "recall": 1.0}}},
            {"id": "h2", "split": "holdout", "language": "c", "scored": True, "scores": {"symbols": {"precision": 0.75, "recall": 0.5}, "relations": {"precision": 1.0, "recall": 0.5}}},
        ],
    }), encoding="utf-8")
    result = compute_tri_split_ci(path, resamples=300, seed=9)
    assert result["status"] == "complete"
    assert result["groups"]["holdout:c"]["symbol_precision"]["n"] == 2
    assert any("post-lock" in item for item in result["limitations"])
