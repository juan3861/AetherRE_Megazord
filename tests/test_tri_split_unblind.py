from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.tri_split_evaluate import evaluate_tri_split
from tools.tri_split_release import create_tri_split_release
from tools.tri_split_unblind import unblind_tri_split


def _manifest(root: Path, project_id: str, split: str) -> Path:
    project = root / project_id
    project.mkdir(parents=True)
    (project / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    oracle = {"oracle_schema": "re-megazord-oracle.v1", "family": project_id, "language": "python", "expected_symbols": ["main"], "expected_relations": []}
    (project / "oracle.json").write_text(json.dumps(oracle), encoding="utf-8")
    manifest = {"schema": "re-megazord-corpus.v1", "projects": [{"id": project_id, "family": project_id, "split": split, "language": "python", "source": f"{project_id}/main.py", "oracle": f"{project_id}/oracle.json", "oracle_sha256": hashlib.sha256((project / "oracle.json").read_bytes()).hexdigest(), "artifacts": [], "authorization": "test"}]}
    path = root / "manifest.json"; path.write_text(json.dumps(manifest), encoding="utf-8"); return path


def test_unblind_requires_blind_holdout_and_scores_afterward(tmp_path: Path):
    hold = _manifest(tmp_path / "hold", "hold-one", "holdout")
    dev = _manifest(tmp_path / "dev", "dev-one", "development")
    cal = _manifest(tmp_path / "cal", "cal-one", "calibration")
    release = tmp_path / "release"; escrow = tmp_path / "escrow"
    create_tri_split_release([dev, cal, hold], release, escrow)
    blind = tmp_path / "blind.json"
    blind.write_text(json.dumps(evaluate_tri_split(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json")), encoding="utf-8")
    report = unblind_tri_split(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json", blind)
    assert report["status"] == "complete"
    assert report["phase"] == "unblind_after_blind_lock"
    assert report["summary"]["scored"] == 1
    assert report["projects"][0]["scores"]["symbols"]["recall"] == 1.0


def test_unblind_fails_if_blind_report_exposes_holdout(tmp_path: Path):
    hold = _manifest(tmp_path / "hold", "hold-one", "holdout")
    dev = _manifest(tmp_path / "dev", "dev-one", "development")
    cal = _manifest(tmp_path / "cal", "cal-one", "calibration")
    release = tmp_path / "release"; escrow = tmp_path / "escrow"
    create_tri_split_release([dev, cal, hold], release, escrow)
    blind = tmp_path / "bad.json"
    blind.write_text(json.dumps({"schema": "f03-tri-split-evaluation.v1", "status": "complete", "summary": {"withheld": 1}, "projects": [{"id": "hold-one", "oracle_status": "public", "scored": True, "scores": {}}]}), encoding="utf-8")
    report = unblind_tri_split(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json", blind)
    assert report["status"] == "invalid"
    assert any(error["code"] == "blind_holdout_not_withheld" for error in report["errors"])
