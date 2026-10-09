from __future__ import annotations

import json
from pathlib import Path

from tools.tri_split_release import create_tri_split_release
from tools.tri_split_evaluate import evaluate_tri_split


def _manifest(root: Path, project_id: str, split: str) -> Path:
    project = root / project_id
    project.mkdir(parents=True)
    (project / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    oracle = {"oracle_schema": "re-megazord-oracle.v1", "family": project_id, "language": "python", "expected_symbols": ["main"], "expected_relations": []}
    (project / "oracle.json").write_text(json.dumps(oracle), encoding="utf-8")
    import hashlib
    manifest = {"schema": "re-megazord-corpus.v1", "projects": [{"id": project_id, "family": project_id, "split": split, "language": "python", "source": f"{project_id}/main.py", "oracle": f"{project_id}/oracle.json", "oracle_sha256": hashlib.sha256((project / "oracle.json").read_bytes()).hexdigest(), "artifacts": [], "authorization": "test"}]}
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_tri_split_evaluation_scores_public_and_withholds_holdout(tmp_path: Path):
    dev = _manifest(tmp_path / "dev", "dev-one", "development")
    cal = _manifest(tmp_path / "cal", "cal-one", "calibration")
    hold = _manifest(tmp_path / "hold", "hold-one", "holdout")
    release = tmp_path / "release"
    escrow = tmp_path / "escrow"
    create_tri_split_release([dev, cal, hold], release, escrow)
    report = evaluate_tri_split(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json")
    assert report["status"] == "complete"
    assert report["summary"] == {"projects": 3, "scored": 2, "withheld": 1, "errors": 0}
    by_id = {item["id"]: item for item in report["projects"]}
    assert by_id["dev-one"]["scored"] is True
    assert by_id["hold-one"]["oracle_status"] == "withheld"
    assert by_id["hold-one"]["scores"] is None
