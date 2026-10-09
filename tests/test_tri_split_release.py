from __future__ import annotations

import json
from pathlib import Path

from tools.tri_split_release import create_tri_split_release, verify_tri_split_release


def _make_manifest(root: Path, project_id: str, split: str) -> Path:
    project = root / project_id
    project.mkdir(parents=True)
    (project / "main.py").write_text("print('safe')\n", encoding="utf-8")
    (project / "oracle.json").write_text(json.dumps({"id": project_id, "split": split}), encoding="utf-8")
    manifest = {
        "schema": "re-megazord-corpus.v1",
        "projects": [{
            "id": project_id, "family": project_id, "split": split, "language": "python",
            "source": f"{project_id}/main.py", "oracle": f"{project_id}/oracle.json",
            "oracle_sha256": __import__("hashlib").sha256((project / "oracle.json").read_bytes()).hexdigest(),
            "artifacts": [], "authorization": "test",
        }],
    }
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_tri_split_release_public_and_holdout_oracles_are_separated(tmp_path: Path):
    dev = _make_manifest(tmp_path / "dev", "dev-one", "development")
    cal = _make_manifest(tmp_path / "cal", "cal-one", "calibration")
    hold = _make_manifest(tmp_path / "hold", "hold-one", "holdout")
    release = tmp_path / "release"
    escrow = tmp_path / "escrow"
    created = create_tri_split_release([dev, cal, hold], release, escrow)
    assert created["status"] == "complete"
    public = json.loads((release / "manifest.tri-split.json").read_text(encoding="utf-8"))
    assert public["split_counts"] == {"calibration": 1, "development": 1, "holdout": 1}
    assert all(not Path(item["path"]).is_absolute() for item in public["source_manifests"])
    by_id = {item["id"]: item for item in public["projects"]}
    assert "oracle" in by_id["dev-one"] and "oracle" in by_id["cal-one"]
    assert "oracle" not in by_id["hold-one"] and by_id["hold-one"]["oracle_withheld"] is True
    assert not (release / "oracles" / "holdout" / "hold-one.json").exists()
    verified = verify_tri_split_release(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json")
    assert verified["status"] == "pass"
    (release / by_id["hold-one"]["source"]).write_text("tampered\n", encoding="utf-8")
    assert verify_tri_split_release(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json")["status"] == "invalid"


def test_tri_split_release_detects_holdout_escrow_tamper(tmp_path: Path):
    dev = _make_manifest(tmp_path / "dev", "dev-one", "development")
    cal = _make_manifest(tmp_path / "cal", "cal-one", "calibration")
    hold = _make_manifest(tmp_path / "hold", "hold-one", "holdout")
    release = tmp_path / "release"
    escrow = tmp_path / "escrow"
    create_tri_split_release([dev, cal, hold], release, escrow)
    assert verify_tri_split_release(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json")["status"] == "pass"
    escrow_oracle = escrow / "oracles" / "holdout" / "hold-one.json"
    escrow_oracle.write_text(escrow_oracle.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
    tampered = verify_tri_split_release(release / "manifest.tri-split.json", escrow / "manifest.holdout-escrow.json")
    assert tampered["status"] == "invalid"
    assert any(issue["code"] == "escrow_oracle_hash_mismatch" for issue in tampered["issues"])
