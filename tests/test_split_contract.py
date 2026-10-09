import json
from pathlib import Path

from tools.split_contract import audit_split_contract


def _manifest(path: Path, entries: list[dict], *, blind_holdout=None) -> Path:
    path.write_text(json.dumps({"schema": "re-megazord-corpus.v1", "blind_holdout": blind_holdout, "projects": entries}), encoding="utf-8")
    return path


def _entry(project_id: str, family: str, split: str, *, independent: bool = True, blind=None) -> dict:
    return {"id": project_id, "family": family, "language": "python", "split": split, "blind_holdout": blind, "provenance": {"oracle_independent": independent}}


def test_split_contract_reports_structural_counts_and_unverified_blindness(tmp_path: Path):
    manifest = _manifest(
        tmp_path / "manifest.json",
        [_entry("dev", "f_dev", "development"), _entry("cal", "f_cal", "calibration"), _entry("hold", "f_hold", "holdout")],
    )
    report = audit_split_contract([manifest])
    assert report["status"] == "partial"
    assert report["split_counts"] == {"calibration": 1, "development": 1, "holdout": 1}
    assert report["blind_control"]["verified"] is False
    assert report["blind_control"]["missing_projects"] == ["hold"]


def test_split_contract_rejects_duplicate_ids_and_family_leaks(tmp_path: Path):
    first = _manifest(tmp_path / "first.json", [_entry("same", "leak", "development")])
    second = _manifest(tmp_path / "second.json", [_entry("same", "leak", "holdout")])
    report = audit_split_contract([first, second])
    codes = {item["code"] for item in report["errors"]}
    assert {"duplicate_project_id", "family_split_leak", "split_insufficient"} <= codes
    assert report["status"] == "invalid"


def test_split_contract_can_be_complete_only_when_blindness_is_declared(tmp_path: Path):
    manifest = _manifest(
        tmp_path / "manifest.json",
        [
            _entry("dev", "f_dev", "development"),
            _entry("cal", "f_cal", "calibration"),
            _entry("hold", "f_hold", "holdout", blind=True),
        ],
        blind_holdout=True,
    )
    report = audit_split_contract([manifest])
    assert report["status"] == "complete"
    assert report["blind_control"]["declared_for_all_holdout"] is True
    assert report["blind_control"]["verified"] is False
