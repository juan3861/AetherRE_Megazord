import json
import subprocess
import sys
from pathlib import Path

from tools.f12_universal_release import (
    evaluate_universal_release,
    evaluate_universal_release_from_rows,
)


def _complete_rows():
    return [
        {"gate": f"F{i:02d}", "status": "QUITADA", "evidence_valid": True}
        for i in range(13)
    ]


def test_release_stays_partial_when_vm_gate_is_unproved():
    rows = _complete_rows()
    rows[8] = {"gate": "F08", "status": "NAO_COMPROVADA", "evidence_valid": True}
    report = evaluate_universal_release_from_rows(rows)
    assert report["gate_passed"] is False
    assert report["status"] == "PARCIALMENTE_QUITADA"
    assert report["remaining_debt"] == ["F08"]


def test_release_fails_closed_for_missing_duplicate_and_invalid_evidence():
    rows = _complete_rows()
    rows.pop(4)
    rows.append({"gate": "F03", "status": "QUITADA", "evidence_valid": True})
    rows[6]["evidence_valid"] = False
    report = evaluate_universal_release_from_rows(rows)
    assert report["gate_passed"] is False
    assert {"F03", "F04", "F07"} <= set(report["remaining_debt"])
    assert next(row for row in report["gates"] if row["gate"] == "F04")["reason"] == "gate_missing"
    assert "duplicate_gate" in report["integrity_errors"]


def test_release_reads_phase_gate_report_and_verifies_source_hash(tmp_path: Path):
    rows = _complete_rows()
    source = tmp_path / "phase.json"
    source.write_text(json.dumps({"gates": rows}), encoding="utf-8")
    report = evaluate_universal_release(tmp_path, [source])
    assert report["gate_passed"] is True
    assert report["status"] == "QUITADA"
    assert report["sources"][0]["sha256"]


def test_phase_gate_parent_failure_cannot_be_promoted_by_complete_rows(tmp_path: Path):
    phases = [
        {
            "phase_id": f"F{i:02d}",
            "status": "QUITADA",
            "evidence": [{"verified": True}],
            "errors": [],
        }
        for i in range(13)
    ]
    source = tmp_path / "phase-parent-failed.json"
    source.write_text(
        json.dumps({
            "schema": "phase-gate-report.v1",
            "status": "partial",
            "gate_passed": False,
            "phases": phases,
            "errors": [],
        }),
        encoding="utf-8",
    )
    report = evaluate_universal_release(tmp_path, [source])
    assert report["gate_passed"] is False
    assert report["status"] == "PARCIALMENTE_QUITADA"
    assert report["remaining_debt"] == [f"F{i:02d}" for i in range(13)]
    assert {"source_gate_not_passed", "source_status_not_complete"} <= set(report["integrity_errors"])


def test_release_rejects_evidence_outside_root_and_malformed_json(tmp_path: Path):
    outside = tmp_path.parent / "outside-release.json"
    outside.write_text(json.dumps({"gates": _complete_rows()}), encoding="utf-8")
    malformed = tmp_path / "bad.json"
    malformed.write_text("{", encoding="utf-8")
    report = evaluate_universal_release(tmp_path, [outside, malformed])
    assert report["status"] == "PARCIALMENTE_QUITADA"
    assert report["remaining_debt"] == [f"F{i:02d}" for i in range(13)]
    assert {"evidence_path_escape", "evidence_json_invalid"} <= set(report["integrity_errors"])


def test_cli_materializes_partial_report_and_returns_nonzero(tmp_path: Path):
    output = tmp_path / "release.json"
    script = Path(__file__).parents[1] / "tools" / "f12_universal_release.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--root", str(tmp_path), "--output", str(output)],
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert completed.returncode == 3
    assert report["gate_passed"] is False
    assert report["remaining_debt"] == [f"F{i:02d}" for i in range(13)]
