import json
from pathlib import Path

from megazord import main


def test_release_build_refuses_partial_phase_report(tmp_path: Path, monkeypatch) -> None:
    phase = tmp_path / "phases.json"; out = tmp_path / "release.json"
    phase.write_text(json.dumps({"schema": "phase-gate-report.v1", "phases": [{"phase_id": "F00", "status": "PARCIALMENTE QUITADA"}]}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord", "release-build", "--phase-report", str(phase), "--out", str(out)])
    assert main() == 3
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["status"] == "blocked" and result["manifest_built"] is False
    assert len(result["blocking_gates"]) == 13
