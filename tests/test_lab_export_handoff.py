import json
import zipfile
from pathlib import Path

from megazord import main


def test_lab_export_handoff_creates_non_attestation_template(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "handoff.zip"; report = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", ["megazord", "lab-export-handoff", "--out", str(output), "--report", str(report)])
    assert main() == 0
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["status"] == "template_exported"
    assert result["qualified"] is False and result["execution"] is False
    with zipfile.ZipFile(output) as archive:
        template = json.loads(archive.read("handoff-template.json"))
    assert template["status"] == "NOT_EXECUTED"
    assert "dynamic-lab-handoff.v1" in template["limitations"][0]
