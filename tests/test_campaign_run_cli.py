import json
import sys
from pathlib import Path

from megazord import main


def test_campaign_run_cli_executes_declared_no_shell_case(tmp_path: Path, monkeypatch) -> None:
    campaign = tmp_path / "campaign.json"
    output = tmp_path / "result.json"
    campaign.write_text(json.dumps({"schema": "validation-campaign-input.v1", "cases": [{
        "case_id": "cli-ok", "category": "timeout", "command": [sys.executable, "-c", "print('CAMPAIGN_OK')"],
        "expected_exit": 0, "expected_codes": ["CAMPAIGN_OK"], "timeout_s": 5,
    }]}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord", "campaign-run", str(campaign), "--root", str(tmp_path), "--out", str(output)])
    assert main() == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "passed"


def test_campaign_run_cli_rejects_schema(tmp_path: Path, monkeypatch) -> None:
    campaign = tmp_path / "campaign.json"; output = tmp_path / "result.json"
    campaign.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord", "campaign-run", str(campaign), "--root", str(tmp_path), "--out", str(output)])
    assert main() == 3
    assert json.loads(output.read_text(encoding="utf-8"))["errors"][0]["code"] == "campaign_input_invalid"
