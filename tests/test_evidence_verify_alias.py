import json
from pathlib import Path

from megazord import main


def test_evidence_verify_alias_uses_same_fail_closed_validator(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "evidence.json"; out = tmp_path / "report.json"
    source.write_text(json.dumps([{
        "evidence_id": "ev-1", "run_id": "run-1", "input_hash": "a" * 64,
        "producer": "worker", "method": "static", "validation_status": "observed", "supports": True,
    }]), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord", "evidence-verify", "--input", str(source), "--out", str(out)])
    assert main() == 0
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "valid"
