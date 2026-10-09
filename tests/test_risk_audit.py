from pathlib import Path
import json
from argparse import Namespace

from aether_re.risk_audit import audit_source_risks, write_risk_report
from aether_re.source import analyze_python_project
from megazord import cmd_risk_audit


def test_risk_audit_emits_causal_location_without_claiming_reachability(tmp_path: Path):
    (tmp_path / "app.py").write_text("import os\ndef run(user):\n    eval(user)\n    os.system(user)\n", encoding="utf-8")
    report = audit_source_risks(analyze_python_project(tmp_path))
    assert report["summary"]["total"] == 2
    assert {item["rule"] for item in report["indicators"]} == {"eval", "os.system"}
    assert all(item["state"] == "static_indicator" and item["reachable"] == "unknown" for item in report["indicators"])
    assert all(item["source"] == "app.py" and item["line"] in {3, 4} for item in report["indicators"])
    out = tmp_path / "risk.json"
    write_risk_report(report, out)
    assert out.is_file()


def test_risk_audit_rejects_malformed_source_report_without_promoting_findings():
    report = audit_source_risks({"calls": [{"callee": 123}]})
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "call_callee_invalid"
    assert report["indicators"] == []


def test_risk_audit_cli_rejects_unreadable_source_report(tmp_path: Path):
    out = tmp_path / "risk.json"
    code = cmd_risk_audit(Namespace(source_report=str(tmp_path / "missing.json"), project_root=None, out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"


def test_taint_cli_path_failure_is_propagated_as_invalid(tmp_path: Path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"calls": []}), encoding="utf-8")
    out = tmp_path / "risk.json"
    code = cmd_risk_audit(Namespace(source_report=str(source), project_root=str(tmp_path / "missing"), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][-1]["code"] == "taint_audit_invalid"
