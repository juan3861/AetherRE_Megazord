import json
from argparse import Namespace

from aether_re.sarif import report_to_sarif, write_sarif
from megazord import cmd_sarif


def test_sarif_export_preserves_heuristic_properties_and_locations(tmp_path):
    report = {
        "limitations": ["static only"],
        "findings": [{"engine": "risk", "severity": "high", "title": "eval", "detail": "dynamic code", "confidence": 0.4, "source": "src/main.py", "line": 7}],
        "indicators": [{"rule": "taint", "severity": "medium", "reason": "flow", "state": "static_indicator", "reachable": "unknown", "requires_validation": True, "source": "src/main.py", "line": 8}],
    }
    sarif = report_to_sarif(report, tool_version="test")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert len(run["results"]) == 2
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] in {7, 8}
    assert any(rule["properties"]["heuristic"] for rule in run["tool"]["driver"]["rules"])
    out = tmp_path / "report.sarif"
    write_sarif(report, out, tool_version="test")
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_sarif_export_rejects_malformed_records_without_traceback():
    sarif = report_to_sarif({"findings": {"not": "a-list"}, "indicators": [{"severity": 3}], "limitations": "bad"})
    props = sarif["runs"][0]["properties"]
    codes = {item["code"] for item in props["errors"]}
    assert {"records_must_be_list", "severity_invalid", "limitations_must_be_list"} <= codes
    assert len(sarif["runs"][0]["results"]) == 1


def test_sarif_cli_rejects_unreadable_input_and_returns_nonzero(tmp_path):
    out = tmp_path / "missing.sarif"
    code = cmd_sarif(Namespace(input=str(tmp_path / "missing.json"), out=str(out)))
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert sarif["runs"][0]["properties"]["errors"][0]["code"] == "upstream_error"
