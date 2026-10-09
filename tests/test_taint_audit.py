from pathlib import Path

from aether_re.taint_audit import audit_python_taint


def test_taint_audit_finds_source_to_sink_and_preserves_unknown_reachability(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import os\ndef bad():\n    value = input()\n    os.system(value)\n\ndef constant():\n    value = 'fixed'\n    os.system(value)\n",
        encoding="utf-8",
    )
    report = audit_python_taint(tmp_path)
    assert report["schema"] == "python-taint-audit.v1"
    assert report["summary"]["flows"] == 1
    flow = report["flows"][0]
    assert flow["source_line"] == 3 and flow["sink_line"] == 4
    assert flow["reachable"] == "unknown"
