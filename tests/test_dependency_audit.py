import json
from argparse import Namespace
from pathlib import Path

from aether_re.dependency_audit import audit_python_dependencies, write_dependency_report
from aether_re.source import analyze_python_project
from megazord import cmd_dependencies_audit


def test_dependency_audit_distinguishes_declared_and_observed(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests>=2\nunused-pkg==1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import requests\nimport os\n", encoding="utf-8")
    report = audit_python_dependencies(tmp_path)
    states = {item["normalized"]: item["state"] for item in report["dependencies"]}
    assert states["requests"] == "declared_and_imported"
    assert states["unused_pkg"] == "declared_not_observed"
    assert report["summary"]["declared_not_observed"] == 1
    out = tmp_path / "dependencies.json"
    write_dependency_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == "python-dependency-audit.v1"


def test_dependency_audit_does_not_call_imports(tmp_path: Path):
    (tmp_path / "main.py").write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
    report = audit_python_dependencies(tmp_path)
    assert report["summary"]["declared"] == 0
    assert report["schema"] == "python-dependency-audit.v1"


def test_dependency_audit_reuses_same_root_source_report(tmp_path: Path, monkeypatch):
    (tmp_path / "main.py").write_text("import json\n", encoding="utf-8")
    source = analyze_python_project(tmp_path)
    def fail_rescan(*_args, **_kwargs):
        raise AssertionError("source parsed twice")
    monkeypatch.setattr("aether_re.dependency_audit.analyze_python_project", fail_rescan)
    report = audit_python_dependencies(tmp_path, source_report=source)
    assert report["status"] == "complete"
    assert report["errors"] == []


def test_dependency_audit_rejects_foreign_source_report(tmp_path: Path):
    report = audit_python_dependencies(tmp_path, source_report={"root": "other", "modules": [], "imports": []})
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "source_report_root_mismatch"


def test_dependency_audit_rejects_missing_root_without_traceback(tmp_path: Path):
    report = audit_python_dependencies(tmp_path / "missing")
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "root_missing"


def test_dependency_audit_cli_propagates_invalid_root(tmp_path: Path):
    out = tmp_path / "dependencies.json"
    code = cmd_dependencies_audit(Namespace(root=str(tmp_path / "missing"), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
