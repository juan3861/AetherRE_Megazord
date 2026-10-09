from argparse import Namespace
import json
from pathlib import Path
import pytest

from aether_re.source import analyze_python_project, write_source_report
from megazord import cmd_source_analyze


def test_python_source_analysis_is_static_and_tracks_uncertainty(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text(
        "import pkg.b\nfrom os import path\nimport importlib\nif FLAG:\n    import optional\n\ndef helper(value):\n    return value\n\n@decorator\ndef main():\n    importlib.import_module('late_module')\n    return helper(path.join('a', 'b'))\n",
        encoding="utf-8",
    )
    (tmp_path / "pkg" / "b.py").write_text("def other():\n    return 1\n", encoding="utf-8")
    (tmp_path / "pkg" / "__init__.py").write_text("\n", encoding="utf-8")
    (tmp_path / "evil.py").write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "ignored.py").write_text("def ignored(): pass\n", encoding="utf-8")
    report = analyze_python_project(tmp_path)
    assert report["schema"] == "python-source-analysis.v1"
    assert all("vendor" not in item["path"] for item in report["modules"])
    assert {item["name"] for item in report["functions"]} >= {"helper", "main", "other"}
    assert any(item["callee"] == "helper" for item in report["calls"])
    assert any(item["module"] == "optional" and item["conditional"] for item in report["imports"])
    assert report["dynamic_imports"][0]["reason"] == "runtime_import_expression"
    assert any(item["caller"].endswith(".main") and item["callee"] == "helper" for item in report["calls"])
    assert report["graph"]["schema"] == "source-graph.v1"
    assert any(edge["kind"] == "calls" and edge["resolved"] is False for edge in report["graph"]["edges"])
    assert any(edge["kind"] == "calls" and edge.get("target") == "helper" and edge["resolved"] is True for edge in report["graph"]["edges"])
    assert any(edge["kind"] == "imports" and edge.get("target") == "pkg.b" and edge["resolved"] is True for edge in report["graph"]["edges"])
    assert not any(item["kind"] == "runtime_execution" for item in report["errors"])


def test_python_relative_import_is_resolved_without_importing(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("\n", encoding="utf-8")
    (tmp_path / "pkg" / "a.py").write_text("from .b import other\n", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("def other():\n    return 1\n", encoding="utf-8")
    report = analyze_python_project(tmp_path)
    edge = next(item for item in report["graph"]["edges"] if item["kind"] == "imports")
    assert edge["target"] == ".b"
    assert edge["resolved"] is True
    assert edge["resolution"] == "relative_local_module"


def test_python_relative_import_that_escapes_package_stays_unresolved(tmp_path: Path):
    (tmp_path / "a.py").write_text("from ..b import other\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def other():\n    return 1\n", encoding="utf-8")
    report = analyze_python_project(tmp_path)
    edge = next(item for item in report["graph"]["edges"] if item["kind"] == "imports")
    assert edge["resolved"] is False
    assert edge["resolution"] == "unresolved"


def test_python_source_analysis_records_syntax_error_and_report_is_replayable(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    report = analyze_python_project(tmp_path)
    assert report["errors"][0]["kind"] == "syntax_error"
    out = tmp_path / "report.json"
    write_source_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == "python-source-analysis.v1"


def test_source_cli_rejects_missing_root_without_traceback(tmp_path: Path):
    out = tmp_path / "invalid-source.json"
    code = cmd_source_analyze(Namespace(root=str(tmp_path / "missing"), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["errors"][0]["kind"] == "input_invalid"


def test_python_source_skips_symlinked_source_with_explicit_error(tmp_path: Path):
    real = tmp_path / "real.py"
    real.write_text("def safe():\n    return 1\n", encoding="utf-8")
    linked = tmp_path / "linked.py"
    try:
        linked.symlink_to(real)
    except OSError:
        pytest.skip("symlink capability unavailable")
    report = analyze_python_project(tmp_path)
    assert not any(item["path"] == "linked.py" for item in report["modules"])
    assert any(item["kind"] == "symlink_skipped" and item["path"] == "linked.py" for item in report["errors"])


def test_python_source_budget_abstains_before_large_read(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n" * 10, encoding="utf-8")
    report = analyze_python_project(tmp_path, max_file_bytes=8)
    assert report["modules"] == []
    assert report["errors"][0]["kind"] == "max_file_bytes_exceeded"
    assert report["summary"]["bytes_read"] == 0
    assert report["summary"]["candidates"] == 1


def test_python_source_max_files_is_explicit(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
    report = analyze_python_project(tmp_path, max_files=1)
    assert len(report["modules"]) == 1
    assert report["errors"][-1]["kind"] == "max_files_exceeded"
