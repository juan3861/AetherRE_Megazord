import json
from argparse import Namespace
import pytest

from aether_re.project_audit import analyze_project, write_project_audit
from aether_re.project_inventory import inventory_project
from megazord import cmd_project_audit


def test_project_audit_composes_inventory_source_and_build_without_execution(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "main.py").write_text("import os\ndef run(value):\n    return value\n", encoding="utf-8")
    (root / "src" / "native.c").write_text("int helper(int x) { return x + 1; }\n", encoding="utf-8")
    (root / "tests" / "test_main.py").write_text("def test_run(): pass\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    report = analyze_project(root)
    assert report["schema"] == "project-audit.v1"
    assert report["status"] == "complete"
    assert set(report["source"]) >= {"python", "c_family", "python_dependencies", "python_risks"}
    assert report["documentation"]["status"] == "not_found"
    assert report["summary"]["modules"] >= 2
    assert report["summary"]["functions"] >= 2
    assert report["build"]["status"] == "observed"
    assert "nenhum import" in report["limitations"][0]
    out = tmp_path / "audit.json"
    write_project_audit(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["root_digest"] == report["root_digest"]


def test_project_audit_rejects_missing_root_without_traceback(tmp_path):
    report = analyze_project(tmp_path / "missing")
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "root_missing"


def test_project_audit_abstains_from_full_coverage_when_directory_excluded(tmp_path):
    (tmp_path / "main.py").write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "third_party.py").write_text("def hidden(): pass\n", encoding="utf-8")
    report = analyze_project(tmp_path)
    assert report["status"] == "partial"
    assert report["scope"]["full_project_covered"] is False
    assert report["scope"]["skipped_inventory_paths"] >= 1
    assert not any(item["path"].startswith("vendor/") for item in report["source"]["python"]["modules"])


def test_project_audit_cli_propagates_invalid_root(tmp_path):
    out = tmp_path / "audit.json"
    code = cmd_project_audit(Namespace(root=str(tmp_path / "missing"), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"


def test_project_audit_rejects_symlink_root(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink capability unavailable")
    report = analyze_project(link)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "root_symlink_not_allowed"


def test_project_audit_detects_target_change_between_readers(tmp_path, monkeypatch):
    target = tmp_path / "main.py"
    target.write_text("value = 1\n", encoding="utf-8")
    calls = 0
    def inventory_with_mutation(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            target.write_text("value = 2\n", encoding="utf-8")
        return inventory_project(root)
    monkeypatch.setattr("aether_re.project_audit.inventory_project", inventory_with_mutation)
    report = analyze_project(tmp_path)
    assert calls == 2
    assert report["status"] == "partial"
    assert report["consistency"] == "changed_during_analysis"
    assert report["root_digest"] != report["post_root_digest"]
