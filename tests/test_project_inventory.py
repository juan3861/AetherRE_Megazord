import json
import subprocess
import sys
import pytest

from aether_re.project_inventory import inventory_project, write_inventory_report


def test_inventory_is_static_categorized_and_deterministic(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "tools").mkdir()
    (root / "src" / "main.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    (root / "tests" / "test_main.py").write_text("def test_run(): pass\n", encoding="utf-8")
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    (root / "tools" / "ignored.py").write_text("raise RuntimeError()\n", encoding="utf-8")
    first = inventory_project(root)
    second = inventory_project(root)
    assert first["status"] == "complete"
    assert first["root_digest"] == second["root_digest"]
    assert {item["category"] for item in first["files"]} >= {"source", "test", "documentation", "build_or_dependency"}
    assert any(item["reason"] == "excluded_directory" for item in first["skipped"])


def test_inventory_marks_budget_truncation_and_cli_report_is_json(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    for index in range(3):
        (root / f"file_{index}.py").write_text(f"value = {index}\n", encoding="utf-8")
    report = inventory_project(root, max_files=2)
    assert report["status"] == "partial"
    assert any(item["reason"] == "max_files" for item in report["skipped"])
    out = tmp_path / "inventory.json"
    write_inventory_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == "project-inventory.v1"


def test_inventory_rejects_symlink_root(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink capability unavailable")
    report = inventory_project(link)
    assert report["status"] == "invalid"
    assert report["issues"][0]["code"] == "root_symlink_not_allowed"


def test_inventory_does_not_descend_directory_link(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("secret = 1\n", encoding="utf-8")
    link = root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink capability unavailable")
    report = inventory_project(root)
    assert not any(item["path"].startswith("linked/") for item in report["files"])
    assert any(item["path"] == "linked" and item["reason"] == "symlink_directory" for item in report["skipped"])
    nested = inventory_project(link / "subdir")
    assert nested["status"] == "invalid"
    assert nested["issues"][0]["code"] == "root_symlink_not_allowed"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction contract")
def test_inventory_does_not_descend_windows_junction(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("secret = 1\n", encoding="utf-8")
    junction = root / "junction"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")
    try:
        assert junction.is_junction()
        report = inventory_project(root)
        assert not any(item["path"].startswith("junction/") for item in report["files"])
        assert any(item["path"] == "junction" and item["reason"] == "symlink_directory" for item in report["skipped"])
    finally:
        junction.rmdir()
    assert (outside / "secret.py").is_file()
