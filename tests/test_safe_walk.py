from pathlib import Path

import pytest

from aether_re.safe_walk import iter_files_pruned, should_exclude_dir
from aether_re.source import analyze_python_project


def test_generated_and_vendor_trees_are_pruned_before_source_read(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "first.py").write_text("def first(): pass\n", encoding="utf-8")
    for dirname in ("node_modules", "browser_profiles", "_vendored_copy", ".clean_gate_venv3", "wheel_replay_venv", "chrome_stealth_profile", "runtimecopy-abc", "vendor"):
        directory = tmp_path / dirname
        directory.mkdir()
        (directory / "wrong.py").write_text("def wrong(): pass\n", encoding="utf-8")
    files = [path.relative_to(tmp_path).as_posix() for path in iter_files_pruned(tmp_path, {"vendor"})]
    assert files == ["src/first.py"]
    report = analyze_python_project(tmp_path)
    assert [item["path"] for item in report["modules"]] == ["src/first.py"]
    assert should_exclude_dir("_VENDORED_FOO", set())


def test_directory_symlink_is_not_followed(tmp_path: Path):
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "file.py").write_text("pass\n", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(tmp_path / "target", target_is_directory=True)
    except OSError:
        pytest.skip("symlink capability unavailable")
    files = [path.relative_to(tmp_path).as_posix() for path in iter_files_pruned(tmp_path, set())]
    assert files == ["target/file.py"]
