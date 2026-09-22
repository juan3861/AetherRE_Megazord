from pathlib import Path

from tools.f00_program_baseline import capture_program_baseline


def test_baseline_hashes_project_and_rejects_rotor_scope(tmp_path: Path) -> None:
    root = tmp_path / "RE"
    root.mkdir()
    (root / "aether_re").mkdir()
    (root / "aether_re" / "core.py").write_text("x = 1\n", encoding="utf-8")
    (root / "replay_rotor_static_audit.py").write_text("legacy\n", encoding="utf-8")

    report = capture_program_baseline(root, tmp_path / "baseline.json")

    assert report["schema"] == "program-baseline.v1"
    assert report["scope"]["included_count"] == 1
    assert report["scope"]["excluded"] == ["replay_rotor_static_audit.py"]
    assert len(report["files"][0]["sha256"]) == 64


def test_baseline_prunes_generated_tool_distribution(tmp_path: Path) -> None:
    root = tmp_path / "RE"
    generated = root / "tools" / "ghidra_12.1.2_PUBLIC"
    generated.mkdir(parents=True)
    (generated / "ghidra.jar").write_bytes(b"third-party")
    (root / "tools" / "audit.py").write_text("pass\n", encoding="utf-8")

    report = capture_program_baseline(root, tmp_path / "baseline.json")

    assert [entry["path"] for entry in report["files"]] == ["tools/audit.py"]
