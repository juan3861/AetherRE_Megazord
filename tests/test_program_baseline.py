import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import tools.f00_program_baseline as baseline_module
from tools.f00_program_baseline import capture_program_baseline, hash_file_stable


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
    assert report["files"][0]["sha256"] == "eccc39336aa8fb60a3dd2e3eb2c56a0f2759b67df27ac8a27a48f22dd691fb34"


def test_baseline_prunes_generated_tool_distribution(tmp_path: Path) -> None:
    root = tmp_path / "RE"
    generated = root / "tools" / "ghidra_12.1.2_PUBLIC"
    generated.mkdir(parents=True)
    (generated / "ghidra.jar").write_bytes(b"third-party")
    (root / "tools" / "audit.py").write_text("pass\n", encoding="utf-8")

    report = capture_program_baseline(root, tmp_path / "baseline.json")

    assert [entry["path"] for entry in report["files"]] == ["tools/audit.py"]


def test_baseline_prunes_generated_composite_path_and_preserves_sibling(tmp_path: Path) -> None:
    root = tmp_path / "RE"
    generated = root / "samples" / "generated" / "nested"
    generated.mkdir(parents=True)
    (generated / "fixture.bin").write_bytes(b"generated")
    (root / "samples" / "keep.py").write_text("pass\n", encoding="utf-8")

    report = capture_program_baseline(root, tmp_path / "baseline.json")

    assert [entry["path"] for entry in report["files"]] == ["samples/keep.py"]


def test_baseline_captures_git_junit_inventory_and_validates_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "RE"
    root.mkdir()
    (root / "main.py").write_text("value = 1\n", encoding="utf-8")
    junit = tmp_path / "suite.xml"
    junit.write_text(
        '<testsuite tests="3" failures="1" errors="0" skipped="1"></testsuite>',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args, returncode=0, stdout=b" M README.md\n?? added.py\n", stderr=b""
        ),
    )
    report = capture_program_baseline(root, tmp_path / "baseline.json", junit_path=junit)
    schema = json.loads(
        (Path(__file__).parents[1] / "docs" / "evidence" / "program-baseline.schema.json").read_text(
            encoding="utf-8"
        )
    )

    Draft202012Validator(schema).validate(report)
    assert report["inventory"] == {
        "file_count": 1,
        "sha256": hashlib.sha256(
            json.dumps(report["files"], ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }
    assert report["git"]["available"] is True
    assert report["git"]["status_porcelain_v1"] == [" M README.md", "?? added.py"]
    assert report["junit"]["provided"] is True
    assert report["junit"]["summary"] == {"errors": 0, "failures": 1, "skipped": 1, "tests": 3}
    assert report["junit"]["sha256"] == hashlib.sha256(junit.read_bytes()).hexdigest()


def test_baseline_fails_closed_when_file_changes_during_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"before")
    actual_stat = Path.stat
    calls = 0

    def changing_stat(self: Path, *args, **kwargs):
        nonlocal calls
        if self == payload:
            calls += 1
            if calls == 2:
                payload.write_bytes(b"after-with-different-size")
        return actual_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", changing_stat)
    with pytest.raises(ValueError, match="baseline_file_changed_during_hash"):
        hash_file_stable(payload)


def test_junit_testsuites_aggregates_child_suites_without_namespace_duplicates(
    tmp_path: Path,
) -> None:
    root = tmp_path / "RE"
    root.mkdir()
    (root / "main.py").write_text("pass\n", encoding="utf-8")
    junit = tmp_path / "suite.xml"
    junit.write_text(
        """<testsuites xmlns="urn:junit" tests="0" failures="0" errors="0" skipped="0">
        <testsuite name="one" tests="2" failures="1" errors="0" skipped="0">
          <testcase name="ok"/><testcase name="bad"><failure/></testcase>
        </testsuite>
        <testsuite name="two" tests="2" failures="0" errors="1" skipped="1">
          <testcase name="error"><error/></testcase><testcase name="skip"><skipped/></testcase>
        </testsuite>
        </testsuites>""",
        encoding="utf-8",
    )

    report = capture_program_baseline(root, tmp_path / "baseline.json", junit)

    assert report["junit"]["summary"] == {
        "errors": 1,
        "failures": 1,
        "skipped": 1,
        "tests": 4,
    }


def test_junit_provenance_uses_one_snapshot_when_file_mutates_before_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "RE"
    root.mkdir()
    (root / "main.py").write_text("pass\n", encoding="utf-8")
    junit = tmp_path / "suite.xml"
    junit.write_text('<testsuite tests="1"><testcase name="ok"/></testsuite>', encoding="utf-8")
    original = junit.read_bytes()
    actual_fromstring = baseline_module.ElementTree.fromstring

    def mutate_then_parse(payload: bytes):
        junit.write_text(
            '<testsuite tests="1"><testcase name="bad"><failure/></testcase></testsuite>',
            encoding="utf-8",
        )
        return actual_fromstring(payload)

    monkeypatch.setattr(baseline_module.ElementTree, "fromstring", mutate_then_parse)
    report = capture_program_baseline(root, tmp_path / "baseline.json", junit)

    assert report["junit"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert report["junit"]["size"] == len(original)
    assert report["junit"]["summary"] == {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "tests": 1,
    }


def test_gitignore_does_not_mask_referenced_tools_or_locks() -> None:
    import ast

    root = Path(__file__).resolve().parents[1]
    required_tools = set((
        "tools/authorized_local_corpus.py",
        "tools/blind_release.py",
        "tools/bootstrap_corpus.py",
        "tools/build_dia_extract.ps1",
        "tools/build_phase_declaration.py",
        "tools/complex_corpus.py",
        "tools/custody_snapshot.py",
        "tools/dia_extract.cpp",
        "tools/dotnet_workers.lock.json",
        "tools/f00_program_baseline.py",
        "tools/f02_commit_crash_campaign.py",
        "tools/f02_concurrency_stress.py",
        "tools/f02_fault_campaign.py",
        "tools/f02_process_crash_campaign.py",
        "tools/f08_windows_sandbox_probe.py",
        "tools/f11_adversarial_campaign.py",
        "tools/f11_adversarial_cli_campaign.py",
        "tools/f11_remaining_boundary_campaign.py",
        "tools/f12_universal_release.py",
        "tools/ghidra_distribution.candidate.json",
        "tools/hyperv_benign_trace_run.bat",
        "tools/hyperv_benign_trace_run.ps1",
        "tools/hyperv_observe.ps1",
        "tools/hyperv_observe_and_verify.bat",
        "tools/hyperv_prepare_nocloud.bat",
        "tools/hyperv_prepare_nocloud.ps1",
        "tools/hyperv_provision.bat",
        "tools/hyperv_provision.ps1",
        "tools/jar_workers.lock.json",
        "tools/juliet_multifile_corpus.py",
        "tools/phase_test_map.py",
        "tools/rea_static_workers.lock.json",
        "tools/run_tests.py",
        "tools/run_validation_campaign.py",
        "tools/split_contract.py",
        "tools/static_workers.lock.json",
        "tools/toolchain.lock.json",
        "tools/tri_split_ci.py",
        "tools/tri_split_evaluate.py",
        "tools/tri_split_release.py",
        "tools/tri_split_unblind.py",
        "tools/verify_ubuntu_source.py",
    ))
    for test_file in (root / "tests").glob("test_*.py"):
        tree = ast.parse(test_file.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("tools."):
                        required_tools.add(f"tools/{alias.name.split('.')[1]}.py")
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("tools"):
                parts = node.module.split(".")
                if len(parts) >= 2:
                    required_tools.add(f"tools/{parts[1]}.py")
    for rel in sorted(required_tools):
        assert (root / rel).is_file(), f"missing required tool/lock: {rel}"
        check = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--no-index", "-q", rel],
            capture_output=True,
            check=False,
        )
        assert check.returncode != 0, f"required tool/lock is masked by .gitignore: {rel}"


def test_phase_test_map_has_zero_unmapped_modules() -> None:
    from tools.phase_test_map import build_map

    root = Path(__file__).resolve().parents[1]
    mapping = build_map(root)
    assert mapping["unmapped_modules"] == []

