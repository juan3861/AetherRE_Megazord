import json
from pathlib import Path

from aether_re.adapters import ilspy as ilspy_module
from aether_re.adapters.ilspy import ILSpyAdapter


def _write_lock(tmp_path: Path) -> Path:
    path = tmp_path / "dotnet-workers.lock.json"
    path.write_text(
        json.dumps(
            {
                "schema": "dotnet-worker-lock.v1",
                "profile": "dotnet",
                "runtime": {
                    "name": "dotnet",
                    "path": str(tmp_path / "dotnet.exe"),
                    "sha256": "0" * 64,
                    "sdk_version": "10.0.203",
                    "version_argv": ["--version"],
                    "framework": "Microsoft.NETCore.App",
                    "framework_major": 10,
                    "framework_version": "10.0.7",
                    "framework_version_argv": ["--list-runtimes"],
                },
                "worker": {
                    "name": "ilspycmd",
                    "path": str(tmp_path / "ilspycmd.dll"),
                    "sha256": "1" * 64,
                    "version": "11.1.0.9782",
                    "version_argv": ["--version"],
                    "version_contains": "ilspycmd: 11.1.0.9782",
                    "official_url": "https://github.com/icsharpcode/ILSpy/releases/tag/v11.1",
                    "license_spdx": "MIT",
                },
                "limits": {
                    "wall_seconds": 120,
                    "memory_mb": 1536,
                    "cpu_seconds": 120,
                    "input_bytes": 268435456,
                    "output_bytes": 16777216,
                    "probe_output_bytes": 65536,
                },
                "invocation": {
                    "argv_template": ["{dotnet}", "{ilspycmd}", "{input}"],
                    "shell": False,
                    "output_mode": "bounded_stdout",
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _worker_result(stdout: str = "", **overrides):
    result = {
        "returncode": 0,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "resource_exceeded": False,
        "output_limit_exceeded": False,
        "output_bytes": len(stdout.encode("utf-8")),
    }
    result.update(overrides)
    return result


def test_ilspy_adapter_fails_closed_when_pinned_tools_missing(tmp_path):
    adapter = ILSpyAdapter(
        dotnet=str(tmp_path / "dotnet.exe"),
        ilspycmd=str(tmp_path / "ilspycmd.dll"),
    )
    assert adapter.available() is False
    assert adapter.analyze(tmp_path / "x.dll", tmp_path / "out")["error"] == (
        "ilspycmd_worker_unavailable_or_hash_mismatch"
    )


def test_adapter_fails_closed_on_duplicate_lock_keys(tmp_path):
    lock_path = tmp_path / "duplicate-lock.json"
    lock_path.write_text(
        '{"schema":"dotnet-worker-lock.v1","schema":"evil"}',
        encoding="utf-8",
    )
    assert ILSpyAdapter(lock_path=lock_path).available() is False


def test_checked_in_dotnet_lock_matches_the_installed_worker():
    lock_path = Path(__file__).parents[1] / "tools" / "dotnet_workers.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))

    assert lock["schema"] == "dotnet-worker-lock.v1"
    assert lock["profile"] == "dotnet"
    assert lock["worker"]["version"] == "11.1.0.9782"
    assert lock["worker"]["license_spdx"] == "MIT"
    assert lock["runtime"]["sdk_version"] == "10.0.203"


def test_analyze_rejects_nonfile_target_before_starting_worker(tmp_path, monkeypatch):
    adapter = ILSpyAdapter(lock_path=_write_lock(tmp_path))
    monkeypatch.setattr(adapter, "available", lambda: True)

    def unexpected_worker(*args, **kwargs):
        raise AssertionError("worker must not start for a missing target")

    monkeypatch.setattr(ilspy_module, "run_bounded", unexpected_worker)
    result = adapter.analyze(tmp_path / "missing.dll", tmp_path / "out")

    assert result["ok"] is False
    assert result["executed"] is False
    assert result["error"] == "target_invalid_or_symlink"


def test_analyze_uses_versioned_worker_and_bounded_stdout(tmp_path, monkeypatch):
    lock_path = _write_lock(tmp_path)
    adapter = ILSpyAdapter(lock_path=lock_path)
    monkeypatch.setattr(adapter, "available", lambda: True)
    target = tmp_path / "sample.dll"
    target.write_bytes(b"benign assembly fixture")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((list(map(str, command)), kwargs))
        if command[-1] == "--version" and len(command) == 2:
            return _worker_result("10.0.203")
        if command[-1] == "--list-runtimes":
            return _worker_result("Microsoft.NETCore.App 10.0.7 [C:/dotnet/shared]")
        if command[-1] == "--version":
            return _worker_result(
                "ilspycmd: 11.1.0.9782\nICSharpCode.Decompiler: 11.1.0.9782"
            )
        return _worker_result("namespace Fixture; public class Sample { }\n")

    monkeypatch.setattr(ilspy_module, "run_bounded", fake_run)
    result = adapter.analyze(target, tmp_path / "out")

    assert result["ok"] is True
    assert result["executed"] is True
    assert result["decompiled_files"] == ["decompiled.cs"]
    source = tmp_path / "out" / "dotnet_static" / "decompiled.cs"
    assert source.read_text(encoding="utf-8").startswith("namespace Fixture;")
    assert calls[0][0][-1] == "--version"
    assert calls[1][0][-1] == "--list-runtimes"
    assert calls[2][0][-1] == "--version"
    analysis_command, analysis_kwargs = calls[3]
    assert analysis_command[-1] == str(target)
    assert "-p" not in analysis_command and "-o" not in analysis_command
    assert analysis_kwargs["output_limit_bytes"] == 16 * 1024 * 1024
    assert analysis_kwargs["shell"] is not True
    assert "encoding" not in analysis_kwargs
    assert "errors" not in analysis_kwargs


def test_version_mismatch_stops_before_target_analysis(tmp_path, monkeypatch):
    adapter = ILSpyAdapter(lock_path=_write_lock(tmp_path))
    monkeypatch.setattr(adapter, "available", lambda: True)
    target = tmp_path / "sample.dll"
    target.write_bytes(b"benign assembly fixture")
    commands = []

    def fake_run(command, **kwargs):
        commands.append(list(map(str, command)))
        if command[-1] == "--version" and len(command) == 2:
            return _worker_result("10.0.203")
        if command[-1] == "--list-runtimes":
            return _worker_result("Microsoft.NETCore.App 10.0.7 [C:/dotnet/shared]")
        if command[-1] == "--version":
            return _worker_result("ilspycmd: 99.0.0\n")
        return _worker_result("should not decompile")

    monkeypatch.setattr(ilspy_module, "run_bounded", fake_run)
    result = adapter.analyze(target, tmp_path / "out")

    assert result["ok"] is False
    assert result["executed"] is False
    assert result["error"] == "ilspycmd_version_mismatch"
    assert len(commands) == 3


def test_output_limit_marks_analysis_partial_and_does_not_save_pseudo_source(
    tmp_path, monkeypatch
):
    adapter = ILSpyAdapter(lock_path=_write_lock(tmp_path))
    monkeypatch.setattr(adapter, "available", lambda: True)
    target = tmp_path / "sample.dll"
    target.write_bytes(b"benign assembly fixture")
    calls = 0

    def fake_run(command, **kwargs):
        nonlocal calls
        calls += 1
        if command[-1] == "--version" and len(command) == 2:
            return _worker_result("10.0.203")
        if command[-1] == "--list-runtimes":
            return _worker_result("Microsoft.NETCore.App 10.0.7 [C:/dotnet/shared]")
        if command[-1] == "--version":
            return _worker_result("ilspycmd: 11.1.0.9782\n")
        return _worker_result(
            "truncated",
            output_limit_exceeded=True,
            output_bytes=16 * 1024 * 1024 + 1,
        )

    monkeypatch.setattr(ilspy_module, "run_bounded", fake_run)
    result = adapter.analyze(target, tmp_path / "out")

    assert result["ok"] is False
    assert result["partial"] is True
    assert result["error"] == "worker_output_limit_exceeded"
    assert not (tmp_path / "out" / "dotnet_static" / "decompiled.cs").exists()
