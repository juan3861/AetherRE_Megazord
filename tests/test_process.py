import os
import subprocess
import sys
import time

import pytest

from aether_re.process import _cpu_tree_seconds, _rss_tree_mb, cpu_limit_from_env, disk_budget_from_env, has_free_disk, memory_limit_from_env, run_bounded, timeout_from_env


def test_run_bounded_reports_success():
    result = run_bounded([sys.executable, "-c", "print('ok')"], timeout=5)
    assert result["returncode"] == 0
    assert result["timed_out"] is False
    assert result["stdout"].strip() == "ok"


def test_run_bounded_rejects_shell_and_invalid_commands():
    with pytest.raises(ValueError, match="shell_execution_forbidden"):
        run_bounded([sys.executable, "-c", "print('no')"], timeout=5, shell=True)
    with pytest.raises(ValueError, match="command_sequence_required"):
        run_bounded("echo no", timeout=5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="timeout_out_of_range"):
        run_bounded([sys.executable, "-c", "print('no')"], timeout=0)


def test_run_bounded_kills_timeout():
    result = run_bounded([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)
    assert result["timed_out"] is True


def test_run_bounded_enforces_combined_stdout_stderr_limit():
    script = (
        "import sys,time; "
        "sys.stdout.buffer.write(b'o'*65536); sys.stdout.flush(); "
        "sys.stderr.buffer.write(b'e'*65536); sys.stderr.flush(); "
        "time.sleep(10)"
    )
    result = run_bounded(
        [sys.executable, "-c", script],
        timeout=5,
        output_limit_bytes=4096,
    )

    assert result["resource_exceeded"] is True
    assert result["resource_kind"] == "output"
    assert result["output_limit_exceeded"] is True
    assert result["output_limit_bytes"] == 4096
    assert result["output_bytes"] > 4096
    assert len(result["stdout"].encode("utf-8")) + len(result["stderr"].encode("utf-8")) <= 4096
    assert result["timed_out"] is False


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_run_bounded_rejects_invalid_output_limit(limit):
    with pytest.raises(ValueError, match="output_limit_out_of_range"):
        run_bounded(
            [sys.executable, "-c", "print('no')"],
            timeout=5,
            output_limit_bytes=limit,
        )


def test_run_bounded_requires_output_cap_when_process_tree_containment_is_mandatory():
    with pytest.raises(ValueError, match="process_tree_requires_output_limit"):
        run_bounded(
            [sys.executable, "-c", "raise SystemExit(0)"],
            timeout=5,
            require_process_tree=True,
        )


def test_timeout_from_env_is_bounded_and_fail_closed(monkeypatch):
    monkeypatch.setenv("AETHER_TEST_TIMEOUT", "99999")
    assert timeout_from_env("AETHER_TEST_TIMEOUT", 5.0, maximum=60.0) == 60.0
    monkeypatch.setenv("AETHER_TEST_TIMEOUT", "invalid")
    assert timeout_from_env("AETHER_TEST_TIMEOUT", 5.0) == 5.0
    monkeypatch.setenv("AETHER_TEST_TIMEOUT", "-1")
    assert timeout_from_env("AETHER_TEST_TIMEOUT", 5.0) == 5.0


def test_memory_limit_from_env_is_bounded_and_fail_closed(monkeypatch):
    monkeypatch.setenv("AETHER_TEST_MEMORY", "9999999")
    assert memory_limit_from_env("AETHER_TEST_MEMORY", 10, maximum=1024) == 1024
    monkeypatch.setenv("AETHER_TEST_MEMORY", "invalid")
    assert memory_limit_from_env("AETHER_TEST_MEMORY", 10) == 10


def test_cpu_limit_from_env_is_bounded_and_fail_closed(monkeypatch):
    monkeypatch.setenv("AETHER_TEST_CPU", "9999999")
    assert cpu_limit_from_env("AETHER_TEST_CPU", 10.0, maximum=60.0) == 60.0
    monkeypatch.setenv("AETHER_TEST_CPU", "invalid")
    assert cpu_limit_from_env("AETHER_TEST_CPU", 10.0) == 10.0


def test_disk_budget_is_bounded_and_checks_existing_mount(tmp_path):
    assert disk_budget_from_env("AETHER_MISSING_DISK_BUDGET", 10) == 10
    assert has_free_disk(tmp_path, 1) is True


def test_resource_sampling_race_fails_closed_without_raising():
    missing_pid = os.getpid() + 10_000_000
    assert _rss_tree_mb(missing_pid) is None
    assert _cpu_tree_seconds(missing_pid) is None


@pytest.mark.skipif(os.name != "nt", reason="process-tree termination proof requires Windows taskkill /T")
def test_run_bounded_kills_process_tree():
    """Timeout must terminate a launcher and its child, not only the root PID."""
    child_code = "import time; time.sleep(30)"
    launcher_code = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable, '-c', " + repr(child_code) + "]); "
        "print(child.pid, flush=True); time.sleep(30)"
    )
    result = run_bounded([sys.executable, "-c", launcher_code], timeout=0.5)
    assert result["timed_out"] is True
    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    assert lines and lines[0].isdigit()
    child_pid = int(lines[0])
    def pid_exists(pid: int) -> bool:
        try:
            import psutil
        except ImportError:
            try:
                probe = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            if probe.returncode != 0:
                return False
            return any(token.isdigit() and int(token) == pid for line in probe.stdout.splitlines() for token in line.split())
        return bool(psutil.pid_exists(pid))

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and pid_exists(child_pid):
        time.sleep(0.05)
    if pid_exists(child_pid):
        subprocess.run(["taskkill", "/PID", str(child_pid), "/T", "/F"], capture_output=True, text=True)
        pytest.fail(f"child process survived timeout tree termination: {child_pid}")


@pytest.mark.skipif(os.name != "nt", reason="orphan cleanup proof requires a Windows job object")
def test_run_bounded_output_cap_kills_descendant_after_launcher_exits(tmp_path):
    """A short-lived launcher must not orphan a child that retains its pipes."""
    import json

    pid_file = tmp_path / "child.pid"
    child_code = (
        "import sys,time; time.sleep(1.1); "
        "sys.stdout.buffer.write(b'x'*65536); sys.stdout.flush(); time.sleep(30)"
    )
    launcher_code = (
        "import pathlib,subprocess,sys; "
        "child=subprocess.Popen([sys.executable, '-c', " + repr(child_code) + "]); "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid)); "
        "print(child.pid, flush=True)"
    )
    worker_code = (
        "import json; from aether_re.process import run_bounded; "
        "result=run_bounded(["
        + repr(sys.executable)
        + ", '-c', "
        + repr(launcher_code)
        + "], timeout=3, output_limit_bytes=4096); print(json.dumps(result))"
    )
    helper = subprocess.Popen(
        [sys.executable, "-c", worker_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = helper.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_test_process_tree(helper)
        child_pid = int(pid_file.read_text()) if pid_file.exists() else None
        if child_pid is not None:
            subprocess.run(["taskkill", "/PID", str(child_pid), "/T", "/F"], capture_output=True, text=True)
        pytest.fail("bounded runner hung after launcher exited with descendant holding pipes")
    assert helper.returncode == 0, stderr
    payload = next(line for line in reversed(stdout.splitlines()) if line.startswith("{"))
    result = json.loads(payload)

    child_pid = int(pid_file.read_text())
    try:
        import psutil
    except ImportError:
        psutil = None

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        alive = psutil.pid_exists(child_pid) if psutil else _windows_pid_exists(child_pid)
        if not alive:
            break
        time.sleep(0.05)
    else:
        if psutil and psutil.pid_exists(child_pid):
            subprocess.run(["taskkill", "/PID", str(child_pid), "/T", "/F"], capture_output=True, text=True)
        pytest.fail(f"descendant survived output cap after launcher exit: {child_pid}")

    assert result["output_limit_exceeded"] is True
    assert result["resource_kind"] == "output"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object preflight proof")
def test_run_bounded_require_process_tree_fails_before_command_starts(tmp_path, monkeypatch):
    from aether_re import process

    marker = tmp_path / "must-not-exist.txt"
    monkeypatch.setattr(process._WindowsJob, "attach", lambda _proc: None)
    result = run_bounded(
        [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"],
        timeout=5,
        output_limit_bytes=4096,
        require_process_tree=True,
    )

    assert result["resource_exceeded"] is True
    assert result["resource_kind"] == "process_tree_unavailable"
    assert result["process_tree_contained"] is False
    assert not marker.exists()


def _kill_test_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    subprocess.run(
        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if proc.poll() is None:
        proc.kill()


def _windows_pid_exists(pid: int) -> bool:
    probe = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}"],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    return probe.returncode == 0 and any(
        token.isdigit() and int(token) == pid
        for line in probe.stdout.splitlines()
        for token in line.split()
    )


