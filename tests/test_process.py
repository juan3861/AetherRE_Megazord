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


