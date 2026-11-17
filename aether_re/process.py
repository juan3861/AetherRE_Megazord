"""Execução governada de subprocessos externos, com timeout e limpeza."""

from __future__ import annotations

import os
import subprocess
import shutil
import time
from threading import Event, Lock, Thread
from pathlib import Path
from typing import Any, Sequence


MAX_OUTPUT_LIMIT_BYTES = 256 * 1024 * 1024
_OUTPUT_READ_CHUNK_BYTES = 64 * 1024
_PIPE_DRAIN_GRACE_SECONDS = 0.5
_PIPE_POST_EXIT_OUTPUT_GRACE_SECONDS = 1.5


def timeout_from_env(name: str, default: float, *, maximum: float = 3600.0) -> float:
    """Lê budget de tempo configurável sem aceitar valores inválidos/perigosos."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if value <= 0:
        return default
    return min(value, maximum)


def memory_limit_from_env(name: str, default: int | None = None, *, maximum: int = 1024 * 1024) -> int | None:
    """Lê limite de RSS em MiB, rejeitando valores inválidos e excessivos."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    if value <= 0:
        return default
    return min(value, maximum)


def cpu_limit_from_env(name: str, default: float | None = None, *, maximum: float = 86400.0) -> float | None:
    """Lê limite de tempo de CPU acumulado (segundos), não wall-clock."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if value <= 0:
        return default
    return min(value, maximum)


def disk_budget_from_env(name: str, default: int = 128, *, maximum: int = 1024 * 1024) -> int:
    """Lê reserva mínima de espaço livre em MiB para uma execução."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return default if value <= 0 else min(value, maximum)


def has_free_disk(path: Path, minimum_mb: int) -> bool:
    """Preflight conservador de espaço; não remove arquivos para liberar quota."""
    try:
        return shutil.disk_usage(path).free >= minimum_mb * 1024 * 1024
    except OSError:
        return False


def _rss_tree_mb(pid: int) -> float | None:
    try:
        import psutil
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
        return sum(item.memory_info().rss for item in processes if item.is_running()) / (1024 * 1024)
    except (ImportError, OSError, ValueError):
        return None
    except Exception:
        # psutil can race with a process that exits between Process() and
        # children()/memory_info(); resource accounting must fail open to the
        # normal bounded wait, never crash the orchestrator.
        return None


def _cpu_tree_seconds(pid: int) -> float | None:
    try:
        import psutil
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
        return sum(item.cpu_times().user + item.cpu_times().system for item in processes if item.is_running())
    except (ImportError, OSError, ValueError):
        return None
    except Exception:
        # Same exit race as RSS accounting; an unavailable sample is not a
        # reason to fabricate a resource violation or abort the job.
        return None


class _WindowsJob:
    """Best-effort Job Object containment for a bounded worker and descendants."""

    def __init__(self, handle: Any, kernel32: Any) -> None:
        self._handle = handle
        self._kernel32 = kernel32

    @classmethod
    def attach(cls, proc: subprocess.Popen[Any]) -> "_WindowsJob | None":
        if os.name != "nt":
            return None
        try:
            import ctypes
            from ctypes import wintypes

            class BasicLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_ulonglong) for name in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
                )]

            class ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", BasicLimitInformation),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
            ]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel32.TerminateJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return None
            information = ExtendedLimitInformation()
            # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JobObjectExtendedLimitInformation.
            information.BasicLimitInformation.LimitFlags = 0x00002000
            configured = kernel32.SetInformationJobObject(
                handle, 9, ctypes.byref(information), ctypes.sizeof(information)
            )
            assigned = configured and kernel32.AssignProcessToJobObject(
                handle, wintypes.HANDLE(int(proc._handle))
            )
            if not assigned:
                kernel32.CloseHandle(handle)
                return None
            return cls(handle, kernel32)
        except (AttributeError, OSError, TypeError, ValueError):
            return None

    def terminate(self) -> bool:
        try:
            return bool(self._kernel32.TerminateJobObject(self._handle, 1))
        except (OSError, ValueError):
            return False

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._kernel32.CloseHandle(self._handle)
            except (OSError, ValueError):
                pass
            self._handle = None


def _resume_suspended_windows_process(pid: int) -> bool:
    """Resume the suspended primary thread after Job Object assignment.

    A CREATE_SUSPENDED launch closes the race where a worker can create an
    uncontained child before it is assigned to its Job Object. A new process
    has only its primary thread at this point, so enumerate that thread and
    resume it after containment is established.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class ThreadEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
        kernel32.Thread32First.restype = wintypes.BOOL
        kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry32)]
        kernel32.Thread32Next.restype = wintypes.BOOL
        kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
        if not snapshot or snapshot == wintypes.HANDLE(-1).value:
            return False
        try:
            entry = ThreadEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            found_thread = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
            while found_thread:
                if entry.th32OwnerProcessID == pid:
                    thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)  # THREAD_SUSPEND_RESUME
                    if not thread:
                        return False
                    try:
                        return kernel32.ResumeThread(thread) != 0xFFFFFFFF
                    finally:
                        kernel32.CloseHandle(thread)
                found_thread = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
            return False
        finally:
            kernel32.CloseHandle(snapshot)
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _kill_process_tree(proc: subprocess.Popen[Any], job: _WindowsJob | None = None) -> None:
    if job is not None:
        job.terminate()
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        if proc.poll() is None:
            proc.kill()
    else:
        proc.kill()


def _run_bounded_with_output_limit(
    command: Sequence[str | Path],
    *,
    timeout: float,
    memory_limit_mb: int | None,
    cpu_time_limit_s: float | None,
    output_limit_bytes: int,
    require_process_tree: bool,
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    conflicting_capture_options = {
        "stdout", "stderr", "text", "encoding", "errors", "universal_newlines"
    }.intersection(kwargs)
    if conflicting_capture_options:
        raise ValueError("output_capture_options_conflict")

    if require_process_tree and os.name != "nt":
        return {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "resource_exceeded": True,
            "resource_kind": "process_tree_unavailable",
            "output_limit_exceeded": False,
            "output_limit_bytes": output_limit_bytes,
            "output_bytes": 0,
            "captured_output_bytes": 0,
            "capture_complete": True,
            "process_tree_contained": False,
        }

    if os.name == "nt":
        # Do not allow user code to run until its process is inside the Job
        # Object. Otherwise a fast-spawning child can escape containment.
        kwargs["creationflags"] = int(kwargs.get("creationflags", 0)) | 0x00000004  # CREATE_SUSPENDED

    proc = subprocess.Popen(
        [str(item) for item in command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        **kwargs,
    )
    job = _WindowsJob.attach(proc)
    if require_process_tree and job is None:
        proc.kill()
        proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
        return {
            "returncode": proc.returncode,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "resource_exceeded": True,
            "resource_kind": "process_tree_unavailable",
            "output_limit_exceeded": False,
            "output_limit_bytes": output_limit_bytes,
            "output_bytes": 0,
            "captured_output_bytes": 0,
            "capture_complete": True,
            "process_tree_contained": False,
        }
    if os.name == "nt" and not _resume_suspended_windows_process(proc.pid):
        if job is not None:
            job.terminate()
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
        if job is not None:
            job.close()
        return {
            "returncode": proc.returncode,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "resource_exceeded": True,
            "resource_kind": "process_tree_resume_failed",
            "output_limit_exceeded": False,
            "output_limit_bytes": output_limit_bytes,
            "output_bytes": 0,
            "captured_output_bytes": 0,
            "capture_complete": True,
            "process_tree_contained": job is not None,
        }
    assert proc.stdout is not None and proc.stderr is not None
    buffers: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    state = {"observed_bytes": 0, "captured_bytes": 0}
    state_lock = Lock()
    exceeded = Event()
    reader_errors: list[str] = []

    def drain(pipe: Any, name: str) -> None:
        try:
            while True:
                chunk = pipe.read1(_OUTPUT_READ_CHUNK_BYTES)
                if not chunk:
                    return
                with state_lock:
                    state["observed_bytes"] += len(chunk)
                    remaining = output_limit_bytes - state["captured_bytes"]
                    retained = chunk[:max(0, remaining)]
                    if retained:
                        buffers[name].append(retained)
                        state["captured_bytes"] += len(retained)
                    if state["observed_bytes"] > output_limit_bytes:
                        exceeded.set()
        except (OSError, ValueError) as exc:
            reader_errors.append(type(exc).__name__)

    readers = [
        Thread(target=drain, args=(proc.stdout, "stdout"), daemon=True),
        Thread(target=drain, args=(proc.stderr, "stderr"), daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    reason: str | None = None
    sampled_rss: float | None = None
    sampled_cpu: float | None = None
    while proc.poll() is None:
        if exceeded.is_set():
            reason = "output"
            _kill_process_tree(proc, job)
            break
        if memory_limit_mb is not None:
            sampled_rss = _rss_tree_mb(proc.pid)
            if sampled_rss is not None and sampled_rss > memory_limit_mb:
                reason = "rss"
                _kill_process_tree(proc, job)
                break
        if cpu_time_limit_s is not None:
            sampled_cpu = _cpu_tree_seconds(proc.pid)
            if sampled_cpu is not None and sampled_cpu > cpu_time_limit_s:
                reason = "cpu"
                _kill_process_tree(proc, job)
                break
        if time.monotonic() >= deadline:
            reason = "timeout"
            _kill_process_tree(proc, job)
            break
        time.sleep(0.05)

    if reason is None and any(reader.is_alive() for reader in readers):
        # A launcher can exit cleanly while a contained descendant still owns
        # its inherited pipes. Keep watching that bounded grace window before
        # terminating the Job Object, otherwise the descendant's over-limit
        # write can race the cleanup and be lost as a false normal exit.
        post_exit_deadline = min(
            deadline, time.monotonic() + _PIPE_POST_EXIT_OUTPUT_GRACE_SECONDS,
        )
        while any(reader.is_alive() for reader in readers) and time.monotonic() < post_exit_deadline:
            if exceeded.is_set():
                reason = "output"
                _kill_process_tree(proc, job)
                break
            time.sleep(0.01)

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc, job)
        proc.wait(timeout=5)

    for reader in readers:
        reader.join(timeout=_PIPE_DRAIN_GRACE_SECONDS)
    capture_complete = not any(reader.is_alive() for reader in readers)
    if not capture_complete:
        # The root may already have exited while a descendant still owns an
        # inherited pipe. Job Object termination works after that root exit.
        if job is not None:
            job.terminate()
        for reader in readers:
            reader.join(timeout=1.0)
        capture_complete = not any(reader.is_alive() for reader in readers)

    with state_lock:
        observed_bytes = state["observed_bytes"]
        captured_bytes = state["captured_bytes"]
        stdout = b"".join(buffers["stdout"]).decode("utf-8", errors="replace")
        stderr = b"".join(buffers["stderr"]).decode("utf-8", errors="replace")

    if exceeded.is_set():
        reason = "output"
    elif not capture_complete and reason is None:
        reason = "pipe_cleanup"

    result: dict[str, Any] = {
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": reason == "timeout",
        "resource_exceeded": reason in {"output", "rss", "cpu", "pipe_cleanup"},
        "output_limit_exceeded": exceeded.is_set(),
        "output_limit_bytes": output_limit_bytes,
        "output_bytes": observed_bytes,
        "captured_output_bytes": captured_bytes,
        "capture_complete": capture_complete,
        "process_tree_contained": job is not None,
    }
    if reason in {"output", "rss", "cpu", "pipe_cleanup"}:
        result["resource_kind"] = "output" if reason == "output" else reason
    if reason == "rss" and sampled_rss is not None:
        result["rss_mb"] = round(sampled_rss, 2)
    if reason == "cpu" and sampled_cpu is not None:
        result["cpu_seconds"] = round(sampled_cpu, 3)
    if reader_errors:
        result["capture_errors"] = reader_errors
        result["capture_complete"] = False
        result["resource_exceeded"] = True
        result["resource_kind"] = "pipe_cleanup"
    if job is not None:
        job.close()
    return result


def _finish_legacy_capture(proc: subprocess.Popen[Any], expired: subprocess.TimeoutExpired) -> tuple[str, str, bool]:
    """Bound cleanup even if taskkill stalls or an escaped child retains pipes."""
    _kill_process_tree(proc)
    try:
        stdout, stderr = proc.communicate(timeout=5)
        return stdout or "", stderr or "", True
    except subprocess.TimeoutExpired as cleanup_expired:
        # Do not close buffered pipes here: a communicate reader may hold their
        # lock while a descendant retains a handle. Closing can itself hang.
        def text_output(value: Any) -> str:
            if isinstance(value, bytes):
                return value.decode(getattr(proc, "encoding", None) or "utf-8", errors="replace")
            return value or ""
        return (text_output(cleanup_expired.output if cleanup_expired.output is not None else expired.output),
                text_output(cleanup_expired.stderr if cleanup_expired.stderr is not None else expired.stderr), False)


def run_bounded(
    command: Sequence[str | Path],
    *,
    timeout: float,
    memory_limit_mb: int | None = None,
    cpu_time_limit_s: float | None = None,
    output_limit_bytes: int | None = None,
    require_process_tree: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run a subprocess with wall-clock/RSS/CPU limits and optional bounded output capture."""
    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence) or not command:
        raise ValueError("command_sequence_required")
    if any(item is None or str(item) == "" for item in command):
        raise ValueError("command_item_invalid")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < float(timeout) <= 86400.0:
        raise ValueError("timeout_out_of_range")
    if kwargs.get("shell") is True:
        raise ValueError("shell_execution_forbidden")
    if not isinstance(require_process_tree, bool):
        raise ValueError("require_process_tree_must_be_bool")
    if require_process_tree and output_limit_bytes is None:
        raise ValueError("process_tree_requires_output_limit")
    kwargs["shell"] = False
    if output_limit_bytes is not None:
        if (
            not isinstance(output_limit_bytes, int)
            or isinstance(output_limit_bytes, bool)
            or not 0 < output_limit_bytes <= MAX_OUTPUT_LIMIT_BYTES
        ):
            raise ValueError("output_limit_out_of_range")
        return _run_bounded_with_output_limit(
            command,
            timeout=float(timeout),
            memory_limit_mb=memory_limit_mb,
            cpu_time_limit_s=cpu_time_limit_s,
            output_limit_bytes=output_limit_bytes,
            require_process_tree=require_process_tree,
            kwargs=kwargs,
        )
    proc = subprocess.Popen([str(item) for item in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = max(0.05, min(0.25, deadline - time.monotonic()))
            try:
                stdout, stderr = proc.communicate(timeout=remaining)
                return {"returncode": proc.returncode, "stdout": stdout or "", "stderr": stderr or "", "timed_out": False, "resource_exceeded": False}
            except subprocess.TimeoutExpired as exc:
                if memory_limit_mb is not None:
                    rss = _rss_tree_mb(proc.pid)
                    if rss is not None and rss > memory_limit_mb:
                        stdout, stderr, complete = _finish_legacy_capture(proc, exc)
                        return {"returncode": proc.returncode, "stdout": stdout, "stderr": stderr, "capture_complete": complete, "timed_out": False, "resource_exceeded": True, "resource_kind": "rss", "rss_mb": round(rss, 2)}
                if cpu_time_limit_s is not None:
                    cpu = _cpu_tree_seconds(proc.pid)
                    if cpu is not None and cpu > cpu_time_limit_s:
                        stdout, stderr, complete = _finish_legacy_capture(proc, exc)
                        return {"returncode": proc.returncode, "stdout": stdout, "stderr": stderr, "capture_complete": complete, "timed_out": False, "resource_exceeded": True, "resource_kind": "cpu", "cpu_seconds": round(cpu, 3)}
                if time.monotonic() < deadline:
                    continue
                raise exc
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, complete = _finish_legacy_capture(proc, exc)
        return {"returncode": proc.returncode, "stdout": stdout, "stderr": stderr, "capture_complete": complete, "timed_out": True, "resource_exceeded": False}


def terminate_processes_under(root: Path) -> int:
    """Encerra processos por caminho de executável, de modo restrito."""
    try:
        import psutil
    except ImportError:
        return 0
    root = root.resolve()
    killed = 0
    for item in psutil.process_iter(["pid", "exe"]):
        try:
            exe = item.info.get("exe")
            if exe and Path(exe).resolve().is_relative_to(root):
                item.kill()
                killed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
            continue
    return killed
