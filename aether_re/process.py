"""Execução governada de subprocessos externos, com timeout e limpeza."""

from __future__ import annotations

import os
import subprocess
import shutil
import time
from pathlib import Path
from typing import Any, Sequence


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


def run_bounded(command: Sequence[str | Path], *, timeout: float, memory_limit_mb: int | None = None, cpu_time_limit_s: float | None = None, **kwargs: Any) -> dict[str, Any]:
    """Executa comando com limites de wall-clock/RSS/CPU e limpa a árvore."""
    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence) or not command:
        raise ValueError("command_sequence_required")
    if any(item is None or str(item) == "" for item in command):
        raise ValueError("command_item_invalid")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < float(timeout) <= 86400.0:
        raise ValueError("timeout_out_of_range")
    if kwargs.get("shell") is True:
        raise ValueError("shell_execution_forbidden")
    kwargs["shell"] = False
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
                        if os.name == "nt":
                            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True)
                        else:
                            proc.kill()
                        stdout, stderr = proc.communicate()
                        return {"returncode": proc.returncode, "stdout": stdout or str(exc.stdout or ""), "stderr": stderr or str(exc.stderr or ""), "timed_out": False, "resource_exceeded": True, "resource_kind": "rss", "rss_mb": round(rss, 2)}
                if cpu_time_limit_s is not None:
                    cpu = _cpu_tree_seconds(proc.pid)
                    if cpu is not None and cpu > cpu_time_limit_s:
                        if os.name == "nt":
                            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True)
                        else:
                            proc.kill()
                        stdout, stderr = proc.communicate()
                        return {"returncode": proc.returncode, "stdout": stdout or str(exc.stdout or ""), "stderr": stderr or str(exc.stderr or ""), "timed_out": False, "resource_exceeded": True, "resource_kind": "cpu", "cpu_seconds": round(cpu, 3)}
                if time.monotonic() < deadline:
                    continue
                raise exc
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True)
        else:
            proc.kill()
        stdout, stderr = proc.communicate()
        return {"returncode": proc.returncode, "stdout": stdout or str(exc.stdout or ""), "stderr": stderr or str(exc.stderr or ""), "timed_out": True, "resource_exceeded": False}


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
