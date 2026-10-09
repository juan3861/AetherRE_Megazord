"""Lock de execução para impedir dois jobs publicando no mesmo diretório."""

from __future__ import annotations

import json
import os
import secrets
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class _DuplicateLockKey(ValueError):
    """A lock owner record must not have an ambiguous JSON interpretation."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateLockKey(key)
        value[key] = item
    return value


class RunLockError(RuntimeError):
    """Diretório de execução já está sob custódia de outro processo."""


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import psutil

            return bool(psutil.pid_exists(pid))
        except ImportError:
            # Não use ``os.kill(pid, 0)`` como primeiro fallback no Windows:
            # sua semântica varia entre versões e pode bloquear em PID inválido.
            # OpenProcess com consulta limitada é uma sonda bounded e não
            # injeta sinal nem executa o processo observado.
            try:
                import ctypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
                kernel32.OpenProcess.restype = ctypes.c_void_p
                kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel32.CloseHandle.restype = ctypes.c_int
                kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
                kernel32.GetExitCodeProcess.restype = ctypes.c_int
                handle = kernel32.OpenProcess(0x1000, 0, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
                if not handle:
                    return False
                try:
                    exit_code = ctypes.c_uint32()
                    if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                        # Access/query failure is not proof of death; fail closed.
                        return True
                    # Windows keeps a terminating process queryable briefly.
                    # STILL_ACTIVE (259) is the only state treated as alive.
                    return int(exit_code.value) == 259
                finally:
                    kernel32.CloseHandle(handle)
            except (AttributeError, OSError, TypeError, ValueError):
                pass
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError, PermissionError):
        return False
    return True


class RunLock:
    """Lock baseado em criação exclusiva, com recuperação de lock órfão."""

    def __init__(self, path: Path):
        self.path = path
        self._owned = False
        self._owner_token: str | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "owner_token": secrets.token_hex(16),
        }
        self._owner_token = str(payload["owner_token"])
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        for attempt in range(2):
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                try:
                    try:
                        written = 0
                        while written < len(encoded):
                            written += os.write(fd, encoded[written:])
                        os.fsync(fd)
                    except Exception:
                        # A failed write/fsync must not strand a lock owned by
                        # this acquisition attempt.  Never remove a file whose
                        # owner token no longer matches (another actor may have
                        # recovered it after an unusual filesystem race).
                        # Close first on Windows: an open handle can prevent
                        # reading/unlinking the lock file under restrictive
                        # sharing modes.
                        os.close(fd)
                        fd = -1
                        try:
                            current = json.loads(
                                self.path.read_text(encoding="utf-8"),
                                object_pairs_hook=_unique_json_object,
                            )
                            if current.get("owner_token") == self._owner_token and int(current.get("pid", -1)) == os.getpid():
                                self.path.unlink(missing_ok=True)
                        except (OSError, ValueError, TypeError, json.JSONDecodeError):
                            pass
                        raise
                finally:
                    if fd != -1:
                        os.close(fd)
                self._owned = True
                return
            except FileExistsError:
                if attempt == 0 and self._is_stale():
                    try:
                        self.path.unlink()
                    except FileNotFoundError:
                        pass
                    continue
                raise RunLockError(f"run_locked:{self.path}")

    def _is_stale(self) -> bool:
        try:
            data = json.loads(
                self.path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
            )
            return not _pid_alive(int(data.get("pid", -1)))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            # Lock ilegível não é prova de que está livre; só pode ser
            # recuperado se não houver processo vivo associado.
            return False

    def verify_owner(self) -> bool:
        """Confirm this instance's live token still owns the lock record."""
        if not self._owned or not self._owner_token:
            return False
        try:
            data = json.loads(
                self.path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False
        return (
            isinstance(data, dict)
            and type(data.get("pid")) is int
            and data.get("pid") == os.getpid()
            and data.get("host") == socket.gethostname()
            and data.get("owner_token") == self._owner_token
        )

    def release(self) -> bool:
        """Remove this instance's matching lock; return true only if unlinked."""
        if not self._owned:
            return False
        if not self.verify_owner():
            return False
        try:
            self.path.unlink()
        except FileNotFoundError:
            return False
        self._owned = False
        self._owner_token = None
        return True

    def __enter__(self) -> "RunLock":
        self.acquire()
        return self

    def __exit__(self, *_: object) -> None:
        self.release()



