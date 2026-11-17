"""Hash-pinned, bounded, static-only adapter for .NET assemblies via ILSpyCmd."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from aether_re.adapters._static_base import doc
from aether_re.adapters.base import Adapter
from aether_re.ir import IRDocument
from aether_re.process import run_bounded


_DEFAULT_LOCK_PATH = Path(__file__).resolve().parents[2] / "tools" / "dotnet_workers.lock.json"
_DEFAULT_DOTNET = Path(r"C:\Program Files\dotnet\dotnet.exe")
_DEFAULT_ILSPYCMD = Path(
    r"E:\AetherRE_Toolchain\packages\ilspycmd-11.1.0.9782\content\tools\net10.0\any\ilspycmd.dll"
)
_LOCK_SCHEMA = "dotnet-worker-lock.v1"
_EVIDENCE_SCHEMA = "dotnet-static-evidence.v2"
_PROBE_TIMEOUT_SECONDS = 15.0


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _atomic_write(path: Path, payload: bytes) -> None:
    temp_path = path.with_name(path.name + ".tmp")
    with temp_path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    temp_path.replace(path)


def normalize_ilspy(payload: dict[str, Any], artifact_id: str, evidence_ref: str) -> IRDocument:
    """Normalize explicit ILSpy metadata; decompiled C# remains inferred output."""
    if payload.get("schema", "ilspy.v1") not in {"ilspy.v1", "ilspy-json.v1"}:
        raise ValueError("ilspy_schema_unsupported")
    return doc(
        "dotnet",
        artifact_id,
        (evidence_ref,),
        payload,
        "dotnet",
        {"types": "type", "methods": "method", "fields": "field", "resources": "resource"},
        ("native_code_mapping",) if payload.get("ready_to_run") else (),
    )


class ILSpyAdapter(Adapter):
    """Decompile one managed assembly to bounded stdout; never execute the target."""

    name = "ilspy"

    def __init__(
        self,
        *,
        dotnet: str | Path | None = None,
        ilspycmd: str | Path | None = None,
        lock_path: str | Path | None = None,
    ) -> None:
        self.lock_path = Path(lock_path or _DEFAULT_LOCK_PATH)
        self._dotnet_override = dotnet or os.environ.get("AETHER_DOTNET_BIN")
        self._ilspycmd_override = ilspycmd or os.environ.get("AETHER_ILSPYCMD_DLL")
        lock = self._load_lock()
        runtime = lock.get("runtime", {}) if lock else {}
        worker = lock.get("worker", {}) if lock else {}
        self.dotnet = Path(self._dotnet_override or runtime.get("path") or _DEFAULT_DOTNET)
        self.ilspycmd = Path(self._ilspycmd_override or worker.get("path") or _DEFAULT_ILSPYCMD)

    @staticmethod
    def _valid_lock(payload: Any) -> bool:
        if not isinstance(payload, dict) or payload.get("schema") != _LOCK_SCHEMA:
            return False
        if payload.get("profile") != "dotnet":
            return False
        runtime = payload.get("runtime")
        worker = payload.get("worker")
        limits = payload.get("limits")
        invocation = payload.get("invocation")
        if not all(isinstance(value, dict) for value in (runtime, worker, limits, invocation)):
            return False
        required_runtime = ("path", "sha256", "sdk_version", "version_argv", "framework", "framework_version", "framework_version_argv")
        required_worker = ("path", "sha256", "version", "version_argv", "version_contains", "official_url", "license_spdx")
        if any(not isinstance(runtime.get(key), str) or not runtime[key] for key in required_runtime if key not in {"version_argv", "framework_version_argv"}):
            return False
        if any(not isinstance(worker.get(key), str) or not worker[key] for key in required_worker if key != "version_argv"):
            return False
        if not isinstance(runtime.get("version_argv"), list) or not all(isinstance(item, str) for item in runtime["version_argv"]):
            return False
        if not isinstance(runtime.get("framework_version_argv"), list) or not all(isinstance(item, str) for item in runtime["framework_version_argv"]):
            return False
        if not isinstance(worker.get("version_argv"), list) or not all(isinstance(item, str) for item in worker["version_argv"]):
            return False
        for digest in (runtime.get("sha256"), worker.get("sha256")):
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                return False
        for key in ("wall_seconds", "memory_mb", "cpu_seconds", "input_bytes", "output_bytes", "probe_output_bytes"):
            value = limits.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                return False
        if limits["output_bytes"] > 64 * 1024 * 1024 or limits["probe_output_bytes"] > 1024 * 1024:
            return False
        if invocation.get("shell") is not False or invocation.get("output_mode") != "bounded_stdout":
            return False
        if invocation.get("argv_template") != ["{dotnet}", "{ilspycmd}", "{input}"]:
            return False
        return True

    def _load_lock(self) -> dict[str, Any] | None:
        try:
            payload = json.loads(self.lock_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
        except (OSError, ValueError, json.JSONDecodeError):
            return None
        return payload if self._valid_lock(payload) else None

    def available(self) -> bool:
        lock = self._load_lock()
        if lock is None:
            return False
        return (
            _sha256_file(self.dotnet) == lock["runtime"]["sha256"]
            and _sha256_file(self.ilspycmd) == lock["worker"]["sha256"]
        )

    @staticmethod
    def _run_probe(command: list[str], limits: dict[str, Any]) -> dict[str, Any]:
        return run_bounded(
            command,
            timeout=min(_PROBE_TIMEOUT_SECONDS, float(limits["wall_seconds"])),
            memory_limit_mb=int(limits["memory_mb"]),
            cpu_time_limit_s=min(float(limits["cpu_seconds"]), _PROBE_TIMEOUT_SECONDS),
            output_limit_bytes=int(limits["probe_output_bytes"]),
            shell=False,
        )

    @staticmethod
    def _probe_ok(result: dict[str, Any]) -> bool:
        return (
            result.get("returncode") == 0
            and not result.get("timed_out")
            and not result.get("resource_exceeded")
            and not result.get("output_limit_exceeded")
        )

    def _verify_versions(self, lock: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
        runtime = lock["runtime"]
        worker = lock["worker"]
        limits = lock["limits"]
        probes = [
            (
                [str(self.dotnet), *runtime["version_argv"]],
                runtime["sdk_version"],
                "dotnet_sdk_version_mismatch",
            ),
            (
                [str(self.dotnet), *runtime["framework_version_argv"]],
                f'{runtime["framework"]} {runtime["framework_version"]}',
                "dotnet_runtime_version_mismatch",
            ),
            (
                [str(self.dotnet), str(self.ilspycmd), *worker["version_argv"]],
                worker["version_contains"],
                "ilspycmd_version_mismatch",
            ),
        ]
        evidence: list[dict[str, Any]] = []
        for command, expected, mismatch_error in probes:
            try:
                result = self._run_probe(command, limits)
            except (OSError, ValueError):
                return False, {"probes": evidence}, "worker_version_probe_failed"
            stdout = str(result.get("stdout", ""))
            evidence.append(
                {
                    "argv": command,
                    "returncode": result.get("returncode"),
                    "stdout": stdout[: int(limits["probe_output_bytes"])],
                    "output_limit_exceeded": bool(result.get("output_limit_exceeded")),
                }
            )
            if not self._probe_ok(result):
                return False, {"probes": evidence}, "worker_version_probe_failed"
            if expected not in stdout:
                return False, {"probes": evidence}, mismatch_error
        return True, {"probes": evidence}, None

    def analyze(self, target: Path, out_dir: Path) -> dict[str, Any]:
        target = Path(target)
        out_dir = Path(out_dir)
        if not self.available():
            return {
                "ok": False,
                "available": False,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "ilspycmd_worker_unavailable_or_hash_mismatch",
            }
        lock = self._load_lock()
        if lock is None:
            return {
                "ok": False,
                "available": False,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "dotnet_worker_lock_invalid",
            }
        limits = lock["limits"]
        if target.is_symlink() or not target.is_file():
            return {
                "ok": False,
                "available": True,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "target_invalid_or_symlink",
            }
        try:
            input_size = target.stat().st_size
        except OSError:
            input_size = -1
        if input_size < 0 or input_size > limits["input_bytes"]:
            return {
                "ok": False,
                "available": True,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "target_input_limit_exceeded",
            }

        root = out_dir / "dotnet_static"
        if root.exists():
            return {
                "ok": False,
                "available": True,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "dotnet_evidence_already_exists",
            }

        versions_ok, version_evidence, version_error = self._verify_versions(lock)
        if not versions_ok:
            return {
                "ok": False,
                "available": True,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": version_error or "worker_version_probe_failed",
                "version_evidence": version_evidence,
            }

        input_sha_before = _sha256_file(target)
        if input_sha_before is None:
            return {
                "ok": False,
                "available": True,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "target_hash_failed",
            }
        try:
            root.mkdir(parents=True, exist_ok=False)
        except (FileExistsError, OSError):
            return {
                "ok": False,
                "available": True,
                "executed": False,
                "produced_evidence": False,
                "partial": False,
                "error": "dotnet_output_directory_unavailable",
            }

        command = [str(self.dotnet), str(self.ilspycmd), str(target.resolve())]
        try:
            process = run_bounded(
                command,
                timeout=float(limits["wall_seconds"]),
                memory_limit_mb=int(limits["memory_mb"]),
                cpu_time_limit_s=float(limits["cpu_seconds"]),
                output_limit_bytes=int(limits["output_bytes"]),
                cwd=str(root),
                shell=False,
            )
        except (OSError, ValueError) as exc:
            process = {
                "returncode": None,
                "stdout": "",
                "stderr": f"worker_start_failed:{exc.__class__.__name__}",
                "timed_out": False,
                "resource_exceeded": False,
                "output_limit_exceeded": False,
                "output_bytes": 0,
            }

        stdout = str(process.get("stdout", ""))
        stderr = str(process.get("stderr", ""))
        output_limited = bool(process.get("output_limit_exceeded"))
        timed_out = bool(process.get("timed_out"))
        resource_exceeded = bool(process.get("resource_exceeded"))
        input_sha_after = _sha256_file(target)
        input_stable = input_sha_after == input_sha_before
        returncode = process.get("returncode")
        successful = (
            returncode == 0
            and not timed_out
            and not resource_exceeded
            and not output_limited
            and bool(stdout.strip())
            and input_stable
        )
        error: str | None = None
        if output_limited:
            error = "worker_output_limit_exceeded"
        elif timed_out:
            error = "worker_timed_out"
        elif resource_exceeded:
            error = "worker_resource_limit_exceeded"
        elif not input_stable:
            error = "target_changed_during_analysis"
        elif returncode != 0:
            error = "ilspycmd_nonzero_exit"
        elif not stdout.strip():
            error = "ilspycmd_empty_output"

        source_path = root / "decompiled.cs"
        source_bytes = stdout.encode("utf-8", errors="replace")
        if successful:
            try:
                _atomic_write(source_path, source_bytes)
            except OSError:
                successful = False
                error = "decompiled_output_write_failed"

        source_sha = _sha256_file(source_path) if source_path.is_file() else None
        report_path = root / "summary.json"
        evidence = {
            "schema": _EVIDENCE_SCHEMA,
            "status": "complete" if successful else "partial_or_rejected",
            "input": {
                "path": str(target.resolve()),
                "size_bytes": input_size,
                "sha256_before": input_sha_before,
                "sha256_after": input_sha_after,
                "stable": input_stable,
            },
            "worker": {
                "name": lock["worker"]["name"],
                "version": lock["worker"]["version"],
                "path": str(self.ilspycmd),
                "sha256": lock["worker"]["sha256"],
                "license_spdx": lock["worker"]["license_spdx"],
                "official_url": lock["worker"]["official_url"],
            },
            "runtime": {
                "name": lock["runtime"]["name"],
                "sdk_version": lock["runtime"]["sdk_version"],
                "path": str(self.dotnet),
                "sha256": lock["runtime"]["sha256"],
                "framework": lock["runtime"]["framework"],
                "framework_version": lock["runtime"]["framework_version"],
            },
            "version_probes": version_evidence["probes"],
            "command_argv": command,
            "execution": {
                "returncode": returncode,
                "timed_out": timed_out,
                "resource_exceeded": resource_exceeded,
                "output_limit_exceeded": output_limited,
                "output_bytes": process.get("output_bytes", len(source_bytes)),
                "stderr_tail": stderr[-2000:],
            },
            "decompiled_output": {
                "path": str(source_path) if successful else None,
                "sha256": source_sha,
                "size_bytes": len(source_bytes) if successful else None,
            },
            "limitations": [
                "decompiled C# is inferred output, not original source",
                "static analysis only; the assembly was not executed",
                "this worker smoke does not certify accuracy or profile coverage",
            ],
            "error": error,
        }
        try:
            _atomic_write(
                report_path,
                (json.dumps(evidence, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            )
        except OSError:
            return {
                "ok": False,
                "available": True,
                "executed": True,
                "produced_evidence": False,
                "partial": True,
                "error": "dotnet_evidence_write_failed",
                "returncode": returncode,
            }

        result = {
            "ok": successful,
            "available": True,
            "executed": True,
            "produced_evidence": report_path.is_file(),
            "partial": not successful,
            "returncode": returncode,
            "timed_out": timed_out,
            "resource_exceeded": resource_exceeded,
            "output_limit_exceeded": output_limited,
            "decompiled_files": ["decompiled.cs"] if successful else [],
            "report": str(report_path),
            "source_sha256": source_sha,
            "target_sha256": input_sha_before,
            "stderr_tail": stderr[-2000:],
        }
        if error:
            result["error"] = error
        return result


def verify_dotnet_worker_lock(path: str | Path | None = None) -> dict[str, Any]:
    """Rehash the pinned .NET runtime and ILSpyCmd assembly without executing a target."""
    lock_file = Path(path or _DEFAULT_LOCK_PATH)
    try:
        payload = json.loads(lock_file.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema": "dotnet-worker-verification.v1",
            "verified": False,
            "errors": [str(exc) if isinstance(exc, ValueError) else "dotnet_worker_lock_unreadable"],
        }
    if not ILSpyAdapter._valid_lock(payload):
        return {
            "schema": "dotnet-worker-verification.v1",
            "verified": False,
            "errors": ["dotnet_worker_lock_schema_invalid"],
        }
    runtime = payload["runtime"]
    worker = payload["worker"]
    dotnet_path = Path(runtime["path"])
    ilspy_path = Path(worker["path"])
    dotnet_actual = _sha256_file(dotnet_path) if dotnet_path.is_file() else None
    ilspy_actual = _sha256_file(ilspy_path) if ilspy_path.is_file() else None
    errors: list[str] = []
    if dotnet_actual is None:
        errors.append("dotnet_runtime_missing")
    elif dotnet_actual != runtime["sha256"]:
        errors.append("dotnet_runtime_hash_mismatch")
    if ilspy_actual is None:
        errors.append("ilspycmd_worker_missing")
    elif ilspy_actual != worker["sha256"]:
        errors.append("ilspycmd_worker_hash_mismatch")
    return {
        "schema": "dotnet-worker-verification.v1",
        "verified": not errors,
        "runtime": {
            "name": runtime["name"],
            "expected_sha256": runtime["sha256"],
            "observed_sha256": dotnet_actual or "",
            "state": "verified" if dotnet_actual == runtime["sha256"] else ("missing" if dotnet_actual is None else "hash_mismatch"),
        },
        "worker": {
            "name": worker["name"],
            "expected_sha256": worker["sha256"],
            "observed_sha256": ilspy_actual or "",
            "state": "verified" if ilspy_actual == worker["sha256"] else ("missing" if ilspy_actual is None else "hash_mismatch"),
        },
        "errors": errors,
        "limitations": ["verification rehashes runtime and assembly bytes only; it does not execute a target or prove analysis quality"],
    }

