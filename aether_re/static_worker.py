"""Pinned bounded static worker invocation. It remains importable without optional process infrastructure."""
from __future__ import annotations
import hashlib, re, subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_FORBIDDEN = re.compile(r"[|&;<>\r\n\0]|(?:^|/)\.\.(?:/|$)|^@")
_SPDX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:OR|AND|WITH)\s+[A-Za-z0-9.+-]+)*$")

@dataclass(frozen=True)
class StaticWorkerSpec:
    name: str; executable: Path; executable_sha256: str; expected_version: str; license_spdx: str
    timeout_s: float; memory_mb: int; cpu_s: int; max_output_bytes: int
    version_args: tuple[str, ...] = ('--version',)

@dataclass(frozen=True)
class StaticWorkerProbe:
    name: str; available: bool; executable_sha256: str; version: str; license_spdx: str; errors: tuple[str, ...]

def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''): digest.update(chunk)
    return digest.hexdigest()

def _run_bounded(command: list[str], **kwargs: Any) -> dict[str, Any]:
    """Use the kernel helper when present; otherwise retain bounded no-shell semantics."""
    try:
        from aether_re.process import run_bounded
    except ImportError:
        completed = subprocess.run(command, shell=False, capture_output=True, text=True, timeout=kwargs['timeout'], cwd=kwargs.get('cwd'))
        return {'returncode': completed.returncode, 'stdout': completed.stdout, 'stderr': completed.stderr, 'timed_out': False}
    return run_bounded(command, **kwargs)

def _spec_errors(spec: StaticWorkerSpec) -> list[str]:
    errors=[]
    if not isinstance(spec.expected_version, str) or not spec.expected_version.strip(): errors.append('worker_expected_version_missing')
    if not isinstance(spec.license_spdx, str) or not _SPDX.fullmatch(spec.license_spdx.strip()): errors.append('worker_license_missing')
    return errors

def probe_static_worker(spec: StaticWorkerSpec) -> StaticWorkerProbe:
    errors = _spec_errors(spec)
    if errors: return StaticWorkerProbe(spec.name, False, '', '', spec.license_spdx, tuple(errors))
    try:
        exe = spec.executable.resolve(strict=True)
        if not exe.is_file() or _hash(exe) != spec.executable_sha256:
            return StaticWorkerProbe(spec.name, False, '', '', spec.license_spdx, ('worker_executable_hash_mismatch',))
        if not spec.version_args or any(not isinstance(arg,str) or not arg or _FORBIDDEN.search(arg) for arg in spec.version_args):
            return StaticWorkerProbe(spec.name, False, '', '', spec.license_spdx, ('worker_version_args_invalid',))
        value = _run_bounded([str(exe), *spec.version_args], timeout=min(spec.timeout_s, 10), memory_limit_mb=spec.memory_mb, cpu_time_limit_s=spec.cpu_s, cwd=str(exe.parent))
        version = str(value.get('stdout', '')).strip()
        if value.get('returncode') not in (0, None): errors.append('worker_version_failed')
        elif spec.expected_version not in version: errors.append('worker_version_mismatch')
        return StaticWorkerProbe(spec.name, not errors, spec.executable_sha256, version, spec.license_spdx, tuple(errors))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return StaticWorkerProbe(spec.name, False, '', '', spec.license_spdx, (f'worker_probe_failed:{exc.__class__.__name__}',))

def run_static_worker(spec: StaticWorkerSpec, args: tuple[str, ...], input_path: Path, out_dir: Path) -> dict[str, Any]:
    errors = _spec_errors(spec)
    if errors: raise ValueError(errors[0])
    exe = spec.executable.resolve(strict=True)
    if _hash(exe) != spec.executable_sha256: raise ValueError('worker_executable_hash_mismatch')
    inp = input_path.resolve(strict=True); out = out_dir.resolve()
    if not inp.is_file() or inp.is_symlink(): raise ValueError('worker_input_invalid')
    if out.exists(): raise ValueError('worker_out_dir_must_be_new')
    if inp.parent == out or out.is_relative_to(inp.parent): raise ValueError('worker_output_location_invalid')
    if any(not isinstance(x, str) or _FORBIDDEN.search(x) for x in args): raise ValueError('worker_argument_forbidden')
    out.mkdir(parents=True)
    value = _run_bounded([str(exe), *args, str(inp)], timeout=spec.timeout_s, memory_limit_mb=spec.memory_mb, cpu_time_limit_s=spec.cpu_s, cwd=str(out))
    stdout, stderr = str(value.get('stdout','')), str(value.get('stderr',''))
    base={'schema':'static-worker-result.v1','name':spec.name,'available':True,'executed':True,'produced_evidence':False,'stdout':stdout,'stderr':stderr,'returncode':value.get('returncode')}
    if len(stdout.encode()) + len(stderr.encode()) > spec.max_output_bytes: return {**base,'state':'failed','ok':False,'partial':False,'error':'worker_output_limit_exceeded','stdout':'','stderr':''}
    state = 'timed_out' if value.get('timed_out') else ('failed' if value.get('returncode') else 'succeeded')
    return {**base,'state':state,'ok':state=='succeeded','partial':state=='timed_out','error':stderr}

def validate_static_worker_result(name: str, result: dict[str, Any]) -> dict[str, Any]:
    required={'schema','name','state','ok','available','executed','produced_evidence','partial','error','stdout','stderr','returncode'}
    if set(result)!=required or result.get('schema')!='static-worker-result.v1' or result.get('name')!=name: raise ValueError('static_worker_result_schema_invalid')
    if result['state'] not in {'unavailable','succeeded','partial','failed','timed_out'}: raise ValueError('static_worker_result_state_invalid')
    if result['state']=='succeeded' and (not result['executed'] or not result['ok']): raise ValueError('static_worker_result_invalid')
    return dict(result)
