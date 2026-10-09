"""Windows Sandbox transport for authorized, benign paired executable runs.

The host writes only the two hash-bound binaries and a generated PowerShell
worker into a fresh mapped directory.  The guest has networking disabled and
returns a bounded JSON observation.  This transport does not claim snapshot
rollback attestation; that remains a separate F08 gate.
"""
from __future__ import annotations

from html import escape
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Callable, Mapping


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name}_invalid")
    return value


def _sha(value: Any, name: str) -> str:
    value = _text(value, name)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
        raise ValueError(f"{name}_invalid")
    return value.lower()


def build_sandbox_config(mapped_directory: str | Path) -> str:
    """Return the fixed-network-off Sandbox configuration for one run folder."""
    mapped = Path(mapped_directory).resolve()
    logon = (
        'cmd.exe /d /c "powershell.exe -NoProfile -ExecutionPolicy Bypass '
        '-File C:\\Megazord\\guest_runner.ps1 '
        '1&gt;C:\\Megazord\\guest_stdout.log 2&gt;C:\\Megazord\\guest_stderr.log '
        '&amp; shutdown.exe /s /t 0"'
    )
    return f'''<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{escape(str(mapped))}</HostFolder>
      <SandboxFolder>C:\\Megazord</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>{logon}</Command>
  </LogonCommand>
</Configuration>
'''


def build_guest_runner(request: Mapping[str, Any]) -> str:
    """Build a guest-only PowerShell runner for one request.

    The runner verifies both binary hashes before launching, has no network
    operations, limits collected output and serializes only one paired case.
    """
    if not isinstance(request, Mapping):
        raise ValueError("request_invalid")
    if request.get("network_enabled") is not False or request.get("execution_environment") != "vm":
        raise ValueError("guest_policy_invalid")
    original_sha = _sha(request.get("original_binary_sha256"), "original_binary_sha256")
    candidate_sha = _sha(request.get("candidate_binary_sha256"), "candidate_binary_sha256")
    case = request.get("case")
    if not isinstance(case, Mapping) or not isinstance(case.get("input"), Mapping):
        raise ValueError("guest_case_invalid")
    argv = case["input"].get("argv")
    if not isinstance(argv, list) or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv):
        raise ValueError("guest_argv_invalid")
    timeout = request.get("timeout_s")
    cap = request.get("max_output_bytes")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise ValueError("guest_timeout_invalid")
    if isinstance(cap, bool) or not isinstance(cap, int) or not 1 <= cap <= 1_048_576:
        raise ValueError("guest_output_cap_invalid")
    quoted_args = ", ".join("'" + arg.replace("'", "''") + "'" for arg in argv)
    return f'''$ErrorActionPreference = 'Stop'
$root = 'C:\\Megazord'
$limit = {cap}
$timeout = {timeout}
function Read-Program([string]$path, [string]$expected) {{
  $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {{ throw "binary_hash_mismatch:$path" }}
}}
function Invoke-Paired([string]$path) {{
  $stdout = Join-Path $root ([IO.Path]::GetRandomFileName())
  $stderr = Join-Path $root ([IO.Path]::GetRandomFileName())
  try {{
    $process = Start-Process -FilePath $path -ArgumentList @({quoted_args}) -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ended = $process.WaitForExit($timeout * 1000)
    if (-not $ended) {{ $process.Kill(); $process.WaitForExit() }}
    else {{ $process.WaitForExit(); $process.Refresh() }}
    $exitCode = if ($ended) {{ [int]$process.ExitCode }} else {{ $null }}
    $out = if (Test-Path -LiteralPath $stdout) {{ [IO.File]::ReadAllText($stdout) }} else {{ '' }}
    $err = if (Test-Path -LiteralPath $stderr) {{ [IO.File]::ReadAllText($stderr) }} else {{ '' }}
    if ([Text.Encoding]::UTF8.GetByteCount($out) -gt $limit -or [Text.Encoding]::UTF8.GetByteCount($err) -gt $limit) {{ throw 'guest_output_over_budget' }}
    return @{{stdout=$out; stderr=$err; exit_code=$exitCode; exception=$null; timeout=(-not $ended); effects=@{{status='unknown';events=@()}}}}
  }} catch {{
    return @{{stdout=''; stderr=''; exit_code=$null; exception=@{{type=$_.Exception.GetType().FullName;message=$_.Exception.Message}}; timeout=$false; effects=@{{status='unknown';events=@()}}}}
  }} finally {{ Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue }}
}}
Read-Program (Join-Path $root 'original.exe') '{original_sha}'
Read-Program (Join-Path $root 'candidate.exe') '{candidate_sha}'
$original = Invoke-Paired (Join-Path $root 'original.exe')
$candidate = Invoke-Paired (Join-Path $root 'candidate.exe')
@{{schema='sandbox-pair-observation.v1'; original=$original; candidate=$candidate}} | ConvertTo-Json -Depth 8 -Compress | Set-Content -LiteralPath (Join-Path $root 'guest_observation.json') -Encoding UTF8
shutdown.exe /s /t 0
'''


def read_guest_observation(path: str | Path, *, timeout_s: float, poll_interval_s: float = 0.1) -> dict[str, Any]:
    """Wait until a mapped guest result is both unlocked and complete JSON."""
    result_path = Path(path)
    deadline = time.monotonic() + max(0.0, timeout_s)
    last_error: Exception | None = None
    while True:
        try:
            raw = json.loads(result_path.read_text(encoding="utf-8-sig"))
            if not isinstance(raw, dict):
                raise ValueError("guest_observation_not_object")
            return raw
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise RuntimeError("guest_observation_unreadable") from last_error
            time.sleep(max(0.001, poll_interval_s))


class WindowsSandboxPairExecutor:
    """Materialize and collect one pair request inside Windows Sandbox.

    ``signer`` belongs to the caller's evidence identity.  The executor never
    accepts executable paths: it writes the bytes carried by the hash-bound
    request into a unique mapped directory, launches Sandbox, and returns only
    its typed observation to the supplied signer.
    """

    def __init__(
        self,
        evidence_root: str | Path,
        *,
        signer: Callable[[dict[str, Any]], dict[str, Any]],
        launcher: Callable[[Path, Path], None] | None = None,
        cleanup: Callable[[Path], None] | None = None,
        sandbox_executable: str | Path = r"C:\Windows\System32\WindowsSandbox.exe",
        poll_interval_s: float = 0.2,
    ) -> None:
        if not callable(signer):
            raise ValueError("signer_required")
        self.root = Path(evidence_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        self.launcher = launcher
        self.cleanup = cleanup
        self.sandbox_executable = Path(sandbox_executable)
        self.poll_interval_s = poll_interval_s

    def _cleanup(self, config: Path) -> None:
        if self.cleanup is not None:
            self.cleanup(config)
            return
        script = (
            "$target=$env:AETHERRE_SANDBOX_CONFIG; "
            "$owned=Get-CimInstance Win32_Process | Where-Object { "
            "$_.Name -eq 'WindowsSandboxRemoteSession.exe' -and $_.CommandLine -and $_.CommandLine.Contains($target) }; "
            "$owned | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }; "
            "Start-Sleep -Milliseconds 500; "
            "$left=Get-CimInstance Win32_Process | Where-Object { "
            "$_.Name -eq 'WindowsSandboxRemoteSession.exe' -and $_.CommandLine -and $_.CommandLine.Contains($target) }; "
            "if($left){exit 2}else{exit 0}"
        )
        environment = os.environ.copy()
        environment["AETHERRE_SANDBOX_CONFIG"] = str(config)
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                check=False,
                timeout=20,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("sandbox_cleanup_failed") from exc
        if result.returncode != 0:
            raise RuntimeError("sandbox_cleanup_failed")

    def _launch(self, config: Path, mapped: Path, timeout_s: int) -> None:
        if self.launcher is not None:
            self.launcher(config, mapped)
            return
        if not self.sandbox_executable.is_file():
            raise RuntimeError("windows_sandbox_missing")
        process = subprocess.Popen([str(self.sandbox_executable), str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + max(15, timeout_s + 30)
        result = mapped / "guest_observation.json"
        while time.monotonic() < deadline:
            if result.is_file():
                break
            time.sleep(max(0.01, self.poll_interval_s))
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if not result.is_file():
            raise RuntimeError("guest_observation_missing")

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict) or request.get("schema") != "guest-pair-request.v1":
            raise ValueError("guest_request_invalid")
        if request.get("network_enabled") is not False or request.get("execution_environment") != "vm":
            raise ValueError("guest_policy_invalid")
        lease = request.get("run_lease")
        if not isinstance(lease, Mapping):
            raise ValueError("guest_lease_invalid")
        run_id, guest_id, nonce = (_text(lease.get(key), f"guest_{key}_invalid") for key in ("run_id", "guest_id", "nonce"))
        case = request.get("case")
        if not isinstance(case, Mapping):
            raise ValueError("guest_case_invalid")
        case_id = _text(case.get("case_id"), "guest_case_id_invalid")
        case_index, case_total = request.get("case_index"), request.get("case_total")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in (case_index, case_total)) or case_index < 0 or case_total < 1 or case_index >= case_total:
            raise ValueError("guest_case_denominator_invalid")
        for field in ("original_binary", "candidate_binary"):
            if not isinstance(request.get(field), bytes) or not request[field]:
                raise ValueError(f"{field}_invalid")
        for field in ("candidate_manifest_sha256", "input_sha256", "input_manifest_sha256", "original_binary_sha256", "candidate_binary_sha256"):
            _sha(request.get(field), field)
        run_dir = self.root / f"{run_id}-{case_index:05d}"
        if run_dir.exists():
            raise RuntimeError("guest_run_directory_exists")
        mapped = run_dir / "mapped"
        mapped.mkdir(parents=True)
        (mapped / "original.exe").write_bytes(request["original_binary"])
        (mapped / "candidate.exe").write_bytes(request["candidate_binary"])
        (mapped / "guest_runner.ps1").write_text(build_guest_runner(request), encoding="utf-8", newline="\n")
        config = run_dir / "sandbox.wsb"
        config.write_text(build_sandbox_config(mapped), encoding="utf-8", newline="\n")
        try:
            self._launch(config, mapped, request["timeout_s"])
            try:
                raw = read_guest_observation(
                    mapped / "guest_observation.json",
                    timeout_s=min(15, request["timeout_s"] + 3),
                    poll_interval_s=self.poll_interval_s,
                )
            except RuntimeError as exc:
                raise RuntimeError("guest_observation_invalid") from exc
        finally:
            self._cleanup(config)
        if not isinstance(raw, dict) or set(raw) != {"schema", "original", "candidate"} or raw.get("schema") != "sandbox-pair-observation.v1":
            raise RuntimeError("guest_observation_invalid")
        payload = {
            "schema": "guest-pair-result.v1", "run_id": run_id, "guest_id": guest_id, "nonce": nonce,
            "case_id": case_id, "case_index": case_index, "case_total": case_total,
            "input": case.get("input"), "input_sha256": request["input_sha256"],
            "input_manifest_sha256": request["input_manifest_sha256"],
            "candidate_manifest_sha256": request["candidate_manifest_sha256"],
            "original_binary_sha256": request["original_binary_sha256"], "candidate_binary_sha256": request["candidate_binary_sha256"],
            "timeout_s": request["timeout_s"], "max_output_bytes": request["max_output_bytes"],
            "original": raw["original"], "candidate": raw["candidate"],
        }
        envelope = self.signer(payload)
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"} or envelope.get("payload") != payload:
            raise RuntimeError("guest_signer_contract_invalid")
        return envelope
