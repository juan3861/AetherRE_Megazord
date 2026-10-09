from __future__ import annotations

import hashlib
import json

from aether_re.windows_sandbox_guest import WindowsSandboxPairExecutor, build_sandbox_config, build_guest_runner, read_guest_observation


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_guest_runner_binds_pair_hashes_and_never_enables_network():
    request = {
        "original_binary": b"original",
        "candidate_binary": b"candidate",
        "original_binary_sha256": _sha(b"original"),
        "candidate_binary_sha256": _sha(b"candidate"),
        "case": {"case_id": "zero", "input": {"argv": ["0"]}},
        "timeout_s": 5,
        "max_output_bytes": 4096,
        "network_enabled": False,
        "execution_environment": "vm",
    }
    script = build_guest_runner(request)
    assert "Get-FileHash" in script
    assert request["original_binary_sha256"] in script
    assert request["candidate_binary_sha256"] in script
    assert "Start-Process" in script
    assert "$process.WaitForExit()" in script
    assert "$process.Refresh()" in script
    assert "network_enabled" not in script
    assert "utf8NoBOM" not in script  # Windows Sandbox ships Windows PowerShell 5.1.
    assert "-Encoding UTF8" in script


def test_sandbox_config_disables_network_and_uses_only_the_run_mapping(tmp_path):
    config = build_sandbox_config(tmp_path / "mapped")
    assert "<Networking>Disable</Networking>" in config
    assert "<VGpu>Disable</VGpu>" in config
    assert "<ReadOnly>false</ReadOnly>" in config
    assert "C:\\Megazord" in config
    assert "guest_runner.ps1" in config
    assert "guest_stdout.log" in config
    assert "guest_stderr.log" in config
    assert "shutdown.exe /s /t 0" in config


def test_executor_returns_only_a_signed_complete_guest_pair(tmp_path):
    request = {
        "schema": "guest-pair-request.v1", "run_lease": {"run_id": "run-1", "guest_id": "guest-1", "nonce": "nonce-1"},
        "case_index": 0, "case_total": 1, "candidate_manifest_sha256": "a" * 64,
        "case": {"case_id": "zero", "input": {"argv": ["0"]}}, "input_sha256": "b" * 64,
        "input_manifest_sha256": "c" * 64, "original_binary": b"original", "candidate_binary": b"candidate",
        "original_binary_sha256": _sha(b"original"), "candidate_binary_sha256": _sha(b"candidate"),
        "timeout_s": 5, "max_output_bytes": 4096, "network_enabled": False, "execution_environment": "vm",
    }
    def launch(_config, mapped):
        (mapped / "guest_observation.json").write_text(json.dumps({
            "schema": "sandbox-pair-observation.v1",
            "original": {"stdout": "0\n", "stderr": "", "exit_code": 0, "exception": None, "timeout": False, "effects": {"status": "unknown", "events": []}},
            "candidate": {"stdout": "0\n", "stderr": "", "exit_code": 0, "exception": None, "timeout": False, "effects": {"status": "unknown", "events": []}},
        }), encoding="utf-8")
    cleaned = []
    executor = WindowsSandboxPairExecutor(
        tmp_path,
        signer=lambda payload: {"payload": payload, "signature": {"test": "ok"}},
        launcher=launch,
        cleanup=lambda config: cleaned.append(config),
    )
    envelope = executor(request)
    assert envelope["payload"]["schema"] == "guest-pair-result.v1"
    assert envelope["payload"]["case_total"] == 1
    assert envelope["payload"]["original"]["stdout"] == "0\n"
    assert len(cleaned) == 1 and cleaned[0].name == "sandbox.wsb"


def test_observation_reader_retries_a_mapped_file_while_guest_holds_it(tmp_path, monkeypatch):
    path = tmp_path / "guest_observation.json"
    path.write_text('{"schema":"sandbox-pair-observation.v1","original":{},"candidate":{}}', encoding="utf-8")
    original = type(path).read_text
    attempts = 0
    def flaky(self, *args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError("guest still owns mapped handle")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(type(path), "read_text", flaky)
    result = read_guest_observation(path, timeout_s=1, poll_interval_s=0.001)
    assert result["schema"] == "sandbox-pair-observation.v1"
    assert attempts == 3
