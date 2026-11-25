from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from aether_re.custody_release import capture_custody_snapshot, verify_custody_snapshot
from aether_re.mcp_server import AetherMcpDispatcher, TOOLS


def test_v120_custody_sha512_hmac_signature_and_tamper_detection(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    sample = src / "evidence.bin"
    sample.write_bytes(b"ORIGINAL_FORENSIC_BYTES_2026")

    out = tmp_path / "custody"
    key = b"super-secret-forensic-signing-key"
    manifest = capture_custody_snapshot(src, out, signing_key=key)
    assert len(manifest["inventory_sha512"]) == 128
    assert manifest["attestation"]["algorithm"] == "HMAC-SHA512"

    ok_ver = verify_custody_snapshot(manifest["output"], signing_key=key, verify_files_on_disk=True)
    assert ok_ver["verified"] is True
    assert ok_ver["hmac_attestation_ok"] is True
    assert ok_ver["tampered_files"] == []

    # Wrong HMAC key must fail verification
    bad_key_ver = verify_custody_snapshot(manifest["output"], signing_key=b"wrong-key", verify_files_on_disk=True)
    assert bad_key_ver["hmac_attestation_ok"] is False
    assert bad_key_ver["verified"] is False

    # Disk tampering must be detected immediately
    sample.write_bytes(b"TAMPERED_FORENSIC_BYTES_2026")
    tamper_ver = verify_custody_snapshot(manifest["output"], signing_key=key, verify_files_on_disk=True)
    assert tamper_ver["verified"] is False
    assert "evidence.bin" in tamper_ver["tampered_files"]


def test_v120_mcp_server_v12_tools_registered_and_stdio_roundtrip(tmp_path: Path) -> None:
    names = {t["name"] for t in TOOLS}
    expected_new = {
        "aether_cxx_eh_analyze",
        "aether_flirt_fidb_match",
        "aether_mba_simplify",
        "aether_vm_devirtualize",
        "aether_elf_unpack",
        "aether_concolic_fuzz",
        "aether_patch_diff_cve",
        "aether_cil_decompile",
        "aether_ioctl_prove",
        "aether_ram_forensics",
        "aether_disk_registry_evtx",
        "aether_pcap_forensics",
        "aether_supertimeline",
        "aether_custody_verify",
    }
    assert expected_new.issubset(names)

    dispatcher = AetherMcpDispatcher()
    patch_res = dispatcher.handle_patch_diff_cve(
        "void g(int n) { char *p = malloc(n); memcpy(p, s, n); }",
        "void g(int n) { if (n > 256) return; char *p = malloc(n); memcpy(p, s, n); }",
    )
    assert patch_res["patch_candidates_count"] == 1
    assert patch_res["alerts"][0]["is_likely_security_patch"] is True

    # Live JSON-RPC 2.0 stdio handshake + tools/call test
    repo_root = Path(__file__).resolve().parents[1]
    requests_jsonl = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "aether_mba_simplify", "arguments": {"expr": "(a ^ b) + 2 * (a & b)"}}}),
    ]) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "aether_re.mcp_server"],
        input=requests_jsonl,
        text=True,
        capture_output=True,
        cwd=str(repo_root),
        timeout=30,
        check=True,
    )
    lines = [json.loads(line) for line in proc.stdout.strip().splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0]["result"]["protocolVersion"]
    tool_payload = json.loads(lines[1]["result"]["content"][0]["text"])
    assert tool_payload["mba"]["proven"] is True
    assert tool_payload["mba"]["simplified"] in ("(a + b)", "a + b", "(b + a)", "b + a")


def test_v120_world_sota_benchmark_runner(tmp_path: Path) -> None:
    from tools.benchmark_world_sota_corpus import run_benchmark

    rep = run_benchmark(work_dir=tmp_path / "bench")
    assert rep["all_pillars_passed"] is True
    assert (tmp_path / "bench" / "world_sota_benchmark_report.json").is_file()
