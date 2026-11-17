from __future__ import annotations

import json
from pathlib import Path
import pytest

from aether_re.capabilities import (
    SCHEMA,
    analyze_target_capabilities,
    detect_capabilities_from_features,
)


def test_detect_capabilities_matches_anti_debug_and_injection():
    imports = ["IsDebuggerPresent", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    strings = ["Please disable your debugger", "SomeNormalString"]
    sections = [{"name": ".text", "entropy": 6.1}, {"name": ".upx1", "entropy": 7.8}]

    caps = detect_capabilities_from_features(
        imports=imports,
        strings=strings,
        sections=sections,
    )
    cap_ids = {c["id"] for c in caps}

    assert "anti-analysis/debugger-detection-api" in cap_ids
    assert "process-injection/remote-thread" in cap_ids
    assert "process-injection/hollowing-or-injection-primitives" in cap_ids
    assert "evasion/packed-high-entropy-section" in cap_ids

    # Verifica evidência estruturada
    debugger_cap = next(c for c in caps if c["id"] == "anti-analysis/debugger-detection-api")
    assert debugger_cap["mitre_id"] == "T1622"
    assert debugger_cap["severity"] == "medium"
    assert any(e["matched"] == "IsDebuggerPresent" for e in debugger_cap["evidence"])


def test_detect_capabilities_matches_crypto_and_c2():
    imports = ["InternetOpenA", "HttpSendRequestA", "CryptEncrypt", "WSAStartup"]
    strings = ["https://c2.malicious-domain.example/beacon", "AES-256", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"]

    caps = detect_capabilities_from_features(
        imports=imports,
        strings=strings,
    )
    cap_ids = {c["id"] for c in caps}

    assert "cryptography/windows-crypto-api" in cap_ids
    assert "cryptography/known-algorithms" in cap_ids
    assert "communication/http-network-client" in cap_ids
    assert "communication/raw-sockets" in cap_ids
    assert "persistence/registry-run-keys" in cap_ids


def test_analyze_target_capabilities_nonexistent_fails_closed():
    res = analyze_target_capabilities(Path("does_not_exist_at_all.bin"))
    assert res["schema"] == SCHEMA
    assert res["status"] == "error"
    assert res["errors"][0]["code"] == "target_not_found"
    assert res["capabilities"] == []


def test_analyze_target_capabilities_on_real_file(tmp_path: Path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00IsDebuggerPresent\x00VirtualAllocEx\x00https://example.com/api\x00")

    res = analyze_target_capabilities(target)
    assert res["schema"] == SCHEMA
    assert res["status"] == "complete"
    assert res["target_sha256"] is not None
    assert res["summary"]["total"] >= 2
    assert "anti-analysis" in res["summary"]["categories"]
