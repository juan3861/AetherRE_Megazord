"""Tests for GEAR-21: Zero-Copy Parallel Omni-Gear Forensic Orchestrator & Bottleneck Elimination."""

from __future__ import annotations

import os
import time
from pathlib import Path

from aether_re.api_hash_resolve import scan_bytes_for_api_hashes
from aether_re.crypto_detect import AES_SBOX
from aether_re.floss_strings import scan_single_byte_xor
from aether_re.omni_audit import run_omni_audit_bytes, scan_file_omni_audit


def test_omni_audit_parallel_pe_and_multi_gear_highlights(tmp_path: Path):
    # Construct a synthetic PE buffer containing AES S-Box, XORed URL (key 0x5A), and ROR13 VirtualAlloc hash
    blob = bytearray(b"MZ" + b"\x90" * 4094)
    blob.extend(AES_SBOX)
    xor_url = bytes(b ^ 0x5A for b in b"https://c2.aether.internal/stage2.bin")
    blob.extend(xor_url)
    blob.extend((0x91AFCA54).to_bytes(4, "little"))

    p = tmp_path / "poly_payload.exe"
    p.write_bytes(bytes(blob))

    report = scan_file_omni_audit(p)
    assert report.status == "complete"
    assert report.detected_format == "pe"
    assert report.gears_executed_count >= 10
    assert "crypto:AES" in report.highlights
    assert any("VirtualAlloc" in h for h in report.highlights)
    assert any("xor_strings:" in h for h in report.highlights)
    assert report.throughput_mib_s > 0


def test_vectorized_xor_and_api_hash_bottleneck_elimination():
    # 512 KiB buffer: verify XOR Differential Invariant completes in < 250 ms (was 14,447 ms)
    blob = bytearray(os.urandom(512 * 1024))
    ind = bytes(b ^ 0x3C for b in b"http://198.51.100.42/beacon")
    blob[200000 : 200000 + len(ind)] = ind
    blob[300000:300004] = (0x91AFCA54).to_bytes(4, "little")
    data = bytes(blob)

    t0 = time.perf_counter()
    xor_hits = scan_single_byte_xor(data)
    xor_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    hash_res = scan_bytes_for_api_hashes(data)
    hash_ms = (time.perf_counter() - t1) * 1000.0

    assert len(xor_hits) >= 1
    assert any("http://198.51.100.42/beacon" in h["decoded"] for h in xor_hits)
    assert xor_ms < 250.0, f"XOR scan regression: {xor_ms:.2f}ms"

    assert hash_res["total_resolved"] >= 1
    assert "VirtualAlloc" in hash_res["unique_apis"]
    assert hash_ms < 300.0, f"API hash scan regression: {hash_ms:.2f}ms"
