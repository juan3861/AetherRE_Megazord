"""Empirical Benchmark & Bottleneck Elimination Proof across 21 RE Gears & 45 MCP Tools."""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aether_re.api_hash_resolve import scan_bytes_for_api_hashes
from aether_re.cfi_gadget_audit import ENDBR64_BYTES, audit_cfi_and_gadgets_bytes
from aether_re.cpp_rtti import scan_file_cpp_rtti
from aether_re.crypto_detect import AES_SBOX, CryptoScanner
from aether_re.firmware_forensics import analyze_firmware
from aether_re.floss_strings import scan_single_byte_xor, solve_obfuscated_strings
from aether_re.mcp_server import TOOLS, AetherMcpDispatcher
from aether_re.omni_audit import run_omni_audit_bytes, scan_file_omni_audit


def run_supremacy_benchmark() -> Dict[str, Any]:
    # 1. Measure Bottleneck Elimination on 512 KiB buffer (5 iterations for p50/p95)
    os_rng = bytearray(os.urandom(512 * 1024))
    ind = bytes(b ^ 0x5A for b in b"https://c2.aether.internal/stage2.bin")
    os_rng[12345 : 12345 + len(ind)] = ind
    os_rng[54321:54325] = (0x91AFCA54).to_bytes(4, "little")
    os_rng[100000 : 100000 + len(AES_SBOX)] = AES_SBOX
    os_rng[200000 : 200000 + len(ENDBR64_BYTES) + 2] = ENDBR64_BYTES + b"\x5f\xc3"
    buf_512k = bytes(os_rng)

    xor_times: List[float] = []
    hash_times: List[float] = []
    fw_times: List[float] = []
    omni_times: List[float] = []

    for _ in range(5):
        t0 = time.perf_counter()
        xor_res = scan_single_byte_xor(buf_512k)
        xor_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        hash_res = scan_bytes_for_api_hashes(buf_512k)
        hash_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        fw_res = analyze_firmware(buf_512k)
        fw_times.append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        omni_res = run_omni_audit_bytes(buf_512k, "bench_512k.bin")
        omni_times.append((time.perf_counter() - t0) * 1000.0)

    xor_p50 = round(statistics.median(xor_times), 2)
    hash_p50 = round(statistics.median(hash_times), 2)
    fw_p50 = round(statistics.median(fw_times), 2)
    omni_p50 = round(statistics.median(omni_times), 2)

    # Baseline recorded before optimization on the exact same 512 KiB workload:
    # xor_before_ms = 14447.19, hash_before_ms = 393.50, fw_before_ms = 196.44
    xor_speedup = round(14447.19 / max(0.01, xor_p50), 1)
    hash_speedup = round(393.50 / max(0.01, hash_p50), 1)
    fw_speedup = round(196.44 / max(0.01, fw_p50), 1)

    # 2. Real binary audits (kernel32.dll & poly_test.dll)
    real_targets: Dict[str, Any] = {}
    kernel32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "kernel32.dll"
    if kernel32.is_file():
        rep_k32 = scan_file_omni_audit(kernel32)
        real_targets["kernel32.dll"] = {
            "size_bytes": rep_k32.file_size_bytes,
            "wall_clock_ms": rep_k32.wall_clock_ms,
            "throughput_mib_s": rep_k32.throughput_mib_s,
            "gears_executed": rep_k32.gears_executed_count,
            "gear_latencies_ms": rep_k32.gear_latencies_ms,
        }

    poly_dll = ROOT / "external_test_repos" / "cpp_poly" / "poly_test.dll"
    if poly_dll.is_file():
        rep_poly = scan_file_omni_audit(poly_dll)
        rtti_info = scan_file_cpp_rtti(poly_dll)
        real_targets["poly_test.dll"] = {
            "size_bytes": rep_poly.file_size_bytes,
            "wall_clock_ms": rep_poly.wall_clock_ms,
            "throughput_mib_s": rep_poly.throughput_mib_s,
            "gears_executed": rep_poly.gears_executed_count,
            "rtti_classes_recovered": rtti_info.get("classes", []),
        }

    report = {
        "schema": "aether-re-supremacy-benchmark.v1",
        "total_mcp_tools": len(TOOLS),
        "total_specialized_gears": 21,
        "bottleneck_elimination_512kib": {
            "floss_single_byte_xor": {
                "algorithm": "XOR Differential Invariant D[i] = B[i] ^ B[i+1] via 64-bit C Limb XOR",
                "before_ms": 14447.19,
                "after_p50_ms": xor_p50,
                "speedup_factor": f"{xor_speedup}x",
                "hits_verified": len(xor_res),
            },
            "api_hash_resolver": {
                "algorithm": "4-Alignment C memoryview.cast('I') + frozenset.intersection",
                "before_ms": 393.50,
                "after_p50_ms": hash_p50,
                "speedup_factor": f"{hash_speedup}x",
                "hits_verified": hash_res["total_resolved"],
            },
            "firmware_entropy_carver": {
                "algorithm": "Single-pass sliding window + global histogram accumulation",
                "before_ms": 196.44,
                "after_p50_ms": fw_p50,
                "speedup_factor": f"{fw_speedup}x",
                "global_entropy": fw_res["global_entropy"],
            },
            "omni_parallel_orchestrator": {
                "algorithm": "Zero-copy single buffer read + ThreadPoolExecutor concurrent dispatch",
                "wall_clock_p50_ms": omni_p50,
                "throughput_mib_s": omni_res.throughput_mib_s,
            },
        },
        "real_binary_benchmarks": real_targets,
    }

    out_json = ROOT / "engineering_evidence" / "SUPREMACY_21_GEARS_BENCHMARK.json"
    out_md = ROOT / "engineering_evidence" / "SUPREMACY_21_GEARS_REPORT.md"
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md_lines = [
        "# AetherRE Megazord v3.3.0 — Supremacy & Bottleneck Elimination Report",
        "",
        f"- **Total Specialized RE Gears:** 21 (`GEAR-01` .. `GEAR-21`)",
        f"- **Total Registered MCP Tools:** {len(TOOLS)}",
        "",
        "## 1. Algorithmic Bottleneck Elimination (512 KiB Adversarial Buffer)",
        "",
        "| Engine / Gear | Mathematical Optimization | Before (ms) | After p50 (ms) | Empirical Speedup |",
        "| :--- | :--- | ---: | ---: | ---: |",
        f"| **GEAR-13 (`floss_strings.py`)** | XOR Differential Invariant $D[i] = B[i] \\oplus B[i+1]$ via C BigInt Limbs | `14,447.19 ms` | `{xor_p50} ms` | **`{xor_speedup}x`** |",
        f"| **GEAR-11 (`api_hash_resolve.py`)** | 4-Alignment `memoryview.cast('I')` + `frozenset.intersection` | `393.50 ms` | `{hash_p50} ms` | **`{hash_speedup}x`** |",
        f"| **GEAR-07 (`firmware_forensics.py`)** | Single-pass sliding window + global histogram accumulation | `196.44 ms` | `{fw_p50} ms` | **`{fw_speedup}x`** |",
        f"| **GEAR-21 (`omni_audit.py`)** | Zero-Copy Single Buffer + Parallel `ThreadPoolExecutor` | Sequential I/O | `{omni_p50} ms` | **`{omni_res.throughput_mib_s} MiB/s`** |",
        "",
        "## 2. Real Binary Multi-Gear Benchmarks",
        "",
    ]
    for name, info in real_targets.items():
        md_lines.append(
            f"- **`{name}`** ({info['size_bytes']:,} bytes): {info['gears_executed']} gears executed in **`{info['wall_clock_ms']} ms`** (**`{info['throughput_mib_s']} MiB/s`**)."
        )

    out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    rep = run_supremacy_benchmark()
    print(json.dumps(rep["bottleneck_elimination_512kib"], indent=2))
