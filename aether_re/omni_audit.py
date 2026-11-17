"""Zero-Copy Parallel Omni-Gear Forensic Orchestrator (GEAR-21).

Eliminates I/O and sequential execution bottlenecks by:
  1. Reading the target binary once into a shared immutable memory buffer.
  2. Performing instant header/magic classification to route format-specific engines
     while concurrently running universal static scanners (Crypto, API-Hash, FLOSS,
     CFI/Gadgets, Firmware/Entropy, Installer/SFX).
  3. Executing all applicable gears in parallel via ThreadPoolExecutor and recording
     per-gear latency telemetry (ms) and aggregate throughput (MiB/s).
"""

from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from aether_re.api_hash_resolve import scan_bytes_for_api_hashes
from aether_re.authenticode_audit import audit_pe_authenticode
from aether_re.cfi_gadget_audit import audit_cfi_and_gadgets_bytes
from aether_re.cpp_rtti import recover_cpp_rtti
from aether_re.crypto_detect import CryptoScanner
from aether_re.dex_forensics import analyze_dex_or_apk_bytes
from aether_re.dotnet_forensics import analyze_dotnet_metadata
from aether_re.dwarf_types import analyze_elf_and_dwarf
from aether_re.firmware_forensics import analyze_firmware
from aether_re.floss_strings import solve_obfuscated_strings
from aether_re.golang_recover import GolangRecoverEngine
from aether_re.installer_forensics import analyze_installer_bytes
from aether_re.kernel_driver_audit import audit_pe_driver_bytes
from aether_re.macho_forensics import analyze_macho
from aether_re.ole_macro import CFB_SIGNATURE, scan_ole_vba
from aether_re.rust_recover import recover_rust_metadata
from aether_re.vmlinux_extract import analyze_vmlinux_bytes
from aether_re.wasm_forensics import WASM_MAGIC, analyze_wasm_bytes

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
}


@dataclass
class OmniAuditReport:
    schema: str = "re-megazord-omni-audit.v1"
    status: str = "complete"
    file_path: str = ""
    file_size_bytes: int = 0
    sha256: str = ""
    detected_format: str = "unknown"
    wall_clock_ms: float = 0.0
    throughput_mib_s: float = 0.0
    gears_executed_count: int = 0
    gear_latencies_ms: Dict[str, float] = field(default_factory=dict)
    gear_results: Dict[str, Any] = field(default_factory=dict)
    highlights: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_container_format(data: bytes) -> str:
    if len(data) < 4:
        return "raw"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in MACHO_MAGICS:
        return "macho"
    if data.startswith(CFB_SIGNATURE):
        return "ole2"
    if data.startswith(b"dex\n"):
        return "dex"
    if data.startswith(b"PK\x03\x04"):
        return "apk_or_zip"
    if data.startswith(WASM_MAGIC):
        return "wasm"
    if len(data) > 0x206 and data[0x202:0x206] == b"HdrS":
        return "bzimage"
    return "raw_or_firmware"


def run_omni_audit_bytes(
    data: bytes,
    file_path: str = "",
    *,
    run_all_20_gears: bool = False,
    max_workers: int = 8,
) -> OmniAuditReport:
    """Executes multi-gear forensic analysis in parallel over a single in-memory buffer."""
    t_start = time.perf_counter()
    fmt = detect_container_format(data)
    report = OmniAuditReport(
        file_path=file_path,
        file_size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        detected_format=fmt,
    )
    if not data:
        report.status = "invalid"
        report.error = "Empty input buffer."
        return report

    tasks: Dict[str, Callable[[], Any]] = {
        "crypto_detect": lambda: {
            "matches_count": len(CryptoScanner(data).scan()),
            "algorithms": sorted({m.algorithm for m in CryptoScanner(data).scan()}),
        },
        "api_hash_resolve": lambda: scan_bytes_for_api_hashes(data),
        "floss_strings": lambda: solve_obfuscated_strings(data),
        "firmware_entropy": lambda: analyze_firmware(data),
        "installer_forensics": lambda: analyze_installer_bytes(data, file_path).to_dict(),
    }

    if fmt == "pe" or run_all_20_gears:
        tasks["authenticode_audit"] = lambda: audit_pe_authenticode(data)
        tasks["kernel_driver_audit"] = lambda: audit_pe_driver_bytes(data, file_path).to_dict()
        tasks["cpp_rtti"] = lambda: recover_cpp_rtti(data)
        tasks["dotnet_forensics"] = lambda: analyze_dotnet_metadata(data)
        tasks["cfi_gadget_audit"] = lambda: audit_cfi_and_gadgets_bytes(data, file_path).to_dict()
        tasks["rust_recover"] = lambda: recover_rust_metadata(data)
        tasks["golang_recover"] = lambda: asdict(GolangRecoverEngine(data).recover())

    if fmt == "elf" or run_all_20_gears:
        tasks["elf_dwarf"] = lambda: analyze_elf_and_dwarf(data)
        tasks["cfi_gadget_audit"] = lambda: audit_cfi_and_gadgets_bytes(data, file_path).to_dict()
        tasks["rust_recover"] = lambda: recover_rust_metadata(data)
        tasks["golang_recover"] = lambda: asdict(GolangRecoverEngine(data).recover())
        tasks["vmlinux_extract"] = lambda: analyze_vmlinux_bytes(data, file_path).to_dict()

    if fmt == "macho" or run_all_20_gears:
        tasks["macho_forensics"] = lambda: analyze_macho(data)
        tasks["rust_recover"] = lambda: recover_rust_metadata(data)
        tasks["golang_recover"] = lambda: asdict(GolangRecoverEngine(data).recover())

    if fmt == "ole2" or run_all_20_gears:
        tasks["ole_macro"] = lambda: scan_ole_vba(data, file_path).to_dict()

    if fmt in ("dex", "apk_or_zip") or run_all_20_gears:
        tasks["dex_forensics"] = lambda: analyze_dex_or_apk_bytes(data, file_path).to_dict()

    if fmt == "wasm" or run_all_20_gears:
        tasks["wasm_forensics"] = lambda: analyze_wasm_bytes(data, file_path).to_dict()

    if fmt in ("bzimage", "raw_or_firmware") or run_all_20_gears:
        tasks["vmlinux_extract"] = lambda: analyze_vmlinux_bytes(data, file_path).to_dict()
        tasks["cfi_gadget_audit"] = lambda: audit_cfi_and_gadgets_bytes(data, file_path).to_dict()

    def _timed_exec(name: str, fn: Callable[[], Any]) -> tuple[str, float, Any]:
        t0 = time.perf_counter()
        try:
            res = fn()
        except Exception as exc:
            res = {"error": str(exc)}
        dt_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return name, dt_ms, res

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_timed_exec, name, fn) for name, fn in tasks.items()]
        for fut in as_completed(futures):
            gname, dt_ms, gres = fut.result()
            report.gear_latencies_ms[gname] = dt_ms
            report.gear_results[gname] = gres

    report.gears_executed_count = len(report.gear_results)
    wall_s = max(1e-6, time.perf_counter() - t_start)
    report.wall_clock_ms = round(wall_s * 1000.0, 3)
    report.throughput_mib_s = round((len(data) / (1024.0 * 1024.0)) / wall_s, 3)

    # Extract concise highlights
    if report.gear_results.get("crypto_detect", {}).get("algorithms"):
        algos = report.gear_results["crypto_detect"]["algorithms"]
        report.highlights.append(f"crypto:{','.join(algos)}")
    if report.gear_results.get("api_hash_resolve", {}).get("total_resolved", 0) > 0:
        apis = report.gear_results["api_hash_resolve"].get("unique_apis", [])
        report.highlights.append(f"api_hashes:{','.join(apis[:5])}")
    if report.gear_results.get("floss_strings", {}).get("total_xor_strings", 0) > 0:
        report.highlights.append(
            f"xor_strings:{report.gear_results['floss_strings']['total_xor_strings']}"
        )
    if report.gear_results.get("ole_macro", {}).get("has_vba"):
        report.highlights.append("vba_macros_detected")
    if report.gear_results.get("kernel_driver_audit", {}).get("is_kernel_driver"):
        report.highlights.append(
            f"kernel_driver:hvci={report.gear_results['kernel_driver_audit'].get('hvci_compatible')}"
        )

    return report


def scan_file_omni_audit(
    file_path: str | Path,
    *,
    run_all_20_gears: bool = False,
) -> OmniAuditReport:
    """Reads a target file once and executes parallel Omni-Gear audit."""
    p = Path(file_path)
    if not p.is_file():
        return OmniAuditReport(
            status="invalid",
            file_path=str(p),
            error=f"File not found: {p}",
        )
    try:
        return run_omni_audit_bytes(
            p.read_bytes(),
            str(p),
            run_all_20_gears=run_all_20_gears,
        )
    except Exception as exc:
        return OmniAuditReport(
            status="invalid",
            file_path=str(p),
            error=f"Read error: {exc}",
        )
