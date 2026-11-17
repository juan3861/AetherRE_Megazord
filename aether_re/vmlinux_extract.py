"""Linux Kernel Carving, Decompression & Symbol Table Forensics (GEAR-16).

Covers Discovery-100 candidate CAN-078 (vmlinux-to-elf) and embedded kernel recovery.

Capabilities:
  1. Detects x86 bzImage setup header ('HdrS' at 0x202) and ARM64 Image magic ('ARM\\x64').
  2. Carves and safely decompresses embedded Gzip, XZ, LZMA, and Bzip2 streams.
  3. Extracts 'Linux version X.Y.Z...' kernel banners and compiler toolchains.
  4. Locates embedded ELF vmlinux images and reconstructs kernel symbol references
     (kallsyms markers, sys_call_table, commit_creds, prepare_kernel_cred, init_task).
"""

from __future__ import annotations

import bz2
import lzma
import re
import struct
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024  # 64 MiB safety cap

COMPRESSION_SIGNATURES = [
    ("gzip", b"\x1f\x8b\x08"),
    ("xz", b"\xfd7zXZ\x00"),
    ("bzip2", b"BZh"),
    ("lzma", b"\x5d\x00\x00\x80"),
]

LINUX_BANNER_RE = re.compile(rb"Linux version \d+\.\d+[^\x00\r\n]{0,220}")

NOTABLE_KERNEL_SYMBOLS = [
    b"init_task",
    b"sys_call_table",
    b"commit_creds",
    b"prepare_kernel_cred",
    b"printk",
    b"_stext",
    b"kallsyms_names",
    b"kallsyms_addresses",
    b"kallsyms_num_syms",
    b"selinux_state",
]


@dataclass
class CarvedStreamInfo:
    compression: str
    offset: int
    decompressed_size: int
    contains_elf: bool
    elf_offset_in_stream: int = -1


@dataclass
class VmlinuxExtractReport:
    file_path: str
    file_size: int
    is_bzimage: bool = False
    is_arm64_image: bool = False
    is_direct_elf: bool = False
    linux_banners: List[str] = field(default_factory=list)
    carved_streams: List[Dict[str, Any]] = field(default_factory=list)
    discovered_symbols: Dict[str, int] = field(default_factory=dict)
    has_kallsyms_markers: bool = False
    architecture: str = "unknown"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _safe_decompress(algo: str, payload: bytes, max_bytes: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Safely decompresses a stream up to max_bytes."""
    try:
        if algo == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            return d.decompress(payload, max_bytes)
        if algo == "xz":
            d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            return d.decompress(payload, max_bytes)
        if algo == "lzma":
            d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            return d.decompress(payload, max_bytes)
        if algo == "bzip2":
            d = bz2.BZ2Decompressor()
            return d.decompress(payload, max_bytes)
    except Exception:
        pass
    return b""


def _detect_elf_arch(elf_bytes: bytes) -> str:
    if len(elf_bytes) < 20 or elf_bytes[:4] != b"\x7fELF":
        return "unknown"
    e_machine = struct.unpack_from("<H", elf_bytes, 18)[0]
    arch_map = {
        0x3E: "x86_64",
        0x03: "x86",
        0x28: "arm",
        0xB7: "aarch64",
        0x08: "mips",
        0xF3: "riscv",
    }
    return arch_map.get(e_machine, f"0x{e_machine:x}")


def _scan_payload_for_kernel_artifacts(blob: bytes, report: VmlinuxExtractReport) -> None:
    for match in LINUX_BANNER_RE.finditer(blob):
        banner = match.group(0).decode("utf-8", errors="replace").strip()
        if banner not in report.linux_banners:
            report.linux_banners.append(banner)

    for sym_bytes in NOTABLE_KERNEL_SYMBOLS:
        idx = blob.find(sym_bytes)
        if idx != -1:
            sym_name = sym_bytes.decode("ascii")
            report.discovered_symbols.setdefault(sym_name, idx)
            if sym_name.startswith("kallsyms"):
                report.has_kallsyms_markers = True


def analyze_vmlinux_bytes(data: bytes, file_path: str = "") -> VmlinuxExtractReport:
    """Carves compressed kernel images and reconstructs version and symbol artifacts."""
    report = VmlinuxExtractReport(file_path=file_path, file_size=len(data))
    if not data:
        report.error = "Empty input buffer."
        return report

    # Check direct ELF
    if data.startswith(b"\x7fELF"):
        report.is_direct_elf = True
        report.architecture = _detect_elf_arch(data)

    # Check x86 bzImage header ('HdrS' at 0x202)
    if len(data) > 0x206 and data[0x202:0x206] == b"HdrS":
        report.is_bzimage = True
        if report.architecture == "unknown":
            report.architecture = "x86_64"

    # Check ARM64 Image header ('ARM\x64' at offset 0x38)
    if len(data) > 0x3C and data[0x38:0x3C] == b"ARM\x64":
        report.is_arm64_image = True
        if report.architecture == "unknown":
            report.architecture = "aarch64"

    # Scan outer container first
    _scan_payload_for_kernel_artifacts(data, report)

    # Search and decompress embedded streams
    for algo, magic in COMPRESSION_SIGNATURES:
        search_pos = 0
        while True:
            idx = data.find(magic, search_pos)
            if idx == -1:
                break
            search_pos = idx + len(magic)

            decompressed = _safe_decompress(algo, data[idx:])
            if len(decompressed) >= 64:
                elf_idx = decompressed.find(b"\x7fELF")
                has_elf = elf_idx != -1
                if has_elf and report.architecture == "unknown":
                    report.architecture = _detect_elf_arch(decompressed[elf_idx:])

                info = CarvedStreamInfo(
                    compression=algo,
                    offset=idx,
                    decompressed_size=len(decompressed),
                    contains_elf=has_elf,
                    elf_offset_in_stream=elf_idx,
                )
                report.carved_streams.append(asdict(info))
                _scan_payload_for_kernel_artifacts(decompressed, report)

    return report


def scan_file_vmlinux(file_path: str | Path) -> VmlinuxExtractReport:
    """Reads a kernel image from disk and runs vmlinux carving & symbol analysis."""
    p = Path(file_path)
    if not p.is_file():
        return VmlinuxExtractReport(
            file_path=str(p),
            file_size=0,
            error=f"File not found: {p}",
        )
    try:
        return analyze_vmlinux_bytes(p.read_bytes(), str(p))
    except Exception as exc:
        return VmlinuxExtractReport(
            file_path=str(p),
            file_size=0,
            error=f"Read error: {exc}",
        )
