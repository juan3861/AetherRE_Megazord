"""Tests for GEAR-16: Linux Kernel Carving, Decompression & Symbol Table Forensics."""

from __future__ import annotations

import gzip
import lzma
import struct
from pathlib import Path

from aether_re.vmlinux_extract import analyze_vmlinux_bytes, scan_file_vmlinux


def _build_synthetic_vmlinux_elf(arch_machine: int = 0x3E) -> bytes:
    """Builds a minimal synthetic ELF vmlinux image containing banner and kallsyms markers."""
    elf_hdr = bytearray(64)
    elf_hdr[0:4] = b"\x7fELF"
    elf_hdr[4] = 2  # 64-bit
    elf_hdr[5] = 1  # Little endian
    elf_hdr[6] = 1  # Version
    struct.pack_into("<H", elf_hdr, 16, 2)  # ET_EXEC
    struct.pack_into("<H", elf_hdr, 18, arch_machine)

    payload = (
        bytes(elf_hdr)
        + b"\x00" * 128
        + b"Linux version 6.8.12-aether-amd64 (root@buildhost) (gcc 13.2.0) #1 SMP PREEMPT_DYNAMIC\x00"
        + b"\x00" * 64
        + b"init_task\x00sys_call_table\x00commit_creds\x00prepare_kernel_cred\x00"
        + b"kallsyms_names\x00kallsyms_addresses\x00kallsyms_num_syms\x00"
    )
    return payload


def test_bzimage_gzip_kernel_carving_and_symbol_recovery(tmp_path: Path):
    inner_elf = _build_synthetic_vmlinux_elf(0x3E)  # x86_64
    compressed_gz = gzip.compress(inner_elf)

    # Construct x86 bzImage setup stub with 'HdrS' at 0x202
    bzimage = bytearray(0x400)
    bzimage[0x202:0x206] = b"HdrS"
    bzimage.extend(compressed_gz)

    img_path = tmp_path / "vmlinuz-6.8.12"
    img_path.write_bytes(bytes(bzimage))

    report = scan_file_vmlinux(img_path)
    assert report.is_bzimage is True
    assert report.architecture == "x86_64"
    assert len(report.carved_streams) >= 1
    assert report.carved_streams[0]["compression"] == "gzip"
    assert report.carved_streams[0]["contains_elf"] is True
    assert any("6.8.12-aether-amd64" in b for b in report.linux_banners)
    assert report.has_kallsyms_markers is True
    assert "commit_creds" in report.discovered_symbols
    assert "sys_call_table" in report.discovered_symbols


def test_arm64_xz_compressed_kernel():
    inner_elf = _build_synthetic_vmlinux_elf(0xB7)  # aarch64
    compressed_xz = lzma.compress(inner_elf, format=lzma.FORMAT_XZ)

    arm_hdr = bytearray(0x100)
    arm_hdr[0x38:0x3C] = b"ARM\x64"
    blob = bytes(arm_hdr) + compressed_xz

    report = analyze_vmlinux_bytes(blob, "Image.xz")
    assert report.is_arm64_image is True
    assert report.architecture == "aarch64"
    assert any(s["compression"] == "xz" and s["contains_elf"] for s in report.carved_streams)
    assert "prepare_kernel_cred" in report.discovered_symbols
