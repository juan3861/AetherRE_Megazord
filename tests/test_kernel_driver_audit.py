"""Tests for GEAR-15: Windows Kernel Driver & HVCI / BYOVD Security Forensics."""

from __future__ import annotations

import struct
from pathlib import Path

from aether_re.kernel_driver_audit import (
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    IMAGE_SUBSYSTEM_NATIVE,
    audit_pe_driver_bytes,
    scan_file_driver_audit,
)


def _build_synthetic_driver_pe64(
    *,
    subsystem: int = IMAGE_SUBSYSTEM_NATIVE,
    dll_characteristics: int = 0x41E0,  # DynamicBase + HighEntropy + ForceIntegrity + NX + CFG
    text_characteristics: int = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    include_byovd_imports: bool = True,
) -> bytes:
    """Builds a minimal valid 64-bit PE (.sys driver) with an import table."""
    dos_header = bytearray(0x40)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x40)  # e_lfanew = 0x40

    pe_sig = b"PE\x00\x00"
    # COFF File Header (20 bytes): Machine=AMD64 (0x8664), NumberOfSections=2, SizeOfOptionalHeader=240, Characteristics=0x0022
    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine
        2,       # NumberOfSections (.text, .idata)
        0x65000000,
        0,
        0,
        240,     # SizeOfOptionalHeader
        0x0022,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)  # PE32+ magic
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt_header, 20, 0x1000)  # BaseOfCode
    struct.pack_into("<Q", opt_header, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)   # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x200)   # SizeOfHeaders
    struct.pack_into("<H", opt_header, 68, subsystem)
    struct.pack_into("<H", opt_header, 70, dll_characteristics)
    struct.pack_into("<I", opt_header, 108, 16)     # NumberOfRvaAndSizes

    if include_byovd_imports:
        # DataDirectory[1] = Import Directory at RVA 0x2000, size 40
        struct.pack_into("<II", opt_header, 112 + 8, 0x2000, 40)

    # Section 1: .text at RVA 0x1000, raw offset 0x200, size 0x200
    sec_text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        text_characteristics,
    )

    # Section 2: .idata at RVA 0x2000, raw offset 0x400, size 0x200
    sec_idata = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\x00\x00",
        0x200,
        0x2000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        IMAGE_SCN_MEM_READ,
    )

    headers = bytes(dos_header) + pe_sig + coff_header + bytes(opt_header) + sec_text + sec_idata
    headers = headers.ljust(0x200, b"\x00")

    text_raw = b"\xC3" + b"\x90" * (0x200 - 1)
    idata_raw = bytearray(0x200)

    if include_byovd_imports:
        # Import Descriptor 0 at offset 0 (RVA 0x2000):
        # OriginalFirstThunk = 0x2030, TimeDateStamp = 0, ForwarderChain = 0, Name = 0x2060, FirstThunk = 0x2030
        struct.pack_into("<IIIII", idata_raw, 0, 0x2030, 0, 0, 0x2060, 0x2030)
        # Null descriptor at offset 20

        # ILT / IAT at offset 0x30 (RVA 0x2030): 3 64-bit entries + null terminator
        struct.pack_into("<QQQQ", idata_raw, 0x30, 0x2070, 0x2088, 0x20A0, 0)

        # DLL name at offset 0x60 (RVA 0x2060)
        idata_raw[0x60 : 0x60 + 13] = b"ntoskrnl.exe\x00"

        # Hint/Name 1 at offset 0x70 (RVA 0x2070): MmMapIoSpace
        idata_raw[0x70 : 0x70 + 15] = b"\x00\x00MmMapIoSpace\x00"
        # Hint/Name 2 at offset 0x88 (RVA 0x2088): IoCreateDevice
        idata_raw[0x88 : 0x88 + 17] = b"\x00\x00IoCreateDevice\x00"
        # Hint/Name 3 at offset 0xA0 (RVA 0x20A0): ZwTerminateProcess
        idata_raw[0xA0 : 0xA0 + 21] = b"\x00\x00ZwTerminateProcess\x00"

    return headers + text_raw + bytes(idata_raw)


def test_hvci_compliant_driver():
    pe_bytes = _build_synthetic_driver_pe64(
        text_characteristics=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        include_byovd_imports=False,
    )
    report = audit_pe_driver_bytes(pe_bytes, "clean_driver.sys")
    assert report.is_pe is True
    assert report.is_kernel_driver is True
    assert report.architecture == "x86_64"
    assert report.hvci_compatible is True
    assert report.wx_violations == []
    assert report.mitigations["control_flow_guard"] is True
    assert report.mitigations["force_integrity"] is True
    assert report.byovd_risk_score == 0


def test_vulnerable_byovd_driver_with_wx_violation(tmp_path: Path):
    pe_bytes = _build_synthetic_driver_pe64(
        dll_characteristics=0x0040,  # DynamicBase only, no CFG
        text_characteristics=IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ,
        include_byovd_imports=True,
    )
    drv_path = tmp_path / "vuln_byovd.sys"
    drv_path.write_bytes(pe_bytes)

    report = scan_file_driver_audit(drv_path)
    assert report.is_pe is True
    assert report.is_kernel_driver is True
    assert report.hvci_compatible is False
    assert ".text" in report.wx_violations
    assert "ntoskrnl.exe" in report.kernel_imports
    assert "MmMapIoSpace" in report.byovd_primitives.get("physical_memory", [])
    assert "IoCreateDevice" in report.byovd_primitives.get("ioctl_surface", [])
    assert "ZwTerminateProcess" in report.byovd_primitives.get("process_manipulation", [])
    assert report.byovd_risk_score >= 75
