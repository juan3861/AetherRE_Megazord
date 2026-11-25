"""Pilar 5 (v11.0) Empirical Tests: UEFI PI Firmware Volume, FDT/DTB MMIO Re-Hosting & Driver IOCTL Prover."""
from __future__ import annotations

import struct
from pathlib import Path

from aether_re.driver_ioctl_fuzzer import audit_driver_ioctls_and_irps, decode_ctl_code
from aether_re.firmware_reconstructor import reconstruct_firmware_project


def test_v110_firmware_uefi_fv_and_fdt_dtb_auto_mmio(tmp_path: Path) -> None:
    # 1. Construct valid Flattened Device Tree (.dtb, magic 0xD00DFEED) with UART MMIO node (0x40011000, size 0x400)
    # Build strings block: "compatible\0reg\0"
    str_tbl = b"compatible\x00reg\x00"
    # Build struct block:
    # BEGIN_NODE "/" -> align 4
    #   BEGIN_NODE "uart@40011000" -> prop reg=<0x40011000, 0x400> -> END_NODE
    # END_NODE
    # FDT_END (9)
    def _pad4(b: bytes) -> bytes:
        rem = len(b) % 4
        return b + (b"\x00" * (4 - rem) if rem else b"")

    sb = bytearray()
    sb += struct.pack(">I", 1) + _pad4(b"\x00")
    sb += struct.pack(">I", 1) + _pad4(b"uart@40011000\x00")
    sb += struct.pack(">III", 3, 8, 11) + struct.pack(">II", 0x40011000, 0x400)
    sb += struct.pack(">III", 3, 12, 0) + _pad4(b"arm,pl011\x00")
    sb += struct.pack(">II", 2, 2)
    sb += struct.pack(">I", 9)

    dtb_hdr_sz = 40
    total_dtb = dtb_hdr_sz + len(sb) + len(str_tbl)
    dtb = struct.pack(">10I", 0xD00DFEED, total_dtb, dtb_hdr_sz, dtb_hdr_sz + len(sb), 0, 17, 16, 0, len(str_tbl), len(sb)) + bytes(sb) + str_tbl

    fw_p = tmp_path / "router_dtb.bin"
    fw_p.write_bytes(b"\xFF" * 16 + dtb)
    out_fw = tmp_path / "fw_dtb_proj"
    rep = reconstruct_firmware_project(fw_p, out_fw)
    assert rep["dtb_found"] is True
    harness = (out_fw / "rehosting" / "unicorn_mmio_harness.py").read_text(encoding="utf-8")
    assert "uart@40011000" in harness and "0x40011000" in harness

    # 2. Construct UEFI PI Firmware Volume (`_FVH`) containing an SMM Driver (0x0A) with gBS + MZ risk
    ffs_payload = b"MZ" + b"\x00" * 14 + b"gBS->LocateProtocol"
    ffs_sz = 24 + len(ffs_payload)
    ffs_hdr = struct.pack("<IHH8sHBB3sB", 0x11223344, 0x5566, 0x7788, b"\x01\x02\x03\x04\x05\x06\x07\x08", 0, 0x0A, 0x00, bytes([ffs_sz & 0xFF, (ffs_sz >> 8) & 0xFF, 0]), 0)
    ffs_entry = (ffs_hdr + ffs_payload).ljust((ffs_sz + 7) & ~7, b"\xFF")
    fv_len = 64 + len(ffs_entry)
    fv_hdr = b"\x00" * 32 + struct.pack("<QIIH", fv_len, 0x4856465F, 0, 64) + b"\x00" * 14
    uefi_bin = tmp_path / "bios_fv.bin"
    uefi_bin.write_bytes(fv_hdr + ffs_entry)
    out_uefi = tmp_path / "uefi_proj"
    rep_u = reconstruct_firmware_project(uefi_bin, out_uefi)
    assert rep_u["uefi_found"] is True
    assert rep_u["uefi_modules_count"] >= 1


def test_v110_driver_ioctl_decoder_method_neither_and_irp_z3_poc() -> None:
    # Build Native-Subsystem PE64 driver containing IOCTL 0x222003 (METHOD_NEITHER!) + `wrmsr` (0F 30)
    dec = decode_ctl_code(0x00222003)
    assert dec["method"] == "METHOD_NEITHER"
    assert dec["function"] == "0x800"

    pe = bytearray(0x1000)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    opt = 0x98
    struct.pack_into("<H", pe, opt, 0x020B)
    struct.pack_into("<I", pe, opt + 16, 0x1000)
    struct.pack_into("<II", pe, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", pe, opt + 56, 0x2000, 0x200)
    struct.pack_into("<HI", pe, opt + 68, 1, 0x10)  # Subsystem = 1 (IMAGE_SUBSYSTEM_NATIVE)
    s0 = opt + 0xF0
    pe[s0 : s0 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", pe, s0 + 8, 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    # Machine code at 0x200: cmp eax, 0x222003 (3D 03 20 22 00); wrmsr (0F 30); ret (C3)
    pe[0x200:0x208] = bytes.fromhex("3D 03 20 22 00 0F 30 C3")

    irp_c = """
    int64_t DispatchIoctl(int64_t InputBufferLength) {
        void *p = ExAllocatePoolWithTag(0, (InputBufferLength * 8) + 16);
        return (int64_t)p;
    }
    """
    rep = audit_driver_ioctls_and_irps(bytes(pe), driver_c_code=irp_c)
    assert rep["ioctls_count"] >= 1
    assert any(i["method"] == "METHOD_NEITHER" for i in rep["ioctls"])
    rules = {f["rule_id"] for f in rep["irp_findings"]}
    assert "AETHER-DRV-NEITHER-NOPROBE" in rules
    assert "AETHER-DRV-PRIV-INSN" in rules
    assert "AETHER-DRV-IRP-INT-OVERFLOW" in rules
