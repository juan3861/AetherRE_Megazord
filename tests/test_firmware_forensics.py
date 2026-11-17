from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from aether_re.firmware_forensics import analyze_firmware, scan_file_firmware


def test_firmware_uboot_fdt_squashfs_and_entropy_carving(tmp_path: Path):
    # U-Boot uImage header (64 bytes)
    uboot = struct.pack(
        ">IIIIIIIBBBB32s",
        0x27051956, 0, 0, 128, 0x80008000, 0x80008000, 0, 5, 2, 2, 1, b"Linux-AetherRE\x00"
    )
    # FDT/DTB header (40 bytes)
    fdt = struct.pack(">IIIIIIIIII", 0xD00DFEED, 64, 40, 56, 0, 17, 16, 0, 8, 16) + b"\x00" * 24
    # SquashFS magic + random high-entropy block
    squash = b"hsqs" + b"\x00" * 32
    high_ent = os.urandom(4096)

    fw = uboot + fdt + squash + high_ent
    p = tmp_path / "router.bin"
    p.write_bytes(fw)

    res = scan_file_firmware(p)
    assert res["status"] == "complete"
    kinds = [s["kind"] for s in res["signatures"]]
    assert "uboot_uimage" in kinds
    assert "fdt_dtb" in kinds
    assert "squashfs_le" in kinds

    ub_entry = next(s for s in res["signatures"] if s["kind"] == "uboot_uimage")
    assert ub_entry["metadata"]["name"] == "Linux-AetherRE"
    assert ub_entry["metadata"]["entry_point"] == "0x80008000"

    fdt_entry = next(s for s in res["signatures"] if s["kind"] == "fdt_dtb")
    assert fdt_entry["metadata"]["totalsize"] == 64
    assert res["high_entropy_chunk_count"] >= 1


def test_invalid_firmware_fails_closed():
    assert analyze_firmware(b"")["status"] == "invalid"
    assert analyze_firmware("bad")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_firmware_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_firmware(r"D:\AetherRE_Megazord\missing_fw_999.bin")
