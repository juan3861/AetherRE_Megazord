"""Tests for GEAR-20: Installer, Cabinet (MSCF) & SFX Overlay Forensics."""

from __future__ import annotations

import struct
from pathlib import Path

from aether_re.installer_forensics import (
    CAB_MAGIC,
    NSIS_MAGIC,
    analyze_installer_bytes,
    scan_file_installer,
)


def _build_synthetic_cabinet() -> bytes:
    # CFHEADER (36 bytes):
    # 0..4: 'MSCF', 4..8: 0, 8..12: cbCabinet, 12..16: 0, 16..20: coffFiles (36),
    # 20..24: 0, 24: vMinor(3), 25: vMajor(1), 26..28: cFolders(1), 28..30: cFiles(2),
    # 30..32: flags(0), 32..34: setID(1), 34..36: iCabinet(0)
    f1 = struct.pack("<IIHHHH", 4096, 0, 0, 0, 0, 0x20) + b"payload.dll\x00"
    f2 = struct.pack("<IIHHHH", 512, 4096, 0, 0, 0, 0x20) + b"config.ini\x00"
    files_blob = f1 + f2
    total_size = 36 + len(files_blob)
    hdr = struct.pack(
        "<8sIIIIBBHHHH",
        CAB_MAGIC,
        total_size,  # 8..12: cbCabinet
        0,           # 12..16: reserved2
        36,          # 16..20: coffFiles
        0,           # 20..24: reserved3
        3,           # 24: vMinor
        1,           # 25: vMajor
        1,           # 26..28: cFolders
        2,           # 28..30: cFiles
        0,           # 30..32: flags
        1,           # 32..34: setID
    ) + struct.pack("<H", 0)  # 34..36: iCabinet
    return hdr + files_blob


def test_inno_setup_and_nsis_detection():
    inno_blob = b"MZ" + b"\x00" * 128 + b"Inno Setup Setup Data (6.2.2) (u)\x00"
    rep_inno = analyze_installer_bytes(inno_blob, "setup.exe")
    assert rep_inno.installer_type == "inno_setup"
    assert "6.2.2" in rep_inno.inno_version

    nsis_blob = (
        b"MZ"
        + b"\x00" * 510
        + struct.pack("<I", 0)
        + NSIS_MAGIC
        + struct.pack("<II", 32768, 1048576)
    )
    rep_nsis = analyze_installer_bytes(nsis_blob, "nsis_setup.exe")
    assert rep_nsis.installer_type == "nsis"
    assert rep_nsis.nsis_info["header_inflated_size"] == 32768
    assert rep_nsis.nsis_info["archive_compressed_size"] == 1048576


def test_cabinet_file_enumeration_in_overlay(tmp_path: Path):
    cab = _build_synthetic_cabinet()
    sfx = b"MZ" + b"\x00" * 254 + cab
    p = tmp_path / "cab_sfx.exe"
    p.write_bytes(sfx)

    rep = scan_file_installer(p)
    assert rep.installer_type == "cabinet"
    assert rep.cabinet_info["file_count"] == 2
    names = [f["name"] for f in rep.cabinet_files]
    assert "payload.dll" in names
    assert "config.ini" in names
