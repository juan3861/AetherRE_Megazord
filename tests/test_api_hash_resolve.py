from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aether_re.api_hash_resolve import (
    hash_crc32,
    hash_djb2,
    hash_fnv1a_32,
    hash_ror13,
    resolve_api_hash,
    scan_bytes_for_api_hashes,
    scan_file_api_hashes,
)


def test_resolve_embedded_api_hashes_in_shellcode_stub(tmp_path: Path):
    h1 = hash_ror13("VirtualAlloc")
    h2 = hash_fnv1a_32("LoadLibraryA")
    h3 = hash_djb2("CreateRemoteThread")
    h4 = hash_crc32("InternetOpenA")

    # Embed inside x86 `mov edx, imm32` (0xBA) instructions at unaligned offsets
    blob = (
        b"\x90\xba" + struct.pack("<I", h1) +
        b"\xba" + struct.pack("<I", h2) +
        b"\xba" + struct.pack("<I", h3) +
        b"\xba" + struct.pack("<I", h4) +
        b"\xc3"
    )
    p = tmp_path / "shellcode.bin"
    p.write_bytes(blob)

    res = scan_file_api_hashes(p)
    assert res["status"] == "complete"
    assert res["total_resolved"] == 4
    assert set(res["unique_apis"]) == {"VirtualAlloc", "LoadLibraryA", "CreateRemoteThread", "InternetOpenA"}
    assert set(res["algorithms_matched"]) == {"ror13", "fnv1a_32", "djb2", "crc32"}


def test_single_hash_lookup():
    hits = resolve_api_hash(hash_ror13("GetProcAddress"))
    assert any(h["api_name"] == "GetProcAddress" and h["algorithm"] == "ror13" for h in hits)


def test_invalid_inputs_fail_closed():
    assert scan_bytes_for_api_hashes(b"")["total_resolved"] == 0
    assert scan_bytes_for_api_hashes("bad")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_api_hashes(r"D:\AetherRE_Megazord\missing_hash_999.bin")
