from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aether_re.dotnet_forensics import analyze_dotnet_metadata, scan_file_dotnet


def _build_synthetic_dotnet_blob() -> bytes:
    ver = b"v4.0.30319\x00\x00"  # 12 bytes (4-byte aligned)
    strings_stream = b"\x00AetherAgent\x00BeaconMain\x00kernel32.dll\x00"
    us_item = "https://c2.aether.local/gate".encode("utf-16-le") + b"\x00"
    us_stream = b"\x00" + bytes([len(us_item)]) + us_item

    # BSJB header: magic(4), major(2), minor(2), reserved(4), ver_len(4), ver(12), flags(2), num_streams(2) = 32 bytes
    bsjb_hdr_size = 32
    s1_name = b"#Strings\x00\x00\x00\x00"  # 12 bytes
    s2_name = b"#US\x00"  # 4 bytes
    dir_size = (8 + len(s1_name)) + (8 + len(s2_name))

    s1_off = bsjb_hdr_size + dir_size
    s2_off = s1_off + len(strings_stream)

    hdr = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(ver)) + ver + struct.pack("<HH", 0, 2)
    s1_hdr = struct.pack("<II", s1_off, len(strings_stream)) + s1_name
    s2_hdr = struct.pack("<II", s2_off, len(us_stream)) + s2_name

    return b"MZ" + b"\x00" * 62 + hdr + s1_hdr + s2_hdr + strings_stream + us_stream


def test_dotnet_bsjb_strings_and_user_strings_parsed(tmp_path: Path):
    p = tmp_path / "agent.dll"
    p.write_bytes(_build_synthetic_dotnet_blob())

    res = scan_file_dotnet(p)
    assert res["status"] == "complete"
    assert res["is_dotnet"] is True
    assert res["runtime_version"] == "v4.0.30319"
    assert "AetherAgent" in res["strings"]
    assert "BeaconMain" in res["strings"]
    assert "https://c2.aether.local/gate" in res["user_strings"]


def test_non_dotnet_binary_returns_not_dotnet():
    res = analyze_dotnet_metadata(b"MZ" + b"\x00" * 128)
    assert res["status"] == "not_dotnet"
    assert res["is_dotnet"] is False


def test_invalid_inputs_fail_closed():
    assert analyze_dotnet_metadata(b"")["status"] == "invalid"
    assert analyze_dotnet_metadata("bad")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_dotnet(r"D:\AetherRE_Megazord\missing_dotnet_999.dll")
