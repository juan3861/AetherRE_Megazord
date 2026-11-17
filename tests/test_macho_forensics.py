from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aether_re.macho_forensics import analyze_macho, scan_file_macho


def _build_synthetic_macho64_with_codesig_and_objc() -> bytes:
    """Construct a valid Mach-O 64-bit ARM64 binary with LC_SEGMENT_64, LC_LOAD_DYLIB, LC_SYMTAB, and LC_CODE_SIGNATURE."""
    entitlements = b'<?xml version="1.0" encoding="UTF-8"?><plist><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>'
    ident = b"com.aetherre.sample\x00"
    team = b"TEAM123456\x00"

    # CodeDirectory blob (0xfade0c02)
    cd_hdr_size = 52
    cd_total = cd_hdr_size + len(ident) + len(team)
    cd_blob = bytearray(struct.pack(
        ">IIIIIIIIIBB",
        0xFADE0C02, cd_total, 0x20200, 0x10000,  # magic, len, ver, flags=hardened_runtime
        cd_total, cd_hdr_size, 0, 0, 0x1000, 32, 2,  # hashOff, identOff, nSpecial, nCode, codeLimit, hashSize, hashType
    ))
    cd_blob.extend(b"\x00" * (48 - len(cd_blob)))
    cd_blob.extend(struct.pack(">I", cd_hdr_size + len(ident)))
    cd_blob.extend(ident)
    cd_blob.extend(team)

    ent_blob = struct.pack(">II", 0xFADE7171, 8 + len(entitlements)) + entitlements

    # SuperBlob (0xfade0cc0) with 2 blobs
    sb_hdr = 12 + 2 * 8
    cd_off = sb_hdr
    ent_off = sb_hdr + len(cd_blob)
    sb_len = ent_off + len(ent_blob)
    superblob = bytearray(struct.pack(">III", 0xFADE0CC0, sb_len, 2))
    superblob.extend(struct.pack(">II", 0, cd_off))
    superblob.extend(struct.pack(">II", 5, ent_off))
    superblob.extend(cd_blob)
    superblob.extend(ent_blob)

    # ObjC classnames section data & symtab
    objc_names = b"AetherPayload\x00MalwareBeacon\x00"
    strtab = b"\x00_main\x00_$s10AetherTest4runyyF\x00"
    nlist = struct.pack("<IBBHQ", 1, 0x0F, 1, 0, 0x100001000) + struct.pack("<IBBHQ", 7, 0x0F, 1, 0, 0x100001040)

    # Load commands:
    # 1. LC_SEGMENT_64 (72 + 80 = 152 bytes) with 1 section __objc_classname
    # 2. LC_LOAD_DYLIB (24 + 24 = 48 bytes) "/usr/lib/libSystem.B.dylib\x00" padded to 8
    dylib_str = b"/usr/lib/libSystem.B.dylib\x00\x00\x00\x00\x00\x00"
    lc_dylib = struct.pack("<IIIIII", 0xC, 24 + len(dylib_str), 24, 0, 1, 1) + dylib_str
    # 3. LC_SYMTAB (24 bytes)
    # 4. LC_CODE_SIGNATURE (16 bytes)
    ncmds = 4
    sizeofcmds = 152 + len(lc_dylib) + 24 + 16
    hdr_end = 32 + sizeofcmds

    objc_off = hdr_end
    sym_off = objc_off + len(objc_names)
    str_off = sym_off + len(nlist)
    cs_off = str_off + len(strtab)

    sec_bytes = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__objc_classname", b"__DATA", 0x100004000, len(objc_names), objc_off, 0, 0, 0, 0, 0, 0, 0
    )
    lc_seg = struct.pack(
        "<II16sQQQQIIII",
        0x19, 152, b"__DATA", 0x100004000, 0x1000, objc_off, len(objc_names), 3, 3, 1, 0
    ) + sec_bytes
    lc_sym = struct.pack("<IIIIII", 0x2, 24, sym_off, 2, str_off, len(strtab))
    lc_cs = struct.pack("<IIII", 0x1D, 16, cs_off, len(superblob))

    mh = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, ncmds, sizeofcmds, 0x200000, 0)
    return mh + lc_seg + lc_dylib + lc_sym + lc_cs + objc_names + nlist + strtab + bytes(superblob)


def test_macho64_codesig_entitlements_objc_swift_parsed(tmp_path: Path):
    data = _build_synthetic_macho64_with_codesig_and_objc()
    p = tmp_path / "sample.macho"
    p.write_bytes(data)

    res = scan_file_macho(p)
    assert res["status"] == "complete"
    assert res["is_universal_fat"] is False
    sl = res["slices"][0]
    assert sl["cpu_type"] == "arm64"
    assert sl["file_type"] == "MH_EXECUTE"
    assert sl["mitigations"]["pie"] is True
    assert "/usr/lib/libSystem.B.dylib" in sl["dylibs"]
    assert "AetherPayload" in sl["objc_classes"]
    assert "MalwareBeacon" in sl["objc_classes"]
    assert "_$s10AetherTest4runyyF" in sl["swift_symbols"]

    cs = sl["code_signature"]
    assert cs["present"] is True
    assert cs["valid_superblob"] is True
    assert cs["code_directory"]["identifier"] == "com.aetherre.sample"
    assert cs["code_directory"]["team_id"] == "TEAM123456"
    assert cs["code_directory"]["hardened_runtime"] is True
    assert "com.apple.security.cs.allow-jit" in cs["entitlement_keys"]


def test_invalid_macho_and_java_class_rejected():
    # Java class (0xCAFEBABE, minor=0, major=55) must NOT be misparsed as Fat Mach-O
    java_hdr = struct.pack(">II", 0xCAFEBABE, 55) + b"\x00" * 32
    assert analyze_macho(java_hdr)["status"] == "invalid"
    assert analyze_macho(b"MZ_NOT_MACHO_123456")["status"] == "invalid"
    assert analyze_macho("bad")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_macho_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_macho(r"D:\AetherRE_Megazord\missing_macho_123")
