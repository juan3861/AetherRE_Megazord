"""Tests for GEAR-17: Pure-Python Android Dalvik DEX & APK Offline Forensics."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from pathlib import Path

from aether_re.dex_forensics import ENDIAN_CONSTANT, analyze_dex_or_apk_bytes, scan_file_dex


def _encode_uleb128(val: int) -> bytes:
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        out.append(byte)
        if val == 0:
            break
    return bytes(out)


def _build_synthetic_dex() -> bytes:
    """Constructs a valid minimal DEX 035 binary in memory."""
    str_list = [
        "<init>",
        "Lcom/aether/MainActivity;",
        "Ldalvik/system/DexClassLoader;",
        "Ljava/lang/Runtime;",
        "exec",
        "loadLibrary",
    ]
    # Layout:
    # 0x00..0x70: Header (112 bytes)
    # 0x70..0x88: string_ids (6 * 4 = 24 bytes)
    # 0x88..0x94: type_ids (3 * 4 = 12 bytes) -> indices 1, 2, 3 in str_list
    # 0x94..0xA4: method_ids (2 * 8 = 16 bytes)
    # 0xA4..0xC4: class_defs (1 * 32 = 32 bytes)
    # 0xC4..    : string_data pool

    string_ids_off = 0x70
    type_ids_off = string_ids_off + len(str_list) * 4
    method_ids_off = type_ids_off + 3 * 4
    class_defs_off = method_ids_off + 2 * 8
    string_pool_off = class_defs_off + 1 * 32

    string_pool = bytearray()
    string_offsets = []
    for s in str_list:
        string_offsets.append(string_pool_off + len(string_pool))
        raw = s.encode("utf-8")
        string_pool.extend(_encode_uleb128(len(s)))
        string_pool.extend(raw)
        string_pool.append(0x00)

    string_ids = b"".join(struct.pack("<I", off) for off in string_offsets)
    # Types: 0 -> MainActivity (str 1), 1 -> DexClassLoader (str 2), 2 -> Runtime (str 3)
    type_ids = struct.pack("<III", 1, 2, 3)

    # Methods:
    # Method 0: class_idx=2 (Runtime), proto_idx=0, name_idx=4 ("exec")
    # Method 1: class_idx=1 (DexClassLoader), proto_idx=0, name_idx=0 ("<init>")
    method_ids = struct.pack("<HHIHHI", 2, 0, 4, 1, 0, 0)

    # Class def 0: class_idx=0 (MainActivity)
    class_defs = bytearray(32)
    struct.pack_into("<I", class_defs, 0, 0)

    body = string_ids + type_ids + method_ids + bytes(class_defs) + bytes(string_pool)
    total_size = 0x70 + len(body)

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, total_size)
    struct.pack_into("<I", header, 36, 0x70)
    struct.pack_into("<I", header, 40, ENDIAN_CONSTANT)
    struct.pack_into("<II", header, 56, len(str_list), string_ids_off)
    struct.pack_into("<II", header, 64, 3, type_ids_off)
    struct.pack_into("<II", header, 88, 2, method_ids_off)
    struct.pack_into("<II", header, 96, 1, class_defs_off)

    full_dex = bytearray(header) + body
    checksum = zlib.adler32(bytes(full_dex[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", full_dex, 8, checksum)
    return bytes(full_dex)


def test_standalone_dex_parsing():
    dex_bytes = _build_synthetic_dex()
    report = analyze_dex_or_apk_bytes(dex_bytes, "classes.dex")
    assert report.is_valid is True
    assert report.container_type == "dex"
    assert report.dex_version == "035"
    assert report.string_count == 6
    assert "Lcom/aether/MainActivity;" in report.classes
    assert "Ljava/lang/Runtime;->exec" in report.methods
    assert "dynamic_code_loading" in report.sensitive_indicators
    assert "native_execution" in report.sensitive_indicators


def test_apk_container_with_dex_and_native_jni(tmp_path: Path):
    dex_bytes = _build_synthetic_dex()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("lib/arm64-v8a/libcrypto_jni.so", b"\x7fELF" + b"\x00" * 60)

    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(buf.getvalue())

    report = scan_file_dex(apk_path)
    assert report.is_valid is True
    assert report.container_type == "apk"
    assert "classes.dex" in report.apk_dex_files
    assert "lib/arm64-v8a/libcrypto_jni.so" in report.apk_native_libs
    assert "Lcom/aether/MainActivity;" in report.classes
