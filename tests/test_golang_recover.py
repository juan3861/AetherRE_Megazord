"""
Unit and Adversarial Test Suite for AetherRE Golang Stripped Symbol Recovery Engine (GoReSym)
"""
from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

import pytest

from aether_re.golang_recover import (
    GolangRecoverEngine,
    recover_golang_symbols_from_file,
)


def _build_go116_test_blob(ptr_size: int = 8) -> bytes:
    magic = 0xFFFFFFF0  # Go 1.16
    min_lc = 1
    pad0 = 0
    pad1 = 0

    fn_names = [b"runtime.morestack", b"main.main", b"net/http.Get"]
    funcnametab = bytearray()
    name_offsets = []
    for name in fn_names:
        name_offsets.append(len(funcnametab))
        funcnametab.extend(name + b"\x00")

    header_size = 8 + 7 * ptr_size
    funcname_offset = header_size

    functab_offset = funcname_offset + len(funcnametab)
    if functab_offset % ptr_size != 0:
        padding = ptr_size - (functab_offset % ptr_size)
        funcnametab.extend(b"\x00" * padding)
        functab_offset = funcname_offset + len(funcnametab)

    nfunc = len(fn_names)
    functab_entry_size = 2 * ptr_size
    functab_size = (nfunc + 1) * functab_entry_size
    func_structs_offset = functab_offset + functab_size

    func_structs = bytearray()
    struct_offsets = []
    base_pc = 0x00401000
    pcs = [base_pc, base_pc + 0x100, base_pc + 0x250]

    for pc, name_off in zip(pcs, name_offsets):
        struct_offsets.append(func_structs_offset + len(func_structs))
        if ptr_size == 8:
            func_structs.extend(struct.pack("<QiI", pc, name_off, 0))
        else:
            func_structs.extend(struct.pack("<IiI", pc, name_off, 0))

    fmt_ptr = "<Q" if ptr_size == 8 else "<I"
    header = bytearray(struct.pack("<IBBBB", magic, pad0, pad1, min_lc, ptr_size))
    header.extend(struct.pack(fmt_ptr, nfunc))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, funcname_offset))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, functab_offset))

    functab = bytearray()
    for pc, s_off in zip(pcs, struct_offsets):
        functab.extend(struct.pack(fmt_ptr, pc))
        functab.extend(struct.pack(fmt_ptr, s_off))
    functab.extend(struct.pack(fmt_ptr, pcs[-1] + 0x100))
    functab.extend(struct.pack(fmt_ptr, 0))

    return bytes(header + funcnametab + functab + func_structs)


def _build_go118_test_blob(ptr_size: int = 8) -> bytes:
    magic = 0xFFFFFFFA  # Go 1.18
    min_lc = 1
    pad0 = 0
    pad1 = 0

    fn_names = [b"runtime.goexit", b"main.decryptPayload", b"crypto/aes.NewCipher"]
    funcnametab = bytearray()
    name_offsets = []
    for name in fn_names:
        name_offsets.append(len(funcnametab))
        funcnametab.extend(name + b"\x00")

    header_size = 8 + 8 * ptr_size
    funcname_offset = header_size

    functab_offset = funcname_offset + len(funcnametab)
    if functab_offset % 4 != 0:
        padding = 4 - (functab_offset % 4)
        funcnametab.extend(b"\x00" * padding)
        functab_offset = funcname_offset + len(funcnametab)

    nfunc = len(fn_names)
    functab_size = (nfunc + 1) * 8
    func_structs_offset = functab_offset + functab_size

    func_structs = bytearray()
    struct_offsets = []
    text_start = 0x00400000
    offsets_pc = [0x1000, 0x1500, 0x2200]

    for off, name_off in zip(offsets_pc, name_offsets):
        struct_offsets.append(func_structs_offset + len(func_structs))
        func_structs.extend(struct.pack("<II", off, name_off))

    fmt_ptr = "<Q" if ptr_size == 8 else "<I"
    header = bytearray(struct.pack("<IBBBB", magic, pad0, pad1, min_lc, ptr_size))
    header.extend(struct.pack(fmt_ptr, nfunc))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, text_start))  # textStart
    header.extend(struct.pack(fmt_ptr, funcname_offset))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, 0))
    header.extend(struct.pack(fmt_ptr, functab_offset))

    functab = bytearray()
    for off, s_off in zip(offsets_pc, struct_offsets):
        functab.extend(struct.pack("<II", off, s_off))
    functab.extend(struct.pack("<II", offsets_pc[-1] + 0x100, 0))

    return bytes(header + funcnametab + functab + func_structs)


def test_non_go_binary():
    noise = os.urandom(8192)
    engine = GolangRecoverEngine(noise)
    report = engine.recover()
    assert report.is_go_binary is False
    assert report.total_functions == 0
    assert len(report.functions) == 0


def test_go116_pclntab_recovery():
    blob = _build_go116_test_blob(ptr_size=8)
    # Wrap with padding
    full_data = b"\x90" * 512 + blob + b"\x90" * 512
    engine = GolangRecoverEngine(full_data)
    report = engine.recover()

    assert report.is_go_binary is True
    assert "Go 1.16" in (report.go_version or "")
    assert report.total_functions == 3
    func_names = [f["name"] for f in report.functions]
    assert func_names == ["runtime.morestack", "main.main", "net/http.Get"]
    assert "main" in report.packages
    assert "runtime" in report.packages


def test_go118_pclntab_recovery():
    blob = _build_go118_test_blob(ptr_size=8)
    full_data = b"\x00" * 256 + blob + b"\x00" * 256
    engine = GolangRecoverEngine(full_data)
    report = engine.recover()

    assert report.is_go_binary is True
    assert "Go 1.18" in (report.go_version or "")
    assert report.total_functions == 3
    func_names = [f["name"] for f in report.functions]
    assert func_names == ["runtime.goexit", "main.decryptPayload", "crypto/aes.NewCipher"]
    assert "crypto/aes" in report.packages or "crypto" in report.packages or "main" in report.packages


def test_recover_from_file_on_disk(tmp_path: Path):
    target = tmp_path / "sample_go.exe"
    blob = _build_go116_test_blob(ptr_size=8)
    target.write_bytes(b"\x90" * 128 + blob)

    res = recover_golang_symbols_from_file(target)
    assert res["is_go_binary"] is True
    assert res["total_functions"] == 3
    assert "main.main" in [f["name"] for f in res["functions"]]


def test_file_not_found():
    with pytest.raises(FileNotFoundError):
        recover_golang_symbols_from_file(Path("non_existent_file_xyz.exe"))
