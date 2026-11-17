"""Unit tests for Reverse Engineering Graph — Automatic Struct Recovery."""

from __future__ import annotations

import pytest

from aether_re.struct_recovery import (
    SCHEMA,
    _infer_access_size,
    recover_struct_layouts,
)


def test_infer_access_size():
    assert _infer_access_size("mov", "al, byte ptr [rcx]") == 1
    assert _infer_access_size("mov", "ax, word ptr [rcx+2]") == 2
    assert _infer_access_size("mov", "eax, dword ptr [rcx+4]") == 4
    assert _infer_access_size("mov", "rax, qword ptr [rcx+8]") == 8


def test_recover_struct_layouts_single_object():
    insns = [
        {"mnemonic": "mov", "op_str": "eax, dword ptr [rcx + 0x0]"},
        {"mnemonic": "mov", "op_str": "ebx, dword ptr [rcx + 0x4]"},
        {"mnemonic": "mov", "op_str": "rdx, qword ptr [rcx + 0x8]"},
        {"mnemonic": "mov", "op_str": "al, byte ptr [rcx + 0x10]"},
    ]
    rep = recover_struct_layouts(insns, base_registers={"rcx"})
    assert rep["schema"] == SCHEMA
    assert rep["total_structs_recovered"] == 1
    st = rep["structs"][0]
    assert st["base_register"] == "rcx"
    assert st["fields_count"] == 4
    assert st["total_size_bytes"] == 0x11  # 16 + 1
    assert "typedef struct RecoveredStruct_RCX" in st["c_declaration"]
    assert "uint32_t field_0x00;" in st["c_declaration"]
    assert "uint64_t field_0x08;" in st["c_declaration"]
    assert "uint8_t field_0x10;" in st["c_declaration"]


def test_recover_struct_layouts_with_padding():
    insns = [
        {"mnemonic": "mov", "op_str": "al, byte ptr [rsi + 0x0]"},   # 1 byte
        {"mnemonic": "mov", "op_str": "eax, dword ptr [rsi + 0x4]"}, # 4 bytes -> gap de 3 bytes
    ]
    rep = recover_struct_layouts(insns, base_registers={"rsi"})
    st = rep["structs"][0]
    assert "_pad_0[3]" in st["c_declaration"]
