"""Unit tests for Reverse Engineering Graph — Calling Convention & Prototype Inference."""

from __future__ import annotations

import pytest

from aether_re.calling_convention import (
    SCHEMA,
    infer_calling_convention,
    infer_function_prototype,
)


def test_infer_win64_calling_convention():
    # Em Win64, rcx e rdx lidos antes de escritos
    insns = [
        {"mnemonic": "mov", "op_str": "rax, rcx"},
        {"mnemonic": "add", "op_str": "rax, rdx"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    res = infer_calling_convention(insns, arch="x86_64", file_format="pe")
    assert res["convention"] == "win64"
    assert "rcx" in res["param_registers"]
    assert "rdx" in res["param_registers"]
    assert res["cleaned_by"] == "caller"


def test_infer_sysv64_calling_convention():
    # Em SysV64 (Linux ELF), rdi e rsi são primeiros argumentos
    insns = [
        {"mnemonic": "mov", "op_str": "[rbp-8], rdi"},
        {"mnemonic": "mov", "op_str": "[rbp-16], rsi"},
        {"mnemonic": "mov", "op_str": "rax, 0"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    res = infer_calling_convention(insns, arch="x86_64", file_format="elf")
    assert res["convention"] == "sysv64"
    assert "rdi" in res["param_registers"]
    assert "rsi" in res["param_registers"]


def test_infer_x86_stdcall_and_prototype():
    # Em stdcall x86, callee limpa a pilha com ret 0x10 (4 parâmetros)
    insns = [
        {"mnemonic": "push", "op_str": "ebp"},
        {"mnemonic": "mov", "op_str": "ebp, esp"},
        {"mnemonic": "mov", "op_str": "eax, [ebp+8]"},
        {"mnemonic": "add", "op_str": "eax, [ebp+12]"},
        {"mnemonic": "pop", "op_str": "ebp"},
        {"mnemonic": "ret", "op_str": "0x10"},
    ]
    proto = infer_function_prototype(insns, function_name="AddFourInts", arch="x86", file_format="pe")
    assert proto["schema"] == SCHEMA
    assert proto["calling_convention"] == "stdcall"
    assert proto["estimated_param_count"] == 4
    assert proto["return_type"] == "int / pointer"
    assert proto["c_prototype"] == "int / pointer AddFourInts(arg_1, arg_2, arg_3, arg_4)"


def test_infer_x86_cdecl_void_prototype():
    insns = [
        {"mnemonic": "push", "op_str": "ebp"},
        {"mnemonic": "mov", "op_str": "ebp, esp"},
        {"mnemonic": "nop", "op_str": ""},
        {"mnemonic": "pop", "op_str": "ebp"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    proto = infer_function_prototype(insns, function_name="DoNothing", arch="x86", file_format="pe")
    assert proto["calling_convention"] == "cdecl"
    assert proto["return_type"] == "void"
