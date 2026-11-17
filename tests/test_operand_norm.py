from __future__ import annotations

import pytest
from aether_re.operand_norm import (
    normalize_instruction,
    normalize_instruction_stream,
    normalize_operands,
)


def test_normalize_registers_x86_x64():
    # Test accumulator normalization
    _, ops, _ = normalize_instruction("mov", "rax, rbx")
    assert ops == "REG_ACC, REG_BASE"

    _, ops, _ = normalize_instruction("mov", "eax, ecx")
    assert ops == "REG_ACC, REG_CTR"

    _, ops, _ = normalize_instruction("xor", "edx, edx")
    assert ops == "REG_DATA, REG_DATA"

    # Test extended registers
    _, ops, _ = normalize_instruction("mov", "r8, r15d")
    assert ops == "REG_EXT, REG_EXT"

    # Test vector registers
    _, ops, _ = normalize_instruction("movdqa", "xmm0, xmm1")
    assert ops == "REG_VEC, REG_VEC"


def test_normalize_memory_operands():
    # Stack variable access
    _, ops, _ = normalize_instruction("mov", "eax, [rbp - 0x18]")
    assert ops == "REG_ACC, [STACK_VAR]"

    _, ops, _ = normalize_instruction("mov", "dword ptr [rsp + 8], 1")
    assert ops == "[STACK_VAR], IMM_1"

    # RIP-relative access
    _, ops, _ = normalize_instruction("lea", "rax, [rip + 0x2034]")
    assert ops == "REG_ACC, [RIP_REL]"


def test_normalize_branch_instructions():
    _, ops, sig = normalize_instruction("call", "0x401050")
    assert ops == "TARGET_ADDR"
    assert sig == "CALL TARGET_ADDR"

    _, ops, sig = normalize_instruction("jz", "0x140001020")
    assert ops == "TARGET_ADDR"
    assert sig == "JZ TARGET_ADDR"


def test_normalize_instruction_stream():
    insns = [
        {"address": "0x1000", "mnemonic": "mov", "op_str": "eax, [rbp - 0x10]"},
        {"address": "0x1003", "mnemonic": "add", "op_str": "eax, 1"},
        {"address": "0x1006", "mnemonic": "ret", "op_str": ""},
    ]
    norm_stream = normalize_instruction_stream(insns)
    assert len(norm_stream) == 3
    assert norm_stream[0]["signature"] == "MOV REG_ACC, [STACK_VAR]"
    assert norm_stream[1]["signature"] == "ADD REG_ACC, IMM_1"
    assert norm_stream[2]["signature"] == "RET"
