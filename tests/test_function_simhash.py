from __future__ import annotations

from pathlib import Path
import pytest
from aether_re.function_simhash import (
    compute_function_simhash,
    extract_binary_simhashes,
    hamming_distance,
    simhash_similarity,
)


def test_simhash_deterministic():
    insns = [
        {"mnemonic": "mov", "op_str": "eax, 1"},
        {"mnemonic": "add", "op_str": "eax, ebx"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    h1 = compute_function_simhash(insns)
    h2 = compute_function_simhash(insns)
    assert len(h1) == 16
    assert h1 == h2
    assert hamming_distance(h1, h2) == 0
    assert simhash_similarity(h1, h2) == 1.0


def test_simhash_mutation_resilience():
    # Duas funções idênticas com exceção do offset da pilha
    f1 = [
        {"mnemonic": "mov", "op_str": "eax, [rbp - 0x10]"},
        {"mnemonic": "add", "op_str": "eax, 1"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    f2 = [
        {"mnemonic": "mov", "op_str": "eax, [rbp - 0x28]"},
        {"mnemonic": "add", "op_str": "eax, 1"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    h1 = compute_function_simhash(f1)
    h2 = compute_function_simhash(f2)
    # Por causa da normalização PalmTree, os hashes devem ser idênticos
    assert h1 == h2
    assert simhash_similarity(h1, h2) == 1.0


def test_simhash_dissimilar_functions():
    f1 = [
        {"mnemonic": "mov", "op_str": "eax, 1"},
        {"mnemonic": "add", "op_str": "eax, ebx"},
        {"mnemonic": "ret", "op_str": ""},
    ]
    f3 = [
        {"mnemonic": "xor", "op_str": "ecx, ecx"},
        {"mnemonic": "call", "op_str": "0x401050"},
        {"mnemonic": "test", "op_str": "eax, eax"},
    ]
    h1 = compute_function_simhash(f1)
    h3 = compute_function_simhash(f3)
    assert hamming_distance(h1, h3) > 10
    assert simhash_similarity(h1, h3) < 0.85


def test_extract_binary_simhashes(tmp_path: Path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 64 + b"kernel32.dll\x00ExitProcess\x00")
    profiles = extract_binary_simhashes(target)
    assert isinstance(profiles, dict)
    assert len(profiles) >= 1
