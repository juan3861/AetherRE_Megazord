"""Unit tests for Reverse Engineering Graph — Sliding-Window Entropy & Packer Detector."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aether_re.packer_detect import (
    COMPILER_SIGNATURES,
    PACKER_SIGNATURES,
    SCHEMA,
    analyze_packer_and_compiler,
    sliding_window_entropy,
)


def test_sliding_window_entropy_empty_or_small():
    assert sliding_window_entropy(b"") == []
    assert sliding_window_entropy(b"short", window_size=512) == []
    assert sliding_window_entropy(b"abc", window_size=0) == []
    assert sliding_window_entropy(b"abc", step_size=0) == []


def test_sliding_window_entropy_uniform_low():
    # 2048 bytes de zeros têm entropia 0.0 -> nenhum bloco >= 7.2
    data = b"\x00" * 2048
    blocks = sliding_window_entropy(data, window_size=512, step_size=128, threshold=7.2)
    assert blocks == []


def test_sliding_window_entropy_high_random():
    # 2048 bytes aleatórios ou pseudo-aleatórios uniformes
    # Entropia de Shannon máxima teórica = 8.0
    pattern = bytes([i % 256 for i in range(2048)])
    # Para garantir entropia > 7.5, usamos os bytes gerados por urandom
    data = os.urandom(2048)
    blocks = sliding_window_entropy(data, window_size=512, step_size=128, threshold=7.0)
    assert len(blocks) >= 1
    assert blocks[0]["peak_entropy"] >= 7.0
    assert "offset_hex" in blocks[0]
    assert "length_bytes" in blocks[0]


def test_analyze_packer_nonexistent(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        analyze_packer_and_compiler(tmp_path / "nao_existe.exe")


def test_analyze_compiler_detection_dotnet(tmp_path: Path):
    target = tmp_path / "sample_dotnet.exe"
    # Injetar marcadores .NET
    content = b"MZ" + (b"\x00" * 200) + b"mscoree.dll" + b"_CorExeMain" + b"System.Runtime" + (b"\x00" * 200)
    target.write_bytes(content)

    res = analyze_packer_and_compiler(target)
    assert res["schema"] == SCHEMA
    assert res["compiler"]["name"] == ".NET (C#/F#/VB)"
    assert res["compiler"]["confidence"] >= 0.90
    assert "mscoree.dll" in res["compiler"]["matched_signatures"]
    assert res["is_packed"] is False


def test_analyze_compiler_detection_go(tmp_path: Path):
    target = tmp_path / "sample_go.exe"
    content = b"\x7fELF" + (b"\x00" * 100) + b"go.buildid" + b"runtime.main" + (b"\x00" * 100)
    target.write_bytes(content)

    res = analyze_packer_and_compiler(target)
    assert res["compiler"]["name"] == "Go"
    assert res["compiler"]["confidence"] >= 0.90


def test_analyze_packer_detection_upx_bytes(tmp_path: Path):
    target = tmp_path / "packed_upx.exe"
    content = b"MZ" + (b"\x00" * 50) + b"UPX!" + (b"\x00" * 100)
    target.write_bytes(content)

    res = analyze_packer_and_compiler(target)
    assert res["is_packed"] is True
    assert res["packer"]["name"] == "UPX"
    assert res["packer"]["confidence"] == 0.99
    assert "UPX!" in res["packer"]["matched_signatures"]


def test_analyze_generic_high_entropy(tmp_path: Path):
    target = tmp_path / "high_entropy_blob.bin"
    # Criar arquivo > 4096 bytes com > 50% de alta entropia
    content = os.urandom(8192)
    target.write_bytes(content)

    res = analyze_packer_and_compiler(target)
    assert res["is_packed"] is True
    assert "High-Entropy" in res["packer"]["name"]
    assert res["sliding_entropy"]["high_entropy_ratio"] >= 0.50
