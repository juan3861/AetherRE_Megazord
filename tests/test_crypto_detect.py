"""
Unit and Adversarial Test Suite for AetherRE Crypto Detection Engine (FindCrypt)
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from aether_re.crypto_detect import (
    AES_INVSBOX,
    AES_SBOX,
    CHACHA20_CONST_32,
    CRC32_TABLE_LE,
    MD5_T_LE,
    SHA256_K_LE,
    SM4_SBOX,
    CryptoScanner,
    scan_file_for_crypto,
)


def test_detect_aes_sbox():
    buf = bytearray(b"\x90" * 1024)
    buf[0x100 : 0x100 + 256] = AES_SBOX
    buf[0x300 : 0x300 + 256] = AES_INVSBOX

    scanner = CryptoScanner(buf)
    matches = scanner.scan()

    algo_names = [m.algorithm for m in matches]
    assert "AES" in algo_names
    assert len([m for m in matches if m.algorithm == "AES"]) == 2

    offsets = {m.file_offset for m in matches if m.algorithm == "AES"}
    assert 0x100 in offsets
    assert 0x300 in offsets


def test_detect_sha256_and_md5():
    buf = bytearray(b"\x00" * 4096)
    buf[0x200 : 0x200 + len(SHA256_K_LE)] = SHA256_K_LE
    buf[0x600 : 0x600 + len(MD5_T_LE)] = MD5_T_LE

    scanner = CryptoScanner(buf)
    matches = scanner.scan()

    algos = {m.algorithm for m in matches}
    assert "SHA-256" in algos
    assert "MD5" in algos


def test_detect_chacha20_and_crc32():
    buf = bytearray(b"\xcc" * 2048)
    buf[0x80 : 0x80 + len(CHACHA20_CONST_32)] = CHACHA20_CONST_32
    buf[0x200 : 0x200 + len(CRC32_TABLE_LE)] = CRC32_TABLE_LE

    scanner = CryptoScanner(buf)
    matches = scanner.scan()

    algos = {m.algorithm for m in matches}
    assert "ChaCha20" in algos
    assert "CRC32" in algos


def test_detect_sm4_sbox():
    buf = bytearray(b"\x55" * 1024)
    buf[0x150 : 0x150 + len(SM4_SBOX)] = SM4_SBOX

    scanner = CryptoScanner(buf)
    matches = scanner.scan()

    algos = {m.algorithm for m in matches}
    assert "SM4" in algos
    m = [m for m in matches if m.algorithm == "SM4"][0]
    assert m.file_offset == 0x150
    assert m.confidence == "HIGH"


def test_scan_file_for_crypto_on_disk(tmp_path: Path):
    target = tmp_path / "sample_crypto.bin"
    payload = bytearray(b"\x00" * 2048)
    payload[0x50 : 0x50 + len(CHACHA20_CONST_32)] = CHACHA20_CONST_32
    payload[0x400 : 0x400 + 256] = AES_SBOX
    target.write_bytes(payload)

    res = scan_file_for_crypto(target)
    assert res["total_constants_detected"] >= 2
    assert "AES" in res["identified_algorithms"]
    assert "ChaCha20" in res["identified_algorithms"]
    assert res["high_confidence_matches_count"] >= 2


def test_random_noise_zero_false_positives():
    # 64 KB of random bytes should have zero high confidence signature matches
    noise = os.urandom(65536)
    scanner = CryptoScanner(noise)
    matches = scanner.scan()
    high_conf = [m for m in matches if m.confidence == "HIGH"]
    assert len(high_conf) == 0, f"Expected 0 false positives, got {len(high_conf)}"


def test_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_for_crypto(Path("non_existent_binary_12345.bin"))
