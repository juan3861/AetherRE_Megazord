from __future__ import annotations

from pathlib import Path
import pytest

from aether_re.binary_diff import (
    SCHEMA,
    _jaccard_similarity,
    diff_binaries,
)


def test_jaccard_similarity():
    assert _jaccard_similarity(set(), set()) == 1.0
    assert _jaccard_similarity({"a", "b"}, {"a", "b"}) == 1.0
    assert _jaccard_similarity({"a"}, {"b"}) == 0.0
    assert _jaccard_similarity({"a", "b"}, {"b", "c"}) == 1 / 3


def test_binary_diff_identical(tmp_path: Path):
    target = tmp_path / "app.bin"
    target.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00" + b"TEST_PAYLOAD" * 10)

    report = diff_binaries(target, target)
    assert report["schema"] == SCHEMA
    assert report["status"] == "identical"
    assert report["overall_similarity"] == 1.0
    assert report["architecture_match"] is True
    assert report["patch_analysis"]["is_patch_candidate"] is False


def test_binary_diff_mutation(tmp_path: Path):
    target_a = tmp_path / "v1.exe"
    target_b = tmp_path / "v2_patched.exe"

    # Criar dois alvos PE válidos ou estruturados com diferenças observáveis
    # v1
    data_a = b"MZ\x90\x00\x03\x00\x00\x00http://legacy-api.com\x00KERNEL32.dll\x00CreateFileA\x00" + b"\x00" * 200
    target_a.write_bytes(data_a)

    # v2 (adiciona nova URL e nova API)
    data_b = b"MZ\x90\x00\x03\x00\x00\x00http://legacy-api.com\x00https://secure-v2.com\x00KERNEL32.dll\x00CreateFileW\x00VirtualProtect\x00" + b"\x00" * 300
    target_b.write_bytes(data_b)

    report = diff_binaries(target_a, target_b)
    assert report["schema"] == SCHEMA
    assert report["status"] == "diff_completed"
    assert 0.0 < report["overall_similarity"] < 1.0

    # Strings novas
    added_str = report["strings_diff"]["added_sample"]
    assert any("https://secure-v2.com" in s for s in added_str)

    # Hash diferente
    assert report["target_a_sha256"] != report["target_b_sha256"]


def test_binary_diff_missing_file_fail_closed(tmp_path: Path):
    missing_a = tmp_path / "ghost_a.bin"
    missing_b = tmp_path / "ghost_b.bin"

    report = diff_binaries(missing_a, missing_b)
    assert report["status"] == "failed"
    assert report["overall_similarity"] == 0.0
    assert any(err["code"] == "target_file_not_found" for err in report["errors"])
