from __future__ import annotations

from pathlib import Path
import pytest

from aether_re.forensic_rules import (
    COMMON_NOISE_STRINGS,
    SCHEMA,
    _filter_discriminative_strings,
    _sanitize_rule_name,
    generate_yara_rule,
)


def test_sanitize_rule_name():
    assert _sanitize_rule_name("valid_name_123") == "valid_name_123"
    assert _sanitize_rule_name("malware-variant.v1!") == "malware_variant_v1_"
    assert _sanitize_rule_name("123bad_start") == "AetherRE_123bad_start"


def test_filter_noise_strings():
    raw = [
        "KERNEL32.dll",
        "https://evil-c2-server.com/beacon",
        "This program cannot be run in DOS mode",
        "HKEY_LOCAL_MACHINE\\Software\\Malware",
        ".rdata",
        "short",  # < 6 chars
    ]
    filtered = _filter_discriminative_strings(raw)
    assert any("evil-c2-server.com" in s for s in filtered)
    assert any("HKEY_LOCAL_MACHINE" in s for s in filtered)
    assert not any("kernel32" in s.lower() for s in filtered)
    assert not any("dos mode" in s.lower() for s in filtered)


def test_generate_yara_and_sigma_rules(tmp_path: Path):
    sample = tmp_path / "sample_trojan.exe"
    # Monta binário mínimo com strings distintas e bytes de PE
    payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00" + b"\x00" * 32
    payload += b"https://command-and-control.org/checkin\x00"
    payload += b"IsDebuggerPresent\x00CreateRemoteThread\x00"
    payload += b"UniqueCustomBotnetMutex_12345\x00"
    payload += b"\x90" * 128
    sample.write_bytes(payload)

    report = generate_yara_rule(sample, rule_name="Trojan_MegaSample")
    assert report["schema"] == SCHEMA
    assert report["status"] == "generated"
    assert report["rule_name"] == "Trojan_MegaSample"

    yara_text = report["yara_rule"]
    assert "rule Trojan_MegaSample" in yara_text
    assert "meta:" in yara_text
    assert "strings:" in yara_text
    assert "condition:" in yara_text
    assert "uint16(0) == 0x5A4D" in yara_text
    assert "UniqueCustomBotnetMutex_12345" in yara_text

    sigma_text = report["sigma_rule"]
    assert "title: Detecção de Execução do Artefato" in sigma_text
    assert "logsource:" in sigma_text
    assert "category: process_creation" in sigma_text
    assert report["target_sha256"] in sigma_text


def test_generate_yara_missing_file_raises(tmp_path: Path):
    missing = tmp_path / "ghost.bin"
    with pytest.raises(FileNotFoundError):
        generate_yara_rule(missing)
