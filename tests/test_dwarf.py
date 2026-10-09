import struct
from pathlib import Path

from aether_re.engines.dwarf import analyze_dwarf


def _minimal_elf64() -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes((2, 1))
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0x401000, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    return bytes(data)


def test_dwarf_reader_rejects_non_elf_without_execution(tmp_path: Path):
    target = tmp_path / "raw.bin"
    target.write_bytes(b"not-elf")
    report = analyze_dwarf(target)
    assert report["status"] == "not_applicable"
    assert report["available"] is False
    assert report["executed"] is False
    assert report["target_sha256"]


def test_dwarf_reader_reports_absence_as_terminal_state(tmp_path: Path):
    target = tmp_path / "minimal.elf"
    target.write_bytes(_minimal_elf64())
    report = analyze_dwarf(target)
    assert report["status"] == "not_present"
    assert report["available"] is True
    assert report["produced_evidence"] is False
    assert report["functions"] == []
    assert any("ausente" in item["title"] for item in report["findings"])
