import os
from pathlib import Path
import struct

import pytest

from aether_re.engines.pe_elf import run_structure


def test_pe_truncation_is_fail_closed_without_guessing():
    result = run_structure(b"MZ")
    assert result["format"].startswith("PE(")
    assert result["sections"] == []
    assert result["imports"] == []
    assert result["segments"] == []
    assert result["relocations"] == []
    assert result["needed_libraries"] == []
    assert result["findings"][0].severity == "medium"


def test_real_pe_exposes_sections_segments_dependencies_and_relocations():
    pytest.importorskip("pefile")
    target = Path(__file__).parents[1] / "samples" / "fixtures" / "notepad_reference.exe"
    result = run_structure(target.read_bytes())

    assert result["format"] in {"PE32", "PE32+"}
    assert result["image_base_kind"] == "preferred_vaddr"
    assert result["is_64"] is True
    assert result["machine"] == 0x8664
    assert result["sections"]
    assert len(result["segments"]) == len(result["sections"])
    assert {section["permissions"] for section in result["sections"]}
    assert result["needed_libraries"]
    assert result["relocations"]
    assert all("type" in item and "rva" in item for item in result["relocations"])


def test_pe_overlapping_raw_sections_are_reported():
    pefile = pytest.importorskip("pefile")
    target = Path(__file__).parents[1] / "samples" / "fixtures" / "notepad_reference.exe"
    data = bytearray(target.read_bytes())
    parsed = pefile.PE(data=bytes(data), fast_load=False)
    first, second = parsed.sections[:2]
    # IMAGE_SECTION_HEADER.PointerToRawData is +20 bytes from the header.
    struct.pack_into("<I", data, second.get_file_offset() + 20, int(first.PointerToRawData) + 1)
    result = run_structure(bytes(data))
    assert any("Seções PE sobrepostas" in finding.title for finding in result["findings"])


def test_pe_exports_are_preserved_as_symbol_observations():
    pytest.importorskip("pefile")
    ghidra_home = os.environ.get("GHIDRA_HOME")
    target = (
        Path(ghidra_home)
        / "GPL"
        / "DMG"
        / "data"
        / "os"
        / "win_x86_32"
        / "llio_i386.dll"
        if ghidra_home
        else None
    )
    if target is None or not target.is_file():
        pytest.skip("fixture PE32 do Ghidra ausente; configure GHIDRA_HOME")
    result = run_structure(target.read_bytes())
    assert result["exports"]
    assert len(result["symbols"]) == len(result["exports"])
    assert all(symbol["source"] == "pe-export" for symbol in result["symbols"])
    assert all(symbol["address_space"] == "preferred_rva" for symbol in result["symbols"])
    assert all(symbol["value_kind"] == "rva" for symbol in result["symbols"])
    assert all(symbol["rva"] == symbol["value"] for symbol in result["symbols"])
