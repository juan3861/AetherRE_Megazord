import random
import struct
from pathlib import Path

from aether_re.engines.pe_elf import run_structure
from aether_re.pipeline import run_megazord


def _elf32_header(*, machine: int = 3, entry: int = 0x08048054) -> bytes:
    data = bytearray(52)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes((1, 1))  # ELF32, little-endian
    struct.pack_into("<HHIIIII", data, 16, 2, machine, 1, entry, 0, 0, 0)
    struct.pack_into("<HHH", data, 46, 40, 0, 0)
    return bytes(data)


def _elf32_with_load_segment() -> bytes:
    data = bytearray(0x140)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes((1, 1))
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 3, 1, 0x08048054, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    struct.pack_into("<IIIIIIII", data, 52, 1, 0, 0x08048000, 0x08048000, len(data), len(data), 5, 0x1000)
    return bytes(data)


def _elf64_header(*, machine: int = 0x3E, entry: int = 0x401000) -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes((2, 1))  # ELF64, little-endian
    struct.pack_into("<HHIQQQ", data, 16, 2, machine, 1, entry, 0, 0)
    struct.pack_into("<HHH", data, 58, 64, 0, 0)
    return bytes(data)


def _elf64_with_tables() -> bytes:
    """Small, synthetic ELF64 carrying one load segment and common tables."""
    data = bytearray(0x500)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes((2, 1))
    # type, machine, version, entry, phoff, shoff, flags, ehsize,
    # phentsize, phnum, shentsize, shnum, shstrndx
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0x401000, 64, 0x100, 0, 64, 56, 1, 64, 7, 1)
    # PT_LOAD, R|X, file offset 0, virtual address 0x400000.
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, len(data), len(data), 0x1000)

    shstr = b"\x00.shstrtab\x00.strtab\x00.symtab\x00.text\x00.rela.text\x00.dynamic\x00"
    strtab = b"\x00foo\x00bar\x00libc.so.6\x00"
    data[0x300:0x300 + len(shstr)] = shstr
    data[0x340:0x340 + len(strtab)] = strtab
    data[0x380:0x380 + 24 * 3] = b"\x00" * (24 * 3)
    # ELF64 symbols: null, defined global foo, undefined global bar.
    struct.pack_into("<IBBHQQ", data, 0x380 + 24, 1, 0x12, 0, 4, 0x401000, 4)
    struct.pack_into("<IBBHQQ", data, 0x380 + 48, 5, 0x12, 0, 0, 0, 0)
    data[0x3d0:0x3d4] = b"\x90\x90\xC3\x00"
    # RELA against .text, referencing undefined symbol bar.
    struct.pack_into("<QQq", data, 0x3e0, 0x401000, (2 << 32) | 7, -4)
    # DT_NEEDED libc.so.6 followed by DT_NULL.
    struct.pack_into("<QQ", data, 0x410, 1, 9)
    struct.pack_into("<QQ", data, 0x420, 0, 0)

    def sh(offset: int, name: int, kind: int, flags: int, addr: int, file_offset: int, size: int, link: int = 0, info: int = 0, align: int = 1, entsize: int = 0) -> None:
        struct.pack_into("<IIQQQQIIQQ", data, offset, name, kind, flags, addr, file_offset, size, link, info, align, entsize)

    sh(0x100, 0, 0, 0, 0, 0, 0)
    sh(0x140, 1, 3, 0, 0, 0x300, len(shstr), 0, 0, 1)
    sh(0x180, 11, 3, 0, 0, 0x340, len(strtab), 0, 0, 1)
    sh(0x1C0, 19, 2, 0, 0, 0x380, 24 * 3, 2, 1, 8, 24)
    sh(0x200, 27, 1, 6, 0x401000, 0x3D0, 4, 0, 0, 16)
    sh(0x240, 33, 4, 0, 0, 0x3E0, 24, 3, 4, 8, 24)
    sh(0x280, 44, 6, 0, 0, 0x410, 32, 2, 0, 8, 16)
    return bytes(data)


def _elf64_dynamic_only() -> bytes:
    """ELF64 with PT_DYNAMIC but no section headers (stripped-style case)."""
    data = bytearray(0x260)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes((2, 1))
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 0x3E, 1, 0x400000, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, len(data), len(data), 0x1000)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 6, 0x100, 0x400100, 0x400100, 64, 64, 8)
    data[0x180:0x18B] = b"\x00libc.so.6\x00"
    struct.pack_into("<QQ", data, 0x100, 5, 0x400180)  # DT_STRTAB
    struct.pack_into("<QQ", data, 0x110, 10, 11)       # DT_STRSZ
    struct.pack_into("<QQ", data, 0x120, 1, 1)         # DT_NEEDED
    struct.pack_into("<QQ", data, 0x130, 0, 0)         # DT_NULL
    return bytes(data)


def _elf64_extended_numbering() -> bytes:
    data = bytearray(0x1C0)
    data[:4] = b"\x7fELF"
    data[4:6] = bytes((2, 1))
    # e_shnum=0/e_shstrndx=SHN_XINDEX; section zero carries the real values.
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 1, 0x3E, 1, 0, 0, 0x100, 0, 64, 0, 0, 64, 0, 0xFFFF)
    shstr = b"\x00.shstrtab\x00"
    data[0x180:0x180 + len(shstr)] = shstr
    # Section 0: sh_size=2 (actual count), sh_link=1 (actual string index).
    struct.pack_into("<IIQQQQIIQQ", data, 0x100, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x140, 1, 3, 0, 0, 0x180, len(shstr), 0, 0, 1, 0)
    return bytes(data)


def test_elf32_header_identity_is_explicit():
    result = run_structure(_elf32_header())
    assert result["format"] == "ELF32"
    assert result["machine"] == 3
    assert result["entry_point"] == "0x8048054"
    assert result["is_64"] is False
    assert result["findings"][0].severity == "info"


def test_elf32_load_segment_identity_and_permissions_are_explicit():
    result = run_structure(_elf32_with_load_segment())
    assert result["format"] == "ELF32"
    assert result["machine_name"] == "i386"
    assert result["segments"][0]["permissions"] == "RX"
    assert result["image_base"] == "0x8048000"


def test_elf64_header_identity_is_explicit():
    result = run_structure(_elf64_header())
    assert result["format"] == "ELF64"
    assert result["machine"] == 0x3E
    assert result["entry_point"] == "0x401000"
    assert result["is_64"] is True
    assert "sections=0" in result["findings"][0].detail
    assert {section["name"] for section in result["sections"]} == {"phoff", "shoff"}


def test_elf64_truncation_is_fail_closed():
    result = run_structure(b"\x7fELF\x02\x01" + b"\x00" * 46)
    assert result["format"] == "ELF(truncated)"
    assert result["sections"] == []
    assert result["imports"] == []
    assert result["findings"][0].severity == "medium"


def test_elf_nonzero_section_count_at_zero_is_rejected():
    data = bytearray(_elf64_header())
    struct.pack_into("<HHHHHH", data, 52, 64, 56, 0, 64, 1, 0)
    result = run_structure(bytes(data))
    assert not any(item["name"].startswith("section_") for item in result["sections"])
    assert any("Tabela ELF de seções inválida" in finding.title for finding in result["findings"])


def test_elf_rwx_segment_is_reported_without_execution():
    data = bytearray(_elf64_with_tables())
    struct.pack_into("<I", data, 68, 7)  # PT_LOAD flags: R|W|X
    result = run_structure(bytes(data))
    assert any("gravável e executável" in finding.title for finding in result["findings"])


def test_elf_overlapping_file_sections_are_reported():
    data = bytearray(_elf64_with_tables())
    # .text (section index 4) starts at section-header table offset 0x200;
    # point its raw bytes into .strtab's range at 0x340.
    struct.pack_into("<Q", data, 0x200 + 24, 0x340)
    result = run_structure(bytes(data))
    assert any("Seções ELF sobrepostas" in finding.title for finding in result["findings"])


def test_elf_tables_expose_segments_symbols_relocations_and_needed_libraries():
    result = run_structure(_elf64_with_tables())
    assert result["image_base"] == "0x400000"
    assert result["segments"][0]["permissions"] == "RX"
    assert result["sections"][4]["name"] == ".text"
    assert "bar" in result["imports"]
    assert "foo" in result["exports"]
    assert result["needed_libraries"] == ["libc.so.6"]
    assert result["relocations"][0]["symbol"] == "bar"
    assert result["relocations"][0]["type"] == 7
    foo = next(symbol for symbol in result["symbols"] if symbol["name"] == "foo")
    assert foo["address_space"] == "preferred_vaddr"
    assert foo["value_kind"] == "virtual_address"
    assert foo["rva"] == "0x1000"


def test_elf_stripped_style_dynamic_segment_recovers_needed_library():
    result = run_structure(_elf64_dynamic_only())
    assert result["format"] == "ELF64"
    assert result["type_name"] == "DYN"
    assert result["needed_libraries"] == ["libc.so.6"]
    assert result["sections"][0]["name"] == "phoff"
    assert result["symbols"] == []


def test_elf_extended_section_numbering_is_resolved_from_section_zero():
    result = run_structure(_elf64_extended_numbering())
    assert result["extended_numbering"] is True
    assert len(result["sections"]) == 2
    assert result["sections"][1]["name"] == ".shstrtab"


def test_non_elf_remains_unknown():
    result = run_structure(b"not-an-executable")
    assert result["format"] == "raw/unknown"
    assert result["findings"][0].title == "Sem PE/ELF reconhecido"


def test_structure_reader_is_total_on_bounded_malformed_bytes():
    rng = random.Random(0x5EED)
    samples = [rng.randbytes(rng.randrange(0, 512)) for _ in range(128)]
    samples.extend([b"\x7fELF" + rng.randbytes(size) for size in (0, 1, 8, 31, 63, 127)])
    for sample in samples:
        result = run_structure(sample)
        assert isinstance(result, dict)
        assert isinstance(result.get("findings"), list)
        assert result.get("format")


def test_elf_identity_survives_static_pipeline_snapshot(tmp_path: Path):
    target = tmp_path / "sample.elf"
    target.write_bytes(_elf64_with_tables())
    report = run_megazord(target, tmp_path / "run", use_adapters=False, deep=False)
    assert report.target_identity["format"] == "ELF64"
    assert report.target_identity["architecture"] == "x86_64"
    assert report.target_identity["entry_point"] == "0x401000"
    assert report.target_identity["image_base_kind"] == "preferred_vaddr"
    assert report.dwarf["status"] in {"not_present", "unavailable"}
    assert report.target_sha256
    assert report.segments[0]["permissions"] == "RX"
    assert report.needed_libraries == ["libc.so.6"]
    assert report.relocations[0]["symbol"] == "bar"
    foo = next(symbol for symbol in report.symbols if symbol["name"] == "foo")
    assert foo["module"] == target.name
    assert foo["rva"] == "0x1000"
    assert foo["qualified_identity"] == f"{target.name}!preferred_vaddr:0x1000:foo"
