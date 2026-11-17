from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aether_re.dwarf_types import analyze_elf_and_dwarf, scan_file_elf_dwarf


def _build_minimal_elf64_with_dwarf(*, nx: bool = True, full_relro: bool = True, pie: bool = True, canary: bool = True) -> bytes:
    """Build a valid ELF64 binary with program headers, dynamic/symtab, and DWARF sections."""
    # Section names string table (.shstrtab)
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.dynamic\x00.debug_str\x00.debug_abbrev\x00.debug_info\x00"
    def _sh_off(name: bytes) -> int:
        return shstrtab.index(b"\x00" + name + b"\x00") + 1

    # .dynstr
    dynstr = bytearray(b"\x00libc.so.6\x00")
    stack_chk_off = len(dynstr)
    if canary:
        dynstr.extend(b"__stack_chk_fail\x00")
    fortify_off = len(dynstr)
    if canary:
        dynstr.extend(b"__memcpy_chk\x00")

    # .dynsym (Elf64_Sym = 24 bytes each: st_name, st_info, st_other, st_shndx, st_value, st_size)
    dynsym = bytearray(24)  # null sym
    if canary:
        dynsym.extend(struct.pack("<IBBHQQ", stack_chk_off, 0x12, 0, 0, 0x1000, 16))
        dynsym.extend(struct.pack("<IBBHQQ", fortify_off, 0x12, 0, 0, 0x1020, 32))

    # .dynamic (Elf64_Dyn = 16 bytes: d_tag, d_val)
    dynamic = bytearray()
    dynamic.extend(struct.pack("<qQ", 1, 1))  # DT_NEEDED -> libc.so.6 at offset 1 in .dynstr
    if full_relro:
        dynamic.extend(struct.pack("<qQ", 24, 0))  # DT_BIND_NOW
        dynamic.extend(struct.pack("<qQ", 30, 0x8))  # DT_FLAGS = DF_BIND_NOW
    if pie:
        dynamic.extend(struct.pack("<qQ", 0x6FFFFFFB, 0x08000000))  # DT_FLAGS_1 = DF_1_PIE
    dynamic.extend(struct.pack("<qQ", 0, 0))  # DT_NULL

    # DWARF .debug_str
    debug_str = b"main.c\x00AetherRE GCC\x00PacketHeader\x00magic\x00flags\x00uint32_t\x00process_pkt\x00pkt\x00"
    def _dstr(s: bytes) -> int:
        return debug_str.index(s + b"\x00")

    # DWARF .debug_abbrev (ULEB128 encoded)
    # Abbrev 1: DW_TAG_compile_unit (0x11), has children (1):
    #   DW_AT_name (0x03) DW_FORM_strp (0x0e)
    #   DW_AT_producer (0x25) DW_FORM_strp (0x0e)
    # Abbrev 2: DW_TAG_base_type (0x24), no children (0):
    #   DW_AT_name (0x03) DW_FORM_strp (0x0e)
    #   DW_AT_byte_size (0x0b) DW_FORM_data1 (0x0b)
    # Abbrev 3: DW_TAG_structure_type (0x13), has children (1):
    #   DW_AT_name (0x03) DW_FORM_strp (0x0e)
    #   DW_AT_byte_size (0x0b) DW_FORM_data1 (0x0b)
    # Abbrev 4: DW_TAG_member (0x0d), no children (0):
    #   DW_AT_name (0x03) DW_FORM_strp (0x0e)
    #   DW_AT_type (0x49) DW_FORM_ref4 (0x13)
    #   DW_AT_data_member_location (0x38) DW_FORM_data1 (0x0b)
    # Abbrev 5: DW_TAG_subprogram (0x2e), has children (1):
    #   DW_AT_name (0x03) DW_FORM_strp (0x0e)
    #   DW_AT_low_pc (0x11) DW_FORM_addr (0x01)
    #   DW_AT_high_pc (0x12) DW_FORM_data4 (0x06)
    #   DW_AT_type (0x49) DW_FORM_ref4 (0x13)
    # Abbrev 6: DW_TAG_formal_parameter (0x05), no children (0):
    #   DW_AT_name (0x03) DW_FORM_strp (0x0e)
    #   DW_AT_type (0x49) DW_FORM_ref4 (0x13)
    debug_abbrev = bytes([
        1, 0x11, 1,  0x03, 0x0e,  0x25, 0x0e,  0, 0,
        2, 0x24, 0,  0x03, 0x0e,  0x0b, 0x0b,  0, 0,
        3, 0x13, 1,  0x03, 0x0e,  0x0b, 0x0b,  0, 0,
        4, 0x0d, 0,  0x03, 0x0e,  0x49, 0x13,  0x38, 0x0b,  0, 0,
        5, 0x2e, 1,  0x03, 0x0e,  0x11, 0x01,  0x12, 0x06,  0x49, 0x13,  0, 0,
        6, 0x05, 0,  0x03, 0x0e,  0x49, 0x13,  0, 0,
        0,
    ])

    # DWARF .debug_info (DWARF v4, addr_size=8)
    # CU header: unit_length (4B), version=4 (2B), abbrev_offset=0 (4B), addr_size=8 (1B) -> 11 bytes header
    cu_body = bytearray()
    # Abbrev 1: compile_unit (offset 11)
    cu_body.append(1)
    cu_body.extend(struct.pack("<II", _dstr(b"main.c"), _dstr(b"AetherRE GCC")))
    # Abbrev 2: base_type uint32_t (cu_relative offset = 11 + len(cu_body))
    u32_ref = 11 + len(cu_body)
    cu_body.append(2)
    cu_body.extend(struct.pack("<IB", _dstr(b"uint32_t"), 4))
    # Abbrev 3: structure_type PacketHeader, size=8
    struct_ref = 11 + len(cu_body)
    cu_body.append(3)
    cu_body.extend(struct.pack("<IB", _dstr(b"PacketHeader"), 8))
    # Abbrev 4: member magic @ 0
    cu_body.append(4)
    cu_body.extend(struct.pack("<IIB", _dstr(b"magic"), u32_ref, 0))
    # Abbrev 4: member flags @ 4
    cu_body.append(4)
    cu_body.extend(struct.pack("<IIB", _dstr(b"flags"), u32_ref, 4))
    cu_body.append(0)  # end children of struct
    # Abbrev 5: subprogram process_pkt
    cu_body.append(5)
    cu_body.extend(struct.pack("<IQII", _dstr(b"process_pkt"), 0x401000, 0x40, u32_ref))
    # Abbrev 6: formal_parameter pkt
    cu_body.append(6)
    cu_body.extend(struct.pack("<II", _dstr(b"pkt"), struct_ref))
    cu_body.append(0)  # end children of subprogram
    cu_body.append(0)  # end children of CU

    unit_len = 7 + len(cu_body)  # version(2)+abbrev_off(4)+addr_size(1)+body
    debug_info = struct.pack("<IHIB", unit_len, 4, 0, 8) + bytes(cu_body)

    # Assemble ELF64
    ehdr_size = 64
    ph_count = 3 if full_relro else 1  # PT_GNU_STACK (+ PT_GNU_RELRO + PT_INTERP)
    phdr_size = 56
    data_start = ehdr_size + ph_count * phdr_size

    sections_data = [
        (b"", 0, 0, 0, 0, 0),  # NULL
        (shstrtab, _sh_off(b".shstrtab"), 3, 0, 0, 0),  # SHT_STRTAB=3
        (bytes(dynstr), _sh_off(b".dynstr"), 3, 2, 0, 0),  # SHT_STRTAB, SHF_ALLOC=2
        (bytes(dynsym), _sh_off(b".dynsym"), 11, 2, 2, 24),  # SHT_DYNSYM=11, link=2 (.dynstr), entsize=24
        (bytes(dynamic), _sh_off(b".dynamic"), 6, 3, 2, 16),  # SHT_DYNAMIC=6, link=2 (.dynstr), entsize=16
        (debug_str, _sh_off(b".debug_str"), 1, 0x30, 0, 1),  # SHT_PROGBITS=1
        (debug_abbrev, _sh_off(b".debug_abbrev"), 1, 0, 0, 0),
        (debug_info, _sh_off(b".debug_info"), 1, 0, 0, 0),
    ]

    blob = bytearray(data_start)
    shdrs = bytearray()
    for idx, (sdata, sname, stype, sflags, slink, sentsize) in enumerate(sections_data):
        soff = len(blob) if idx > 0 else 0
        blob.extend(sdata)
        shdrs.extend(struct.pack(
            "<IIQQQQIIQQ",
            sname, stype, sflags, 0, soff, len(sdata), slink, 0, 1, sentsize
        ))

    shoff = len(blob)
    blob.extend(shdrs)

    # Program headers: PT_GNU_STACK (0x6474e551), PT_GNU_RELRO (0x6474e552), PT_INTERP (3)
    phdrs = bytearray()
    stack_flags = 6 if nx else 7  # RW vs RWX
    phdrs.extend(struct.pack("<IIQQQQQQ", 0x6474E551, stack_flags, 0, 0, 0, 0, 0, 16))
    if full_relro:
        phdrs.extend(struct.pack("<IIQQQQQQ", 0x6474E552, 4, 0, 0, 0, 0, 0, 1))
        phdrs.extend(struct.pack("<IIQQQQQQ", 3, 4, 0, 0, 0, 0, 0, 1))

    e_type = 3 if pie else 2  # ET_DYN=3, ET_EXEC=2
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        e_type, 0x3E, 1, 0x401000, ehdr_size, shoff, 0,
        ehdr_size, phdr_size, ph_count, 64, len(sections_data), 1
    )
    blob[0:ehdr_size] = ehdr
    blob[ehdr_size:ehdr_size + len(phdrs)] = phdrs
    return bytes(blob)


def test_elf64_dwarf_types_subprograms_and_hardened_mitigations(tmp_path: Path):
    elf_bytes = _build_minimal_elf64_with_dwarf(nx=True, full_relro=True, pie=True, canary=True)
    elf_path = tmp_path / "hardened.elf"
    elf_path.write_bytes(elf_bytes)

    res = scan_file_elf_dwarf(elf_path)
    assert res["status"] == "complete"
    assert res["elf_class"] == 64
    assert res["mitigations"]["relro"] == "full"
    assert res["mitigations"]["nx"] is True
    assert res["mitigations"]["pie"] == "enabled"
    assert res["mitigations"]["stack_canary"] is True
    assert res["mitigations"]["fortify_source"] is True
    assert "libc.so.6" in res["needed_libraries"]

    dwarf = res["dwarf"]
    assert dwarf["present"] is True
    assert dwarf["compilation_units"][0]["name"] == "main.c"
    assert dwarf["total_structs"] == 1
    st = dwarf["structs"][0]
    assert st["name"] == "PacketHeader"
    assert st["byte_size"] == 8
    assert st["members"] == [
        {"name": "magic", "type": "uint32_t", "offset": 0},
        {"name": "flags", "type": "uint32_t", "offset": 4},
    ]
    assert dwarf["total_subprograms"] == 1
    fn = dwarf["subprograms"][0]
    assert fn["name"] == "process_pkt"
    assert fn["low_pc"] == "0x401000"
    assert fn["high_pc"] == "0x401040"
    assert fn["return_type"] == "uint32_t"
    assert fn["parameters"] == [{"name": "pkt", "type": "struct PacketHeader"}]


def test_elf64_insecure_mitigations_detected():
    elf_bytes = _build_minimal_elf64_with_dwarf(nx=False, full_relro=False, pie=False, canary=False)
    res = analyze_elf_and_dwarf(elf_bytes)
    assert res["status"] == "complete"
    assert res["mitigations"]["relro"] == "none"
    assert res["mitigations"]["nx"] is False
    assert res["mitigations"]["pie"] == "disabled"
    assert res["mitigations"]["stack_canary"] is False
    assert res["mitigations"]["fortify_source"] is False


def test_invalid_elf_fails_closed():
    assert analyze_elf_and_dwarf(b"MZ_NOT_ELF")["status"] == "invalid"
    assert analyze_elf_and_dwarf(b"\x7fELF\x00\x00")["status"] == "invalid"
    assert analyze_elf_and_dwarf("not_bytes")["status"] == "invalid"  # type: ignore[arg-type]


def test_missing_elf_raises():
    with pytest.raises(FileNotFoundError):
        scan_file_elf_dwarf(r"D:\AetherRE_Megazord\missing_elf_999.elf")
