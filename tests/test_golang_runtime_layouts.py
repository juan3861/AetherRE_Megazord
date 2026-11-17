"""Hand-checked pclntab records; offsets follow Go debug/gosym, not the parser."""
import struct

import pytest

from aether_re.golang_recover import GolangRecoverEngine, recover_golang_symbols_from_file


def runtime_table(magic=0xFFFFFFF1, ptr_size=8, endian="<"):
    ptr = "Q" if ptr_size == 8 else "I"
    modern = magic in (0xFFFFFFFA, 0xFFFFFFF1)
    header_fields = 8 if modern else 7
    names = b"runtime.main\x00main.main\x00"
    names_offset = 8 + ptr_size * header_fields
    table_offset = names_offset + len(names)
    text = 0x401000
    fields = [2, 0, text, names_offset, 0, 0, 0, table_offset] if modern else [2, 0, names_offset, 0, 0, 0, table_offset]
    header = struct.pack(endian + "IBBBB", magic, 0, 0, 1, ptr_size)
    header += struct.pack(endian + ptr * header_fields, *fields)
    if modern:
        # 2 records of 8 bytes and final PC word: _func bases 20 and 28.
        table = struct.pack(endian + "IIIII", 0, 20, 0x20, 28, 0x40)
        metadata = struct.pack(endian + "IiIi", 0, 0, 0x20, 13)
    else:
        size = 5 * ptr_size
        table = struct.pack(endian + ptr * 5, text, size, text + 0x20, size + ptr_size + 4, text + 0x40)
        metadata = struct.pack(endian + ptr + "i", text, 0) + struct.pack(endian + ptr + "i", text + 0x20, 13)
    return header + names + table + metadata


@pytest.mark.parametrize("magic", [0xFFFFFFF0, 0xFFFFFFFA, 0xFFFFFFF1])
@pytest.mark.parametrize("ptr_size", [4, 8])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_runtime_relative_offsets_recover_exact_names_and_pcs(magic, ptr_size, endian):
    result = GolangRecoverEngine(b"prefix" + runtime_table(magic, ptr_size, endian)).recover()
    assert result.is_go_binary is True
    assert [(f["name"], f["entry_pc"]) for f in result.functions] == [
        ("runtime.main", 0x401000), ("main.main", 0x401020),
    ]


def test_function_budget_is_explicit_partial_result():
    result = GolangRecoverEngine(runtime_table()).recover(max_functions=1)
    assert result.total_functions == 1
    assert result.declared_functions == 2
    assert result.truncated is True
    assert result.status == "partial"


def test_truncated_function_table_does_not_return_success():
    result = GolangRecoverEngine(runtime_table()[:-14]).recover()
    assert result.status != "complete"
    assert result.error_message


def test_false_magic_does_not_hide_later_valid_table():
    fake = struct.pack("<IBBBB", 0xFFFFFFF1, 0, 0, 1, 8) + b"\xff" * 80
    result = GolangRecoverEngine(fake + runtime_table()).recover()
    assert [f["name"] for f in result.functions] == ["runtime.main", "main.main"]


def test_corrupt_name_offset_does_not_publish_empty_name():
    blob = bytearray(runtime_table())
    struct.pack_into("<i", blob, len(blob) - 4, -1)
    result = GolangRecoverEngine(bytes(blob)).recover()
    assert result.status != "complete"
    assert all(f["name"] for f in result.functions)


@pytest.mark.parametrize("ptr_size", [4, 8])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_go12_offsets_remain_relative_to_header(ptr_size, endian):
    ptr = "I" if ptr_size == 4 else "Q"
    header = struct.pack(endian + "IBBBB" + ptr, 0xFFFFFFFB, 0, 0, 1, ptr_size, 2)
    record_start = len(header) + 5 * ptr_size
    record_size = ptr_size + 4
    names_start = record_start + 2 * record_size
    table = struct.pack(endian + ptr * 5, 0x401000, record_start,
                        0x401020, record_start + record_size, 0x401040)
    records = struct.pack(endian + ptr + "i", 0x401000, names_start)
    records += struct.pack(endian + ptr + "i", 0x401020, names_start + 13)
    blob = header + table + records + b"runtime.main\0main.main\0"
    result = GolangRecoverEngine(b"prefix" + blob).recover()
    assert result.status == "complete"
    assert [(f["name"], f["entry_pc"]) for f in result.functions] == [
        ("runtime.main", 0x401000), ("main.main", 0x401020),
    ]


def test_explicit_text_base_overrides_unrelocated_runtime_header():
    blob = bytearray(runtime_table())
    struct.pack_into("<Q",blob,24,0)
    report = GolangRecoverEngine(bytes(blob),base_addr=0x140001000).recover()
    assert report.status == "complete"
    assert [f["entry_pc"] for f in report.functions] == [0x140001000,0x140001020]


def test_zero_text_base_without_image_context_is_explicitly_unresolved():
    blob = bytearray(runtime_table())
    struct.pack_into("<Q",blob,24,0)
    report = GolangRecoverEngine(bytes(blob)).recover()
    assert report.status == "partial"
    assert report.pc_address_kind == "text_relative_unresolved"
    assert report.total_functions == 2


def go_pe_image(declared_text_base=0,image_base=0x140000000,text_rva=0x1000):
    blob = bytearray(runtime_table())
    struct.pack_into("<Q",blob,24,declared_text_base)
    image = bytearray(1024)
    image[:2]=b"MZ"
    struct.pack_into("<I",image,0x3c,0x80)
    image[0x80:0x84]=b"PE\0\0"
    struct.pack_into("<HHIIIHH",image,0x84,0x8664,1,0,0,0,240,0x22)
    optional=0x98
    struct.pack_into("<H",image,optional,0x20b)
    struct.pack_into("<Q",image,optional+24,image_base)
    struct.pack_into("<II",image,optional+32,0x1000,0x200)
    struct.pack_into("<II",image,optional+56,0x2000,0x200)
    struct.pack_into("<I",image,optional+108,16)
    section=optional+240
    image[section:section+8]=b".text\0\0\0"
    struct.pack_into("<IIII",image,section+8,0x200,text_rva,0x200,0x200)
    struct.pack_into("<I",image,section+36,0x60000020)
    image[0x200:0x200+len(blob)]=blob
    return bytes(image)


@pytest.mark.parametrize("declared_text_base",[0,0x401000])
def test_pe_wrapper_resolves_preferred_text_address_from_image(tmp_path,declared_text_base):
    target=tmp_path / "owned_go_pe.exe"
    target.write_bytes(go_pe_image(declared_text_base))
    report=recover_golang_symbols_from_file(target)
    assert report["status"] == "complete"
    assert report["pc_address_kind"] == "preferred_virtual_address"
    assert report["text_base_source"] == "pe_text_section"
    assert [f["entry_pc"] for f in report["functions"]] == [0x140001000,0x140001020]


def test_malformed_pe_with_runtime_table_cannot_claim_resolved_image_addresses(tmp_path):
    target=tmp_path / "malformed_pe.exe"
    target.write_bytes(b"MZ"+runtime_table())
    report=recover_golang_symbols_from_file(target)
    assert report["status"] == "partial"
    assert report["pc_address_kind"] == "unverified_image_address"
    assert report["address_resolution_error"]


@pytest.mark.parametrize("image_base,text_rva",[(0xfffffffffffff000,0x1000),(0x140000000,0x3000)])
def test_invalid_pe_virtual_mapping_becomes_partial_not_exception(tmp_path,image_base,text_rva):
    target=tmp_path / "invalid_mapping.exe"
    target.write_bytes(go_pe_image(image_base=image_base,text_rva=text_rva))
    report=recover_golang_symbols_from_file(target)
    assert report["status"] == "partial"
    assert report["pc_address_kind"] == "unverified_image_address"
    assert report["address_resolution_error"]
