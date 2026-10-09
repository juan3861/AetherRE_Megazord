"""Bounded PE CodeView/RSDS metadata reader used for PDB binding."""

from __future__ import annotations

import struct
import uuid
from typing import Any

SCHEMA = "re-megazord-pe-codeview.v1"


def _invalid(code: str, detail: str = "") -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "invalid", "code": code, "detail": detail, "records": []}


def parse_pe_codeview(data: bytes) -> dict[str, Any]:
    """Read IMAGE_DEBUG_DIRECTORY CodeView RSDS records without loading PE."""
    if not isinstance(data, (bytes, bytearray)):
        return _invalid("bytes_required")
    blob = bytes(data)
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        return _invalid("dos_header_invalid")
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(blob) or blob[pe_offset:pe_offset + 4] != b"PE\0\0":
        return _invalid("pe_header_invalid")
    file_header = pe_offset + 4
    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", blob, file_header)
    optional = file_header + 20
    if optional + optional_size > len(blob) or optional_size < 2:
        return _invalid("optional_header_invalid")
    magic = struct.unpack_from("<H", blob, optional)[0]
    if magic == 0x10B:
        number_dir_off, data_dir_off = optional + 92, optional + 96
    elif magic == 0x20B:
        number_dir_off, data_dir_off = optional + 108, optional + 112
    else:
        return _invalid("optional_magic_invalid", hex(magic))
    if number_dir_off + 4 > optional + optional_size:
        return _invalid("directory_count_unavailable")
    number_dirs = struct.unpack_from("<I", blob, number_dir_off)[0]
    if number_dirs <= 6 or data_dir_off + 8 * 7 > optional + optional_size:
        return {"schema": SCHEMA, "status": "complete", "machine": machine, "debug_directory": {"rva": 0, "size": 0}, "records": []}
    debug_rva, debug_size = struct.unpack_from("<II", blob, data_dir_off + 8 * 6)
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(blob):
        return _invalid("section_table_invalid")
    sections = []
    for index in range(min(section_count, 96)):
        off = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, off + 8)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_ptr, raw_size))

    def rva_to_raw(rva: int) -> int | None:
        if rva == 0:
            return None
        for va, span, raw_ptr, raw_size in sections:
            if va <= rva < va + span and raw_ptr <= len(blob):
                delta = rva - va
                if delta < raw_size and raw_ptr + delta <= len(blob):
                    return raw_ptr + delta
        return rva if rva < len(blob) else None

    directory_raw = rva_to_raw(debug_rva)
    records: list[dict[str, Any]] = []
    if directory_raw is None or debug_size == 0:
        return {"schema": SCHEMA, "status": "complete", "machine": machine, "debug_directory": {"rva": debug_rva, "size": debug_size}, "records": records}
    count = min(debug_size // 28, 4096)
    for index in range(count):
        off = directory_raw + index * 28
        if off + 28 > len(blob):
            break
        _, timestamp, major, minor, kind, size_data, address_data, pointer_data = struct.unpack_from("<IIHHIIII", blob, off)
        if kind != 2 or size_data < 24:
            continue
        data_off = pointer_data if pointer_data and pointer_data + size_data <= len(blob) else rva_to_raw(address_data)
        if data_off is None or data_off + 24 > len(blob) or blob[data_off:data_off + 4] != b"RSDS":
            continue
        guid_bytes = blob[data_off + 4:data_off + 20]
        age = struct.unpack_from("<I", blob, data_off + 20)[0]
        raw_name = blob[data_off + 24:data_off + size_data]
        name_bytes = raw_name.split(b"\0", 1)[0]
        try:
            pdb_name = name_bytes.decode("utf-8")
        except UnicodeDecodeError:
            pdb_name = name_bytes.decode("mbcs", errors="replace")
        try:
            guid = "{" + str(uuid.UUID(bytes_le=guid_bytes)).upper() + "}"
        except ValueError:
            guid = ""
        records.append({"index": index, "kind": "RSDS", "guid": guid, "age": age, "pdb_name": pdb_name, "timestamp": timestamp, "major": major, "minor": minor, "record_offset": data_off, "record_size": size_data})
    return {"schema": SCHEMA, "status": "complete", "machine": machine, "debug_directory": {"rva": debug_rva, "size": debug_size, "entries": count}, "records": records}
