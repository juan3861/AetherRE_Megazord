"""Bounded Go pclntab recovery; metadata is not original source.

Layout reference: Go debug/gosym/pclntab.go. Since Go 1.16 the
functab's _func offsets are relative to funcdata, not to pcHeader.
"""
from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

GO_PCLNTAB_MAGICS = {
    0xFFFFFFFB: "Go 1.2 - 1.15",
    0xFFFFFFF0: "Go 1.16 - 1.17",
    0xFFFFFFFA: "Go 1.18 - 1.19",
    0xFFFFFFF1: "Go 1.20+ (layout, not compiler version)",
}


@dataclass
class GolangFunction:
    name: str
    entry_pc: int
    package: str
    hex_pc: str


@dataclass
class GolangRecoveryReport:
    is_go_binary: bool = False
    go_version: str | None = None
    magic: str | None = None
    ptr_size: int = 0
    pclntab_offset: int | None = None
    total_functions: int = 0
    packages: list[str] | None = None
    functions: list[dict[str, Any]] | None = None
    elapsed_seconds: float = 0.0
    error_message: str | None = None
    declared_functions: int = 0
    truncated: bool = False
    status: str = "not_detected"
    byte_order: str | None = None
    text_base: int | None = None
    text_base_source: str | None = None
    pc_address_kind: str = "unknown"


class GolangRecoverEngine:
    def __init__(self, data: bytes, base_addr: int | None = None):
        self.data = data
        if base_addr is not None and (type(base_addr) is not int or not 0 <= base_addr < 2**64):
            raise ValueError("invalid_text_base")
        # Go 1.18+ pcHeader.textStart may be unrelocated in an image file.
        # The containing image's preferred .text address takes precedence.
        self.base_addr = base_addr

    def _find_pclntab_magic(self) -> list[tuple[int, int]]:
        matches = []
        for magic in GO_PCLNTAB_MAGICS:
            for endian in ("<", ">"):
                start = 0
                while len(matches) < 128:
                    idx = self.data.find(struct.pack(endian + "I", magic), start)
                    if idx < 0:
                        break
                    if (idx + 8 <= len(self.data) and self.data[idx + 4:idx + 6] == b"\0\0"
                            and self.data[idx + 6] in (1, 2, 4) and self.data[idx + 7] in (4, 8)):
                        matches.append((idx, magic))
                    start = idx + 4
        return sorted(set(matches))

    def _parse(self, offset: int, magic: int, maximum: int, deadline: float) -> GolangRecoveryReport:
        data = self.data
        endian = "<" if struct.unpack_from("<I", data, offset)[0] == magic else ">"
        ptr_size = data[offset + 7]
        ptr = "Q" if ptr_size == 8 else "I"
        modern = magic in (0xFFFFFFFA, 0xFFFFFFF1)
        fields_count = 8 if modern else (7 if magic == 0xFFFFFFF0 else 1)
        fields = struct.unpack_from(endian + ptr * fields_count, data, offset + 8)
        declared = fields[0]
        if not 0 < declared <= 1000000:
            raise ValueError("invalid_function_count")
        if magic == 0xFFFFFFFB:
            functab, funcdata, names, text = offset + 8 + ptr_size, offset, offset, 0
        else:
            names = offset + fields[3 if modern else 2]
            functab = offset + fields[7 if modern else 6]
            funcdata = functab
            text = (self.base_addr if self.base_addr is not None else fields[2]) if modern else 0
        word_size = 4 if modern else ptr_size
        if (names < offset or names >= len(data) or functab < offset
                or functab + (declared * 2 + 1) * word_size > len(data)):
            raise ValueError("table_out_of_bounds")
        word = "I" if modern else ptr
        functions = []
        invalid = 0
        previous_pc = -1
        for index in range(min(declared, maximum)):
            if index % 256 == 0 and time.monotonic() >= deadline:
                break
            entry, function_offset = struct.unpack_from(endian + word * 2, data, functab + index * 2 * word_size)
            pc = text + entry
            record = funcdata + function_offset
            name_field = record + (4 if modern else ptr_size)
            if record < funcdata or name_field + 4 > len(data) or pc <= previous_pc or pc >= 2**64:
                invalid += 1
                continue
            recorded_entry = struct.unpack_from(endian + word, data, record)[0]
            name_offset = struct.unpack_from(endian + "i", data, name_field)[0]
            name_index = names + name_offset
            if recorded_entry != entry or name_offset < 0 or not names <= name_index < len(data):
                invalid += 1
                continue
            end = data.find(b"\0", name_index, min(name_index + 4097, len(data)))
            if end <= name_index:
                invalid += 1
                continue
            try:
                name = data[name_index:end].decode("utf-8", errors="strict")
            except UnicodeError:
                invalid += 1
                continue
            if not name.strip() or not name.isprintable():
                invalid += 1
                continue
            dot = name.find(".", name.rfind("/") + 1)
            package = name[:dot] if dot >= 0 else "unknown"
            functions.append(asdict(GolangFunction(name, pc, package, hex(pc))))
            previous_pc = pc
        truncated = declared > len(functions) + invalid
        sentinel = struct.unpack_from(endian + word, data, functab + declared * 2 * word_size)[0] + text
        if functions and sentinel <= functions[-1]["entry_pc"]:
            invalid += 1
        unresolved = modern and self.base_addr is None and text == 0
        error = "invalid_function_records" if invalid else ("recovery_budget_exhausted" if truncated else "text_base_unresolved" if unresolved else None)
        return GolangRecoveryReport(
            is_go_binary=bool(functions), go_version=GO_PCLNTAB_MAGICS[magic], magic=hex(magic),
            ptr_size=ptr_size, pclntab_offset=offset, total_functions=len(functions),
            packages=sorted({f["package"] for f in functions}), functions=functions,
            error_message=error, declared_functions=declared, truncated=truncated,
            status="partial" if error else "complete", byte_order="little" if endian == "<" else "big",
            text_base=text if modern else None,
            text_base_source=("explicit_text_base" if self.base_addr is not None else "pclntab_header") if modern else "pclntab_absolute_pc",
            pc_address_kind="text_relative_unresolved" if unresolved else "declared_virtual_address" if modern else "pclntab_absolute_address",
        )

    def recover(self, max_functions: int = 50000, *, timeout_s: float = 5.0) -> GolangRecoveryReport:
        if type(max_functions) is not int or not 1 <= max_functions <= 1000000:
            raise ValueError("invalid_function_budget")
        if type(timeout_s) not in (int, float) or not 0 < timeout_s <= 60:
            raise ValueError("invalid_time_budget")
        start = time.monotonic()
        best = GolangRecoveryReport(packages=[], functions=[])
        candidates = self._find_pclntab_magic()
        for offset, magic in candidates:
            if time.monotonic() >= start + timeout_s:
                best.truncated = True
                best.status = "partial"
                best.error_message = "recovery_budget_exhausted"
                break
            try:
                report = self._parse(offset, magic, max_functions, start + timeout_s)
            except (ValueError, struct.error):
                continue
            if report.total_functions > best.total_functions:
                best = report
        if candidates and not best.total_functions and best.status != "partial":
            best.status = "invalid"
            best.error_message = "no_valid_runtime_table"
        best.elapsed_seconds = round(time.monotonic() - start, 4)
        return best


def recover_golang_symbols_from_file(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Binary file not found: {path}")
    with path.open("rb") as handle:
        data = handle.read(512 * 1024 * 1024 + 1)
    if len(data) > 512 * 1024 * 1024:
        raise ValueError("input_budget_exceeded")
    text_base = None
    image_error = None
    if data.startswith(b"MZ"):
        try:
            import pefile
            image = pefile.PE(data=data,fast_load=True)
            sections = [section for section in image.sections if section.Name.rstrip(b"\0")==b".text"]
            if len(sections)!=1:
                raise ValueError("unique_pe_text_section_required")
            section=sections[0]
            address_space=2**(64 if image.OPTIONAL_HEADER.Magic==0x20b else 32)
            image_base=int(image.OPTIONAL_HEADER.ImageBase)
            image_size=int(image.OPTIONAL_HEADER.SizeOfImage)
            text_rva=int(section.VirtualAddress)
            text_size=max(int(section.Misc_VirtualSize),int(section.SizeOfRawData))
            if (not section.Characteristics & 0x20000000 or section.SizeOfRawData<=0
                    or section.PointerToRawData+section.SizeOfRawData>len(data)
                    or not 0<=text_rva<text_rva+text_size<=image_size
                    or image_base+image_size>address_space):
                raise ValueError("invalid_pe_text_section")
            text_base=image_base+text_rva
            image.close()
        except Exception as exc:
            image_error=type(exc).__name__+":"+str(exc)[:160]
    result = asdict(GolangRecoverEngine(data,base_addr=text_base).recover())
    if result["magic"] in {"0xfffffffa","0xfffffff1"}:
        if text_base is not None:
            result.update(pc_address_kind="preferred_virtual_address",text_base_source="pe_text_section")
        elif image_error and result["is_go_binary"]:
            result.update(status="partial",error_message=result["error_message"] or "image_text_base_unresolved",
                          pc_address_kind="unverified_image_address",address_resolution_error=image_error)
    result.update(target=str(path), file_size_bytes=len(data), target_sha256=hashlib.sha256(data).hexdigest())
    return result
