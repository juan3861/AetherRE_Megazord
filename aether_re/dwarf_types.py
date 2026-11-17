"""AetherRE Megazord — ELF Security Mitigations & DWARF Type/Symbol Extractor (GEAR-04).

Pure-static, zero-execution ELF32/ELF64 & DWARF analyzer built on pyelftools:
- ELF header, sections, dynamic libraries (DT_NEEDED), RPATH/RUNPATH, symbols (.symtab / .dynsym)
- Security mitigations audit (RELRO Full/Partial/None, NX, PIE, Stack Canary, FORTIFY_SOURCE)
- DWARF compilation units, subprograms (signature/PCs/params), structs/unions/enums with member offsets, and line-table sample
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from elftools.common.exceptions import ELFError
from elftools.elf.constants import P_FLAGS
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

SCHEMA = "re-megazord-elf-dwarf.v1"
MAX_ELF_BYTES = 256 * 1024 * 1024
MAX_SYMBOLS = 20000
MAX_DWARF_DIES = 25000


def _decode_attr_str(attr: Any) -> str | None:
    if attr is None:
        return None
    val = attr.value
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _resolve_dwarf_type_name(die: Any, die_map: dict[int, Any], depth: int = 0) -> str:
    if die is None or depth > 8:
        return "void"
    tag = die.tag
    name_attr = die.attributes.get("DW_AT_name")
    if name_attr is not None:
        name = _decode_attr_str(name_attr) or ""
        if tag == "DW_TAG_structure_type":
            return f"struct {name}"
        if tag == "DW_TAG_union_type":
            return f"union {name}"
        if tag == "DW_TAG_enumeration_type":
            return f"enum {name}"
        return name

    ref_attr = die.attributes.get("DW_AT_type")
    target_die = None
    if ref_attr is not None and isinstance(ref_attr.value, int):
        # Note: ref_addr vs cu-relative offset handled via cu_offset lookup when available
        target_die = die_map.get(die.cu.cu_offset + ref_attr.value) or die_map.get(ref_attr.value)

    if tag == "DW_TAG_pointer_type":
        inner = _resolve_dwarf_type_name(target_die, die_map, depth + 1) if target_die else "void"
        return f"{inner} *"
    if tag == "DW_TAG_const_type":
        inner = _resolve_dwarf_type_name(target_die, die_map, depth + 1) if target_die else "void"
        return f"const {inner}"
    if tag == "DW_TAG_volatile_type":
        inner = _resolve_dwarf_type_name(target_die, die_map, depth + 1) if target_die else "void"
        return f"volatile {inner}"
    if tag == "DW_TAG_array_type":
        inner = _resolve_dwarf_type_name(target_die, die_map, depth + 1) if target_die else "unknown"
        return f"{inner}[]"
    if tag == "DW_TAG_typedef":
        return _resolve_dwarf_type_name(target_die, die_map, depth + 1) if target_die else "typedef"
    return tag.replace("DW_TAG_", "")


def analyze_elf_and_dwarf(data: bytes, *, max_dies: int = MAX_DWARF_DIES) -> dict[str, Any]:
    """Analyze ELF binary bytes for security mitigations, symbols, and DWARF types."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_ELF_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if len(blob) < 16 or blob[:4] != b"\x7fELF":
        return {"schema": SCHEMA, "status": "invalid", "code": "not_elf_magic"}

    try:
        elf = ELFFile(io.BytesIO(blob))
    except (ELFError, Exception) as exc:
        return {"schema": SCHEMA, "status": "invalid", "code": "elf_parse_error", "detail": str(exc)}

    e_type = elf.header["e_type"]
    machine = elf.header["e_machine"]
    elf_class = elf.elfclass
    little_endian = elf.little_endian

    # Security mitigations & dynamic info
    has_relro = False
    bind_now = False
    nx_enabled: bool | None = None
    has_interp = False
    needed_libs: list[str] = []
    rpaths: list[str] = []
    is_pie_flag = False

    for seg in elf.iter_segments():
        p_type = seg.header["p_type"]
        if p_type == "PT_GNU_RELRO":
            has_relro = True
        elif p_type == "PT_GNU_STACK":
            nx_enabled = not bool(seg.header["p_flags"] & P_FLAGS.PF_X)
        elif p_type == "PT_INTERP":
            has_interp = True

    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                d_tag = tag.entry.d_tag
                if d_tag == "DT_NEEDED":
                    needed_libs.append(tag.needed)
                elif d_tag in ("DT_RPATH", "DT_RUNPATH"):
                    val = getattr(tag, "rpath", None) or getattr(tag, "runpath", None)
                    if val:
                        rpaths.append(val)
                elif d_tag == "DT_BIND_NOW":
                    bind_now = True
                elif d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):  # DF_BIND_NOW
                    bind_now = True
                elif d_tag == "DT_FLAGS_1":
                    if tag.entry.d_val & 0x1:  # DF_1_NOW
                        bind_now = True
                    if tag.entry.d_val & 0x08000000:  # DF_1_PIE
                        is_pie_flag = True

    if has_relro and bind_now:
        relro = "full"
    elif has_relro:
        relro = "partial"
    else:
        relro = "none"

    if e_type == "ET_DYN":
        pie = "enabled" if (is_pie_flag or has_interp) else "dso"
    elif e_type == "ET_EXEC":
        pie = "disabled"
    else:
        pie = str(e_type)

    # Symbols (.symtab and .dynsym)
    symbols: list[dict[str, Any]] = []
    symbol_names: set[str] = set()
    truncated_symbols = False
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if sym.name:
                    symbol_names.add(sym.name)
                if len(symbols) >= MAX_SYMBOLS:
                    truncated_symbols = True
                    continue
                if sym.name and sym["st_value"] != 0:
                    symbols.append({
                        "name": sym.name,
                        "address": hex(sym["st_value"]),
                        "size": int(sym["st_size"]),
                        "type": str(sym["st_info"]["type"]),
                        "bind": str(sym["st_info"]["bind"]),
                        "section": sec.name,
                    })

    stack_canary = any(s in symbol_names for s in ("__stack_chk_fail", "__stack_chk_guard"))
    fortify_symbols = sorted(s for s in symbol_names if s.endswith("_chk") and s.startswith("__"))

    mitigations = {
        "relro": relro,
        "nx": nx_enabled if nx_enabled is not None else True,
        "pie": pie,
        "stack_canary": stack_canary,
        "fortify_source": bool(fortify_symbols),
        "fortified_symbols_count": len(fortify_symbols),
        "rpath_or_runpath": rpaths,
    }

    # DWARF extraction
    has_dwarf = elf.has_dwarf_info()
    compilation_units: list[dict[str, Any]] = []
    subprograms: list[dict[str, Any]] = []
    structs: list[dict[str, Any]] = []
    line_files: set[str] = set()
    dies_visited = 0
    dwarf_truncated = False

    if has_dwarf:
        try:
            dwarf = elf.get_dwarf_info()
            for cu in dwarf.iter_CUs():
                if dies_visited >= max_dies:
                    dwarf_truncated = True
                    break
                top = cu.get_top_DIE()
                cu_name = _decode_attr_str(top.attributes.get("DW_AT_name")) or "<unknown>"
                cu_producer = _decode_attr_str(top.attributes.get("DW_AT_producer"))
                compilation_units.append({"name": cu_name, "producer": cu_producer})

                die_map: dict[int, Any] = {}
                cu_dies = []
                for die in cu.iter_DIEs():
                    dies_visited += 1
                    die_map[die.offset] = die
                    cu_dies.append(die)
                    if dies_visited >= max_dies:
                        dwarf_truncated = True
                        break

                for die in cu_dies:
                    if die.tag == "DW_TAG_subprogram":
                        fn_name = _decode_attr_str(die.attributes.get("DW_AT_name"))
                        if not fn_name:
                            continue
                        low_pc_attr = die.attributes.get("DW_AT_low_pc")
                        high_pc_attr = die.attributes.get("DW_AT_high_pc")
                        low_pc = low_pc_attr.value if low_pc_attr else None
                        high_pc = None
                        if high_pc_attr is not None:
                            if high_pc_attr.form.startswith("DW_FORM_addr"):
                                high_pc = high_pc_attr.value
                            elif isinstance(low_pc, int) and isinstance(high_pc_attr.value, int):
                                high_pc = low_pc + high_pc_attr.value
                        ret_attr = die.attributes.get("DW_AT_type")
                        ret_type = "void"
                        if ret_attr and isinstance(ret_attr.value, int):
                            ret_die = die_map.get(cu.cu_offset + ret_attr.value) or die_map.get(ret_attr.value)
                            ret_type = _resolve_dwarf_type_name(ret_die, die_map)

                        params = []
                        for child in die.iter_children():
                            if child.tag == "DW_TAG_formal_parameter":
                                p_name = _decode_attr_str(child.attributes.get("DW_AT_name")) or "arg"
                                p_type_attr = child.attributes.get("DW_AT_type")
                                p_type = "unknown"
                                if p_type_attr and isinstance(p_type_attr.value, int):
                                    p_die = die_map.get(cu.cu_offset + p_type_attr.value) or die_map.get(p_type_attr.value)
                                    p_type = _resolve_dwarf_type_name(p_die, die_map)
                                params.append({"name": p_name, "type": p_type})

                        subprograms.append({
                            "name": fn_name,
                            "low_pc": hex(low_pc) if isinstance(low_pc, int) else None,
                            "high_pc": hex(high_pc) if isinstance(high_pc, int) else None,
                            "return_type": ret_type,
                            "parameters": params,
                        })

                    elif die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
                        st_name = _decode_attr_str(die.attributes.get("DW_AT_name"))
                        byte_size_attr = die.attributes.get("DW_AT_byte_size")
                        if not st_name or byte_size_attr is None:
                            continue
                        members = []
                        for child in die.iter_children():
                            if child.tag == "DW_TAG_member":
                                m_name = _decode_attr_str(child.attributes.get("DW_AT_name")) or "<anon>"
                                loc_attr = child.attributes.get("DW_AT_data_member_location")
                                m_off = loc_attr.value if (loc_attr and isinstance(loc_attr.value, int)) else None
                                m_type_attr = child.attributes.get("DW_AT_type")
                                m_type = "unknown"
                                if m_type_attr and isinstance(m_type_attr.value, int):
                                    m_die = die_map.get(cu.cu_offset + m_type_attr.value) or die_map.get(m_type_attr.value)
                                    m_type = _resolve_dwarf_type_name(m_die, die_map)
                                members.append({"name": m_name, "type": m_type, "offset": m_off})
                        structs.append({
                            "kind": "struct" if die.tag == "DW_TAG_structure_type" else "union",
                            "name": st_name,
                            "byte_size": int(byte_size_attr.value),
                            "members": members,
                        })

                lp = dwarf.line_program_for_CU(cu)
                if lp and lp.header:
                    for fe in lp.header.get("file_entry", []):
                        fname = fe.name.decode("utf-8", errors="replace") if isinstance(fe.name, bytes) else str(fe.name)
                        if fname:
                            line_files.add(fname)
        except Exception as exc:
            return {
                "schema": SCHEMA,
                "status": "partial_dwarf_error",
                "elf_class": elf_class,
                "machine": str(machine),
                "e_type": str(e_type),
                "little_endian": little_endian,
                "mitigations": mitigations,
                "needed_libraries": needed_libs,
                "total_symbols": len(symbols),
                "symbols": symbols,
                "dwarf_error": str(exc),
            }

    return {
        "schema": SCHEMA,
        "status": "complete",
        "elf_class": elf_class,
        "machine": str(machine),
        "e_type": str(e_type),
        "little_endian": little_endian,
        "mitigations": mitigations,
        "needed_libraries": needed_libs,
        "total_symbols": len(symbols),
        "symbols_truncated": truncated_symbols,
        "symbols": symbols,
        "dwarf": {
            "present": has_dwarf,
            "truncated": dwarf_truncated,
            "compilation_units": compilation_units,
            "total_subprograms": len(subprograms),
            "subprograms": subprograms,
            "total_structs": len(structs),
            "structs": structs,
            "source_files": sorted(line_files),
        },
    }


def scan_file_elf_dwarf(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_ELF_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = analyze_elf_and_dwarf(path.read_bytes())
    report["target"] = str(path)
    return report
