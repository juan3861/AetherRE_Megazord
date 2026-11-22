"""Reverse Engineering Graph (REG) — Automatic Struct Layout & Field Recovery.

Engenharia de recuperação de estruturas C/C++ a partir de acessos à memória (estilo Hex-Rays / Ghidra Auto-struct):
  1. Identificação de acessos base + deslocamento [reg + offset];
  2. Inferência de tamanho de campo (1, 2, 4, 8 bytes) com base no registrador/mnemônico;
  3. Cálculo de preenchimento (padding) e alinhamento de memória;
  4. Síntese automática de declarações de estruturas em código C (typedef struct).
"""

from __future__ import annotations

import re
from typing import Any, Sequence

SCHEMA = "struct-recovery-report.v1"

SIZE_TO_TYPE = {
    1: "uint8_t",
    2: "uint16_t",
    4: "uint32_t",
    8: "uint64_t",
}


_F64_MNEMS = {"movsd", "addsd", "subsd", "mulsd", "divsd", "comisd", "ucomisd", "sqrtsd", "minsd", "maxsd"}
_F32_MNEMS = {"movss", "addss", "subss", "mulss", "divss", "comiss", "ucomiss", "sqrtss", "minss", "maxss"}


def _infer_access_type(mnemonic: str, op_str: str, size: int) -> str:
    m_low = mnemonic.strip().lower()
    if m_low in _F64_MNEMS:
        return "double"
    if m_low in _F32_MNEMS:
        return "float"
    return SIZE_TO_TYPE.get(size, "uint32_t")


def _infer_access_size(mnemonic: str, op_str: str) -> int:
    m_low = mnemonic.strip().lower()
    if m_low in _F64_MNEMS:
        return 8
    if m_low in _F32_MNEMS:
        return 4
    op_lower = op_str.lower()
    if "qword ptr" in op_lower:
        return 8
    if "dword ptr" in op_lower:
        return 4
    if re.search(r"\bword ptr\b", op_lower):
        return 2
    if "byte ptr" in op_lower:
        return 1

    # Remove o operando de memória em colchetes para não confundir o registrador base
    non_mem = re.sub(r"\[.*?\]", "", op_lower)
    if re.search(r"\b([a-d][lh]|r\d{1,2}b)\b", non_mem):
        return 1
    if re.search(r"\b([a-d]x|[sbi]p|[sd]i|r\d{1,2}w)\b", non_mem):
        return 2
    if re.search(r"\b(e[a-d]x|e[sbi]p|e[sd]i|r\d{1,2}d)\b", non_mem):
        return 4
    if re.search(r"\b(r[a-d]x|r[sbi]p|r[sd]i|r\d{1,2})\b", non_mem):
        return 8
    return 4  # Padrão razoável de 32-bit


def recover_struct_layouts(
    instructions: Sequence[dict[str, Any]],
    *,
    base_registers: set[str] | None = None,
    struct_name_prefix: str = "RecoveredStruct",
) -> dict[str, Any]:
    """Extrai e reconstrói estruturas de dados a partir de acessos à memória."""
    target_regs = {r.lower() for r in base_registers} if base_registers else {"rcx", "rdx", "rsi", "rdi", "rbx", "r8", "r9", "ecx", "edx", "esi", "edi", "ebx"}

    # Mapeia base_reg -> dict[offset, field_info]
    accessed_fields: dict[str, dict[int, dict[str, Any]]] = {}

    pattern = re.compile(r"\[\s*([re]?[a-d]x|[re]?[sbi]p|[re]?[sd]i|r\d{1,2})\s*(?:\+\s*(0x[0-9a-f]+|\d+))?\s*\]", re.IGNORECASE)

    for ins in instructions:
        mnem = str(ins.get("mnemonic", ""))
        op_str = str(ins.get("op_str", ""))
        
        matches = pattern.findall(op_str)
        for base_reg, offset_str in matches:
            base_reg = base_reg.lower()
            if base_reg in target_regs:
                offset = 0
                if offset_str:
                    offset = int(offset_str, 16) if offset_str.lower().startswith("0x") else int(offset_str)
                
                size = _infer_access_size(mnem, op_str)
                inferred_type = _infer_access_type(mnem, op_str, size)
                if base_reg not in accessed_fields:
                    accessed_fields[base_reg] = {}
                
                if offset not in accessed_fields[base_reg]:
                    accessed_fields[base_reg][offset] = {
                        "offset": offset,
                        "size": size,
                        "type": inferred_type,
                        "access_count": 1,
                    }
                else:
                    accessed_fields[base_reg][offset]["access_count"] += 1
                    # Se acessado com tamanho maior ou tipo float explícito, atualiza
                    if size > accessed_fields[base_reg][offset]["size"]:
                        accessed_fields[base_reg][offset]["size"] = size
                        accessed_fields[base_reg][offset]["type"] = inferred_type
                    elif inferred_type in ("double", "float") and size == accessed_fields[base_reg][offset]["size"]:
                        accessed_fields[base_reg][offset]["type"] = inferred_type

    recovered_structs: list[dict[str, Any]] = []

    for base_reg, fields_dict in sorted(accessed_fields.items()):
        if not fields_dict:
            continue
        sorted_offsets = sorted(fields_dict.keys())
        struct_name = f"{struct_name_prefix}_{base_reg.upper()}"
        
        c_lines = [f"typedef struct {struct_name} {{"]
        current_offset = 0
        field_list: list[dict[str, Any]] = []
        pad_idx = 0

        for off in sorted_offsets:
            f = fields_dict[off]
            if off > current_offset:
                pad_size = off - current_offset
                c_lines.append(f"    uint8_t _pad_{pad_idx}[{pad_size}]; /* offset 0x{current_offset:02x} */")
                pad_idx += 1
                current_offset = off

            f_type = f["type"]
            f_name = f"field_0x{off:02x}"
            c_lines.append(f"    {f_type} {f_name}; /* offset 0x{off:02x}, size {f['size']} */")
            field_list.append({
                "name": f_name,
                "offset": off,
                "offset_hex": hex(off),
                "size": f["size"],
                "type": f_type,
                "access_count": f["access_count"],
            })
            current_offset = off + f["size"]

        total_size = current_offset
        c_lines.append(f"}} {struct_name}_t; /* total size: {total_size} bytes (0x{total_size:x}) */")
        c_declaration = "\n".join(c_lines) + "\n"

        recovered_structs.append({
            "name": struct_name,
            "base_register": base_reg,
            "fields_count": len(field_list),
            "total_size_bytes": total_size,
            "fields": field_list,
            "c_declaration": c_declaration,
        })

    return {
        "schema": SCHEMA,
        "total_structs_recovered": len(recovered_structs),
        "structs": recovered_structs,
    }


_STRUCT_MEM_ACCESS_RE = re.compile(
    r"aether_mem_(?:read|write)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*,"
)


def _build_struct_field_lookup(
    structs: Sequence[dict[str, Any]],
) -> dict[tuple[str, int], tuple[str, str, str, int]]:
    lookup: dict[tuple[str, int], tuple[str, str, str, int]] = {}
    for st in structs:
        reg = str(st.get("base_register", "")).lower()
        st_name = str(st.get("name", ""))
        if not reg or not st_name:
            continue
        for fld in st.get("fields", []):
            off = int(fld.get("offset", 0))
            lookup[(reg, off)] = (
                st_name,
                str(fld.get("name", f"field_0x{off:02x}")),
                str(fld.get("type", "uint64_t")),
                int(fld.get("size", 8)),
            )
    return lookup


def annotate_c_with_struct_fields(c_code: str, structs: Sequence[dict[str, Any]]) -> str:
    """Annotates C lines accessing recovered struct offsets with semantic field comments."""
    if not c_code or not structs:
        return c_code
    lookup = _build_struct_field_lookup(structs)
    if not lookup:
        return c_code

    out_lines: list[str] = []
    for ln in c_code.splitlines():
        tags: list[str] = []
        for m in _STRUCT_MEM_ACCESS_RE.finditer(ln):
            reg = m.group(1).lower()
            off = int(m.group(2), 0) if m.group(2) else 0
            hit = lookup.get((reg, off))
            if hit:
                tag = f"{hit[0]}->{hit[1]}:{hit[2]}"
                if tag not in tags:
                    tags.append(tag)
        if tags and "/*" not in ln:
            out_lines.append(f"{ln} /* {'; '.join(tags)} */")
        else:
            out_lines.append(ln)
    return "\n".join(out_lines)


def _split_top_level_args(arg_str: str) -> list[str]:
    """Splits a comma-separated C argument list honoring nested parentheses."""
    args: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(arg_str):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            args.append(arg_str[start:idx].strip())
            start = idx + 1
    tail = arg_str[start:].strip()
    if tail:
        args.append(tail)
    return args


_REG_OFF_EXPR_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*$"
)
_SIMPLE_MEM_READ_RE = re.compile(
    r"aether_mem_read\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*,\s*(\d+)\s*\)"
)


def emit_typed_c_from_structured(
    structured_c: str,
    structs: Sequence[dict[str, Any]],
) -> str:
    """Rewrites raw aether_mem_read/write into typed struct pointer dereferences in decompiled C."""
    if not structured_c or not structs:
        return structured_c
    lookup = _build_struct_field_lookup(structs)
    if not lookup:
        return structured_c

    def _repl_read(match: re.Match[str]) -> str:
        raw_reg = match.group(1)
        off = int(match.group(2), 0) if match.group(2) else 0
        width = int(match.group(3))
        hit = lookup.get((raw_reg.lower(), off))
        if not hit or hit[3] != width:
            return match.group(0)
        st_name, f_name, f_type, _ = hit
        deref = f"(({st_name}_t*)(uintptr_t)({raw_reg}))->{f_name}"
        if f_type == "double":
            return f"aether_f64_to_bits({deref})"
        if f_type == "float":
            return match.group(0)
        return f"(int64_t)({deref})"

    out_lines: list[str] = []
    for ln in structured_c.splitlines():
        new_ln = _SIMPLE_MEM_READ_RE.sub(_repl_read, ln)

        # Check standalone statement aether_mem_write(addr, width, val);
        stripped = new_ln.strip()
        indent = new_ln[: len(new_ln) - len(new_ln.lstrip())]
        if stripped.startswith("aether_mem_write("):
            # Extract balanced call ending before ");" (ignore trailing inline comment)
            open_idx = stripped.find("(")
            depth = 0
            close_idx = -1
            for ci in range(open_idx, len(stripped)):
                if stripped[ci] == "(":
                    depth += 1
                elif stripped[ci] == ")":
                    depth -= 1
                    if depth == 0:
                        close_idx = ci
                        break
            if close_idx > open_idx and stripped[close_idx + 1 :].lstrip().startswith(";"):
                call_args = _split_top_level_args(stripped[open_idx + 1 : close_idx])
                if len(call_args) == 3:
                    m_addr = _REG_OFF_EXPR_RE.match(call_args[0])
                    if m_addr and call_args[1].isdigit():
                        raw_reg = m_addr.group(1)
                        off = int(m_addr.group(2), 0) if m_addr.group(2) else 0
                        width = int(call_args[1])
                        val_expr = call_args[2]
                        hit = lookup.get((raw_reg.lower(), off))
                        if hit and hit[3] == width:
                            st_name, f_name, f_type, _ = hit
                            lhs = f"(({st_name}_t*)(uintptr_t)({raw_reg}))->{f_name}"
                            if f_type == "double":
                                new_ln = f"{indent}{lhs} = aether_bits_to_f64({val_expr});"
                            elif f_type == "float":
                                new_ln = f"{indent}{{ uint32_t _fv = (uint32_t)({val_expr}); memcpy(&{lhs}, &_fv, 4); }}"
                            else:
                                new_ln = f"{indent}{lhs} = ({f_type})({val_expr});"

        out_lines.append(new_ln)
    return "\n".join(out_lines)
