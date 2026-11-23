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

from aether_re.til_engine import CANONICAL_TIL_STRUCTS, match_struct_by_field_offsets

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
        
        c_lines = [
            "#pragma pack(push, 1)",
            f"typedef struct {struct_name} {{",
        ]
        current_offset = 0
        field_list: list[dict[str, Any]] = []
        pad_idx = 0

        for off in sorted_offsets:
            if off < current_offset:
                # Overlapping byte/word access inside an earlier field: omit from flat packed struct
                continue
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
        c_lines.append("#pragma pack(pop)")
        c_declaration = "\n".join(c_lines) + "\n"

        til_match = None
        if len(sorted_offsets) >= 2:
            til_cands = match_struct_by_field_offsets(sorted_offsets)
            if til_cands and til_cands[0]["match_score"] >= 0.75:
                til_match = til_cands[0]["struct_name"]
                til_info = CANONICAL_TIL_STRUCTS.get(til_match, {}).get("fields", {})
                for fld in field_list:
                    if fld["offset"] in til_info:
                        fld["semantic_name"] = til_info[fld["offset"]]["name"]
                        fld["semantic_type"] = til_info[fld["offset"]]["type"]

        recovered_structs.append({
            "name": struct_name,
            "base_register": base_reg,
            "fields_count": len(field_list),
            "total_size_bytes": total_size,
            "fields": field_list,
            "matched_til_struct": til_match,
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
_FN_SIG_START_RE = re.compile(r"^(?:long long|int64_t|double)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_REG_COPY_STMT_RE = re.compile(
    r"^(r[abcd]x|r[sd]i|rbp|r(?:[89]|1[0-5])|x(?:[0-2]?\d|30))\s*=\s*(?:\(\s*(?:long long|int64_t)\s*\)\s*)?(r[abcd]x|r[sd]i|rbp|r(?:[89]|1[0-5])|x(?:[0-2]?\d|30))\s*;\s*(?:/\*.*\*/)?$"
)
_REG_ASSIGN_RE = re.compile(r"^(r[abcd]x|r[sd]i|rbp|r(?:[89]|1[0-5])|x(?:[0-2]?\d|30))\s*(?:\+=|-=|=)")


def propagate_interprocedural_structs(
    records_list: Sequence[dict[str, Any]],
    structs: Sequence[dict[str, Any]],
    *,
    arch: str = "x86_64",
) -> dict[str, dict[str, str]]:
    """Propagates RecoveredStruct_<REG>_t pointer types across caller->callee callsites via worklist."""
    reg_to_struct: dict[str, str] = {}
    for st in structs:
        reg = str(st.get("base_register", "")).lower()
        name = str(st.get("name", ""))
        if reg and name:
            reg_to_struct[reg] = name

    rva_to_name: dict[int, str] = {}
    fn_param_structs: dict[str, dict[str, str]] = {}
    param_regs = (
        ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7")
        if "aarch64" in arch.lower() or "arm64" in arch.lower()
        else ("rcx", "rdx", "r8", "r9")
    )
    for rec in records_list:
        ident = str(rec.get("c_ident") or rec.get("name") or "")
        rva = rec.get("rva")
        if isinstance(rva, int) and ident:
            rva_to_name[rva] = ident
        fn_param_structs[ident] = {
            pr: reg_to_struct[pr] for pr in param_regs if pr in reg_to_struct
        }

    # Propagate caller argument setup across direct call edges (max 4 worklist rounds)
    call_arg_re = re.compile(r"\b(rcx|rdx|r8|r9|x[0-7])\s*=\s*(?:\([^)]*\)\s*)*([A-Za-z_][A-Za-z0-9_]*)")
    fn_call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for _ in range(4):
        changed = False
        for rec in records_list:
            caller_ident = str(rec.get("c_ident") or rec.get("name") or "")
            c_src = str(rec.get("lifted_c_code") or rec.get("c_code") or "")
            if not caller_ident or not c_src:
                continue
            caller_types = dict(fn_param_structs.get(caller_ident, {}))
            last_reg_src: dict[str, str] = {}
            for raw_ln in c_src.splitlines():
                ln = raw_ln.strip()
                m_arg = call_arg_re.search(ln)
                if m_arg:
                    dst_p, src_r = m_arg.group(1).lower(), m_arg.group(2).lower()
                    inferred = caller_types.get(src_r) or reg_to_struct.get(src_r)
                    if inferred:
                        last_reg_src[dst_p] = inferred
                for m_c in fn_call_re.finditer(ln):
                    callee = m_c.group(1)
                    if callee in fn_param_structs and not callee.startswith("aether_"):
                        for p_reg, st_nm in last_reg_src.items():
                            if p_reg not in fn_param_structs[callee]:
                                fn_param_structs[callee][p_reg] = st_nm
                                changed = True
        if not changed:
            break
    return {k: v for k, v in fn_param_structs.items() if v}


def emit_typed_c_from_structured(
    structured_c: str,
    structs: Sequence[dict[str, Any]],
    *,
    function_param_structs: dict[str, dict[str, str]] | None = None,
    function_prototypes: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Rewrites raw aether_mem_read/write into typed struct pointer dereferences with intra- and inter-procedural alias propagation."""
    if not structured_c or not structs:
        return structured_c
    lookup = _build_struct_field_lookup(structs)
    if not lookup:
        return structured_c

    active_alias: dict[str, str] = {}
    current_fn_param_structs: dict[str, str] = {}
    struct_by_name = {str(st.get("name", "")): st for st in structs if st.get("name")}

    def _resolve_field(reg_name: str, off: int, width: int) -> tuple[str, str, str, int] | None:
        rlow = reg_name.lower()
        if rlow in current_fn_param_structs:
            mapped_st = struct_by_name.get(current_fn_param_structs[rlow])
            if mapped_st:
                mapped_reg = str(mapped_st.get("base_register", "")).lower()
                hit_p = lookup.get((mapped_reg, off))
                if hit_p and hit_p[3] == width:
                    return hit_p
        hit = lookup.get((rlow, off))
        if hit and hit[3] == width:
            return hit
        aliased = active_alias.get(rlow)
        if aliased:
            hit_a = lookup.get((aliased, off))
            if hit_a and hit_a[3] == width:
                return hit_a
        return None

    def _repl_read(match: re.Match[str]) -> str:
        raw_reg = match.group(1)
        off = int(match.group(2), 0) if match.group(2) else 0
        width = int(match.group(3))
        hit = _resolve_field(raw_reg, off, width)
        if not hit:
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
        st_orig = ln.strip()
        m_fn = _FN_SIG_START_RE.match(st_orig)
        if m_fn:
            active_alias.clear()
            fn_ident = m_fn.group(1)
            current_fn_param_structs = (function_param_structs or {}).get(fn_ident, {})
            proto_info = (function_prototypes or {}).get(fn_ident)
            if proto_info or current_fn_param_structs:
                parts_anno = []
                if proto_info and proto_info.get("typed_c_signature"):
                    parts_anno.append(f"ABI({proto_info.get('calling_convention', 'win64')}, params={proto_info.get('estimated_param_count', 0)}): {proto_info['typed_c_signature']}")
                if current_fn_param_structs:
                    p_desc = ", ".join(f"{r}: {s}_t*" for r, s in sorted(current_fn_param_structs.items()))
                    parts_anno.append(f"Interproc-Structs: {p_desc}")
                out_lines.append(f"/* {' | '.join(parts_anno)} */")

        new_ln = _SIMPLE_MEM_READ_RE.sub(_repl_read, ln)

        # Check standalone statement aether_mem_write(addr, width, val);
        stripped = new_ln.strip()
        indent = new_ln[: len(new_ln) - len(new_ln.lstrip())]
        if stripped.startswith("aether_mem_write("):
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
                        hit = _resolve_field(raw_reg, off, width)
                        if hit:
                            st_name, f_name, f_type, _ = hit
                            lhs = f"(({st_name}_t*)(uintptr_t)({raw_reg}))->{f_name}"
                            if f_type == "double":
                                new_ln = f"{indent}{lhs} = aether_bits_to_f64({val_expr});"
                            elif f_type == "float":
                                new_ln = f"{indent}{{ uint32_t _fv = (uint32_t)({val_expr}); memcpy(&{lhs}, &_fv, 4); }}"
                            else:
                                new_ln = f"{indent}{lhs} = ({f_type})({val_expr});"

        # Update intra-procedural register alias state after rewriting the statement
        m_copy = _REG_COPY_STMT_RE.match(st_orig)
        if m_copy:
            dst_r = m_copy.group(1).lower()
            src_r = m_copy.group(2).lower()
            # Invalidate existing aliases pointing to dst_r before reassigning
            for ak in [k for k, v in active_alias.items() if v == dst_r]:
                active_alias.pop(ak, None)
            if dst_r != src_r:
                active_alias[dst_r] = active_alias.get(src_r, src_r)
        elif st_orig.startswith("L_") and ":" in st_orig:
            # Conservative reset on raw branch labels unless sequential entry fallthrough
            active_alias.clear()
        else:
            m_as = _REG_ASSIGN_RE.match(st_orig)
            if m_as:
                mut_r = m_as.group(1).lower()
                active_alias.pop(mut_r, None)
                for ak in [k for k, v in active_alias.items() if v == mut_r]:
                    active_alias.pop(ak, None)

        out_lines.append(new_ln)
    return "\n".join(out_lines)
