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


def _infer_access_size(mnemonic: str, op_str: str) -> int:
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
                if base_reg not in accessed_fields:
                    accessed_fields[base_reg] = {}
                
                if offset not in accessed_fields[base_reg]:
                    accessed_fields[base_reg][offset] = {
                        "offset": offset,
                        "size": size,
                        "type": SIZE_TO_TYPE.get(size, "uint32_t"),
                        "access_count": 1,
                    }
                else:
                    accessed_fields[base_reg][offset]["access_count"] += 1
                    # Se acessado com tamanho maior, atualiza
                    if size > accessed_fields[base_reg][offset]["size"]:
                        accessed_fields[base_reg][offset]["size"] = size
                        accessed_fields[base_reg][offset]["type"] = SIZE_TO_TYPE.get(size, "uint32_t")

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
