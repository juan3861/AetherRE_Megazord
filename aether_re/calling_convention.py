"""Reverse Engineering Graph (REG) — Calling Convention & Prototype Arity Inference.

Heurísticas de recuperação de ABI e protótipos de função (estilo RetDec / CMU TIE):
  1. Identificação da convenção de chamada (cdecl, stdcall, fastcall, thiscall, win64, sysv64);
  2. Estimativa de contagem de parâmetros (aridade) via registradores de argumento e ret N;
  3. Indicação de tipo de retorno a partir da escrita em rax/eax/xmm0 antes de ret.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

SCHEMA = "calling-convention-report.v1"

WIN64_PARAM_REGS = {"rcx", "rdx", "r8", "r9"}
SYSV64_PARAM_REGS = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
FASTCALL_PARAM_REGS = {"ecx", "edx"}


def _clean_op(op_str: str) -> list[str]:
    return [p.strip().lower() for p in op_str.split(",") if p.strip()]


def infer_calling_convention(
    instructions: Sequence[dict[str, Any]],
    *,
    arch: str = "x86_64",
    file_format: str = "pe",
) -> dict[str, Any]:
    """Infere a convenção de chamada mais provável a partir do fluxo de instruções."""
    arch_lower = arch.lower()
    is_64 = "64" in arch_lower or arch_lower in {"x64", "amd64"}

    # Extrai mnemônicos e operandos
    insn_list = []
    for ins in instructions:
        mnem = str(ins.get("mnemonic", "")).lower()
        ops = _clean_op(str(ins.get("op_str", "")))
        insn_list.append((mnem, ops))

    # Verifica epílogo ret
    ret_bytes_cleaned = 0
    for mnem, ops in reversed(insn_list):
        if mnem == "ret":
            if ops:
                try:
                    val = ops[0]
                    ret_bytes_cleaned = int(val, 16) if val.startswith("0x") else int(val)
                except ValueError:
                    pass
            break

    # Rastreia leitura de registradores antes de escrita (argumentos de entrada)
    written_regs: set[str] = set()
    read_before_write: set[str] = set()

    for mnem, ops in insn_list:
        if not ops:
            continue
        dest = ops[0]
        # Operando fonte lido
        if len(ops) > 1:
            src = ops[1]
            for r in (WIN64_PARAM_REGS | SYSV64_PARAM_REGS | FASTCALL_PARAM_REGS | {"ecx"}):
                if r in src and r not in written_regs:
                    read_before_write.add(r)
        # Operando destino escrito
        if mnem in {"mov", "xor", "lea", "add", "sub", "pop"}:
            for r in (WIN64_PARAM_REGS | SYSV64_PARAM_REGS | FASTCALL_PARAM_REGS | {"ecx"}):
                if dest == r:
                    written_regs.add(r)

    # Decisão de ABI
    if is_64:
        if file_format.lower() in {"elf", "mach-o"}:
            matched_sysv = SYSV64_PARAM_REGS & read_before_write
            return {
                "convention": "sysv64",
                "confidence": 0.95 if matched_sysv else 0.85,
                "cleaned_by": "caller",
                "param_registers": sorted(matched_sysv),
                "stack_bytes_cleaned": 0,
            }
        else:
            matched_win64 = WIN64_PARAM_REGS & read_before_write
            return {
                "convention": "win64",
                "confidence": 0.95 if matched_win64 else 0.85,
                "cleaned_by": "caller",
                "param_registers": sorted(matched_win64),
                "stack_bytes_cleaned": 0,
            }
    else:
        # x86 (32-bit)
        if ret_bytes_cleaned > 0:
            if "ecx" in read_before_write and "edx" in read_before_write:
                return {
                    "convention": "fastcall",
                    "confidence": 0.90,
                    "cleaned_by": "callee",
                    "stack_bytes_cleaned": ret_bytes_cleaned,
                }
            elif "ecx" in read_before_write and "edx" not in read_before_write:
                return {
                    "convention": "thiscall",
                    "confidence": 0.85,
                    "cleaned_by": "callee",
                    "stack_bytes_cleaned": ret_bytes_cleaned,
                }
            else:
                return {
                    "convention": "stdcall",
                    "confidence": 0.95,
                    "cleaned_by": "callee",
                    "stack_bytes_cleaned": ret_bytes_cleaned,
                }
        else:
            return {
                "convention": "cdecl",
                "confidence": 0.80,
                "cleaned_by": "caller",
                "stack_bytes_cleaned": 0,
            }


def infer_function_prototype(
    instructions: Sequence[dict[str, Any]],
    *,
    function_name: str = "sub_unknown",
    arch: str = "x86_64",
    file_format: str = "pe",
) -> dict[str, Any]:
    """Estima a assinatura da função: aridade de parâmetros e tipo de retorno."""
    cc_info = infer_calling_convention(instructions, arch=arch, file_format=file_format)
    convention = cc_info["convention"]
    is_64 = "64" in arch.lower() or arch.lower() in {"x64", "amd64"}

    # 1. Estimativa de aridade
    param_count = 0
    if convention in {"win64", "sysv64"}:
        reg_count = len(cc_info.get("param_registers", []))
        param_count = max(param_count, reg_count)
    elif convention == "stdcall":
        bytes_clean = cc_info.get("stack_bytes_cleaned", 0)
        param_count = bytes_clean // 4
    elif convention == "fastcall":
        bytes_clean = cc_info.get("stack_bytes_cleaned", 0)
        param_count = (bytes_clean // 4) + 2
    elif convention == "thiscall":
        bytes_clean = cc_info.get("stack_bytes_cleaned", 0)
        param_count = (bytes_clean // 4) + 1

    # Heurística de leitura da pilha [ebp + 8 + 4*i] para x86 ou [rsp + 0x28 + 8*i] para x64
    stack_offsets: set[int] = set()
    for ins in instructions:
        op_str = str(ins.get("op_str", "")).lower()
        m_ebp = re.search(r"\[ebp\s*\+\s*(0x[0-9a-f]+|\d+)\]", op_str)
        if m_ebp:
            val = m_ebp.group(1)
            off = int(val, 16) if val.startswith("0x") else int(val)
            if off >= 8:
                stack_offsets.add(off)

    if stack_offsets:
        stack_params = len(stack_offsets)
        param_count = max(param_count, stack_params)

    # 2. Retorno (se rax / eax / al / xmm0 foi gravado perto de ret)
    return_type = "void"
    for ins in reversed(instructions[-8:]):
        mnem = str(ins.get("mnemonic", "")).lower()
        dest = _clean_op(str(ins.get("op_str", "")))
        if dest:
            target_reg = dest[0]
            if target_reg in {"rax", "eax", "ax", "al"}:
                return_type = "int / pointer"
                break
            elif target_reg in {"xmm0"}:
                return_type = "float / double"
                break

    param_types = [f"arg_{i}" for i in range(1, param_count + 1)]
    arg_list_str = ", ".join(param_types)
    c_prototype = f"{return_type} {function_name}({arg_list_str})"

    return {
        "schema": SCHEMA,
        "function_name": function_name,
        "calling_convention": convention,
        "confidence": cc_info["confidence"],
        "cleaned_by": cc_info["cleaned_by"],
        "estimated_param_count": param_count,
        "return_type": return_type,
        "c_prototype": c_prototype,
    }
