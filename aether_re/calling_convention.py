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
WIN64_PARAM_ORDER = ("rcx", "rdx", "r8", "r9")
WIN64_SUBREGS = {
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9": "r9", "r9d": "r9", "r9w": "r9", "r9b": "r9",
}
SYSV64_PARAM_REGS = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
SYSV64_PARAM_ORDER = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
SYSV64_SUBREGS = {
    **WIN64_SUBREGS,
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
}
ARM64_PARAM_ORDER = tuple(f"x{i}" for i in range(8))
ARM64_PARAM_REGS = set(ARM64_PARAM_ORDER)
FASTCALL_PARAM_REGS = {"ecx", "edx"}


def _clean_op(op_str: str) -> list[str]:
    return [p.strip().lower() for p in op_str.split(",") if p.strip()]


def _extract_arm64_reg(tok: str) -> str | None:
    m = re.fullmatch(r"([xw])([0-7])", tok.strip().lower())
    return f"x{m.group(2)}" if m else None


def infer_calling_convention(
    instructions: Sequence[dict[str, Any]],
    *,
    arch: str = "x86_64",
    file_format: str = "pe",
) -> dict[str, Any]:
    """Infere a convenção de chamada mais provável a partir do fluxo de instruções."""
    arch_lower = arch.lower()
    is_arm64 = any(tag in arch_lower for tag in ("arm64", "aarch64"))
    is_64 = "64" in arch_lower or arch_lower in {"x64", "amd64"} or is_arm64

    insn_list = []
    for ins in instructions:
        mnem = str(ins.get("mnemonic", "")).lower()
        ops = _clean_op(str(ins.get("op_str", "")))
        insn_list.append((mnem, ops))

    if is_arm64:
        written: set[str] = set()
        read_before_write: set[str] = set()
        fp_read: set[str] = set()
        fp_written: set[str] = set()
        for mnem, ops in insn_list:
            if not ops:
                continue
            dest = ops[0]
            srcs = ops[1:] if len(ops) > 1 else ops
            if mnem in {"str", "stp"}:
                srcs = ops
                dest_written = False
            else:
                dest_written = mnem in {"mov", "movz", "movk", "add", "sub", "mul", "ldr", "ldp", "adr", "adrp", "fmov", "fadd", "fsub", "fmul", "fdiv"}
            for s in srcs:
                for m_r in re.finditer(r"\b([xw][0-7])\b", s):
                    canon = f"x{m_r.group(1)[1:]}"
                    if canon not in written:
                        read_before_write.add(canon)
                for m_fp in re.finditer(r"\b([ds][0-7])\b", s):
                    canon_fp = f"d{m_fp.group(1)[1:]}"
                    if canon_fp not in fp_written:
                        fp_read.add(canon_fp)
            if dest_written:
                c_dest = _extract_arm64_reg(dest)
                if c_dest:
                    written.add(c_dest)
                m_dfp = re.fullmatch(r"([ds])([0-7])", dest)
                if m_dfp:
                    fp_written.add(f"d{m_dfp.group(2)}")
        matched_arm = sorted(ARM64_PARAM_REGS & read_before_write, key=lambda r: int(r[1:]))
        return {
            "convention": "aapcs64",
            "confidence": 0.95 if (matched_arm or fp_read) else 0.85,
            "cleaned_by": "caller",
            "param_registers": matched_arm,
            "fp_param_registers": sorted(fp_read, key=lambda r: int(r[1:])),
            "stack_bytes_cleaned": 0,
        }

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
    fp_read: set[str] = set()
    fp_written: set[str] = set()

    reg_aliases = SYSV64_SUBREGS if file_format.lower() in {"elf", "mach-o", "macho"} else WIN64_SUBREGS
    for mnem, ops in insn_list:
        if not ops:
            continue
        dest = ops[0]
        srcs = ops[1:] if len(ops) > 1 else ([] if mnem not in {"cmp", "test", "push"} else ops)
        for src in srcs:
            for tok in re.findall(r"\b([re]?[abcd]x|[re]?[sd]i|[abcd]l|r[89][dwb]?|ecx|edx)\b", src):
                canon = reg_aliases.get(tok, tok)
                if canon not in written_regs:
                    read_before_write.add(canon)
            for xm in re.findall(r"\b(xmm[0-5])\b", src):
                if xm not in fp_written:
                    fp_read.add(xm)
        if "[" in dest:
            # Memory write destination still reads index/base registers!
            for tok in re.findall(r"\b([re]?[abcd]x|[re]?[sd]i|r[89][dwb]?|ecx|edx)\b", dest):
                canon = reg_aliases.get(tok, tok)
                if canon not in written_regs:
                    read_before_write.add(canon)
        if mnem in {"mov", "movzx", "movsx", "movsxd", "xor", "lea", "add", "sub", "pop"}:
            canon_d = reg_aliases.get(dest, dest)
            if canon_d in (WIN64_PARAM_REGS | SYSV64_PARAM_REGS | FASTCALL_PARAM_REGS | {"ecx"}):
                written_regs.add(canon_d)
            if dest in {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"} and mnem not in {"add", "sub"}:
                fp_written.add(dest)

    if is_64:
        if file_format.lower() in {"elf", "mach-o", "macho"}:
            matched_sysv = [r for r in SYSV64_PARAM_ORDER if r in (SYSV64_PARAM_REGS & read_before_write)]
            return {
                "convention": "sysv64",
                "confidence": 0.95 if (matched_sysv or fp_read) else 0.85,
                "cleaned_by": "caller",
                "param_registers": matched_sysv,
                "fp_param_registers": sorted(fp_read),
                "stack_bytes_cleaned": 0,
            }
        matched_win64 = [r for r in WIN64_PARAM_ORDER if r in (WIN64_PARAM_REGS & read_before_write)]
        return {
            "convention": "win64",
            "confidence": 0.95 if (matched_win64 or fp_read) else 0.85,
            "cleaned_by": "caller",
            "param_registers": matched_win64,
            "fp_param_registers": sorted(fp_read),
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
    stack_frame_bytes: int = 0,
) -> dict[str, Any]:
    """Estima a assinatura da função: aridade exata (>4 args via pilha), ABI e tipo de retorno."""
    cc_info = infer_calling_convention(instructions, arch=arch, file_format=file_format)
    convention = cc_info["convention"]

    param_count = 0
    stack_param_offsets: list[int] = []
    if convention == "win64":
        order = WIN64_PARAM_ORDER
        used_set = set(cc_info.get("param_registers", []))
        fp_set = set(cc_info.get("fp_param_registers", []))
        highest_reg_idx = 0
        for idx_r, rn in enumerate(order, start=1):
            xm = f"xmm{idx_r - 1}"
            if rn in used_set or xm in fp_set:
                highest_reg_idx = idx_r
        param_count = highest_reg_idx
        # Detect 5th+ stack args above shadow home (`[rsp + frame + 0x28 + 8*i]`)
        # Even without explicit unwind frame, estimate from prolog `sub rsp, Imm` if stack_frame_bytes==0
        eff_frame = stack_frame_bytes
        if eff_frame == 0:
            push_cnt = 0
            for ins in instructions[:16]:
                mn = str(ins.get("mnemonic", "")).lower()
                ops_i = _clean_op(str(ins.get("op_str", "")))
                if mn == "push":
                    push_cnt += 8
                elif mn == "sub" and len(ops_i) == 2 and ops_i[0] == "rsp":
                    try:
                        eff_frame = int(ops_i[1], 0) + push_cnt
                    except ValueError:
                        pass
                    break
        extra_base = eff_frame + 0x28
        raw_stack_offs: set[int] = set()
        for ins in instructions:
            op_str = str(ins.get("op_str", "")).lower()
            m_rsp = re.search(r"\[rsp\s*\+\s*(0x[0-9a-f]+|\d+)\]", op_str)
            if m_rsp:
                off = int(m_rsp.group(1), 0)
                if eff_frame > 0 and off >= extra_base and (off - extra_base) % 8 == 0 and (off - extra_base) <= 64:
                    raw_stack_offs.add(off)
        if raw_stack_offs:
            stack_param_offsets = sorted(raw_stack_offs)
            max_arg_slot = max((off - extra_base) // 8 for off in raw_stack_offs) + 5
            param_count = max(param_count, max_arg_slot)
    elif convention == "sysv64":
        order_s = SYSV64_PARAM_ORDER
        used_set = set(cc_info.get("param_registers", []))
        fp_set = set(cc_info.get("fp_param_registers", []))
        for idx_r, rn in enumerate(order_s, start=1):
            if rn in used_set:
                param_count = idx_r
        param_count = max(param_count, len(fp_set))
    elif convention == "aapcs64":
        used_set = set(cc_info.get("param_registers", []))
        fp_set = set(cc_info.get("fp_param_registers", []))
        for r in used_set:
            param_count = max(param_count, int(r[1:]) + 1)
        for fp in fp_set:
            param_count = max(param_count, int(fp[1:]) + 1)
    elif convention == "stdcall":
        bytes_clean = cc_info.get("stack_bytes_cleaned", 0)
        param_count = bytes_clean // 4
    elif convention == "fastcall":
        bytes_clean = cc_info.get("stack_bytes_cleaned", 0)
        param_count = (bytes_clean // 4) + 2
    elif convention == "thiscall":
        bytes_clean = cc_info.get("stack_bytes_cleaned", 0)
        param_count = (bytes_clean // 4) + 1

    # Heurística de leitura da pilha [ebp + 8 + 4*i] para x86
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

    # 2. Retorno (varre de trás para frente buscando escrita real em rax/xmm0/x0/d0)
    return_type = "void"
    return_c_type = "void"
    for ins in reversed(instructions[-24:]):
        mnem = str(ins.get("mnemonic", "")).lower()
        if mnem in {"nop", "pop", "add", "ret"} and (not _clean_op(str(ins.get("op_str", ""))) or _clean_op(str(ins.get("op_str", "")))[0] in {"rsp", "esp", "rbp", "sp"}):
            continue
        dest = _clean_op(str(ins.get("op_str", "")))
        if dest:
            target_reg = dest[0]
            if target_reg in {"rax", "eax", "ax", "al", "x0", "w0"}:
                return_type = "int / pointer"
                return_c_type = "int64_t"
                break
            if target_reg in {"xmm0", "d0", "s0"}:
                return_type = "float / double"
                return_c_type = "double"
                break

    param_types = [f"arg_{i}" for i in range(1, param_count + 1)]
    arg_list_str = ", ".join(param_types)
    c_prototype = f"{return_type} {function_name}({arg_list_str})"

    # Typed C signature (C11 compatible)
    fp_regs = set(cc_info.get("fp_param_registers", []))
    c_params: list[str] = []
    for idx_p in range(1, param_count + 1):
        is_fp_p = (f"xmm{idx_p - 1}" in fp_regs) or (f"d{idx_p - 1}" in fp_regs)
        p_ty = "double" if is_fp_p else "int64_t"
        c_params.append(f"{p_ty} arg_{idx_p}")
    typed_c_signature = f"{return_c_type} {function_name}({', '.join(c_params) if c_params else 'void'})"

    return {
        "schema": SCHEMA,
        "function_name": function_name,
        "calling_convention": convention,
        "confidence": cc_info["confidence"],
        "cleaned_by": cc_info["cleaned_by"],
        "estimated_param_count": param_count,
        "param_registers": cc_info.get("param_registers", []),
        "fp_param_registers": cc_info.get("fp_param_registers", []),
        "stack_param_offsets": stack_param_offsets,
        "return_type": return_type,
        "return_c_type": return_c_type,
        "c_prototype": c_prototype,
        "typed_c_signature": typed_c_signature,
    }


def refine_prototypes_interprocedural(
    prototypes: dict[str, dict[str, Any]],
    call_edges: Sequence[tuple[str, str, Sequence[str]]],
) -> dict[str, dict[str, Any]]:
    """Refines function arity using caller register-setup evidence along the call graph."""
    refined = {k: dict(v) for k, v in prototypes.items()}
    win64_idx = {r: i + 1 for i, r in enumerate(WIN64_PARAM_ORDER)}
    sysv_idx = {r: i + 1 for i, r in enumerate(SYSV64_PARAM_ORDER)}
    arm_idx = {r: i + 1 for i, r in enumerate(ARM64_PARAM_ORDER)}

    for _caller, callee, passed_regs in call_edges:
        proto = refined.get(callee)
        if proto is None:
            continue
        conv = proto.get("calling_convention", "win64")
        idx_map = arm_idx if conv == "aapcs64" else (sysv_idx if conv == "sysv64" else win64_idx)
        max_call_arity = max((idx_map.get(r, 0) for r in passed_regs), default=0)
        if max_call_arity > int(proto.get("estimated_param_count", 0)):
            proto["estimated_param_count"] = max_call_arity
            ret_t = proto.get("return_c_type", "int64_t")
            args = ", ".join(f"int64_t arg_{i}" for i in range(1, max_call_arity + 1)) or "void"
            proto["typed_c_signature"] = f"{ret_t} {callee}({args})"
    return refined
