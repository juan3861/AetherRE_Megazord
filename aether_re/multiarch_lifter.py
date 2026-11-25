"""Multi-Architecture Native Lifter & ELF64 Extractor (v6.2.0).

Supports:
  1. ARM64 / AArch64 instruction lifter (`lift_arm64_function_to_c`) emitting C
     fully compatible with `ir_optimizer`, `ctree_structuring`, `llvm_backend`,
     `MCJITSession`, and MSVC native compilation.
  2. Deterministic AArch64 ISA state simulator (`eval_arm64_insns`) for 64-vector
     differential behavioral congruence verification.
  3. ELF64 (`EM_X86_64` & `EM_AARCH64`) symbol, `.rodata`, `DT_NEEDED`, and `.eh_frame`
     extraction via `pyelftools`.
"""
from __future__ import annotations

import ctypes
import io
import math
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

_MASK64 = 0xFFFFFFFFFFFFFFFF
_MASK32 = 0xFFFFFFFF

_ARM64_CC_TO_C: Dict[str, str] = {
    "eq": "(cmp_lhs == cmp_rhs)",
    "ne": "(cmp_lhs != cmp_rhs)",
    "lt": "(cmp_lhs < cmp_rhs)",
    "le": "(cmp_lhs <= cmp_rhs)",
    "gt": "(cmp_lhs > cmp_rhs)",
    "ge": "(cmp_lhs >= cmp_rhs)",
    "lo": "(((cmp_lhs & 0xffffffffffffffffULL) < (cmp_rhs & 0xffffffffffffffffULL)))",
    "cc": "(((cmp_lhs & 0xffffffffffffffffULL) < (cmp_rhs & 0xffffffffffffffffULL)))",
    "ls": "(((cmp_lhs & 0xffffffffffffffffULL) <= (cmp_rhs & 0xffffffffffffffffULL)))",
    "hi": "(((cmp_lhs & 0xffffffffffffffffULL) > (cmp_rhs & 0xffffffffffffffffULL)))",
    "hs": "(((cmp_lhs & 0xffffffffffffffffULL) >= (cmp_rhs & 0xffffffffffffffffULL)))",
    "cs": "(((cmp_lhs & 0xffffffffffffffffULL) >= (cmp_rhs & 0xffffffffffffffffULL)))",
    "mi": "(cmp_lhs < 0)",
    "pl": "(cmp_lhs >= 0)",
}


def _arm64_fp_info(tok: str) -> Optional[Tuple[str, bool]]:
    """Returns (xmm{N}_slot, is_f32) for ARM64 NEON/FP scalar registers d0..d15 / s0..s15."""
    m = re.fullmatch(r"([ds])(\d{1,2})", tok.strip().lower())
    if m:
        idx = int(m.group(2))
        if 0 <= idx <= 15:
            return (f"xmm{idx}", m.group(1) == "s")
    return None


def _arm64_reg_info(tok: str) -> Optional[Tuple[str, bool]]:
    """Returns (canonical_64_name, is_32bit_w) for ARM64 register tokens."""
    t = tok.strip().lower()
    if t in ("xzr", "wzr"):
        return ("zero", t == "wzr")
    if t in ("sp", "wsp"):
        return ("rsp", t == "wsp")
    if t == "fp":
        return ("x29", False)
    if t == "lr":
        return ("x30", False)
    m = re.fullmatch(r"([xw])(\d{1,2})", t)
    if m:
        idx = int(m.group(2))
        if 0 <= idx <= 30:
            return (f"x{idx}", m.group(1) == "w")
    return None


def _parse_arm64_imm(tok: str) -> Optional[int]:
    t = tok.strip()
    if t.startswith("#"):
        t = t[1:].strip()
    try:
        return int(t, 0)
    except ValueError:
        return None


def _arm64_read_expr(tok: str) -> Optional[str]:
    ri = _arm64_reg_info(tok)
    if ri is not None:
        canon, is_w = ri
        if canon == "zero":
            return "0"
        return f"aether_u32({canon})" if is_w else canon
    imm = _parse_arm64_imm(tok)
    if imm is not None:
        return str(imm) if -0x7FFFFFFF <= imm <= 0x7FFFFFFF else f"{imm}LL"
    return None


def _arm64_write_stmt(dst_tok: str, expr: str) -> Optional[str]:
    ri = _arm64_reg_info(dst_tok)
    if ri is None:
        return None
    canon, is_w = ri
    if canon == "zero":
        return "    (void)0;"
    if is_w:
        return f"    {canon} = aether_u32({expr});"
    return f"    {canon} = {expr};"


def _split_arm64_ops(op_str: str) -> List[str]:
    """Splits ARM64 operand string honoring square-bracket memory operands."""
    out: List[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(op_str):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            out.append(op_str[start:idx].strip())
            start = idx + 1
    tail = op_str[start:].strip()
    if tail:
        out.append(tail)
    return out


def _parse_arm64_mem(mem_tok: str, tail_ops: List[str]) -> Optional[Tuple[str, Optional[str], int, str]]:
    """Parses `[base]`, `[base, #imm]`, `[base, #imm]!`, `[base], #imm`.

    Returns (base_canon, addr_expr, pre_post_mode, delta_expr) where pre_post_mode in {'none','pre','post'}.
    """
    raw = mem_tok.strip()
    pre = False
    if raw.endswith("!"):
        pre = True
        raw = raw[:-1].strip()
    if not (raw.startswith("[") and raw.endswith("]")):
        return None
    inner = raw[1:-1].strip()
    parts = [p.strip() for p in inner.split(",") if p.strip()]
    if not parts:
        return None
    base_ri = _arm64_reg_info(parts[0])
    if base_ri is None:
        return None
    base_c, _ = base_ri

    off_expr = "0"
    if len(parts) >= 2:
        p1 = _arm64_read_expr(parts[1])
        if p1 is None:
            return None
        if len(parts) == 3 and parts[2].lower().startswith("lsl"):
            sh = _parse_arm64_imm(parts[2].split("#", 1)[-1]) or 0
            p1 = f"(({p1}) << {sh})"
        off_expr = p1

    if pre:
        return base_c, f"(int64_t)({base_c} + ({off_expr}))", "pre", off_expr

    if tail_ops:
        post_e = _arm64_read_expr(tail_ops[0])
        if post_e is not None:
            return base_c, base_c, "post", post_e

    addr = base_c if off_expr == "0" else f"(int64_t)({base_c} + ({off_expr}))"
    return base_c, addr, "none", "0"


def lift_arm64_function_to_c(
    fn_name: str,
    code_bytes: bytes,
    entry_addr: int,
    *,
    rva_to_symbol: Optional[Dict[int, str]] = None,
    ro_ranges: Optional[List[Tuple[int, int]]] = None,
) -> Tuple[str, List[capstone.CsInsn], bool, Set[int], Set[int]]:
    """Lifts AArch64 machine code into structured-ready Aether C."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    raw_insns = list(md.disasm(code_bytes, entry_addr))
    if not raw_insns:
        return (
            f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{ return 0; }}",
            [],
            False,
            set(),
            set(),
        )

    # Trim function slice cleanly at final unconditional ret outside internal branches
    max_branch = entry_addr
    last_ret = -1
    for idx, ins in enumerate(raw_insns):
        m = ins.mnemonic.lower()
        ops = _split_arm64_ops(ins.op_str)
        if m in ("b", "bl") or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
            tgt = _parse_arm64_imm(ops[-1]) if ops else None
            if tgt is not None and entry_addr <= tgt < entry_addr + len(code_bytes):
                if m != "bl" and tgt > max_branch:
                    max_branch = tgt
        elif m == "ret":
            last_ret = idx
            if ins.address >= max_branch:
                break
    insns = raw_insns[: last_ret + 1] if last_ret >= 0 else raw_insns

    insn_addrs = {ins.address for ins in insns}
    branch_targets: Set[int] = {entry_addr}
    for ins in insns:
        m = ins.mnemonic.lower()
        ops = _split_arm64_ops(ins.op_str)
        if m == "b" or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
            tgt = _parse_arm64_imm(ops[-1]) if ops else None
            if tgt is not None and tgt in insn_addrs:
                branch_targets.add(tgt)

    used_regs: Set[str] = {"rax", "x0", "x1", "x2", "x3"}
    used_fps: Set[str] = set()
    for ins in insns:
        for tok in re.findall(r"\b([xw]\d{1,2}|fp|lr)\b", ins.op_str.lower()):
            ri = _arm64_reg_info(tok)
            if ri and ri[0].startswith("x"):
                used_regs.add(ri[0])
        for ft in re.findall(r"\b([ds]\d{1,2})\b", ins.op_str.lower()):
            fi = _arm64_fp_info(ft)
            if fi:
                used_fps.add(fi[0])

    reg_decls = ", ".join(f"{r} = 0" for r in sorted(used_regs))
    lines = [
        f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{",
        f"    int64_t {reg_decls};",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
    ]
    if used_fps:
        lines.append("    int64_t " + ", ".join(f"{x} = 0" for x in sorted(used_fps)) + ";")

    called_rvas: Set[int] = set()
    ro_refs: Set[int] = set()
    all_lifted = True
    rva_sym = rva_to_symbol or {}

    for idx, ins in enumerate(insns):
        addr = ins.address
        if idx == 0:
            lines.append(f"L_{addr:x}: ; /* entry aarch64 */")
            lines.append("    x0 = rcx;")
            lines.append("    x1 = rdx;")
            lines.append("    x2 = r8;")
            lines.append("    x3 = r9;")
        elif addr in branch_targets:
            lines.append(f"L_{addr:x}: ; /* bb */")

        m = ins.mnemonic.lower()
        ops = _split_arm64_ops(ins.op_str)

        if m == "nop":
            continue
        if m == "ret":
            lines.append("    rax = x0;")
            lines.append("    return rax;")
            continue

        if m in ("mov", "movz", "sxtw", "uxtw") and len(ops) >= 2:
            src_e = _arm64_read_expr(ops[1])
            if src_e is not None:
                if m == "sxtw":
                    src_e = f"aether_i32({src_e})"
                elif m == "uxtw":
                    src_e = f"aether_u32({src_e})"
                elif len(ops) == 3 and ops[2].lower().startswith("lsl"):
                    sh = _parse_arm64_imm(ops[2].split("#", 1)[-1]) or 0
                    src_e = f"(({src_e}) << {sh})"
                st = _arm64_write_stmt(ops[0], src_e)
                if st:
                    lines.append(st)
                    continue

        if m == "movk" and len(ops) >= 2:
            imm = _parse_arm64_imm(ops[1])
            dst_ri = _arm64_reg_info(ops[0])
            sh = 0
            if len(ops) == 3 and ops[2].lower().startswith("lsl"):
                sh = _parse_arm64_imm(ops[2].split("#", 1)[-1]) or 0
            if imm is not None and dst_ri is not None:
                dst_c, _ = dst_ri
                mask = _MASK64 ^ (0xFFFF << sh)
                val_sh = (imm & 0xFFFF) << sh
                lines.append(f"    {dst_c} = (int64_t)((({dst_c}) & 0x{mask:x}ULL) | 0x{val_sh:x}ULL);")
                continue

        if m == "movn" and len(ops) >= 2:
            imm = _parse_arm64_imm(ops[1])
            if imm is not None:
                sh = 0
                if len(ops) == 3 and ops[2].lower().startswith("lsl"):
                    sh = _parse_arm64_imm(ops[2].split("#", 1)[-1]) or 0
                val = (~((imm & 0xFFFF) << sh)) & _MASK64
                dst_ri = _arm64_reg_info(ops[0])
                if dst_ri and dst_ri[1]:
                    val &= _MASK32
                st = _arm64_write_stmt(ops[0], str(ctypes.c_int64(val).value) + "LL")
                if st:
                    lines.append(st)
                    continue

        if m in ("add", "adds", "sub", "subs", "and", "ands", "orr", "eor", "lsl", "lsr", "asr", "mul") and len(ops) == 3:
            op_map = {
                "add": "+", "adds": "+",
                "sub": "-", "subs": "-",
                "and": "&", "ands": "&",
                "orr": "|", "eor": "^",
                "lsl": "<<", "asr": ">>", "mul": "*",
            }
            a1 = _arm64_read_expr(ops[1])
            a2 = _arm64_read_expr(ops[2])
            if a1 is not None and a2 is not None:
                if m == "lsr":
                    dst_ri = _arm64_reg_info(ops[0])
                    res_e = f"(int64_t)((uint64_t)({a1}) >> (({a2}) & 63))"
                    if dst_ri and dst_ri[1]:
                        res_e = f"(aether_u32({a1}) >> (({a2}) & 31))"
                else:
                    c_op = op_map[m]
                    if c_op in ("<<", ">>"):
                        res_e = f"(int64_t)(({a1}) {c_op} (({a2}) & 63))"
                    else:
                        res_e = f"(int64_t)(({a1}) {c_op} ({a2}))"
                st = _arm64_write_stmt(ops[0], res_e)
                if st:
                    lines.append(st)
                    if m in ("adds", "subs", "ands"):
                        lines.append(f"    cmp_lhs = {ops[0].lower() if _arm64_reg_info(ops[0])[0] != 'zero' else res_e}; cmp_rhs = 0;")
                    continue

        if m in ("sdiv", "udiv") and len(ops) == 3:
            a1 = _arm64_read_expr(ops[1])
            a2 = _arm64_read_expr(ops[2])
            if a1 is not None and a2 is not None:
                res_e = f"(({a2}) ? (int64_t)(({a1}) / ({a2})) : 0)"
                st = _arm64_write_stmt(ops[0], res_e)
                if st:
                    lines.append(st)
                    continue

        if m == "madd" and len(ops) == 4:
            a1, a2, a3 = _arm64_read_expr(ops[1]), _arm64_read_expr(ops[2]), _arm64_read_expr(ops[3])
            if a1 is not None and a2 is not None and a3 is not None:
                st = _arm64_write_stmt(ops[0], f"(int64_t)((({a1}) * ({a2})) + ({a3}))")
                if st:
                    lines.append(st)
                    continue

        if m == "neg" and len(ops) == 2:
            a1 = _arm64_read_expr(ops[1])
            if a1 is not None:
                st = _arm64_write_stmt(ops[0], f"(int64_t)(-(({a1})))")
                if st:
                    lines.append(st)
                    continue

        if m in ("cmp", "cmn", "tst") and len(ops) == 2:
            a1 = _arm64_read_expr(ops[0])
            a2 = _arm64_read_expr(ops[1])
            if a1 is not None and a2 is not None:
                if m == "cmp":
                    lines.append(f"    cmp_lhs = {a1}; cmp_rhs = {a2};")
                elif m == "cmn":
                    lines.append(f"    cmp_lhs = {a1}; cmp_rhs = (int64_t)(-(({a2})));")
                else:
                    lines.append(f"    cmp_lhs = (int64_t)(({a1}) & ({a2})); cmp_rhs = 0;")
                continue

        if m == "cset" and len(ops) == 2:
            cond_c = _ARM64_CC_TO_C.get(ops[1].lower().strip())
            if cond_c:
                st = _arm64_write_stmt(ops[0], f"({cond_c} ? 1LL : 0LL)")
                if st:
                    lines.append(st)
                    continue

        if m == "csel" and len(ops) == 4:
            a1, a2 = _arm64_read_expr(ops[1]), _arm64_read_expr(ops[2])
            cond_c = _ARM64_CC_TO_C.get(ops[3].lower().strip())
            if a1 is not None and a2 is not None and cond_c:
                st = _arm64_write_stmt(ops[0], f"({cond_c} ? ({a1}) : ({a2}))")
                if st:
                    lines.append(st)
                    continue

        if m == "b" and len(ops) == 1:
            tgt = _parse_arm64_imm(ops[0])
            if tgt is not None and tgt in insn_addrs:
                lines.append(f"    if (1) goto L_{tgt:x};")
                continue
            if tgt is not None and tgt in rva_sym:
                lines.append(f"    _aether_sp = rsp; rax = {rva_sym[tgt]}(x0, x1, x2, x3); _aether_sp = _aether_saved_sp; return rax;")
                continue

        if m.startswith("b.") and len(ops) == 1:
            cc = m[2:]
            tgt = _parse_arm64_imm(ops[0])
            cond_c = _ARM64_CC_TO_C.get(cc)
            if tgt is not None and tgt in insn_addrs and cond_c:
                lines.append(f"    if {cond_c} goto L_{tgt:x};")
                continue

        if m in ("cbz", "cbnz") and len(ops) == 2:
            v_e = _arm64_read_expr(ops[0])
            tgt = _parse_arm64_imm(ops[1])
            if v_e is not None and tgt is not None and tgt in insn_addrs:
                op_cmp = "==" if m == "cbz" else "!="
                lines.append(f"    if (({v_e}) {op_cmp} 0) goto L_{tgt:x};")
                continue

        if m == "bl" and len(ops) == 1:
            tgt = _parse_arm64_imm(ops[0])
            if tgt is not None:
                called_rvas.add(tgt)
                sym = rva_sym.get(tgt, f"sub_{tgt:x}")
                lines.append(f"    _aether_sp = rsp; x0 = {sym}(x0, x1, x2, x3); _aether_sp = _aether_saved_sp;")
                continue

        if m == "blr" and len(ops) == 1:
            fp_e = _arm64_read_expr(ops[0])
            if fp_e is not None:
                lines.append(f"    _aether_sp = rsp; x0 = aether_icall({fp_e}, x0, x1, x2, x3); _aether_sp = _aether_saved_sp;")
                continue

        if m == "br" and len(ops) == 1:
            fp_e = _arm64_read_expr(ops[0])
            if fp_e is not None:
                lines.append(f"    _aether_sp = rsp; rax = aether_icall({fp_e}, x0, x1, x2, x3); _aether_sp = _aether_saved_sp; return rax;")
                continue

        if m in ("fadd", "fsub", "fmul", "fdiv") and len(ops) == 3:
            fd = _arm64_fp_info(ops[0])
            fa = _arm64_fp_info(ops[1])
            fb = _arm64_fp_info(ops[2])
            if fd and fa and fb:
                helper = {"fadd": "aether_f64_add", "fsub": "aether_f64_sub", "fmul": "aether_f64_mul", "fdiv": "aether_f64_div"}[m]
                lines.append(f"    {fd[0]} = {helper}({fa[0]}, {fb[0]});")
                continue

        if m == "fmov" and len(ops) == 2:
            fd = _arm64_fp_info(ops[0])
            fs = _arm64_fp_info(ops[1])
            if fd and fs:
                lines.append(f"    {fd[0]} = {fs[0]};")
                continue
            if fd and _arm64_read_expr(ops[1]) is not None:
                src_e = _arm64_read_expr(ops[1])
                lines.append(f"    {fd[0]} = aether_f32_to_f64({src_e});" if fd[1] else f"    {fd[0]} = {src_e};")
                continue
            if not fd and fs:
                st = _arm64_write_stmt(ops[0], fs[0])
                if st:
                    lines.append(st)
                    continue

        if m == "scvtf" and len(ops) == 2:
            fd = _arm64_fp_info(ops[0])
            sr = _arm64_read_expr(ops[1])
            if fd and sr is not None:
                lines.append(f"    {fd[0]} = aether_i32_to_f64({sr});")
                continue

        if m in ("fcvtzs", "fcvtz") and len(ops) == 2:
            fs = _arm64_fp_info(ops[1])
            if fs:
                st = _arm64_write_stmt(ops[0], f"aether_f64_to_i32({fs[0]})")
                if st:
                    lines.append(st)
                    continue

        if m in ("fcmp", "fcmpe") and len(ops) == 2:
            fa = _arm64_fp_info(ops[0])
            fb = _arm64_fp_info(ops[1])
            if fa and (fb or ops[1].strip().lstrip("#") in ("0", "0.0")):
                rhs_b = fb[0] if fb else "0"
                lines.append(f"    cmp_lhs = aether_f64_comisd({fa[0]}, {rhs_b}); cmp_rhs = 1;")
                continue

        if m in ("ldr", "ldrb", "ldrh", "ldrsw", "str", "strb", "strh") and len(ops) >= 2:
            # Handle optional post-index tail operand cleanly
            mem_idx = 1
            tail = ops[2:]
            parsed_m = _parse_arm64_mem(ops[mem_idx], tail)
            if parsed_m is not None:
                base_c, addr_e, mode, delta_e = parsed_m
                dst_ri = _arm64_reg_info(ops[0])
                w = 1 if m.endswith("b") else (2 if m.endswith("h") else (4 if (m == "ldrsw" or (dst_ri and dst_ri[1])) else 8))
                if mode == "pre":
                    lines.append(f"    {base_c} = (int64_t)({base_c} + ({delta_e}));")
                if m.startswith("ldr"):
                    rd_e = f"aether_mem_read({addr_e}, {w})"
                    if m == "ldrsw":
                        rd_e = f"aether_i32({rd_e})"
                    elif dst_ri and not dst_ri[1] and w < 8:
                        rd_e = f"(int64_t)({rd_e})"
                    st = _arm64_write_stmt(ops[0], rd_e)
                    if st:
                        lines.append(st)
                else:
                    val_e = _arm64_read_expr(ops[0]) or "0"
                    lines.append(f"    aether_mem_write({addr_e}, {w}, {val_e});")
                if mode == "post":
                    lines.append(f"    {base_c} = (int64_t)({base_c} + ({delta_e}));")
                continue

        if m in ("stp", "ldp") and len(ops) >= 3:
            parsed_m = _parse_arm64_mem(ops[2], ops[3:])
            if parsed_m is not None:
                base_c, addr_e, mode, delta_e = parsed_m
                r0 = _arm64_reg_info(ops[0])
                r1 = _arm64_reg_info(ops[1])
                w = 4 if (r0 and r0[1]) else 8
                if mode == "pre":
                    lines.append(f"    {base_c} = (int64_t)({base_c} + ({delta_e}));")
                base_ptr = base_c if mode in ("pre", "post") else addr_e
                if m == "stp":
                    v0 = _arm64_read_expr(ops[0]) or "0"
                    v1 = _arm64_read_expr(ops[1]) or "0"
                    lines.append(f"    aether_mem_write({base_ptr}, {w}, {v0});")
                    lines.append(f"    aether_mem_write((int64_t)({base_ptr} + {w}), {w}, {v1});")
                else:
                    s0 = _arm64_write_stmt(ops[0], f"aether_mem_read({base_ptr}, {w})")
                    s1 = _arm64_write_stmt(ops[1], f"aether_mem_read((int64_t)({base_ptr} + {w}), {w})")
                    if s0:
                        lines.append(s0)
                    if s1:
                        lines.append(s1)
                if mode == "post":
                    lines.append(f"    {base_c} = (int64_t)({base_c} + ({delta_e}));")
                continue

        if m in ("adr", "adrp") and len(ops) == 2:
            tgt = _parse_arm64_imm(ops[1])
            if tgt is not None:
                in_ro = any(lo <= tgt < hi for lo, hi in (ro_ranges or []))
                if in_ro:
                    ro_refs.add(tgt)
                    st = _arm64_write_stmt(ops[0], f"aether_ro_ptr(0x{tgt:x})")
                else:
                    st = _arm64_write_stmt(ops[0], f"0x{tgt:x}LL")
                if st:
                    lines.append(st)
                    continue

        all_lifted = False
        lines.append(f"    /* unhandled aarch64: {m} {ins.op_str} */")

    lines.append("    rax = x0;")
    lines.append("    return rax;")
    lines.append("}")
    return "\n".join(lines), insns, all_lifted, called_rvas, ro_refs


def eval_arm64_insns(
    insns: List[capstone.CsInsn],
    args: Tuple[int, int, int, int],
    arena: Any,
    max_steps: int = 4000,
    halt_info: Optional[Dict[str, bool]] = None,
) -> int:
    """Independent instruction-level AArch64 ISA simulator for differential verification."""
    if not insns:
        return 0
    regs: Dict[str, int] = {f"x{i}": 0 for i in range(31)}
    regs["x0"] = ctypes.c_int64(args[0]).value & _MASK64
    regs["x1"] = ctypes.c_int64(args[1]).value & _MASK64
    regs["x2"] = ctypes.c_int64(args[2]).value & _MASK64
    regs["x3"] = ctypes.c_int64(args[3]).value & _MASK64
    regs["rsp"] = arena.base + 0x1A000
    regs["zero"] = 0
    fpregs: Dict[str, int] = {f"xmm{i}": 0 for i in range(16)}

    def _bits_to_f64(b: int) -> float:
        return struct.unpack("<d", struct.pack("<q", ctypes.c_int64(b).value))[0]

    def _f64_to_bits(v: float) -> int:
        return struct.unpack("<q", struct.pack("<d", float(v)))[0] & _MASK64

    cmp_lhs = 0
    cmp_rhs = 0
    addr_to_idx = {ins.address: idx for idx, ins in enumerate(insns)}

    def _r(tok: str) -> int:
        ri = _arm64_reg_info(tok)
        if ri is not None:
            canon, is_w = ri
            v = regs.get(canon, 0)
            return (v & _MASK32) if is_w else (v & _MASK64)
        imm = _parse_arm64_imm(tok)
        return (imm & _MASK64) if imm is not None else 0

    def _w(tok: str, val: int) -> None:
        ri = _arm64_reg_info(tok)
        if ri is None:
            return
        canon, is_w = ri
        if canon == "zero":
            return
        regs[canon] = (val & _MASK32) if is_w else (val & _MASK64)

    def _cc_holds(cc: str) -> bool:
        sl = ctypes.c_int64(cmp_lhs).value
        sr = ctypes.c_int64(cmp_rhs).value
        ul = cmp_lhs & _MASK64
        ur = cmp_rhs & _MASK64
        return {
            "eq": sl == sr, "ne": sl != sr,
            "lt": sl < sr, "le": sl <= sr,
            "gt": sl > sr, "ge": sl >= sr,
            "lo": ul < ur, "cc": ul < ur,
            "ls": ul <= ur, "hi": ul > ur,
            "hs": ul >= ur, "cs": ul >= ur,
            "mi": sl < 0, "pl": sl >= 0,
        }.get(cc, False)

    pc = 0
    steps = 0
    while 0 <= pc < len(insns) and steps < max_steps:
        steps += 1
        ins = insns[pc]
        m = ins.mnemonic.lower()
        ops = _split_arm64_ops(ins.op_str)

        if m == "nop":
            pc += 1
            continue
        if m == "ret":
            return ctypes.c_int64(regs["x0"]).value
        if m in ("mov", "movz", "sxtw", "uxtw") and len(ops) >= 2:
            v = _r(ops[1])
            if m == "sxtw":
                v = ctypes.c_int64(ctypes.c_int32(v & _MASK32).value).value & _MASK64
            elif m == "uxtw":
                v &= _MASK32
            elif len(ops) == 3 and ops[2].lower().startswith("lsl"):
                sh = _parse_arm64_imm(ops[2].split("#", 1)[-1]) or 0
                v = (v << sh) & _MASK64
            _w(ops[0], v)
        elif m == "movk" and len(ops) >= 2:
            imm = _parse_arm64_imm(ops[1]) or 0
            sh = (_parse_arm64_imm(ops[2].split("#", 1)[-1]) or 0) if len(ops) == 3 else 0
            dst_ri = _arm64_reg_info(ops[0])
            if dst_ri:
                cur = regs.get(dst_ri[0], 0)
                mask = _MASK64 ^ (0xFFFF << sh)
                _w(ops[0], (cur & mask) | ((imm & 0xFFFF) << sh))
        elif m == "movn" and len(ops) >= 2:
            imm = _parse_arm64_imm(ops[1]) or 0
            sh = (_parse_arm64_imm(ops[2].split("#", 1)[-1]) or 0) if len(ops) == 3 else 0
            _w(ops[0], (~((imm & 0xFFFF) << sh)) & _MASK64)
        elif m in ("add", "adds", "sub", "subs", "and", "ands", "orr", "eor", "lsl", "lsr", "asr", "mul") and len(ops) == 3:
            a, b = _r(ops[1]), _r(ops[2])
            if m in ("add", "adds"):
                r = (a + b) & _MASK64
            elif m in ("sub", "subs"):
                r = (a - b) & _MASK64
            elif m in ("and", "ands"):
                r = a & b
            elif m == "orr":
                r = a | b
            elif m == "eor":
                r = a ^ b
            elif m == "lsl":
                r = (a << (b & 63)) & _MASK64
            elif m == "lsr":
                ri = _arm64_reg_info(ops[0])
                r = ((a & _MASK32) >> (b & 31)) if (ri and ri[1]) else (a >> (b & 63))
            elif m == "asr":
                r = (ctypes.c_int64(a).value >> (b & 63)) & _MASK64
            else:
                r = (a * b) & _MASK64
            _w(ops[0], r)
            if m in ("adds", "subs", "ands"):
                cmp_lhs, cmp_rhs = r, 0
        elif m == "sdiv" and len(ops) == 3:
            a, b = ctypes.c_int64(_r(ops[1])).value, ctypes.c_int64(_r(ops[2])).value
            _w(ops[0], int(a / b) if b else 0)
        elif m == "udiv" and len(ops) == 3:
            a, b = _r(ops[1]), _r(ops[2])
            _w(ops[0], (a // b) if b else 0)
        elif m == "madd" and len(ops) == 4:
            _w(ops[0], (_r(ops[1]) * _r(ops[2]) + _r(ops[3])) & _MASK64)
        elif m == "neg" and len(ops) == 2:
            _w(ops[0], (-_r(ops[1])) & _MASK64)
        elif m == "cmp" and len(ops) == 2:
            cmp_lhs, cmp_rhs = _r(ops[0]), _r(ops[1])
        elif m == "cmn" and len(ops) == 2:
            cmp_lhs, cmp_rhs = _r(ops[0]), (-_r(ops[1])) & _MASK64
        elif m == "tst" and len(ops) == 2:
            cmp_lhs, cmp_rhs = (_r(ops[0]) & _r(ops[1])), 0
        elif m == "cset" and len(ops) == 2:
            _w(ops[0], 1 if _cc_holds(ops[1].lower().strip()) else 0)
        elif m == "csel" and len(ops) == 4:
            _w(ops[0], _r(ops[1]) if _cc_holds(ops[3].lower().strip()) else _r(ops[2]))
        elif m == "b" and len(ops) == 1:
            tgt = _parse_arm64_imm(ops[0])
            if tgt in addr_to_idx:
                pc = addr_to_idx[tgt]
                continue
        elif m.startswith("b.") and len(ops) == 1:
            tgt = _parse_arm64_imm(ops[0])
            if _cc_holds(m[2:]) and tgt in addr_to_idx:
                pc = addr_to_idx[tgt]
                continue
        elif m in ("cbz", "cbnz") and len(ops) == 2:
            tgt = _parse_arm64_imm(ops[1])
            cond = (_r(ops[0]) == 0) if m == "cbz" else (_r(ops[0]) != 0)
            if cond and tgt in addr_to_idx:
                pc = addr_to_idx[tgt]
                continue
        elif m in ("ldr", "ldrb", "ldrh", "ldrsw", "str", "strb", "strh") and len(ops) >= 2:
            parsed = _parse_arm64_mem(ops[1], ops[2:])
            if parsed is not None:
                base_c, _, mode, _ = parsed
                raw_mem = ops[1].rstrip("!").strip()[1:-1]
                mparts = [p.strip() for p in raw_mem.split(",") if p.strip()]
                off_v = _r(mparts[1]) if len(mparts) >= 2 else 0
                if len(mparts) == 3 and mparts[2].lower().startswith("lsl"):
                    off_v <<= (_parse_arm64_imm(mparts[2].split("#", 1)[-1]) or 0)
                base_v = regs.get(base_c, 0)
                if mode == "pre":
                    base_v = (base_v + ctypes.c_int64(off_v).value) & _MASK64
                    regs[base_c] = base_v
                    addr = base_v
                elif mode == "post":
                    addr = base_v
                else:
                    addr = (base_v + ctypes.c_int64(off_v).value) & _MASK64
                dst_ri = _arm64_reg_info(ops[0])
                w = 1 if m.endswith("b") else (2 if m.endswith("h") else (4 if (m == "ldrsw" or (dst_ri and dst_ri[1])) else 8))
                if m.startswith("ldr"):
                    v = arena.read(addr, w)
                    if m == "ldrsw":
                        v = ctypes.c_int64(ctypes.c_int32(v & _MASK32).value).value & _MASK64
                    _w(ops[0], v)
                else:
                    arena.write(addr, w, _r(ops[0]))
                if mode == "post":
                    post_delta = _r(ops[2]) if len(ops) >= 3 else 0
                    regs[base_c] = (regs[base_c] + ctypes.c_int64(post_delta).value) & _MASK64
        elif m in ("stp", "ldp") and len(ops) >= 3:
            parsed = _parse_arm64_mem(ops[2], ops[3:])
            if parsed is not None:
                base_c, _, mode, _ = parsed
                raw_mem = ops[2].rstrip("!").strip()[1:-1]
                mparts = [p.strip() for p in raw_mem.split(",") if p.strip()]
                off_v = _r(mparts[1]) if len(mparts) >= 2 else 0
                base_v = regs.get(base_c, 0)
                if mode == "pre":
                    base_v = (base_v + ctypes.c_int64(off_v).value) & _MASK64
                    regs[base_c] = base_v
                    addr = base_v
                elif mode == "post":
                    addr = base_v
                else:
                    addr = (base_v + ctypes.c_int64(off_v).value) & _MASK64
                r0 = _arm64_reg_info(ops[0])
                w = 4 if (r0 and r0[1]) else 8
                if m == "stp":
                    arena.write(addr, w, _r(ops[0]))
                    arena.write(addr + w, w, _r(ops[1]))
                else:
                    _w(ops[0], arena.read(addr, w))
                    _w(ops[1], arena.read(addr + w, w))
                if mode == "post":
                    post_delta = _r(ops[3]) if len(ops) >= 4 else 0
                    regs[base_c] = (regs[base_c] + ctypes.c_int64(post_delta).value) & _MASK64
        elif m in ("fadd", "fsub", "fmul", "fdiv") and len(ops) == 3:
            fd, fa, fb = _arm64_fp_info(ops[0]), _arm64_fp_info(ops[1]), _arm64_fp_info(ops[2])
            if fd and fa and fb:
                va = _bits_to_f64(fpregs[fa[0]])
                vb = _bits_to_f64(fpregs[fb[0]])
                res_f = va + vb if m == "fadd" else (va - vb if m == "fsub" else (va * vb if m == "fmul" else (va / vb if vb != 0.0 else float("nan"))))
                fpregs[fd[0]] = _f64_to_bits(res_f)
        elif m == "fmov" and len(ops) == 2:
            fd, fs = _arm64_fp_info(ops[0]), _arm64_fp_info(ops[1])
            if fd and fs:
                fpregs[fd[0]] = fpregs[fs[0]]
            elif fd:
                v = _r(ops[1])
                if fd[1]:
                    fv = struct.unpack("<f", struct.pack("<I", v & _MASK32))[0]
                    fpregs[fd[0]] = _f64_to_bits(float(fv))
                else:
                    fpregs[fd[0]] = v & _MASK64
            elif fs:
                _w(ops[0], fpregs[fs[0]])
        elif m == "scvtf" and len(ops) == 2:
            fd = _arm64_fp_info(ops[0])
            if fd:
                iv = ctypes.c_int32(_r(ops[1]) & _MASK32).value
                fpregs[fd[0]] = _f64_to_bits(float(iv))
        elif m in ("fcvtzs", "fcvtz") and len(ops) == 2:
            fs = _arm64_fp_info(ops[1])
            if fs:
                dv = _bits_to_f64(fpregs[fs[0]])
                iv = 0x80000000 if (not math.isfinite(dv) or dv >= 2147483648.0 or dv < -2147483648.0) else (int(dv) & _MASK32)
                _w(ops[0], iv)
        elif m in ("fcmp", "fcmpe") and len(ops) == 2:
            fa, fb = _arm64_fp_info(ops[0]), _arm64_fp_info(ops[1])
            if fa:
                a_f = _bits_to_f64(fpregs[fa[0]])
                b_f = _bits_to_f64(fpregs[fb[0]]) if fb else 0.0
                if math.isnan(a_f) or math.isnan(b_f):
                    cmp_lhs, cmp_rhs = -1, 1
                elif a_f == b_f:
                    cmp_lhs, cmp_rhs = 1, 1
                elif a_f > b_f:
                    cmp_lhs, cmp_rhs = 2, 1
                else:
                    cmp_lhs, cmp_rhs = 0, 1

        pc += 1

    if halt_info is not None and steps >= max_steps and 0 <= pc < len(insns):
        halt_info["fuel_exhausted"] = True
    return ctypes.c_int64(regs["x0"]).value


def extract_elf64_metadata(elf_data: bytes) -> Optional[Dict[str, Any]]:
    """Extracts architecture, exported STT_FUNC symbols, `.rodata` slices, `.eh_frame` & `DT_NEEDED` from ELF64."""
    if len(elf_data) < 64 or elf_data[:4] != b"\x7fELF" or elf_data[4] != 2:
        return None
    ef = ELFFile(io.BytesIO(elf_data))
    e_machine = str(ef.header["e_machine"]).upper()
    if "AARCH64" in e_machine:
        arch = "aarch64"
    elif "X86_64" in e_machine:
        arch = "x86_64"
    elif "RISCV" in e_machine:
        arch = "riscv64"
    elif "MIPS" in e_machine:
        arch = "mips64"
    else:
        arch = e_machine.lower()

    exec_ranges: List[Tuple[int, int]] = []
    ro_ranges: List[Tuple[int, int]] = []
    eh_frame_bytes = 0
    imported_libs: List[str] = []

    for sec in ef.iter_sections():
        flags = int(sec["sh_flags"])
        vaddr = int(sec["sh_addr"])
        sz = int(sec["sh_size"])
        if (flags & 0x4) and sz > 0:  # SHF_EXECINSTR
            exec_ranges.append((vaddr, vaddr + sz))
        elif (flags & 0x2) and not (flags & 0x1) and sz > 0:  # SHF_ALLOC and not SHF_WRITE
            ro_ranges.append((vaddr, vaddr + sz))
        if sec.name == ".eh_frame":
            eh_frame_bytes = sz
        if sec.name == ".dynamic":
            try:
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        imported_libs.append(str(tag.needed))
            except Exception:
                pass

    def _vaddr_to_offset(va: int) -> Optional[int]:
        for sec in ef.iter_sections():
            s_va = int(sec["sh_addr"])
            s_sz = int(sec["sh_size"])
            if s_va <= va < s_va + s_sz and sec["sh_type"] != "SHT_NOBITS":
                return int(sec["sh_offset"]) + (va - s_va)
        return None

    exports_seen: Set[str] = set()
    exports: List[Dict[str, Any]] = []
    for sec in ef.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for sym in sec.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            if sym["st_shndx"] == "SHN_UNDEF" or sym["st_value"] == 0:
                continue
            nm = sym.name or f"sub_{int(sym['st_value']):x}"
            if nm.startswith("_") and nm in ("_init", "_fini", "__do_global_dtors_aux", "register_tm_clones", "deregister_tm_clones", "frame_dummy"):
                continue
            if nm in exports_seen:
                continue
            va = int(sym["st_value"])
            off = _vaddr_to_offset(va)
            if off is None:
                continue
            fn_sz = int(sym["st_size"]) or 1024
            exports_seen.add(nm)
            exports.append({
                "name": nm,
                "ordinal": len(exports) + 1,
                "rva": va,
                "size": fn_sz,
                "code": elf_data[off : off + min(4096, max(64, fn_sz))],
            })

    # Resolve dynamic .plt / .rela.plt / .rela.dyn import stubs
    plt_symbols: Dict[int, str] = {}
    plt_sec = ef.get_section_by_name(".plt.sec") or ef.get_section_by_name(".plt")
    rela_plt = ef.get_section_by_name(".rela.plt") or ef.get_section_by_name(".rela.dyn")
    if plt_sec is not None and isinstance(rela_plt, RelocationSection):
        plt_va = int(plt_sec["sh_addr"])
        plt_entsz = int(plt_sec["sh_entsize"]) or 16
        base_skip = 0 if plt_sec.name == ".plt.sec" else 1
        symtab_sec = ef.get_section(rela_plt["sh_link"]) if rela_plt["sh_link"] < ef.num_sections() else None
        if isinstance(symtab_sec, SymbolTableSection):
            for idx_rel, rel in enumerate(rela_plt.iter_relocations()):
                s_idx = int(rel["r_info_sym"])
                if 0 < s_idx < symtab_sec.num_symbols():
                    sn = symtab_sec.get_symbol(s_idx).name
                    if sn:
                        plt_symbols[plt_va + (idx_rel + base_skip) * plt_entsz] = sn

    return {
        "arch": arch,
        "e_type": str(ef.header["e_type"]),
        "exports": exports,
        "exec_ranges": exec_ranges,
        "ro_ranges": ro_ranges,
        "eh_frame_bytes": eh_frame_bytes,
        "imported_libs": sorted(set(imported_libs)),
        "plt_symbols": plt_symbols,
    }


def extract_macho64_metadata(macho_data: bytes) -> Optional[Dict[str, Any]]:
    """Extracts architecture, __TEXT.__text symbols, segments, and dylibs from Mach-O 64 (thin or Fat)."""
    if len(macho_data) < 32:
        return None
    base_off = 0
    magic_be = struct.unpack_from(">I", macho_data, 0)[0]
    if magic_be == 0xCAFEBABE:
        nfat = struct.unpack_from(">I", macho_data, 4)[0]
        if nfat == 0 or nfat > 32 or 8 + nfat * 20 > len(macho_data):
            return None
        chosen = False
        for i in range(nfat):
            cputype, _, offset, size, _ = struct.unpack_from(">IIIII", macho_data, 8 + i * 20)
            if cputype in (0x01000007, 0x0100000C) and offset + size <= len(macho_data):
                base_off = offset
                chosen = True
                break
        if not chosen:
            return None

    if base_off + 32 > len(macho_data):
        return None
    magic_le = struct.unpack_from("<I", macho_data, base_off)[0]
    if magic_le != 0xFEEDFACF:
        return None
    _, cputype, _, filetype, ncmds, sizeofcmds, _flags, _reserved = struct.unpack_from("<IIIIIIII", macho_data, base_off)
    arch = "x86_64" if cputype == 0x01000007 else ("aarch64" if cputype == 0x0100000C else "")
    if not arch:
        return None

    exec_ranges: List[Tuple[int, int]] = []
    ro_ranges: List[Tuple[int, int]] = []
    imported_libs: List[str] = []
    sec_mappings: List[Tuple[int, int, int]] = []
    sym_table_info: Optional[Tuple[int, int, int, int]] = None

    cursor = base_off + 32
    cmd_end = min(len(macho_data), cursor + sizeofcmds)
    for _ in range(min(ncmds, 2048)):
        if cursor + 8 > cmd_end:
            break
        cmd, cmdsize = struct.unpack_from("<II", macho_data, cursor)
        if cmdsize < 8 or cursor + cmdsize > cmd_end:
            break
        if cmd == 0x19 and cmdsize >= 72:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", macho_data, cursor + 64)[0]
            sc = cursor + 72
            for _ in range(min(nsects, 512)):
                if sc + 80 > cursor + cmdsize:
                    break
                sectname = macho_data[sc : sc + 16].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                segname = macho_data[sc + 16 : sc + 32].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                s_addr, s_size, s_off = struct.unpack_from("<QQI", macho_data, sc + 32)
                if s_size > 0 and s_off > 0 and base_off + s_off + s_size <= len(macho_data):
                    sec_mappings.append((s_addr, s_size, base_off + s_off))
                    if sectname == "__text" or segname == "__TEXT" and sectname in ("__text", "__stubs"):
                        exec_ranges.append((s_addr, s_addr + s_size))
                    elif sectname in ("__cstring", "__const"):
                        ro_ranges.append((s_addr, s_addr + s_size))
                sc += 80
        elif cmd == 0x2 and cmdsize >= 24:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", macho_data, cursor + 8)
            sym_table_info = (base_off + symoff, nsyms, base_off + stroff, strsize)
        elif cmd in (0xC, 0x80000018) and cmdsize >= 24:
            str_off = struct.unpack_from("<I", macho_data, cursor + 8)[0]
            if 8 <= str_off < cmdsize:
                raw_s = macho_data[cursor + str_off : cursor + cmdsize].split(b"\x00", 1)[0]
                if raw_s:
                    imported_libs.append(raw_s.decode("utf-8", errors="replace"))
        cursor += cmdsize

    def _macho_va_to_off(va: int) -> Optional[Tuple[int, int]]:
        for s_addr, s_sz, s_off in sec_mappings:
            if s_addr <= va < s_addr + s_sz:
                return s_off + (va - s_addr), s_sz - (va - s_addr)
        return None

    raw_syms: List[Tuple[int, str]] = []
    if sym_table_info is not None:
        symoff, nsyms, stroff, strsize = sym_table_info
        if symoff + nsyms * 16 <= len(macho_data) and stroff + strsize <= len(macho_data):
            strtab = macho_data[stroff : stroff + strsize]
            for idx in range(min(nsyms, 10000)):
                n_strx, n_type, n_sect, _n_desc, n_value = struct.unpack_from("<IBBHQ", macho_data, symoff + idx * 16)
                if n_sect > 0 and n_value > 0 and (n_type & 0x0E) == 0x0E and n_strx < len(strtab):
                    raw_nm = strtab[n_strx:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    nm = raw_nm[1:] if raw_nm.startswith("_") and len(raw_nm) > 1 else raw_nm
                    if nm:
                        raw_syms.append((n_value, nm))
    raw_syms.sort(key=lambda item: item[0])

    exports: List[Dict[str, Any]] = []
    seen_nm: Set[str] = set()
    for i, (va, nm) in enumerate(raw_syms):
        if nm in seen_nm:
            continue
        loc = _macho_va_to_off(va)
        if loc is None:
            continue
        f_off, max_avail = loc
        nxt_va = raw_syms[i + 1][0] if i + 1 < len(raw_syms) and raw_syms[i + 1][0] > va else va + 512
        sz = min(max_avail, max(16, nxt_va - va), 4096)
        seen_nm.add(nm)
        exports.append({
            "name": nm,
            "ordinal": len(exports) + 1,
            "rva": va,
            "size": sz,
            "code": macho_data[f_off : f_off + sz],
        })

    return {
        "arch": arch,
        "file_type": filetype,
        "exports": exports,
        "exec_ranges": exec_ranges,
        "ro_ranges": ro_ranges,
        "imported_libs": sorted(set(imported_libs)),
    }


# ---------------------------------------------------------------------------
# v8.0 Multi-Arch Extensions: x86_32, ARM32, RISC-V RV64GC, MIPS32 & angr VEX
# ---------------------------------------------------------------------------

def _x86_32_reg_canon(tok: str) -> Optional[Tuple[str, int]]:
    """Maps 32/16/8-bit x86 register name to (canonical_64_var, bit_width)."""
    t = tok.strip().lower()
    m32 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"}
    m16 = {"ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx", "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp"}
    if t in m32:
        return (m32[t], 32)
    if t in m16:
        return (m16[t], 16)
    return None


def _parse_x86_32_mem(op: str) -> Optional[Tuple[int, str]]:
    """Returns (width, addr_c_expr) for `[ebp + 8]`, `dword ptr [esp + 4]` etc."""
    s = op.strip().lower()
    width = 4
    if s.startswith("byte ptr "):
        width = 1
    elif s.startswith("word ptr "):
        width = 2
    elif s.startswith("dword ptr "):
        width = 4
    m = re.search(r"\[([^\]]+)\]", s)
    if not m:
        return None
    inner = m.group(1).strip()
    parts = re.split(r"\s*([+-])\s*", inner)
    terms: List[str] = []
    sign = "+"
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if p in ("+", "-"):
            sign = p
            continue
        rc = _x86_32_reg_canon(p)
        t_expr = rc[0] if rc else p
        if "*" in p and rc is None:
            m_sc = re.match(r"([a-z0-9]+)\s*\*\s*(\d+)", p)
            if m_sc:
                rc2 = _x86_32_reg_canon(m_sc.group(1))
                if rc2:
                    t_expr = f"({rc2[0]} * {m_sc.group(2)})"
        terms.append(t_expr if not terms else (f"- {t_expr}" if sign == "-" else f"+ {t_expr}"))
    if not terms:
        return None
    return width, " ".join(terms)


def _x86_32_op_read(op: str) -> str:
    s = op.strip()
    rc = _x86_32_reg_canon(s)
    if rc:
        return f"aether_u32({rc[0]})" if rc[1] == 32 else f"aether_u16({rc[0]})"
    mem = _parse_x86_32_mem(s)
    if mem:
        w, addr_e = mem
        return f"aether_mem_read({addr_e}, {w})"
    return s


def lift_x86_32_function_to_c(
    fn_name: str,
    code_bytes: bytes,
    base_va: int,
    *,
    rva_to_symbol: Optional[Dict[int, str]] = None,
    ro_ranges: Optional[List[Tuple[int, int]]] = None,
) -> Tuple[str, List[Any], bool, Set[int], Set[int]]:
    """Lifts x86-32 (cdecl/stdcall/fastcall) machine instructions into AetherRE C."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    insns: List[Any] = []
    for ins in md.disasm(code_bytes, base_va):
        insns.append(ins)
        if ins.mnemonic in ("ret", "retn", "retf") and len(insns) >= 1:
            # Continue if jumped past ret inside function
            last_target = max(
                (
                    int(o.op_str, 16)
                    for o in insns
                    if o.mnemonic.startswith("j") and re.fullmatch(r"0x[0-9a-fA-F]+", o.op_str.strip())
                ),
                default=0,
            )
            if ins.address >= last_target:
                break
        if len(insns) >= 600:
            break

    if not insns:
        return (
            f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{\n    return 0;\n}}",
            [],
            False,
            set(),
            set(),
        )

    all_addrs = {i.address for i in insns}
    called_set: Set[int] = set()
    ro_set: Set[int] = set()
    sym_map = rva_to_symbol or {}

    lines = [
        f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{",
        "    int64_t rax = 0, rbx = 0, rbp = 0, rsi = 0, rdi = 0;",
        "    int64_t r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;",
        "    int64_t xmm0 = 0, xmm1 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "    /* cdecl 32-bit stack frame entry arguments mapped from host signature */",
        "    aether_mem_write((rsp) + (4), 4, aether_u32(rcx));",
        "    aether_mem_write((rsp) + (8), 4, aether_u32(rdx));",
        "    aether_mem_write((rsp) + (12), 4, aether_u32(r8));",
        "    aether_mem_write((rsp) + (16), 4, aether_u32(r9));",
    ]
    _CC_32 = {
        "je": "(cmp_lhs == cmp_rhs)", "jz": "(cmp_lhs == cmp_rhs)",
        "jne": "(cmp_lhs != cmp_rhs)", "jnz": "(cmp_lhs != cmp_rhs)",
        "jl": "(aether_i32(cmp_lhs) < aether_i32(cmp_rhs))", "jnge": "(aether_i32(cmp_lhs) < aether_i32(cmp_rhs))",
        "jle": "(aether_i32(cmp_lhs) <= aether_i32(cmp_rhs))", "jng": "(aether_i32(cmp_lhs) <= aether_i32(cmp_rhs))",
        "jg": "(aether_i32(cmp_lhs) > aether_i32(cmp_rhs))", "jnle": "(aether_i32(cmp_lhs) > aether_i32(cmp_rhs))",
        "jge": "(aether_i32(cmp_lhs) >= aether_i32(cmp_rhs))", "jnl": "(aether_i32(cmp_lhs) >= aether_i32(cmp_rhs))",
        "jb": "(aether_u32(cmp_lhs) < aether_u32(cmp_rhs))", "jc": "(aether_u32(cmp_lhs) < aether_u32(cmp_rhs))",
        "jbe": "(aether_u32(cmp_lhs) <= aether_u32(cmp_rhs))",
        "ja": "(aether_u32(cmp_lhs) > aether_u32(cmp_rhs))",
        "jae": "(aether_u32(cmp_lhs) >= aether_u32(cmp_rhs))", "jnc": "(aether_u32(cmp_lhs) >= aether_u32(cmp_rhs))",
    }

    supported = True
    for ins in insns:
        lines.append(f"L_{ins.address:x}: ; /* {ins.mnemonic} {ins.op_str} */")
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []

        if m in ("nop", "endbr32", "cdq"):
            continue
        elif m == "push" and len(ops) == 1:
            v = _x86_32_op_read(ops[0])
            lines.append("    rsp = (rsp) - (4);")
            lines.append(f"    aether_mem_write(rsp, 4, {v});")
        elif m == "pop" and len(ops) == 1:
            rc = _x86_32_reg_canon(ops[0])
            if rc:
                lines.append(f"    {rc[0]} = aether_mem_read(rsp, 4);")
                lines.append("    rsp = (rsp) + (4);")
            else:
                supported = False
        elif m in ("mov", "movzx", "movsx") and len(ops) == 2:
            dst_rc = _x86_32_reg_canon(ops[0])
            rhs = _x86_32_op_read(ops[1])
            if dst_rc:
                if m == "movsx":
                    lines.append(f"    {dst_rc[0]} = aether_i32({rhs});")
                else:
                    lines.append(f"    {dst_rc[0]} = aether_u32({rhs});")
            else:
                mem_d = _parse_x86_32_mem(ops[0])
                if mem_d:
                    lines.append(f"    aether_mem_write({mem_d[1]}, {mem_d[0]}, {rhs});")
                else:
                    supported = False
        elif m == "lea" and len(ops) == 2:
            dst_rc = _x86_32_reg_canon(ops[0])
            mem_s = _parse_x86_32_mem(ops[1])
            if dst_rc and mem_s:
                lines.append(f"    {dst_rc[0]} = (int64_t)({mem_s[1]});")
            else:
                supported = False
        elif m in ("add", "sub", "xor", "and", "or", "shl", "sal", "shr", "sar", "imul") and len(ops) in (2, 3):
            if m == "imul" and len(ops) == 3:
                dst_rc = _x86_32_reg_canon(ops[0])
                r1 = _x86_32_op_read(ops[1])
                r2 = _x86_32_op_read(ops[2])
                if dst_rc:
                    lines.append(f"    {dst_rc[0]} = aether_u32(aether_i32({r1}) * aether_i32({r2}));")
                    continue
            dst_rc = _x86_32_reg_canon(ops[0])
            rhs = _x86_32_op_read(ops[1])
            if dst_rc:
                dv = dst_rc[0]
                if m == "xor" and ops[0].lower() == ops[1].lower():
                    lines.append(f"    {dv} = 0;")
                elif m == "imul":
                    lines.append(f"    {dv} = aether_u32(aether_i32({dv}) * aether_i32({rhs}));")
                elif m in ("shl", "sal"):
                    lines.append(f"    {dv} = aether_u32(aether_u32({dv}) << (({rhs}) & 31));")
                elif m == "shr":
                    lines.append(f"    {dv} = aether_u32(aether_u32({dv}) >> (({rhs}) & 31));")
                elif m == "sar":
                    lines.append(f"    {dv} = aether_u32(aether_i32({dv}) >> (({rhs}) & 31));")
                else:
                    op_c = {"add": "+", "sub": "-", "xor": "^", "and": "&", "or": "|"}[m]
                    if dv == "rsp":
                        lines.append(f"    rsp = (rsp) {op_c} ({rhs});")
                    else:
                        lines.append(f"    {dv} = aether_u32(aether_u32({dv}) {op_c} aether_u32({rhs}));")
            else:
                supported = False
        elif m in ("inc", "dec", "neg", "not") and len(ops) == 1:
            dst_rc = _x86_32_reg_canon(ops[0])
            if dst_rc:
                dv = dst_rc[0]
                if m == "inc":
                    lines.append(f"    {dv} = aether_u32({dv} + 1);")
                elif m == "dec":
                    lines.append(f"    {dv} = aether_u32({dv} - 1);")
                elif m == "neg":
                    lines.append(f"    {dv} = aether_u32(-(aether_i32({dv})));")
                else:
                    lines.append(f"    {dv} = aether_u32(~(aether_u32({dv})));")
            else:
                supported = False
        elif m == "cmp" and len(ops) == 2:
            lines.append(f"    cmp_lhs = aether_i32({_x86_32_op_read(ops[0])}); cmp_rhs = aether_i32({_x86_32_op_read(ops[1])});")
        elif m == "test" and len(ops) == 2:
            r0 = _x86_32_op_read(ops[0])
            r1 = _x86_32_op_read(ops[1])
            lines.append(f"    cmp_lhs = aether_i32(({r0}) & ({r1})); cmp_rhs = 0;")
        elif m == "jmp" and len(ops) == 1 and re.fullmatch(r"0x[0-9a-fA-F]+", ops[0]):
            tgt = int(ops[0], 16)
            if tgt in all_addrs:
                lines.append(f"    if (1) goto L_{tgt:x};")
            else:
                called_set.add(tgt)
                sym = sym_map.get(tgt, f"sub_{tgt:x}")
                lines.append(f"    return {sym}(aether_mem_read(rsp + 4, 4), aether_mem_read(rsp + 8, 4), aether_mem_read(rsp + 12, 4), aether_mem_read(rsp + 16, 4));")
        elif m in _CC_32 and len(ops) == 1 and re.fullmatch(r"0x[0-9a-fA-F]+", ops[0]):
            tgt = int(ops[0], 16)
            if tgt in all_addrs:
                lines.append(f"    if ({_CC_32[m]}) goto L_{tgt:x};")
            else:
                supported = False
        elif m == "call" and len(ops) == 1 and re.fullmatch(r"0x[0-9a-fA-F]+", ops[0]):
            tgt = int(ops[0], 16)
            called_set.add(tgt)
            sym = sym_map.get(tgt, f"sub_{tgt:x}")
            lines.append(f"    rax = {sym}(aether_mem_read(rsp, 4), aether_mem_read(rsp + 4, 4), aether_mem_read(rsp + 8, 4), aether_mem_read(rsp + 12, 4));")
        elif m in ("ret", "retn", "retf", "leave"):
            if m == "leave":
                lines.append("    rsp = rbp; rbp = aether_mem_read(rsp, 4); rsp = (rsp) + (4);")
            else:
                lines.append("    _aether_sp = _aether_saved_sp;")
                lines.append("    return aether_i32(rax);")
        else:
            supported = False

    lines.append("    _aether_sp = _aether_saved_sp;")
    lines.append("    return aether_i32(rax);")
    lines.append("}")
    return "\n".join(lines), insns, supported, called_set, ro_set


def eval_x86_32_insns(
    insns: List[Any],
    args: Tuple[int, ...],
    mem_arena: Any,
    *,
    halt_info: Optional[Dict[str, bool]] = None,
    max_steps: int = 8000,
) -> int:
    """Deterministic Python x86-32 simulator matching cdecl lifted semantics."""
    regs: Dict[str, int] = {
        "eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "esi": 0, "edi": 0,
        "ebp": 0, "esp": 0x48000 - 8,
    }
    for idx in range(4):
        av = (args[idx] & _MASK32) if idx < len(args) else 0
        mem_arena.write(regs["esp"] + 4 + idx * 4, 4, av)

    addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
    cmp_lhs, cmp_rhs = 0, 0

    def _r_canon(t: str) -> Optional[str]:
        s = t.strip().lower()
        return s if s in regs else None

    def _read(op: str) -> int:
        s = op.strip().lower()
        if s in regs:
            return regs[s] & _MASK32
        mem = _parse_x86_32_mem(s)
        if mem:
            w, expr = mem
            ev = expr
            for k, v in regs.items():
                canon = _x86_32_reg_canon(k)
                if canon:
                    ev = re.sub(rf"\b{canon[0]}\b", str(v), ev)
            addr = int(eval(ev, {"__builtins__": {}}, {}))
            return int(mem_arena.read(addr, w)) & ((1 << (w * 8)) - 1)
        try:
            return int(s, 0) & _MASK32
        except Exception:
            return 0

    pc = 0
    steps = 0
    while 0 <= pc < len(insns) and steps < max_steps:
        steps += 1
        ins = insns[pc]
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        nxt = pc + 1

        if m in ("nop", "endbr32", "cdq"):
            pass
        elif m == "push" and len(ops) == 1:
            v = _read(ops[0])
            regs["esp"] -= 4
            mem_arena.write(regs["esp"], 4, v)
        elif m == "pop" and len(ops) == 1:
            rc = _r_canon(ops[0])
            if rc:
                regs[rc] = mem_arena.read(regs["esp"], 4) & _MASK32
                regs["esp"] += 4
        elif m == "leave":
            regs["esp"] = regs["ebp"]
            regs["ebp"] = mem_arena.read(regs["esp"], 4) & _MASK32
            regs["esp"] += 4
        elif m in ("mov", "movzx", "movsx") and len(ops) == 2:
            rc = _r_canon(ops[0])
            val = _read(ops[1])
            if rc:
                regs[rc] = val & _MASK32
            else:
                mem = _parse_x86_32_mem(ops[0])
                if mem:
                    w, expr = mem
                    ev = expr
                    for k, v in regs.items():
                        canon = _x86_32_reg_canon(k)
                        if canon:
                            ev = re.sub(rf"\b{canon[0]}\b", str(v), ev)
                    addr = int(eval(ev, {"__builtins__": {}}, {}))
                    mem_arena.write(addr, w, val)
        elif m == "lea" and len(ops) == 2:
            rc = _r_canon(ops[0])
            mem = _parse_x86_32_mem(ops[1])
            if rc and mem:
                ev = mem[1]
                for k, v in regs.items():
                    canon = _x86_32_reg_canon(k)
                    if canon:
                        ev = re.sub(rf"\b{canon[0]}\b", str(v), ev)
                regs[rc] = int(eval(ev, {"__builtins__": {}}, {})) & _MASK32
        elif m in ("add", "sub", "xor", "and", "or", "shl", "sal", "shr", "sar", "imul"):
            if m == "imul" and len(ops) == 3:
                rc = _r_canon(ops[0])
                if rc:
                    regs[rc] = (ctypes.c_int32(_read(ops[1])).value * ctypes.c_int32(_read(ops[2])).value) & _MASK32
            else:
                rc = _r_canon(ops[0])
                if rc:
                    a = regs[rc]
                    b = _read(ops[1])
                    if m == "add":
                        regs[rc] = (a + b) & _MASK32
                    elif m == "sub":
                        regs[rc] = (a - b) & _MASK32
                    elif m == "xor":
                        regs[rc] = (a ^ b) & _MASK32
                    elif m == "and":
                        regs[rc] = (a & b) & _MASK32
                    elif m == "or":
                        regs[rc] = (a | b) & _MASK32
                    elif m in ("shl", "sal"):
                        regs[rc] = (a << (b & 31)) & _MASK32
                    elif m == "shr":
                        regs[rc] = ((a & _MASK32) >> (b & 31)) & _MASK32
                    elif m == "sar":
                        regs[rc] = (ctypes.c_int32(a).value >> (b & 31)) & _MASK32
                    elif m == "imul":
                        regs[rc] = (ctypes.c_int32(a).value * ctypes.c_int32(b).value) & _MASK32
        elif m in ("inc", "dec", "neg", "not") and len(ops) == 1:
            rc = _r_canon(ops[0])
            if rc:
                a = regs[rc]
                if m == "inc":
                    regs[rc] = (a + 1) & _MASK32
                elif m == "dec":
                    regs[rc] = (a - 1) & _MASK32
                elif m == "neg":
                    regs[rc] = (-ctypes.c_int32(a).value) & _MASK32
                else:
                    regs[rc] = (~a) & _MASK32
        elif m == "cmp" and len(ops) == 2:
            cmp_lhs, cmp_rhs = ctypes.c_int32(_read(ops[0])).value, ctypes.c_int32(_read(ops[1])).value
        elif m == "test" and len(ops) == 2:
            cmp_lhs, cmp_rhs = ctypes.c_int32(_read(ops[0]) & _read(ops[1])).value, 0
        elif m == "jmp" and len(ops) == 1:
            tgt = int(ops[0], 0) if re.fullmatch(r"0x[0-9a-fA-F]+", ops[0]) else -1
            if tgt in addr_to_idx:
                nxt = addr_to_idx[tgt]
            else:
                break
        elif m.startswith("j") and len(ops) == 1:
            tgt = int(ops[0], 0) if re.fullmatch(r"0x[0-9a-fA-F]+", ops[0]) else -1
            ul, ur = cmp_lhs & _MASK32, cmp_rhs & _MASK32
            take = {
                "je": cmp_lhs == cmp_rhs, "jz": cmp_lhs == cmp_rhs,
                "jne": cmp_lhs != cmp_rhs, "jnz": cmp_lhs != cmp_rhs,
                "jl": cmp_lhs < cmp_rhs, "jle": cmp_lhs <= cmp_rhs,
                "jg": cmp_lhs > cmp_rhs, "jge": cmp_lhs >= cmp_rhs,
                "jb": ul < ur, "jc": ul < ur, "jbe": ul <= ur,
                "ja": ul > ur, "jae": ul >= ur, "jnc": ul >= ur,
            }.get(m, False)
            if take and tgt in addr_to_idx:
                nxt = addr_to_idx[tgt]
        elif m in ("ret", "retn", "retf"):
            break
        pc = nxt

    if halt_info is not None and steps >= max_steps and 0 <= pc < len(insns):
        halt_info["fuel_exhausted"] = True
    return ctypes.c_int32(regs["eax"]).value


def _rv_reg(tok: str) -> Optional[str]:
    t = tok.strip().lower()
    if t in ("zero", "x0"):
        return "0"
    aliases = {
        "ra": "x1", "sp": "rsp", "x2": "rsp", "gp": "x3", "tp": "x4",
        "t0": "x5", "t1": "x6", "t2": "x7", "s0": "rbp", "fp": "rbp", "x8": "rbp", "s1": "x9",
        "a0": "x10", "a1": "x11", "a2": "x12", "a3": "x13",
        "a4": "x14", "a5": "x15", "a6": "x16", "a7": "x17",
        "t3": "x28", "t4": "x29", "t5": "x30",
    }
    if t in aliases:
        return aliases[t]
    m = re.fullmatch(r"x(\d{1,2})", t)
    if m and 1 <= int(m.group(1)) <= 30:
        return f"x{int(m.group(1))}"
    return None


def lift_riscv64_function_to_c(
    fn_name: str,
    code_bytes: bytes,
    base_va: int,
    *,
    rva_to_symbol: Optional[Dict[int, str]] = None,
) -> Tuple[str, List[Any], bool, Set[int], Set[int]]:
    """Lifts RISC-V RV64GC machine code into canonical AetherRE C."""
    md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)
    md.detail = False
    insns: List[Any] = []
    for ins in md.disasm(code_bytes, base_va):
        insns.append(ins)
        if ins.mnemonic in ("ret", "c.jr", "jr") and ("ra" in ins.op_str or ins.mnemonic == "ret"):
            break
        if len(insns) >= 600:
            break
    if not insns:
        return f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{ return 0; }}", [], False, set(), set()

    all_addrs = {i.address for i in insns}
    called_set: Set[int] = set()
    sym_map = rva_to_symbol or {}
    lines = [
        f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{",
        "    int64_t " + ", ".join(f"x{i} = 0" for i in range(1, 31)) + ";",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t rbp = 0;",
        "    x10 = rcx; x11 = rdx; x12 = r8; x13 = r9;",
    ]
    supported = True
    for ins in insns:
        lines.append(f"L_{ins.address:x}: ; /* {ins.mnemonic} {ins.op_str} */")
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        if m in ("nop", "c.nop"):
            continue
        elif m in ("ret",) or (m in ("jr", "c.jr") and len(ops) == 1 and ops[0].lower() == "ra"):
            lines.append("    _aether_sp = _aether_saved_sp;")
            lines.append("    return x10;")
        elif m in ("mv", "c.mv", "li", "c.li") and len(ops) == 2:
            d = _rv_reg(ops[0])
            s = _rv_reg(ops[1]) or ops[1]
            if d and d != "0":
                lines.append(f"    {d} = (int64_t)({s});")
        elif m in ("addi", "add", "c.add", "c.addi", "addw", "addiw", "sub", "c.sub", "subw", "mul", "mulw", "and", "andi", "or", "ori", "xor", "xori", "sll", "slli", "srl", "srli", "sra", "srai", "slt", "sltu", "slti", "sltiu"):
            if len(ops) == 2:
                d = _rv_reg(ops[0])
                r = _rv_reg(ops[1]) or ops[1]
                s1 = d
            elif len(ops) == 3:
                d = _rv_reg(ops[0])
                s1 = _rv_reg(ops[1]) or ops[1]
                r = _rv_reg(ops[2]) or ops[2]
            else:
                supported = False
                continue
            if not d or d == "0":
                continue
            op_map = {
                "addi": "+", "add": "+", "c.add": "+", "c.addi": "+", "addw": "+", "addiw": "+",
                "sub": "-", "c.sub": "-", "subw": "-", "mul": "*", "mulw": "*",
                "and": "&", "andi": "&", "or": "|", "ori": "|", "xor": "^", "xori": "^",
                "sll": "<<", "slli": "<<", "srl": ">>", "srli": ">>", "sra": ">>", "srai": ">>",
            }
            if m in ("slt", "slti"):
                lines.append(f"    {d} = ((int64_t)({s1}) < (int64_t)({r})) ? 1LL : 0LL;")
            elif m in ("sltu", "sltiu"):
                lines.append(f"    {d} = ((uint64_t)({s1}) < (uint64_t)({r})) ? 1LL : 0LL;")
            elif m in ("srl", "srli"):
                lines.append(f"    {d} = (int64_t)(((uint64_t)({s1})) >> (({r}) & 63));")
            elif m in ("addw", "addiw", "subw", "mulw"):
                lines.append(f"    {d} = (int64_t)(int32_t)(({s1}) {op_map[m]} ({r}));")
            else:
                lines.append(f"    {d} = (int64_t)(({s1}) {op_map[m]} ({r}));")
        elif m in ("lui", "auipc") and len(ops) == 2:
            d = _rv_reg(ops[0])
            if d and d != "0":
                imm_v = int(ops[1], 0) if re.fullmatch(r"-?(?:0x[0-9a-fA-F]+|\d+)", ops[1]) else 0
                val_e = f"(int64_t)((int32_t)({imm_v} << 12))" if m == "lui" else f"(int64_t)({ins.address}LL + ((int32_t)({imm_v} << 12)))"
                lines.append(f"    {d} = {val_e};")
        elif m in ("beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez") and len(ops) >= 2:
            if m in ("beqz", "bnez") and len(ops) == 2:
                r1 = _rv_reg(ops[0]) or "0"
                r2 = "0"
                tgt_s = ops[1]
                c_op = "==" if m == "beqz" else "!="
            elif len(ops) == 3:
                r1 = _rv_reg(ops[0]) or "0"
                r2 = _rv_reg(ops[1]) or "0"
                tgt_s = ops[2]
                c_op = {"beq": "==", "bne": "!=", "blt": "<", "bge": ">=", "bltu": "<", "bgeu": ">="}[m]
            else:
                supported = False
                continue
            try:
                tgt = int(tgt_s, 0)
            except Exception:
                tgt = -1
            if tgt in all_addrs:
                cmp_e = (
                    f"((uint64_t)({r1}) {c_op} (uint64_t)({r2}))"
                    if m.endswith("u")
                    else f"(({r1}) {c_op} ({r2}))"
                )
                lines.append(f"    if ({cmp_e}) goto L_{tgt:x};")
        elif m in ("j", "c.j", "jal", "c.jal") and len(ops) >= 1:
            tgt_s = ops[-1]
            try:
                tgt = int(tgt_s, 0)
            except Exception:
                tgt = -1
            if m in ("jal", "c.jal") and len(ops) == 2:
                called_set.add(tgt)
                sym = sym_map.get(tgt, f"sub_{tgt:x}")
                lines.append(f"    x10 = {sym}(x10, x11, x12, x13);")
            elif tgt in all_addrs:
                lines.append(f"    if (1) goto L_{tgt:x};")
        elif m in ("ld", "lw", "lwu", "lh", "lhu", "lb", "lbu", "sd", "sw", "sh", "sb") and len(ops) == 2:
            rd = _rv_reg(ops[0]) or "x10"
            mm = re.match(r"(-?(?:0x[0-9a-fA-F]+|\d+))\(([^)]+)\)", ops[1])
            if mm:
                off_s, base_r = mm.group(1), (_rv_reg(mm.group(2)) or "rsp")
                w = 8 if m in ("ld", "sd") else (4 if m in ("lw", "lwu", "sw") else (2 if m in ("lh", "lhu", "sh") else 1))
                if m in ("ld", "lw", "lwu", "lh", "lhu", "lb", "lbu"):
                    raw_read = f"aether_mem_read(({base_r}) + ({off_s}), {w})"
                    if m == "lbu":
                        lines.append(f"    {rd} = (({raw_read}) & 0xFFULL);")
                    elif m == "lb":
                        lines.append(f"    {rd} = (int64_t)(int8_t)(({raw_read}) & 0xFFULL);")
                    elif m == "lhu":
                        lines.append(f"    {rd} = (({raw_read}) & 0xFFFFULL);")
                    elif m == "lh":
                        lines.append(f"    {rd} = (int64_t)(int16_t)(({raw_read}) & 0xFFFFULL);")
                    elif m == "lwu":
                        lines.append(f"    {rd} = (({raw_read}) & 0xFFFFFFFFULL);")
                    elif m == "lw":
                        lines.append(f"    {rd} = (int64_t)(int32_t)(({raw_read}) & 0xFFFFFFFFULL);")
                    else:
                        lines.append(f"    {rd} = {raw_read};")
                else:
                    lines.append(f"    aether_mem_write(({base_r}) + ({off_s}), {w}, {rd});")
            else:
                supported = False
        elif m in ("lr.w", "lr.d", "amoadd.w", "amoadd.d", "amoswap.w", "amoswap.d") and len(ops) >= 2:
            rd = _rv_reg(ops[0]) or "x10"
            addr_tok = ops[-1].strip("()")
            addr_r = _rv_reg(addr_tok) or "rsp"
            w = 8 if m.endswith(".d") else 4
            if m.startswith("lr."):
                lines.append(f"    {rd} = aether_mem_read({addr_r}, {w});")
            else:
                rs = _rv_reg(ops[1]) or "0"
                lines.append(f"    {{ int64_t _old = aether_mem_read({addr_r}, {w});")
                lines.append(f"      aether_mem_write({addr_r}, {w}, {'_old + ' + rs if 'amoadd' in m else rs});")
                if rd != "0":
                    lines.append(f"      {rd} = _old; }}")
                else:
                    lines.append("    }")
        else:
            supported = False
    lines.append("    _aether_sp = _aether_saved_sp;")
    lines.append("    return x10;")
    lines.append("}")
    return "\n".join(lines), insns, supported, called_set, set()


def eval_riscv64_insns(
    insns: List[Any],
    args: Tuple[int, ...],
    mem_arena: Any,
    *,
    halt_info: Optional[Dict[str, bool]] = None,
    max_steps: int = 8000,
) -> int:
    regs: Dict[str, int] = {f"x{i}": 0 for i in range(1, 31)}
    regs["rsp"] = 0x48000 - 8
    regs["rbp"] = 0
    for idx, ar in enumerate(("x10", "x11", "x12", "x13")):
        if idx < len(args):
            regs[ar] = ctypes.c_int64(args[idx]).value

    def _rv_get(tok: str) -> int:
        c = _rv_reg(tok)
        if c == "0":
            return 0
        if c in regs:
            return regs[c]
        try:
            return int(tok, 0)
        except Exception:
            return 0

    addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
    pc, steps = 0, 0
    while 0 <= pc < len(insns) and steps < max_steps:
        steps += 1
        ins = insns[pc]
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        nxt = pc + 1
        if m == "ret" or (m in ("jr", "c.jr") and len(ops) == 1 and ops[0].lower() == "ra"):
            break
        elif m in ("mv", "c.mv", "li", "c.li") and len(ops) == 2:
            d = _rv_reg(ops[0])
            if d and d != "0":
                regs[d] = ctypes.c_int64(_rv_get(ops[1])).value
        elif m in ("addi", "add", "c.add", "c.addi", "addw", "addiw", "sub", "c.sub", "subw", "mul", "mulw", "and", "andi", "or", "ori", "xor", "xori", "sll", "slli", "srl", "srli", "sra", "srai", "slt", "sltu", "slti", "sltiu"):
            if len(ops) == 2:
                d, s1, s2 = _rv_reg(ops[0]), _rv_get(ops[0]), _rv_get(ops[1])
            else:
                d, s1, s2 = _rv_reg(ops[0]), _rv_get(ops[1]), _rv_get(ops[2])
            if d and d != "0":
                if m in ("addi", "add", "c.add", "c.addi"):
                    regs[d] = ctypes.c_int64(s1 + s2).value
                elif m in ("addw", "addiw"):
                    regs[d] = ctypes.c_int64(ctypes.c_int32(s1 + s2).value).value
                elif m in ("sub", "c.sub"):
                    regs[d] = ctypes.c_int64(s1 - s2).value
                elif m == "subw":
                    regs[d] = ctypes.c_int64(ctypes.c_int32(s1 - s2).value).value
                elif m == "mul":
                    regs[d] = ctypes.c_int64(s1 * s2).value
                elif m == "mulw":
                    regs[d] = ctypes.c_int64(ctypes.c_int32(s1 * s2).value).value
                elif m in ("slt", "slti"):
                    regs[d] = 1 if s1 < s2 else 0
                elif m in ("sltu", "sltiu"):
                    regs[d] = 1 if (s1 & _MASK64) < (s2 & _MASK64) else 0
                elif m in ("and", "andi"):
                    regs[d] = ctypes.c_int64(s1 & s2).value
                elif m in ("or", "ori"):
                    regs[d] = ctypes.c_int64(s1 | s2).value
                elif m in ("xor", "xori"):
                    regs[d] = ctypes.c_int64(s1 ^ s2).value
                elif m in ("sll", "slli"):
                    regs[d] = ctypes.c_int64(s1 << (s2 & 63)).value
                elif m in ("srl", "srli"):
                    regs[d] = ctypes.c_int64((s1 & _MASK64) >> (s2 & 63)).value
                elif m in ("sra", "srai"):
                    regs[d] = ctypes.c_int64(s1 >> (s2 & 63)).value
        elif m in ("lui", "auipc") and len(ops) == 2:
            d = _rv_reg(ops[0])
            if d and d != "0":
                imm_v = _rv_get(ops[1])
                base_p = ins.address if m == "auipc" else 0
                regs[d] = ctypes.c_int64(base_p + ctypes.c_int32(imm_v << 12).value).value
        elif m in ("beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez"):
            if m in ("beqz", "bnez"):
                v1, v2, tgt_s = _rv_get(ops[0]), 0, ops[1]
                take = (v1 == 0) if m == "beqz" else (v1 != 0)
            else:
                v1, v2, tgt_s = _rv_get(ops[0]), _rv_get(ops[1]), ops[2]
                take = {
                    "beq": v1 == v2, "bne": v1 != v2, "blt": v1 < v2, "bge": v1 >= v2,
                    "bltu": (v1 & _MASK64) < (v2 & _MASK64), "bgeu": (v1 & _MASK64) >= (v2 & _MASK64),
                }[m]
            try:
                tgt = int(tgt_s, 0)
                if take and tgt in addr_to_idx:
                    nxt = addr_to_idx[tgt]
            except Exception:
                pass
        elif m in ("j", "c.j") and len(ops) == 1:
            try:
                tgt = int(ops[0], 0)
                if tgt in addr_to_idx:
                    nxt = addr_to_idx[tgt]
            except Exception:
                pass
        elif m in ("ld", "lw", "lwu", "lh", "lhu", "lb", "lbu", "sd", "sw", "sh", "sb") and len(ops) == 2:
            mm = re.match(r"(-?(?:0x[0-9a-fA-F]+|\d+))\(([^)]+)\)", ops[1])
            if mm:
                addr = _rv_get(mm.group(2)) + int(mm.group(1), 0)
                w = 8 if m in ("ld", "sd") else (4 if m in ("lw", "lwu", "sw") else (2 if m in ("lh", "lhu", "sh") else 1))
                if m in ("ld", "lw", "lwu", "lh", "lhu", "lb", "lbu"):
                    d = _rv_reg(ops[0])
                    if d and d != "0":
                        rv_raw = mem_arena.read(addr, w)
                        if m == "lbu":
                            regs[d] = rv_raw & 0xFF
                        elif m == "lb":
                            regs[d] = ctypes.c_int64(ctypes.c_int8(rv_raw & 0xFF).value).value
                        elif m == "lhu":
                            regs[d] = rv_raw & 0xFFFF
                        elif m == "lh":
                            regs[d] = ctypes.c_int64(ctypes.c_int16(rv_raw & 0xFFFF).value).value
                        elif m == "lwu":
                            regs[d] = rv_raw & 0xFFFFFFFF
                        elif m == "lw":
                            regs[d] = ctypes.c_int64(ctypes.c_int32(rv_raw & 0xFFFFFFFF).value).value
                        else:
                            regs[d] = ctypes.c_int64(rv_raw).value
                else:
                    mem_arena.write(addr, w, _rv_get(ops[0]))
        pc = nxt
    if halt_info is not None and steps >= max_steps and 0 <= pc < len(insns):
        halt_info["fuel_exhausted"] = True
    return ctypes.c_int64(regs["x10"]).value


def lift_arm32_function_to_c(
    fn_name: str,
    code_bytes: bytes,
    base_va: int,
    *,
    thumb: bool = False,
    rva_to_symbol: Optional[Dict[int, str]] = None,
) -> Tuple[str, List[Any], bool, Set[int], Set[int]]:
    """Lifts ARM32 / Thumb-2 machine code into AetherRE C (using x0..x15 / rsp)."""
    mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM
    md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    md.detail = False
    insns: List[Any] = []
    for ins in md.disasm(code_bytes, base_va):
        insns.append(ins)
        if ins.mnemonic.lower() in ("bx",) and "lr" in ins.op_str.lower():
            break
        if len(insns) >= 600:
            break
    if not insns:
        return f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{ return 0; }}", [], False, set(), set()

    def _a32_reg(tok: str) -> str:
        t = tok.strip().lower()
        m_ap = {"r0": "x0", "r1": "x1", "r2": "x2", "r3": "x3", "r4": "x4", "r5": "x5", "r6": "x6", "r7": "x7",
                "r8": "x8", "r9": "x9", "r10": "x10", "r11": "x11", "fp": "x11", "r12": "x12", "ip": "x12",
                "sp": "rsp", "r13": "rsp", "lr": "x30", "r14": "x30"}
        if t in m_ap:
            return m_ap[t]
        if t.startswith("#"):
            return t[1:]
        return t

    lines = [
        f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{",
        "    int64_t " + ", ".join(f"x{i} = 0" for i in range(16)) + ", x30 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
        "    x0 = rcx; x1 = rdx; x2 = r8; x3 = r9;",
    ]
    all_addrs = {i.address for i in insns}
    called_set: Set[int] = set()
    sym_map = rva_to_symbol or {}
    supported = True
    for ins in insns:
        lines.append(f"L_{ins.address:x}: ; /* {ins.mnemonic} {ins.op_str} */")
        m = ins.mnemonic.lower().split(".")[0]
        ops = _split_arm64_ops(ins.op_str)
        if m == "nop":
            continue
        elif m == "bx" and len(ops) == 1 and ops[0].lower() == "lr":
            lines.append("    _aether_sp = _aether_saved_sp;")
            lines.append("    return x0;")
        elif m == "mov" and len(ops) == 2:
            lines.append(f"    {_a32_reg(ops[0])} = aether_u32({_a32_reg(ops[1])});")
        elif m in ("add", "sub", "mul", "and", "orr", "eor") and len(ops) == 3:
            c_op = {"add": "+", "sub": "-", "mul": "*", "and": "&", "orr": "|", "eor": "^"}[m]
            lines.append(f"    {_a32_reg(ops[0])} = aether_u32(({_a32_reg(ops[1])}) {c_op} ({_a32_reg(ops[2])}));")
        elif m == "cmp" and len(ops) == 2:
            lines.append(f"    cmp_lhs = aether_i32({_a32_reg(ops[0])}); cmp_rhs = aether_i32({_a32_reg(ops[1])});")
        elif m in ("ldr", "ldrb", "ldrh", "str", "strb", "strh") and len(ops) == 2 and ops[1].startswith("["):
            rd = _a32_reg(ops[0])
            inner = ops[1].strip("[]")
            mparts = [p.strip() for p in inner.split(",") if p.strip()]
            base_e = _a32_reg(mparts[0]) if mparts else "rsp"
            off_e = _a32_reg(mparts[1]) if len(mparts) >= 2 else "0"
            addr_e = f"({base_e}) + ({off_e})"
            w = 1 if m.endswith("b") else (2 if m.endswith("h") else 4)
            if m.startswith("ldr"):
                lines.append(f"    {rd} = aether_mem_read({addr_e}, {w});")
            else:
                lines.append(f"    aether_mem_write({addr_e}, {w}, {rd});")
        elif m in ("movw", "movt") and len(ops) == 2:
            rd = _a32_reg(ops[0])
            imm_e = _a32_reg(ops[1])
            if m == "movw":
                lines.append(f"    {rd} = (({imm_e}) & 0xFFFFULL);")
            else:
                lines.append(f"    {rd} = (({rd}) & 0xFFFFULL) | (((uint64_t)({imm_e}) & 0xFFFFULL) << 16);")
        elif m in ("lsl", "lsr", "asr") and len(ops) == 3:
            sh_op = {"lsl": "<<", "lsr": ">>", "asr": ">>"}[m]
            if m == "lsr":
                lines.append(f"    {_a32_reg(ops[0])} = aether_u32(((uint32_t){_a32_reg(ops[1])}) >> (({_a32_reg(ops[2])}) & 31));")
            elif m == "asr":
                lines.append(f"    {_a32_reg(ops[0])} = aether_u32(((int32_t){_a32_reg(ops[1])}) >> (({_a32_reg(ops[2])}) & 31));")
            else:
                lines.append(f"    {_a32_reg(ops[0])} = aether_u32(({_a32_reg(ops[1])}) << (({_a32_reg(ops[2])}) & 31));")
        elif m in ("cbz", "cbnz") and len(ops) == 2 and ops[1].startswith("#"):
            tgt = int(ops[1][1:], 0)
            if tgt in all_addrs:
                op_c = "==" if m == "cbz" else "!="
                lines.append(f"    if ((({_a32_reg(ops[0])}) & 0xFFFFFFFFULL) {op_c} 0) goto L_{tgt:x};")
        elif m in ("b", "beq", "bne", "blt", "ble", "bgt", "bge", "blo", "bcc", "bls", "bhi", "bhs", "bcs") and len(ops) == 1 and ops[0].startswith("#"):
            tgt = int(ops[0][1:], 0)
            if tgt in all_addrs:
                cond = "1" if m == "b" else _ARM64_CC_TO_C.get(m[1:], "1")
                lines.append(f"    if ({cond}) goto L_{tgt:x};")
        elif m in ("bl", "blx") and len(ops) == 1 and ops[0].startswith("#"):
            tgt = int(ops[0][1:], 0)
            called_set.add(tgt)
            sym = sym_map.get(tgt, f"sub_{tgt:x}")
            lines.append(f"    x0 = {sym}(x0, x1, x2, x3);")
        else:
            supported = False
    lines.append("    _aether_sp = _aether_saved_sp;")
    lines.append("    return x0;")
    lines.append("}")
    return "\n".join(lines), insns, supported, called_set, set()


def eval_arm32_insns(
    insns: List[Any],
    args: Tuple[int, ...],
    mem_arena: Any,
    *,
    halt_info: Optional[Dict[str, bool]] = None,
    max_steps: int = 8000,
) -> int:
    regs: Dict[str, int] = {f"r{i}": 0 for i in range(15)}
    regs["sp"] = 0x48000 - 8
    for idx in range(4):
        if idx < len(args):
            regs[f"r{idx}"] = args[idx] & _MASK32

    def _get(tok: str) -> int:
        t = tok.strip().lower()
        if t in regs:
            return regs[t]
        if t.startswith("#"):
            return int(t[1:], 0) & _MASK32
        return 0

    addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
    cmp_l, cmp_r = 0, 0
    pc, steps = 0, 0
    while 0 <= pc < len(insns) and steps < max_steps:
        steps += 1
        ins = insns[pc]
        m = ins.mnemonic.lower().split(".")[0]
        ops = _split_arm64_ops(ins.op_str)
        nxt = pc + 1
        if m == "bx" and len(ops) == 1 and ops[0].lower() == "lr":
            break
        elif m == "mov" and len(ops) == 2:
            regs[ops[0].lower()] = _get(ops[1])
        elif m in ("add", "sub", "mul", "and", "orr", "eor") and len(ops) == 3:
            a, b = _get(ops[1]), _get(ops[2])
            res = {"add": a + b, "sub": a - b, "mul": a * b, "and": a & b, "orr": a | b, "eor": a ^ b}[m]
            regs[ops[0].lower()] = res & _MASK32
        elif m == "cmp" and len(ops) == 2:
            cmp_l, cmp_r = ctypes.c_int32(_get(ops[0])).value, ctypes.c_int32(_get(ops[1])).value
        elif m in ("ldr", "ldrb", "ldrh", "str", "strb", "strh") and len(ops) == 2 and ops[1].startswith("["):
            rd = ops[0].lower()
            inner = ops[1].strip("[]")
            mparts = [p.strip() for p in inner.split(",") if p.strip()]
            addr = _get(mparts[0]) + (_get(mparts[1]) if len(mparts) >= 2 else 0)
            w = 1 if m.endswith("b") else (2 if m.endswith("h") else 4)
            if m.startswith("ldr"):
                regs[rd] = mem_arena.read(addr, w) & _MASK32
            else:
                mem_arena.write(addr, w, regs.get(rd, 0))
        elif m in ("movw", "movt") and len(ops) == 2:
            rd = ops[0].lower()
            imm = _get(ops[1]) & 0xFFFF
            if m == "movw":
                regs[rd] = imm
            else:
                regs[rd] = (regs.get(rd, 0) & 0xFFFF) | (imm << 16)
        elif m in ("lsl", "lsr", "asr") and len(ops) == 3:
            a, b = _get(ops[1]), _get(ops[2]) & 31
            if m == "lsl":
                regs[ops[0].lower()] = (a << b) & _MASK32
            elif m == "lsr":
                regs[ops[0].lower()] = ((a & _MASK32) >> b) & _MASK32
            else:
                regs[ops[0].lower()] = (ctypes.c_int32(a).value >> b) & _MASK32
        elif m in ("cbz", "cbnz") and len(ops) == 2 and ops[1].startswith("#"):
            tgt = int(ops[1][1:], 0)
            val = _get(ops[0]) & _MASK32
            take = (val == 0) if m == "cbz" else (val != 0)
            if take and tgt in addr_to_idx:
                nxt = addr_to_idx[tgt]
        elif m in ("b", "beq", "bne", "blt", "ble", "bgt", "bge", "blo", "bcc", "bls", "bhi", "bhs", "bcs") and len(ops) == 1 and ops[0].startswith("#"):
            tgt = int(ops[0][1:], 0)
            u_l, u_r = cmp_l & _MASK32, cmp_r & _MASK32
            take = {
                "b": True, "beq": cmp_l == cmp_r, "bne": cmp_l != cmp_r,
                "blt": cmp_l < cmp_r, "ble": cmp_l <= cmp_r, "bgt": cmp_l > cmp_r, "bge": cmp_l >= cmp_r,
                "blo": u_l < u_r, "bcc": u_l < u_r, "bls": u_l <= u_r,
                "bhi": u_l > u_r, "bhs": u_l >= u_r, "bcs": u_l >= u_r,
            }[m]
            if take and tgt in addr_to_idx:
                nxt = addr_to_idx[tgt]
        pc = nxt
    return ctypes.c_int32(regs["r0"]).value


def lift_mips32_function_to_c(
    fn_name: str,
    code_bytes: bytes,
    base_va: int,
    *,
    big_endian: bool = False,
    rva_to_symbol: Optional[Dict[int, str]] = None,
) -> Tuple[str, List[Any], bool, Set[int], Set[int]]:
    """Lifts MIPS32 (with branch delay-slot reordering) into canonical AetherRE C."""
    mode = capstone.CS_MODE_MIPS32 | (capstone.CS_MODE_BIG_ENDIAN if big_endian else capstone.CS_MODE_LITTLE_ENDIAN)
    md = capstone.Cs(capstone.CS_ARCH_MIPS, mode)
    md.detail = False
    insns = list(ins for _, ins in zip(range(600), md.disasm(code_bytes, base_va)))
    if not insns:
        return f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{ return 0; }}", [], False, set(), set()

    def _m_reg(tok: str) -> str:
        t = tok.strip().lower().lstrip("$")
        mp = {"zero": "0", "at": "x1", "v0": "x2", "v1": "x3",
              "a0": "x4", "a1": "x5", "a2": "x6", "a3": "x7",
              "t0": "x8", "t1": "x9", "t2": "x10", "t3": "x11",
              "s0": "x16", "s1": "x17", "sp": "rsp", "fp": "rbp", "ra": "x30"}
        return mp.get(t, t)

    lines = [
        f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{",
        "    int64_t " + ", ".join(f"x{i} = 0" for i in range(1, 20)) + ", x30 = 0;",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base(), rbp = 0;",
        "    x4 = rcx; x5 = rdx; x6 = r8; x7 = r9;",
    ]
    all_addrs = {i.address for i in insns}

    def _emit_mips_stmt(ins: Any) -> Optional[str]:
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        if m == "nop":
            return None
        if m == "move" and len(ops) == 2:
            return f"    {_m_reg(ops[0])} = aether_i32({_m_reg(ops[1])});"
        if m == "li" and len(ops) == 2:
            return f"    {_m_reg(ops[0])} = (int64_t)({ops[1]});"
        if m == "lui" and len(ops) == 2:
            return f"    {_m_reg(ops[0])} = aether_i32((({ops[1]}) & 0xFFFF) << 16);"
        if m in ("slt", "slti", "sltu", "sltiu") and len(ops) == 3:
            if m.endswith("u"):
                return f"    {_m_reg(ops[0])} = ((uint32_t)({_m_reg(ops[1])}) < (uint32_t)({_m_reg(ops[2])})) ? 1LL : 0LL;"
            return f"    {_m_reg(ops[0])} = ((int32_t)({_m_reg(ops[1])}) < (int32_t)({_m_reg(ops[2])})) ? 1LL : 0LL;"
        if m in ("addu", "addiu", "add", "addi", "subu", "sub", "mul", "and", "andi", "or", "ori", "xor", "xori", "sll", "sllv", "srl", "srlv", "sra", "srav") and len(ops) == 3:
            op_c = {"addu": "+", "addiu": "+", "add": "+", "addi": "+", "subu": "-", "sub": "-", "mul": "*", "and": "&", "andi": "&", "or": "|", "ori": "|", "xor": "^", "xori": "^", "sll": "<<", "sllv": "<<", "srl": ">>", "srlv": ">>", "sra": ">>", "srav": ">>"}[m]
            if m in ("srl", "srlv"):
                return f"    {_m_reg(ops[0])} = aether_i32(((uint32_t)({_m_reg(ops[1])})) >> (({_m_reg(ops[2])}) & 31));"
            return f"    {_m_reg(ops[0])} = aether_i32(({_m_reg(ops[1])}) {op_c} ({_m_reg(ops[2])}));"
        if m in ("lw", "lb", "lbu", "lh", "lhu", "sw", "sb", "sh") and len(ops) == 2:
            mm = re.match(r"(-?(?:0x[0-9a-fA-F]+|\d+))?\(([^)]+)\)", ops[1])
            if mm:
                off_s = mm.group(1) or "0"
                base_r = _m_reg(mm.group(2))
                w = 4 if m in ("lw", "sw") else (2 if m in ("lh", "lhu", "sh") else 1)
                rd = _m_reg(ops[0])
                if m.startswith("l"):
                    if m in ("lbu", "lhu"):
                        mask_s = "0xFFU" if w == 1 else "0xFFFFU"
                        return f"    {rd} = (int64_t)(aether_mem_read(({base_r}) + ({off_s}), {w}) & {mask_s});"
                    return f"    {rd} = aether_i32(aether_mem_read(({base_r}) + ({off_s}), {w}));"
                return f"    aether_mem_write(({base_r}) + ({off_s}), {w}, {rd});"
        return None

    skip_next = False
    for idx, ins in enumerate(insns):
        lines.append(f"L_{ins.address:x}: ; /* {ins.mnemonic} {ins.op_str} */")
        if skip_next:
            skip_next = False
            continue
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        if m == "jr" and ops and "ra" in ops[0].lower():
            if idx + 1 < len(insns):
                ds = _emit_mips_stmt(insns[idx + 1])
                if ds:
                    lines.append(ds)
                skip_next = True
            lines.append("    _aether_sp = _aether_saved_sp;")
            lines.append("    return x2;")
            break
        elif m in ("beq", "bne") and len(ops) == 3:
            if idx + 1 < len(insns):
                ds = _emit_mips_stmt(insns[idx + 1])
                if ds:
                    lines.append(ds)
                skip_next = True
            tgt = int(ops[2], 0) if re.fullmatch(r"0x[0-9a-fA-F]+", ops[2]) else -1
            if tgt in all_addrs:
                cmp_op = "==" if m == "beq" else "!="
                lines.append(f"    if (({_m_reg(ops[0])}) {cmp_op} ({_m_reg(ops[1])})) goto L_{tgt:x};")
        else:
            st = _emit_mips_stmt(ins)
            if st:
                lines.append(st)
    lines.append("    _aether_sp = _aether_saved_sp;")
    lines.append("    return x2;")
    lines.append("}")
    return "\n".join(lines), insns, True, set(), set()


def eval_mips32_insns(insns: List[Any], args: Tuple[int, ...], mem_arena: Any) -> int:
    regs: Dict[str, int] = {"0": 0, "v0": 0, "v1": 0, "a0": 0, "a1": 0, "a2": 0, "a3": 0, "t0": 0, "t1": 0, "t2": 0, "t3": 0, "s0": 0, "s1": 0, "sp": 0x48000 - 8}
    for i, nm in enumerate(("a0", "a1", "a2", "a3")):
        if i < len(args):
            regs[nm] = ctypes.c_int32(args[i]).value

    def _g(t: str) -> int:
        k = t.strip().lower().lstrip("$")
        if k == "zero":
            return 0
        if k in regs:
            return regs[k]
        try:
            return int(k, 0)
        except Exception:
            return 0

    def _step(ins: Any) -> None:
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        if m in ("move", "li") and len(ops) == 2:
            regs[ops[0].strip().lower().lstrip("$")] = ctypes.c_int32(_g(ops[1])).value
        elif m == "lui" and len(ops) == 2:
            regs[ops[0].strip().lower().lstrip("$")] = ctypes.c_int32((_g(ops[1]) & 0xFFFF) << 16).value
        elif m in ("slt", "slti", "sltu", "sltiu") and len(ops) == 3:
            a, b = _g(ops[1]), _g(ops[2])
            res = 1 if ((a & _MASK32) < (b & _MASK32) if m.endswith("u") else a < b) else 0
            regs[ops[0].strip().lower().lstrip("$")] = res
        elif m in ("addu", "addiu", "add", "addi", "subu", "sub", "mul", "and", "andi", "or", "ori", "xor", "xori", "sll", "sllv", "srl", "srlv", "sra", "srav") and len(ops) == 3:
            a, b = _g(ops[1]), _g(ops[2])
            if m in ("srl", "srlv"):
                op_c = (a & _MASK32) >> (b & 31)
            elif m in ("sra", "srav"):
                op_c = a >> (b & 31)
            elif m in ("sll", "sllv"):
                op_c = a << (b & 31)
            else:
                op_c = {"addu": a + b, "addiu": a + b, "add": a + b, "addi": a + b, "subu": a - b, "sub": a - b, "mul": a * b, "and": a & b, "andi": a & b, "or": a | b, "ori": a | b, "xor": a ^ b, "xori": a ^ b}[m]
            regs[ops[0].strip().lower().lstrip("$")] = ctypes.c_int32(op_c).value
        elif m in ("lw", "lb", "lbu", "lh", "lhu", "sw", "sb", "sh") and len(ops) == 2:
            mm = re.match(r"(-?(?:0x[0-9a-fA-F]+|\d+))?\(([^)]+)\)", ops[1])
            if mm:
                addr = _g(mm.group(2)) + (int(mm.group(1), 0) if mm.group(1) else 0)
                w = 4 if m in ("lw", "sw") else (2 if m in ("lh", "lhu", "sh") else 1)
                k = ops[0].strip().lower().lstrip("$")
                if m.startswith("l"):
                    raw_v = mem_arena.read(addr, w)
                    if m == "lbu":
                        regs[k] = raw_v & 0xFF
                    elif m == "lb":
                        regs[k] = ctypes.c_int8(raw_v & 0xFF).value
                    elif m == "lhu":
                        regs[k] = raw_v & 0xFFFF
                    elif m == "lh":
                        regs[k] = ctypes.c_int16(raw_v & 0xFFFF).value
                    else:
                        regs[k] = ctypes.c_int32(raw_v).value
                else:
                    mem_arena.write(addr, w, _g(ops[0]))

    addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
    pc = 0
    for _ in range(8000):
        if not (0 <= pc < len(insns)):
            break
        ins = insns[pc]
        m = ins.mnemonic.lower()
        ops = [o.strip() for o in ins.op_str.split(",")] if ins.op_str else []
        if m == "jr" and ops and "ra" in ops[0].lower():
            if pc + 1 < len(insns):
                _step(insns[pc + 1])
            break
        elif m in ("beq", "bne") and len(ops) == 3:
            take = (_g(ops[0]) == _g(ops[1])) if m == "beq" else (_g(ops[0]) != _g(ops[1]))
            if pc + 1 < len(insns):
                _step(insns[pc + 1])
            tgt = int(ops[2], 0) if re.fullmatch(r"0x[0-9a-fA-F]+", ops[2]) else -1
            if take and tgt in addr_to_idx:
                pc = addr_to_idx[tgt]
                continue
            pc += 2
            continue
        _step(ins)
        pc += 1
    return ctypes.c_int32(regs["v0"]).value


def lift_via_angr_vex_fallback(
    fn_name: str,
    code_bytes: bytes,
    base_va: int = 0x10000,
    arch: str = "amd64",
    *,
    image_bytes: Optional[bytes] = None,
) -> Optional[str]:
    """Universal angr VEX IR / Decompiler fallback supporting full PE/ELF image mapping or raw blob slice."""
    try:
        import angr
        arch_map = {"x86_64": "amd64", "x86_32": "x86", "aarch64": "aarch64", "arm32": "armel", "riscv64": "riscv64", "mips32": "mipsel"}
        angr_arch = arch_map.get(arch, arch)
        if image_bytes and (image_bytes.startswith(b"\x7fELF") or image_bytes.startswith(b"MZ")):
            proj = angr.Project(io.BytesIO(image_bytes), auto_load_libs=False)
            target_va = base_va
            if proj.loader.main_object.min_addr and base_va < proj.loader.main_object.min_addr:
                target_va = proj.loader.main_object.min_addr + base_va
            cfg = proj.analyses.CFGFast(normalize=True, regions=[(target_va, target_va + max(len(code_bytes), 64))])
            fn = cfg.kb.functions.get(target_va) or cfg.kb.functions.get(base_va) or (next(iter(cfg.kb.functions.values()), None))
        else:
            proj = angr.Project(
                io.BytesIO(code_bytes),
                main_opts={"backend": "blob", "arch": angr_arch, "base_addr": base_va, "entry_point": base_va},
                auto_load_libs=False,
            )
            cfg = proj.analyses.CFGFast(normalize=True, regions=[(base_va, base_va + len(code_bytes))])
            fn = cfg.kb.functions.get(base_va) or (next(iter(cfg.kb.functions.values()), None))
        if fn is None:
            return None
        dec = proj.analyses.Decompiler(fn, cfg=cfg.model)
        if dec.codegen and dec.codegen.text:
            return f"/* angr VEX-fallback recovery ({angr_arch}) for {fn_name} */\n{dec.codegen.text}"
    except Exception:
        return None
    return None


def extract_elf_any_metadata(elf_data: bytes) -> Optional[Dict[str, Any]]:
    """Extracts metadata from both ELF64 and ELF32 (x86_32, ARM32, ARM64, x86_64, RISC-V, MIPS)."""
    if len(elf_data) < 52 or elf_data[:4] != b"\x7fELF":
        return None
    if elf_data[4] == 2:
        return extract_elf64_metadata(elf_data)
    if elf_data[4] != 1:
        return None
    ef = ELFFile(io.BytesIO(elf_data))
    em = str(ef.header["e_machine"]).upper()
    if "386" in em:
        arch = "x86_32"
    elif "ARM" in em:
        arch = "arm32"
    elif "MIPS" in em:
        arch = "mips32"
    elif "RISCV" in em:
        arch = "riscv64"
    else:
        arch = em.lower()
    exec_ranges: List[Tuple[int, int]] = []
    ro_ranges: List[Tuple[int, int]] = []
    imported_libs: List[str] = []
    for sec in ef.iter_sections():
        flags, va, sz = int(sec["sh_flags"]), int(sec["sh_addr"]), int(sec["sh_size"])
        if (flags & 0x4) and sz > 0:
            exec_ranges.append((va, va + sz))
        elif (flags & 0x2) and not (flags & 0x1) and sz > 0:
            ro_ranges.append((va, va + sz))
        if sec.name == ".dynamic":
            try:
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        imported_libs.append(str(tag.needed))
            except Exception:
                pass
    exports: List[Dict[str, Any]] = []
    for sec in ef.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if sym["st_info"]["type"] == "STT_FUNC" and sym["st_shndx"] != "SHN_UNDEF" and int(sym["st_value"]) > 0:
                    va = int(sym["st_value"])
                    sz = max(16, int(sym["st_size"]) or 256)
                    for sc in ef.iter_sections():
                        sv, ssz = int(sc["sh_addr"]), int(sc["sh_size"])
                        if sv <= va < sv + ssz and sc["sh_type"] != "SHT_NOBITS":
                            off = int(sc["sh_offset"]) + (va - sv)
                            exports.append({"name": sym.name or f"sub_{va:x}", "ordinal": len(exports) + 1, "rva": va, "size": sz, "code": elf_data[off : off + sz]})
                            break
    return {
        "arch": arch,
        "exports": exports,
        "exec_ranges": exec_ranges,
        "ro_ranges": ro_ranges,
        "eh_frame_bytes": 0,
        "imported_libs": sorted(set(imported_libs)),
        "plt_symbols": {},
    }

