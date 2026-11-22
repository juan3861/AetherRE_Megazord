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
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import capstone
from elftools.elf.elffile import ELFFile
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
    for ins in insns:
        for tok in re.findall(r"\b([xw]\d{1,2}|fp|lr)\b", ins.op_str.lower()):
            ri = _arm64_reg_info(tok)
            if ri and ri[0].startswith("x"):
                used_regs.add(ri[0])

    reg_decls = ", ".join(f"{r} = 0" for r in sorted(used_regs))
    lines = [
        f"int64_t {fn_name}(int64_t rcx, int64_t rdx, int64_t r8, int64_t r9) {{",
        f"    int64_t {reg_decls};",
        "    int64_t _aether_saved_sp = _aether_sp;",
        "    int64_t rsp = aether_stack_base();",
        "    int64_t cmp_lhs = 0, cmp_rhs = 0;",
    ]

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

        pc += 1

    if halt_info is not None and steps >= max_steps and 0 <= pc < len(insns):
        halt_info["fuel_exhausted"] = True
    return ctypes.c_int64(regs["x0"]).value


def extract_elf64_metadata(elf_data: bytes) -> Optional[Dict[str, Any]]:
    """Extracts architecture, exported STT_FUNC symbols, `.rodata` slices, `.eh_frame` & `DT_NEEDED` from ELF64."""
    if len(elf_data) < 64 or elf_data[:4] != b"\x7fELF" or elf_data[4] != 2:
        return None
    ef = ELFFile(io.BytesIO(elf_data))
    e_machine = str(ef.header["e_machine"])
    arch = "aarch64" if "AARCH64" in e_machine.upper() else ("x86_64" if "X86_64" in e_machine.upper() else e_machine)

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

    return {
        "arch": arch,
        "e_type": str(ef.header["e_type"]),
        "exports": exports,
        "exec_ranges": exec_ranges,
        "ro_ranges": ro_ranges,
        "eh_frame_bytes": eh_frame_bytes,
        "imported_libs": sorted(set(imported_libs)),
    }
