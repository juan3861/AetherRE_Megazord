"""Phase II CFG + Dataflow/SSA IR Optimizer for GEAR-23 Lifted Functions.

Operates on lifted basic-block C emitted by ``_lift_x64_function_full`` before
differential AST execution, C-Tree structuring, and native MSVC compilation.
Passes are strictly semantics-preserving:
  1. Basic-block CFG reconstruction & switch/branch target preservation.
  2. CFG cleanup: unreachable block pruning, fallthrough jump elimination,
     jump-to-next removal, jump-threading, and linear block coalescing.
  3. Balanced algebraic & cast redundancy folding (``aether_u32(aether_u32(x))``,
     ``(int64_t)(reg)``, zero-identities, constant arithmetic).
  4. Forward CFG constant propagation (Kildall lattice) + intra-block copy
     propagation + constant-condition branch folding.
  5. Backward CFG liveness analysis & dead assignment / dead flag elimination
     (eliminates unused ``cmp_lhs``/``cmp_rhs``, dead copies, and unused epilog
     register restores while preserving all memory/call/stack side effects).
"""

from __future__ import annotations

import ctypes
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from aether_re.cfg_dominance import find_natural_loops
from aether_re.deobfuscator import detect_opaque_predicate, simplify_mba_expression
from aether_re.ssa_ir import build_ssa_for_cfg_blocks

_TRACKED_VARS: Tuple[str, ...] = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm0_hi", "xmm1_hi", "xmm2_hi", "xmm3_hi", "xmm4_hi", "xmm5_hi", "xmm6_hi", "xmm7_hi",
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    "cmp_lhs", "cmp_rhs",
)
_TRACKED_SET: Set[str] = set(_TRACKED_VARS)

_PURE_HELPERS: Set[str] = {
    "aether_u32", "aether_i32", "aether_i16", "aether_i8", "aether_u16", "aether_u8",
    "aether_bt_cf", "aether_bit_mask", "aether_f64_to_bits", "aether_bits_to_f64",
    "aether_f64_comisd", "aether_f64_to_i32", "aether_i32_to_f64", "aether_f32_to_f64",
    "aether_f64_max", "aether_f64_min", "aether_f64_add", "aether_f64_sub",
    "aether_f64_mul", "aether_f64_div", "aether_pcmpeqb64", "aether_pmaxud64",
    "aether_pcmpeqd64", "aether_psubd64", "aether_tzcnt32", "aether_tzcnt64",
    "aether_ro_ptr", "aether_data_ptr", "aether_fn_ptr", "aether_vtable_ptr",
    "aether_crt_fn_ptr", "aether_mem_read", "aether_stack_base", "aether_set_byte",
    "aether_pow", "aether_fmod", "aether_tolower", "aether_isalpha", "aether_isdigit",
    "aether_isspace", "aether_isxdigit",
}

_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_INT_LIT_RE = re.compile(r"^-?(?:0[xX][0-9a-fA-F]+|\d+)(?:U?LL)?$")
_SIMPLE_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
_COMPOUND_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\+=|-=)\s*(.+)$")
_CAST_I64_ATOM_RE = re.compile(r"\(int64_t\)\(([A-Za-z_][A-Za-z0-9_]*|-?\d+|0[xX][0-9a-fA-F]{1,15}|0[xX][0-7][0-9a-fA-F]{15})\)")
_TYPE_CAST_IDENT_ONLY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class _IRBlock:
    name: str
    label: Optional[str] = None
    pinned_label: bool = False
    stmts: List[str] = field(default_factory=list)
    # kind in {"return", "goto", "cbranch", "fall"}
    term_kind: str = "fall"
    term_cond: str = ""
    term_target: str = ""
    term_ret: str = ""


def _i64(val: int) -> int:
    return ctypes.c_int64(val).value


def _u32(val: int) -> int:
    return val & 0xFFFFFFFF


def _i32(val: int) -> int:
    return ctypes.c_int32(val).value


def _format_c_i64(val: int) -> str:
    val = _i64(val)
    if val == -9223372036854775808:
        return "(-9223372036854775807LL - 1LL)"
    if val < -0x7FFFFFFF or val > 0x7FFFFFFF:
        return f"{val}LL"
    return str(val)


def _extract_identifiers(expr: str, tracked: Set[str] = _TRACKED_SET) -> Set[str]:
    return {m.group(1) for m in _IDENT_RE.finditer(expr) if m.group(1) in tracked}


def _is_pure_rhs(expr: str) -> bool:
    for m in _CALL_RE.finditer(expr):
        fn = m.group(1)
        if fn not in _PURE_HELPERS:
            return False
    return True


def _find_matching_paren(s: str, open_idx: int) -> int:
    depth = 0
    n = len(s)
    for i in range(open_idx, n):
        ch = s[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _strip_outer_parens(s: str) -> str:
    s = s.strip()
    while len(s) >= 2 and s[0] == "(" and _find_matching_paren(s, 0) == len(s) - 1:
        inner = s[1:-1].strip()
        if not inner:
            break
        s = inner
    return s


def _split_top_binop(s: str) -> Optional[Tuple[str, str, str]]:
    """If ``s`` (stripped) has a single top-level binary operator (+,-,^,|,&,<<), split it."""
    s = _strip_outer_parens(s)
    depth = 0
    n = len(s)
    # Only handle clean binary expressions matching our emitted `((lhs) op (rhs))` shape
    i = 0
    while i < n:
        ch = s[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            if s.startswith("<<", i) or s.startswith(">>", i):
                return s[:i].strip(), s[i : i + 2], s[i + 2 :].strip()
            if ch in ("+", "-", "^", "|", "&") and i > 0:
                prev = s[i - 1]
                # Avoid splitting unary +/- on negative numbers or scientific notation
                if prev not in ("(", ",", " ", "e", "E") or (prev == " " and i >= 2):
                    lhs = s[:i].strip()
                    rhs = s[i + 1 :].strip()
                    if lhs and rhs:
                        return lhs, ch, rhs
        i += 1
    return None


def _parse_int_const(s: str) -> Optional[int]:
    s = _strip_outer_parens(s)
    if _INT_LIT_RE.fullmatch(s):
        try:
            raw = re.sub(r"U?LL$", "", s)
            return _i64(int(raw, 0))
        except ValueError:
            return None
    return None


def _simplify_call_wrappers(expr: str) -> str:
    """Folds nested idempotent aether_u32 / aether_i32 wrappers and constant casts."""
    out = expr
    changed = True
    while changed:
        changed = False
        for wrapper in ("aether_u32(", "aether_i32("):
            idx = 0
            while True:
                pos = out.find(wrapper, idx)
                if pos < 0:
                    break
                # Ensure word boundary before wrapper
                if pos > 0 and (out[pos - 1].isalnum() or out[pos - 1] == "_"):
                    idx = pos + len(wrapper)
                    continue
                open_p = pos + len(wrapper) - 1
                close_p = _find_matching_paren(out, open_p)
                if close_p < 0:
                    break
                inner = out[open_p + 1 : close_p].strip()
                cval = _parse_int_const(inner)
                if cval is not None:
                    folded = _u32(cval) if wrapper == "aether_u32(" else _i32(cval)
                    rep = _format_c_i64(folded)
                    out = out[:pos] + rep + out[close_p + 1 :]
                    changed = True
                    break
                # Check redundant nested wrapper:
                # aether_u32(aether_u32(X)) -> aether_u32(X)
                # aether_i32(aether_u32(X)) -> aether_i32(X)
                # aether_i32(aether_i32(X)) -> aether_i32(X)
                inner_s = _strip_outer_parens(inner)
                for sub_w in ("aether_u32(", "aether_i32("):
                    if inner_s.startswith(sub_w) and _find_matching_paren(inner_s, len(sub_w) - 1) == len(inner_s) - 1:
                        if wrapper == "aether_u32(" and sub_w != "aether_u32(":
                            continue
                        sub_arg = inner_s[len(sub_w) : -1].strip()
                        out = out[:pos] + wrapper + sub_arg + ")" + out[close_p + 1 :]
                        changed = True
                        break
                if changed:
                    break
                idx = pos + len(wrapper)
    return out


def _simplify_expr(expr: str, tracked: Set[str] = _TRACKED_SET) -> str:
    """Applies safe algebraic simplifications without altering C or Python semantics."""
    cur = expr.strip()
    for _ in range(4):
        prev = cur
        # Simplify (int64_t)(var_or_literal) -> var_or_literal (canonical regs are already int64_t)
        def _repl_i64(m: re.Match[str]) -> str:
            tok = m.group(1)
            if tok in tracked or _INT_LIT_RE.fullmatch(tok):
                return tok
            return m.group(0)

        cur = _CAST_I64_ATOM_RE.sub(_repl_i64, cur)
        cur = _simplify_call_wrappers(cur)

        # Clean redundant wrapping parens on top-level expression if simple atom/binop
        # First check simple `((X) op (Y))` simplifications recursively on whole expr
        split = _split_top_binop(cur)
        if split is not None:
            lhs, op, rhs = split
            lc = _parse_int_const(lhs)
            rc = _parse_int_const(rhs)
            if lc is not None and rc is not None:
                if op == "+":
                    cur = _format_c_i64(lc + rc)
                elif op == "-":
                    cur = _format_c_i64(lc - rc)
                elif op == "^":
                    cur = _format_c_i64(lc ^ rc)
                elif op == "|":
                    cur = _format_c_i64(lc | rc)
                elif op == "&":
                    cur = _format_c_i64(lc & rc)
                elif op == "<<":
                    cur = _format_c_i64(lc << (rc & 63))
            elif op in ("+", "^", "|") and rc == 0:
                cur = _strip_outer_parens(lhs)
            elif op in ("+", "^", "|") and lc == 0:
                cur = _strip_outer_parens(rhs)
            elif op == "-" and rc == 0:
                cur = _strip_outer_parens(lhs)
            elif op == "&" and rc == 0:
                cur = "0"
            elif op == "&" and lc == 0:
                cur = "0"
            elif op in ("&", "|") and _strip_outer_parens(lhs) == _strip_outer_parens(rhs):
                atom = _strip_outer_parens(lhs)
                if _is_pure_rhs(atom):
                    cur = atom
            elif op == "^" and _strip_outer_parens(lhs) == _strip_outer_parens(rhs):
                atom = _strip_outer_parens(lhs)
                if _is_pure_rhs(atom):
                    cur = "0"
        if cur == prev:
            break
    return cur


def _subst_vars(expr: str, mapping: Dict[str, str]) -> str:
    if not mapping:
        return expr

    def _repl(m: re.Match[str]) -> str:
        tok = m.group(1)
        return mapping.get(tok, tok)

    return _IDENT_RE.sub(_repl, expr)


def _eval_const_condition(cond: str, consts: Dict[str, int], tracked: Set[str] = _TRACKED_SET) -> Optional[bool]:
    """Evaluates pure constant comparison conditions, returning True/False or None."""
    if cond.strip() == "1":
        return True
    if cond.strip() == "0":
        return False
    sub = _subst_vars(cond, {k: str(v) for k, v in consts.items()})
    sub = _simplify_call_wrappers(sub)
    # Only evaluate if zero variables remain
    if _extract_identifiers(sub, tracked) or _CALL_RE.search(sub):
        return None
    py_cond = (
        sub.replace("0xffffffffffffffff", str(0xFFFFFFFFFFFFFFFF))
        .replace("(int64_t)", "")
        .replace("(uint64_t)", "")
    )
    py_cond = re.sub(r"\b(0x[0-9a-fA-F]+|\d+)U?LL\b", r"\1", py_cond)
    if not re.fullmatch(r"[0-9xXa-fA-F\s()+\-*/&|^<>!=~]+", py_cond):
        return None
    try:
        return bool(eval(py_cond, {"__builtins__": {}}, {}))
    except Exception:
        return None


def _parse_c_function(c_code: str) -> Optional[Tuple[List[str], List[_IRBlock], str]]:
    """Splits a lifted C function into (header_lines, ir_blocks, entry_label)."""
    lines = c_code.splitlines()
    if len(lines) < 3:
        return None
    header_lines: List[str] = [lines[0]]
    body_start = 1
    while body_start < len(lines):
        st = lines[body_start].strip()
        if st.startswith(("int64_t ", "double ", "uint8_t ")):
            header_lines.append(lines[body_start])
            body_start += 1
        elif st == "xmm0 = aether_f64_to_bits(xmm0_arg);" or st == "xmm1 = aether_f64_to_bits(xmm1_arg);":
            header_lines.append(lines[body_start])
            body_start += 1
        else:
            break

    # First pass: linear items (label, is_pinned, kind, payload)
    raw_items: List[Tuple[Optional[str], bool, str, str]] = []
    branch_targets: Set[str] = set()
    cur_lbl: Optional[str] = None
    cur_pinned = False

    for raw in lines[body_start:]:
        st = raw.strip()
        if not st or st == "}" or st.startswith("/*"):
            continue
        if st.startswith("L_") and ":" in st:
            if cur_lbl is not None:
                raw_items.append((cur_lbl, cur_pinned, "empty", ""))
            lbl = st.split(":", 1)[0].strip()
            rest = st.split(":", 1)[1].strip()
            is_sw = "_sw" in lbl
            if is_sw:
                branch_targets.add(lbl)
            cur_lbl = lbl
            cur_pinned = is_sw
            # Strip trailing comment if present
            if rest.startswith(";"):
                rest = rest[1:].strip()
            rest = re.sub(r"/\*.*?\*/", "", rest).strip()
            if not rest:
                continue
            st = rest
        else:
            # Strip trailing inline comments outside quotes (C here has no strings)
            st = re.sub(r"/\*.*?\*/", "", st).strip()
            if not st:
                continue

        if st.startswith("if (") and ") goto " in st:
            cond = st[4 : st.index(") goto")].strip()
            tgt = st[st.index("goto ") + 5 : st.rindex(";")].strip()
            branch_targets.add(tgt)
            raw_items.append((cur_lbl, cur_pinned, "branch", f"{cond}::{tgt}"))
            cur_lbl, cur_pinned = None, False
        elif st.startswith("if (") and ") {" in st and st.endswith("}"):
            raw_items.append((cur_lbl, cur_pinned, "cmov", st))
            cur_lbl, cur_pinned = None, False
        elif st.startswith("return "):
            ret_v = st[len("return ") : st.rindex(";")].strip()
            raw_items.append((cur_lbl, cur_pinned, "return", ret_v))
            cur_lbl, cur_pinned = None, False
        else:
            for part in [p.strip() for p in st.split(";") if p.strip()]:
                raw_items.append((cur_lbl, cur_pinned, "stmt", part))
                cur_lbl, cur_pinned = None, False

    if not raw_items:
        return None

    # Ensure entry block gets first label if present
    blocks: List[_IRBlock] = []
    entry_lbl = raw_items[0][0] or "L_entry"
    cur_bb = _IRBlock(name=entry_lbl, label=entry_lbl, pinned_label=True)

    for idx, (lbl, pinned, kind, payload) in enumerate(raw_items):
        if idx > 0 and ((lbl and (lbl in branch_targets or pinned)) or cur_bb.term_kind != "fall"):
            blocks.append(cur_bb)
            bb_lbl = lbl or f"L_opt_bb_{idx}"
            cur_bb = _IRBlock(name=bb_lbl, label=bb_lbl if (lbl and (lbl in branch_targets or pinned)) else None, pinned_label=pinned)

        if kind == "stmt":
            cur_bb.stmts.append(payload)
        elif kind == "cmov":
            cur_bb.stmts.append(payload)
        elif kind == "return":
            cur_bb.term_kind = "return"
            cur_bb.term_ret = payload
        elif kind == "branch":
            cond, tgt = payload.split("::", 1)
            if cond == "1":
                cur_bb.term_kind = "goto"
                cur_bb.term_target = tgt
            else:
                cur_bb.term_kind = "cbranch"
                cur_bb.term_cond = cond
                cur_bb.term_target = tgt

    blocks.append(cur_bb)
    return header_lines, blocks, entry_lbl


def _block_successors(blocks: List[_IRBlock]) -> Tuple[Dict[str, _IRBlock], Dict[str, List[str]]]:
    lbl_map: Dict[str, str] = {}
    name_map: Dict[str, _IRBlock] = {b.name: b for b in blocks}
    for b in blocks:
        if b.label:
            lbl_map[b.label] = b.name
    succs: Dict[str, List[str]] = {b.name: [] for b in blocks}
    for i, b in enumerate(blocks):
        fall_name = blocks[i + 1].name if i + 1 < len(blocks) else None
        if b.term_kind == "return":
            continue
        if b.term_kind == "goto":
            t_name = lbl_map.get(b.term_target)
            if t_name:
                succs[b.name].append(t_name)
        elif b.term_kind == "cbranch":
            t_name = lbl_map.get(b.term_target)
            if t_name:
                succs[b.name].append(t_name)
            if fall_name and fall_name != t_name:
                succs[b.name].append(fall_name)
        else:  # fall
            if fall_name:
                succs[b.name].append(fall_name)
    return name_map, succs


def _cleanup_cfg(blocks: List[_IRBlock], returns_double: bool) -> List[_IRBlock]:
    """Prunes unreachable blocks, eliminates trivial jumps, threads empty jumps, and coalesces blocks."""
    changed = True
    while changed and blocks:
        changed = False
        # 1. Remove jump-to-next-block and cbranch-to-next-block
        for i, b in enumerate(blocks):
            if i + 1 < len(blocks):
                nxt = blocks[i + 1]
                if b.term_kind == "goto" and nxt.label and b.term_target == nxt.label:
                    b.term_kind = "fall"
                    b.term_target = ""
                    changed = True
                elif b.term_kind == "cbranch" and nxt.label and b.term_target == nxt.label:
                    b.term_kind = "fall"
                    b.term_cond = ""
                    b.term_target = ""
                    changed = True

        # 2. Jump threading through empty goto-only blocks
        lbl_to_bb = {b.label: b for b in blocks if b.label}
        for b in blocks:
            if b.term_kind in ("goto", "cbranch") and b.term_target in lbl_to_bb:
                tgt_b = lbl_to_bb[b.term_target]
                seen = {b.name}
                cur_t = tgt_b
                while (
                    not cur_t.stmts
                    and cur_t.term_kind == "goto"
                    and cur_t.term_target in lbl_to_bb
                    and lbl_to_bb[cur_t.term_target].name not in seen
                ):
                    seen.add(cur_t.name)
                    cur_t = lbl_to_bb[cur_t.term_target]
                if cur_t is not tgt_b and cur_t.label:
                    b.term_target = cur_t.label
                    changed = True

        # 3. Unreachable block pruning (keep entry and any switch fallthrough reachable)
        name_map, succs = _block_successors(blocks)
        reachable: Set[str] = set()
        q: deque[str] = deque([blocks[0].name])
        while q:
            u = q.popleft()
            if u in reachable:
                continue
            reachable.add(u)
            for v in succs.get(u, []):
                if v not in reachable:
                    q.append(v)
        # If last block was implicit fallthrough to exit without explicit return, attach default return
        if blocks and blocks[-1].term_kind == "fall":
            blocks[-1].term_kind = "return"
            blocks[-1].term_ret = "aether_bits_to_f64(xmm0)" if returns_double else "rax"

        if len(reachable) < len(blocks):
            blocks = [b for b in blocks if b.name in reachable]
            changed = True
            continue

        # 4. Linear block coalescing (A falls into B, in_degree(B) == 1)
        _, succs = _block_successors(blocks)
        preds_count: Dict[str, int] = {b.name: 0 for b in blocks}
        for u, vs in succs.items():
            for v in vs:
                preds_count[v] = preds_count.get(v, 0) + 1
        merged: List[_IRBlock] = []
        skip_next = False
        for i, b in enumerate(blocks):
            if skip_next:
                skip_next = False
                continue
            if (
                i + 1 < len(blocks)
                and b.term_kind == "fall"
                and preds_count.get(blocks[i + 1].name, 0) == 1
                and not blocks[i + 1].pinned_label
            ):
                nxt = blocks[i + 1]
                b.stmts.extend(nxt.stmts)
                b.term_kind = nxt.term_kind
                b.term_cond = nxt.term_cond
                b.term_target = nxt.term_target
                b.term_ret = nxt.term_ret
                skip_next = True
                changed = True
            merged.append(b)
        blocks = merged

        # 5. Strip dead labels that are no longer referenced by any branch (except entry & pinned _sw)
        referenced = {
            b.term_target for b in blocks if b.term_kind in ("goto", "cbranch") and b.term_target
        }
        for i, b in enumerate(blocks):
            if i > 0 and b.label and not b.pinned_label and b.label not in referenced:
                b.label = None

    return blocks


_BASE_DISP_RE = re.compile(r"^\s*(rbp|rsp)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*$")


def _split_top_args(arg_str: str) -> List[str]:
    args: List[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(arg_str):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(arg_str[start:i].strip())
            start = i + 1
    args.append(arg_str[start:].strip())
    return args


def _rewrite_mem_ops_in_expr(
    expr: str,
    slot_map: Dict[Tuple[str, int], Tuple[str, int]],
    promoted_used: Set[str],
) -> Tuple[str, bool]:
    """Rewrites pure scalar aether_mem_read(base +/- disp, w) calls into promoted slot reads."""
    out = expr
    changed = False
    idx = 0
    while True:
        pos = out.find("aether_mem_read(", idx)
        if pos < 0:
            break
        if pos > 0 and (out[pos - 1].isalnum() or out[pos - 1] == "_"):
            idx = pos + 16
            continue
        open_p = pos + len("aether_mem_read")
        close_p = _find_matching_paren(out, open_p)
        if close_p < 0:
            break
        args = _split_top_args(out[open_p + 1 : close_p])
        if len(args) == 2:
            m_bd = _BASE_DISP_RE.fullmatch(args[0])
            w_val = _parse_int_const(args[1])
            if m_bd and w_val in (4, 8):
                base = m_bd.group(1)
                sign = m_bd.group(2)
                disp_raw = m_bd.group(3)
                off = 0 if not disp_raw else int(disp_raw, 0)
                if sign == "-":
                    off = -off
                info = slot_map.get((base, off))
                if info and info[1] == w_val:
                    slot_var = info[0]
                    promoted_used.add(slot_var)
                    rep = f"aether_u32({slot_var})" if w_val == 4 else slot_var
                    out = out[:pos] + rep + out[close_p + 1 :]
                    changed = True
                    continue
        idx = pos + 16
    return out, changed


def _promote_stack_slots(blocks: List[_IRBlock]) -> Tuple[Set[str], int]:
    """Promotes non-escaping local stack slots ([rbp-off] / [rsp+off]) to SSA virtual scalars."""
    if not blocks:
        return set(), 0

    # Collect all aether_mem_read / aether_mem_write base+offset accesses and check escape safety
    accesses: Dict[str, Dict[int, List[int]]] = {"rbp": {}, "rsp": {}}
    written_offs: Dict[str, Set[int]] = {"rbp": set(), "rsp": set()}
    escaped: Dict[str, bool] = {"rbp": False, "rsp": False}

    # Verify rbp/rsp mutation regions & compute prolog stack frame size (`rsp_frame_bytes`):
    # - rbp may only be assigned once in blocks[0] (`rbp = rsp` or `rbp = (int64_t)(rsp)`)
    # - rsp may only be mutated in blocks[0] (prolog) and return blocks (epilog), never in middle blocks
    rbp_writes = 0
    rsp_frame_ready_idx = 0
    rsp_frame_bytes = 0
    for bi, b in enumerate(blocks):
        for si, st in enumerate(b.stmts):
            m_as = _SIMPLE_ASSIGN_RE.match(st)
            m_cmp = _COMPOUND_ASSIGN_RE.match(st)
            lhs_w = m_as.group(1) if m_as else (m_cmp.group(1) if m_cmp else None)
            if lhs_w == "rbp":
                if bi == 0 and m_as and _strip_outer_parens(m_as.group(2).replace("(int64_t)", "").strip()) == "rsp":
                    rbp_writes += 1
                else:
                    escaped["rbp"] = True
            elif lhs_w == "rsp":
                if bi == 0:
                    rsp_frame_ready_idx = si + 1
                    if m_cmp and m_cmp.group(2) == "-=":
                        dv = _parse_int_const(m_cmp.group(3))
                        if dv is not None and dv > 0:
                            # `rsp -= 8` pushes sit above local `sub rsp, N`
                            pass
                        else:
                            escaped["rsp"] = True
                    elif m_as:
                        rhs_s = _strip_outer_parens(m_as.group(2).replace("(int64_t)", "").strip())
                        sp = _split_top_binop(rhs_s)
                        if sp and sp[1] == "-" and _strip_outer_parens(sp[0]) == "rsp":
                            dv = _parse_int_const(sp[2])
                            if dv is not None and dv > 0:
                                rsp_frame_bytes += dv
                            else:
                                escaped["rsp"] = True
                        else:
                            escaped["rsp"] = True
                    else:
                        escaped["rsp"] = True
                elif b.term_kind != "return":
                    escaped["rsp"] = True
    if rbp_writes != 1:
        escaped["rbp"] = True

    def _scan_stmt_for_mem_and_escape(bi: int, si: int, st: str) -> None:
        # Mask out valid frame prolog/epilog/mem accesses and check if rbp/rsp escapes elsewhere
        masked = st
        # Strip valid stack-arg/sp save/prolog/epilog uses when checking escape
        if bi == 0 and st in ("rbp = rsp", "rbp = (int64_t)(rsp)"):
            return
        if re.fullmatch(r"_aether_sp\s*=\s*rsp", st):
            return
        if bi == 0 and si < rsp_frame_ready_idx and re.match(r"^rsp\s*(?:=|\+=|-=)", st):
            masked = re.sub(r"\brsp\b", "", st, count=1) if st.startswith("rsp =") else ""
        elif blocks[bi].term_kind == "return" and re.match(r"^rsp\s*(?:=|\+=|-=)", st):
            masked = ""

        # Collect aether_mem_write(addr, w, val)
        if masked.startswith("aether_mem_write(") and masked.endswith(")"):
            args = _split_top_args(masked[len("aether_mem_write(") : -1])
            if len(args) == 3:
                m_bd = _BASE_DISP_RE.fullmatch(args[0])
                w_val = _parse_int_const(args[1])
                if m_bd:
                    base = m_bd.group(1)
                    off = 0 if not m_bd.group(3) else int(m_bd.group(3), 0)
                    if m_bd.group(2) == "-":
                        off = -off
                    if base == "rsp" and ((bi == 0 and si < rsp_frame_ready_idx) or off < 0x40):
                        # Prolog save or Win64 shadow/stack-arg home: do not promote, not an escape if < 0x40
                        pass
                    elif w_val in (1, 2, 4, 8):
                        accesses[base].setdefault(off, []).append(w_val)
                        written_offs[base].add(off)
                    else:
                        escaped[base] = True
                    masked = args[2]

        # Scan all aether_mem_read(addr, w)
        scan_s = masked
        while True:
            pos = scan_s.find("aether_mem_read(")
            if pos < 0:
                break
            close_p = _find_matching_paren(scan_s, pos + len("aether_mem_read"))
            if close_p < 0:
                break
            args = _split_top_args(scan_s[pos + len("aether_mem_read(") : close_p])
            if len(args) == 2:
                m_bd = _BASE_DISP_RE.fullmatch(args[0])
                w_val = _parse_int_const(args[1])
                if m_bd:
                    base = m_bd.group(1)
                    off = 0 if not m_bd.group(3) else int(m_bd.group(3), 0)
                    if m_bd.group(2) == "-":
                        off = -off
                    if base == "rsp" and ((bi == 0 and si < rsp_frame_ready_idx) or off < 0x40):
                        pass
                    elif w_val in (1, 2, 4, 8):
                        accesses[base].setdefault(off, []).append(w_val)
                    else:
                        escaped[base] = True
                    scan_s = scan_s[:pos] + "0" + scan_s[close_p + 1 :]
                    continue
            scan_s = scan_s[:pos] + "MEM_OTHER" + scan_s[pos + len("aether_mem_read(") :]

        # If rbp or rsp still appears in scan_s (e.g. `rdx = rbp - 0x40` or `mem_read(rsp + rax)`), escaped!
        if re.search(r"\brbp\b", scan_s):
            escaped["rbp"] = True
        if re.search(r"\brsp\b", scan_s):
            # Ignore `rsp` in epilog return-block restore `r14 = mem_read(rsp, 8)` already masked above
            if not (bi == 0 and si < rsp_frame_ready_idx):
                escaped["rsp"] = True

    for bi, b in enumerate(blocks):
        for si, st in enumerate(b.stmts):
            _scan_stmt_for_mem_and_escape(bi, si, st)
        if b.term_kind == "cbranch":
            if re.search(r"\brbp\b", b.term_cond):
                escaped["rbp"] = True
            if re.search(r"\brsp\b", b.term_cond):
                escaped["rsp"] = True

    slot_map: Dict[Tuple[str, int], Tuple[str, int]] = {}
    for base in ("rbp", "rsp"):
        if escaped[base] or not accesses[base]:
            continue
        sorted_offs = sorted(accesses[base].keys())
        # Filter uniform 4/8-byte non-overlapping slots
        ranges: List[Tuple[int, int]] = []
        for off in sorted_offs:
            widths = set(accesses[base][off])
            if len(widths) != 1:
                continue
            w = next(iter(widths))
            if w not in (4, 8):
                continue
            ranges.append((off, off + w))
        for off in sorted_offs:
            if off not in written_offs[base]:
                continue
            widths = set(accesses[base][off])
            if len(widths) != 1:
                continue
            w = next(iter(widths))
            if w not in (4, 8):
                continue
            if base == "rbp" and off >= 0:
                continue
            if base == "rsp" and (off < 0x40 or off + w > rsp_frame_bytes):
                continue
            # Check no overlap with any other access offset under same base
            overlaps = False
            for off2, widths2 in accesses[base].items():
                if off2 == off:
                    continue
                for w2 in widths2:
                    if not (off + w <= off2 or off2 + w2 <= off):
                        overlaps = True
                        break
                if overlaps:
                    break
            if not overlaps:
                tag = f"n{-off:x}" if off < 0 else f"p{off:x}"
                slot_map[(base, off)] = (f"aether_slot_{base}_{tag}", w)

    if not slot_map:
        return set(), 0

    promoted_vars: Set[str] = set()
    rewrites = 0
    for b in blocks:
        new_stmts: List[str] = []
        for st in b.stmts:
            st_cur, ch1 = _rewrite_mem_ops_in_expr(st, slot_map, promoted_vars)
            if ch1:
                rewrites += 1
            if st_cur.startswith("aether_mem_write(") and st_cur.endswith(")"):
                args = _split_top_args(st_cur[len("aether_mem_write(") : -1])
                if len(args) == 3:
                    m_bd = _BASE_DISP_RE.fullmatch(args[0])
                    w_val = _parse_int_const(args[1])
                    if m_bd and w_val in (4, 8):
                        base = m_bd.group(1)
                        off = 0 if not m_bd.group(3) else int(m_bd.group(3), 0)
                        if m_bd.group(2) == "-":
                            off = -off
                        info = slot_map.get((base, off))
                        if info and info[1] == w_val:
                            slot_var = info[0]
                            promoted_vars.add(slot_var)
                            val_expr = args[2]
                            st_cur = f"{slot_var} = aether_u32({val_expr})" if w_val == 4 else f"{slot_var} = {val_expr}"
                            rewrites += 1
            new_stmts.append(st_cur)
        b.stmts = new_stmts

    return promoted_vars, rewrites


def _forward_const_and_copy_prop(
    blocks: List[_IRBlock],
    tracked: Set[str] = _TRACKED_SET,
) -> int:
    """Kildall forward CFG constant propagation + safe intra-block copy propagation."""
    name_map, succs = _block_successors(blocks)
    preds: Dict[str, List[str]] = {b.name: [] for b in blocks}
    for u, vs in succs.items():
        for v in vs:
            preds[v].append(u)

    def _run_block(
        b: _IRBlock, init_consts: Dict[str, int], apply_edits: bool
    ) -> Tuple[Dict[str, int], int]:
        consts = dict(init_consts)
        copies: Dict[str, str] = {}
        edits = 0

        def _invalidate(var: str) -> None:
            consts.pop(var, None)
            copies.pop(var, None)
            for k in [kk for kk, vv in copies.items() if vv == var]:
                copies.pop(k, None)

        def _active_sub_map() -> Dict[str, str]:
            m: Dict[str, str] = {k: _format_c_i64(v) for k, v in consts.items()}
            for k, src in copies.items():
                if k not in m and src not in tracked or (src in tracked and k not in m):
                    if src in consts:
                        m[k] = _format_c_i64(consts[src])
                    else:
                        m[k] = src
            return m

        new_stmts: List[str] = []
        for stmt in b.stmts:
            if stmt.startswith("if (") and ") {" in stmt:
                cond_part = stmt[4 : stmt.index(") {")].strip()
                body_part = stmt[stmt.index(") {") + 3 : -1].strip()
                sub = _active_sub_map()
                cond_s = _simplify_expr(_subst_vars(cond_part, sub), tracked)
                body_items = [s.strip() for s in body_part.split(";") if s.strip()]
                new_body: List[str] = []
                cond_ev = _eval_const_condition(cond_s, consts, tracked)
                for bi in body_items:
                    m_a = _SIMPLE_ASSIGN_RE.match(bi)
                    if m_a:
                        lhs_b, rhs_b = m_a.group(1), m_a.group(2).strip()
                        rhs_bs = _simplify_expr(_subst_vars(rhs_b, sub), tracked)
                        if cond_ev is not False:
                            new_body.append(f"{lhs_b} = {rhs_bs}")
                        _invalidate(lhs_b)
                    else:
                        new_body.append(bi)
                if cond_ev is True:
                    # Unconditionally execute cmov body!
                    new_stmts.extend(new_body)
                    edits += 1
                    continue
                elif cond_ev is False:
                    edits += 1
                    continue
                if apply_edits:
                    new_stmt = f"if ({cond_s}) {{ {'; '.join(new_body)}; }}"
                    if new_stmt != stmt:
                        edits += 1
                    new_stmts.append(new_stmt)
                continue

            m_cmp = _COMPOUND_ASSIGN_RE.match(stmt)
            if m_cmp:
                lhs, op, rhs = m_cmp.group(1), m_cmp.group(2), m_cmp.group(3).strip()
                sub = _active_sub_map()
                rhs_s = _simplify_expr(_subst_vars(rhs, sub), tracked)
                rc = _parse_int_const(rhs_s)
                lc = consts.get(lhs)
                _invalidate(lhs)
                if lc is not None and rc is not None:
                    nval = _i64(lc + rc if op == "+=" else lc - rc)
                    consts[lhs] = nval
                elif lhs in sub and lhs not in ("_aether_sp",):
                    # Safe to rewrite when operand was replaced cleanly
                    pass
                if apply_edits:
                    nstmt = f"{lhs} {op} {rhs_s}"
                    if nstmt != stmt:
                        edits += 1
                    new_stmts.append(nstmt)
                continue

            m_as = _SIMPLE_ASSIGN_RE.match(stmt)
            if m_as:
                lhs, rhs = m_as.group(1), m_as.group(2).strip()
                sub = _active_sub_map()
                rhs_s = _simplify_expr(_subst_vars(rhs, sub), tracked)
                if lhs == rhs_s and lhs in tracked:
                    # Redundant self-assign (`rax = rax;`)
                    if apply_edits:
                        edits += 1
                    continue
                _invalidate(lhs)
                if lhs in tracked:
                    cval = _parse_int_const(rhs_s)
                    if cval is not None:
                        consts[lhs] = cval
                    elif _TYPE_CAST_IDENT_ONLY_RE.fullmatch(rhs_s) and rhs_s in tracked and rhs_s != lhs:
                        copies[lhs] = rhs_s
                if apply_edits:
                    nstmt = f"{lhs} = {rhs_s}"
                    if nstmt != stmt:
                        edits += 1
                    new_stmts.append(nstmt)
                continue

            # Call or memory write (e.g. aether_mem_write(addr, w, val))
            sub = _active_sub_map()
            stmt_s = _subst_vars(stmt, sub)
            if apply_edits:
                if stmt_s != stmt:
                    edits += 1
                new_stmts.append(stmt_s)

        if apply_edits:
            b.stmts = new_stmts
            if b.term_kind == "cbranch":
                sub = _active_sub_map()
                cond_s = _simplify_expr(_subst_vars(b.term_cond, sub), tracked)
                if cond_s != b.term_cond:
                    b.term_cond = cond_s
                    edits += 1
                ce = _eval_const_condition(cond_s, consts, tracked)
                if ce is True:
                    b.term_kind = "goto"
                    b.term_cond = ""
                    edits += 1
                elif ce is False:
                    b.term_kind = "fall"
                    b.term_cond = ""
                    b.term_target = ""
                    edits += 1

        return consts, edits

    # Kildall worklist over CFG for constant lattice
    out_consts: Dict[str, Optional[Dict[str, int]]] = {b.name: None for b in blocks}
    work = deque([blocks[0].name])
    in_work = {blocks[0].name}
    iters = 0
    max_iters = max(64, len(blocks) * 8)

    while work and iters < max_iters:
        iters += 1
        bname = work.popleft()
        in_work.discard(bname)
        b = name_map[bname]
        if bname == blocks[0].name:
            in_c: Dict[str, int] = {}
        else:
            vis_preds = [out_consts[p] for p in preds[bname] if out_consts[p] is not None]
            if not vis_preds:
                in_c = {}
            else:
                in_c = dict(vis_preds[0])
                for vp in vis_preds[1:]:
                    for k in list(in_c.keys()):
                        if vp.get(k) != in_c[k]:
                            in_c.pop(k, None)
        new_out, _ = _run_block(b, in_c, apply_edits=False)
        if out_consts[bname] != new_out:
            out_consts[bname] = new_out
            for s in succs[bname]:
                if s not in in_work:
                    work.append(s)
                    in_work.add(s)

    # Final rewrite pass using converged CFG constants
    total_edits = 0
    for b in blocks:
        if b.name == blocks[0].name:
            in_c = {}
        else:
            vis_preds = [out_consts[p] for p in preds[b.name] if out_consts[p] is not None]
            if not vis_preds:
                in_c = {}
            else:
                in_c = dict(vis_preds[0])
                for vp in vis_preds[1:]:
                    for k in list(in_c.keys()):
                        if vp.get(k) != in_c[k]:
                            in_c.pop(k, None)
        _, e = _run_block(b, in_c, apply_edits=True)
        total_edits += e

    return total_edits


def _stmt_use_def(stmt: str, tracked: Set[str] = _TRACKED_SET) -> Tuple[Set[str], Optional[str], bool]:
    """Returns (uses, must_def_or_None, is_eliminable_if_dead)."""
    if stmt.startswith("if (") and ") {" in stmt:
        cond_part = stmt[4 : stmt.index(") {")].strip()
        body_part = stmt[stmt.index(") {") + 3 : -1].strip()
        uses = _extract_identifiers(cond_part, tracked)
        for bi in [s.strip() for s in body_part.split(";") if s.strip()]:
            uses |= _extract_identifiers(bi, tracked)
        return uses, None, False

    m_cmp = _COMPOUND_ASSIGN_RE.match(stmt)
    if m_cmp:
        lhs, rhs = m_cmp.group(1), m_cmp.group(3).strip()
        uses = _extract_identifiers(rhs, tracked) | ({lhs} if lhs in tracked else set())
        elim = (lhs in tracked) and _is_pure_rhs(rhs)
        return uses, (lhs if lhs in tracked else None), elim

    m_as = _SIMPLE_ASSIGN_RE.match(stmt)
    if m_as:
        lhs, rhs = m_as.group(1), m_as.group(2).strip()
        uses = _extract_identifiers(rhs, tracked)
        must_def = lhs if lhs in tracked else None
        elim = (lhs in tracked) and _is_pure_rhs(rhs)
        return uses, must_def, elim

    return _extract_identifiers(stmt, tracked), None, False


def _backward_liveness_dce(
    blocks: List[_IRBlock], returns_double: bool, tracked: Set[str] = _TRACKED_SET
) -> Tuple[int, int]:
    """Eliminates dead flag updates (`cmp_lhs`/`cmp_rhs`) and dead register writes across CFG."""
    _, succs = _block_successors(blocks)
    live_in: Dict[str, Set[str]] = {b.name: set() for b in blocks}
    live_out: Dict[str, Set[str]] = {b.name: set() for b in blocks}
    default_ret = "xmm0" if returns_double else "rax"

    changed = True
    while changed:
        changed = False
        for b in reversed(blocks):
            if b.term_kind == "return":
                live: Set[str] = _extract_identifiers(b.term_ret, tracked) or {default_ret}
                out_s: Set[str] = set()
            else:
                out_s = set()
                for s in succs[b.name]:
                    out_s |= live_in[s]
                live = set(out_s)
                if b.term_kind == "cbranch":
                    live |= _extract_identifiers(b.term_cond, tracked)

            for stmt in reversed(b.stmts):
                uses, must_def, elim = _stmt_use_def(stmt, tracked)
                if elim and must_def is not None and must_def not in live:
                    continue
                if must_def is not None:
                    live.discard(must_def)
                live |= uses

            if out_s != live_out[b.name] or live != live_in[b.name]:
                live_out[b.name] = out_s
                live_in[b.name] = live
                changed = True

    dead_flags = 0
    dead_assigns = 0
    for b in blocks:
        if b.term_kind == "return":
            live = _extract_identifiers(b.term_ret, tracked) or {default_ret}
        else:
            live = set(live_out[b.name])
            if b.term_kind == "cbranch":
                live |= _extract_identifiers(b.term_cond, tracked)

        kept_rev: List[str] = []
        for stmt in reversed(b.stmts):
            uses, must_def, elim = _stmt_use_def(stmt, tracked)
            if elim and must_def is not None and must_def not in live:
                if must_def in ("cmp_lhs", "cmp_rhs"):
                    dead_flags += 1
                else:
                    dead_assigns += 1
                continue
            kept_rev.append(stmt)
            if must_def is not None:
                live.discard(must_def)
            live |= uses
        kept_rev.reverse()
        b.stmts = kept_rev

    return dead_flags, dead_assigns


def _compute_cfg_edges_and_defs(
    blocks: List[_IRBlock],
    tracked: Set[str],
) -> Tuple[List[str], List[Tuple[str, str]], Dict[str, List[Tuple[Optional[str], Set[str]]]]]:
    names = [b.name for b in blocks]
    _, succs = _block_successors(blocks)
    edges: List[Tuple[str, str]] = []
    block_defs: Dict[str, List[Tuple[Optional[str], Set[str]]]] = {}
    for b in blocks:
        for s in succs[b.name]:
            edges.append((b.name, s))
        du_list: List[Tuple[Optional[str], Set[str]]] = []
        for stmt in b.stmts:
            uses, must_def, _ = _stmt_use_def(stmt, tracked)
            du_list.append((must_def, uses))
        block_defs[b.name] = du_list
    return names, edges, block_defs


def _inline_flag_comparisons(blocks: List[_IRBlock], tracked: Set[str]) -> int:
    """Inlines single-block pure `cmp_lhs`/`cmp_rhs` definitions directly into `cbranch` predicates."""
    inlined = 0
    for b in blocks:
        if b.term_kind != "cbranch" or not b.term_cond or not b.stmts:
            continue
        cond = b.term_cond
        if "cmp_lhs" not in cond and "cmp_rhs" not in cond:
            continue
        clobbered: Set[str] = set()
        subs: Dict[str, str] = {}
        for stmt in reversed(b.stmts[-8:]):
            m_as = _SIMPLE_ASSIGN_RE.match(stmt)
            if not m_as:
                uses_st, def_st, _ = _stmt_use_def(stmt, tracked)
                if def_st:
                    clobbered.add(def_st)
                if not _is_pure_rhs(stmt) or "aether_mem_read" in stmt:
                    clobbered.add("__mem_barrier__")
                continue
            lhs, rhs = m_as.group(1), m_as.group(2).strip()
            if lhs in ("cmp_lhs", "cmp_rhs") and lhs not in subs and lhs not in clobbered:
                if len(rhs) <= 84 and _is_pure_rhs(rhs) and "aether_mem_read" not in rhs:
                    rhs_uses = _extract_identifiers(rhs, tracked)
                    if not (rhs_uses & clobbered):
                        subs[lhs] = rhs
            clobbered.add(lhs)
            if not _is_pure_rhs(rhs) or "aether_mem_read" in rhs:
                clobbered.add("__mem_barrier__")
        if subs:
            new_cond = _subst_vars(cond, subs)
            if len(new_cond) <= 220:
                new_cond_s = _simplify_expr(new_cond, tracked)
                if new_cond_s != b.term_cond:
                    b.term_cond = new_cond_s
                    inlined += len(subs)
    return inlined


def _gvn_cse_over_domtree(
    blocks: List[_IRBlock],
    tracked: Set[str],
) -> Tuple[int, int, Dict[str, Any]]:
    """Cytron SSA + Dominator-Tree Global Value Numbering (GVN/CSE)."""
    if not blocks:
        return 0, 0, {}
    names, edges, block_defs = _compute_cfg_edges_and_defs(blocks, tracked)
    entry = names[0]
    ssa = build_ssa_for_cfg_blocks(names, edges, block_defs, entry)
    if not ssa.get("idoms"):
        return 0, 0, ssa

    name_to_block = {b.name: b for b in blocks}
    children = ssa["children"]
    phi_nodes = ssa["phi_nodes"]
    stmt_ssa = ssa["stmt_ssa"]

    gvn_hits = 0
    active_ver: Dict[str, str] = {}
    # expr_key -> stack of (holder_var, holder_ver)
    expr_table: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], Tuple[str, str]] = {}

    def _walk_dom(blk: str) -> None:
        nonlocal gvn_hits
        saved_active = dict(active_ver)
        added_expr_keys: List[Tuple[str, Tuple[Tuple[str, str], ...]]] = []

        for phi in phi_nodes.get(blk, ()):
            active_ver[phi["variable"]] = phi["dest"]

        b_obj = name_to_block.get(blk)
        if b_obj is not None:
            for s_idx, stmt in enumerate(b_obj.stmts):
                def_ver, use_vers = stmt_ssa.get((blk, s_idx), (None, {}))
                m_as = _SIMPLE_ASSIGN_RE.match(stmt)
                if m_as and def_ver is not None:
                    lhs, rhs = m_as.group(1), m_as.group(2).strip()
                    if (
                        lhs in tracked
                        and lhs not in ("rsp", "cmp_lhs", "cmp_rhs")
                        and not _TYPE_CAST_IDENT_ONLY_RE.fullmatch(rhs)
                        and _parse_int_const(rhs) is None
                        and "aether_mem_read" not in rhs
                        and _is_pure_rhs(rhs)
                    ):
                        key_uses = tuple(sorted((u, use_vers.get(u, f"{u}_0")) for u in use_vers))
                        ekey = (rhs, key_uses)
                        prev = expr_table.get(ekey)
                        if prev is not None:
                            holder_var, holder_ver = prev
                            if holder_var != lhs and active_ver.get(holder_var) == holder_ver:
                                b_obj.stmts[s_idx] = f"{lhs} = {holder_var}"
                                gvn_hits += 1
                        else:
                            expr_table[ekey] = (lhs, def_ver)
                            added_expr_keys.append(ekey)
                    active_ver[lhs] = def_ver
                else:
                    uses_st, def_st, _ = _stmt_use_def(stmt, tracked)
                    if def_st and def_ver:
                        active_ver[def_st] = def_ver

        for ch in children.get(blk, ()):
            _walk_dom(ch)

        for ek in added_expr_keys:
            expr_table.pop(ek, None)
        active_ver.clear()
        active_ver.update(saved_active)

    _walk_dom(entry)
    return gvn_hits, int(ssa.get("phi_count", 0)), ssa


def _hoist_loop_invariants(blocks: List[_IRBlock], returns_double: bool, tracked: Set[str]) -> int:
    """Hoists side-effect-free loop-invariant pure definitions into unique unconditional preheaders."""
    if len(blocks) < 2:
        return 0
    names, edges, _ = _compute_cfg_edges_and_defs(blocks, tracked)
    entry = names[0]
    from aether_re.cfg_dominance import compute_immediate_dominators_pure

    idoms = compute_immediate_dominators_pure(names, edges, entry)
    loops = find_natural_loops(names, edges, idoms)
    if not loops:
        return 0

    name_to_block = {b.name: b for b in blocks}
    _, succs = _block_successors(blocks)
    preds: Dict[str, List[str]] = {b.name: [] for b in blocks}
    for u, vs in succs.items():
        for v in vs:
            preds[v].append(u)

    hoisted = 0
    for loop in loops:
        header = loop["header"]
        loop_nodes = set(loop["nodes"])
        ext_preds = [p for p in preds.get(header, ()) if p not in loop_nodes]
        if len(ext_preds) != 1:
            continue
        pre_name = ext_preds[0]
        pre_blk = name_to_block.get(pre_name)
        hdr_blk = name_to_block.get(header)
        if pre_blk is None or hdr_blk is None:
            continue
        if pre_blk.term_kind not in ("goto", "fall"):
            continue
        # Only hoist assignments inside header whose LHS is never used before def in header
        loop_defs: Dict[str, int] = {}
        loop_uses_before_def: Set[str] = set()
        ordered_loop_nodes = [header] + [
            b.name for b in blocks if b.name in loop_nodes and b.name != header
        ]
        for ln_name in ordered_loop_nodes:
            lb = name_to_block.get(ln_name)
            if lb is None:
                continue
            for st in lb.stmts:
                u_st, d_st, _ = _stmt_use_def(st, tracked)
                for uv in u_st:
                    if uv not in loop_defs:
                        loop_uses_before_def.add(uv)
                if d_st:
                    loop_defs[d_st] = loop_defs.get(d_st, 0) + 1
            if lb.term_kind == "cbranch":
                for uv in _extract_identifiers(lb.term_cond, tracked):
                    if uv not in loop_defs:
                        loop_uses_before_def.add(uv)
            elif lb.term_kind == "return":
                for uv in _extract_identifiers(lb.term_ret, tracked):
                    if uv not in loop_defs:
                        loop_uses_before_def.add(uv)

        kept_hdr_stmts: List[str] = []
        seen_defs_in_hdr: Set[str] = set()
        for st in hdr_blk.stmts:
            m_as = _SIMPLE_ASSIGN_RE.match(st)
            if m_as:
                lhs, rhs = m_as.group(1), m_as.group(2).strip()
                rhs_uses = _extract_identifiers(rhs, tracked)
                if (
                    lhs in tracked
                    and lhs not in ("rsp", "cmp_lhs", "cmp_rhs")
                    and loop_defs.get(lhs, 0) == 1
                    and lhs not in loop_uses_before_def
                    and lhs not in seen_defs_in_hdr
                    and _is_pure_rhs(rhs)
                    and "aether_mem_read" not in rhs
                    and not (rhs_uses & set(loop_defs.keys()))
                ):
                    pre_blk.stmts.append(st)
                    hoisted += 1
                    seen_defs_in_hdr.add(lhs)
                    continue
            u_st, d_st, _ = _stmt_use_def(st, tracked)
            if d_st:
                seen_defs_in_hdr.add(d_st)
            kept_hdr_stmts.append(st)
        hdr_blk.stmts = kept_hdr_stmts
    return hoisted


def optimize_lifted_c_to_ir_bundle(c_code: str) -> Tuple[str, Dict[str, int], Optional[Dict[str, Any]]]:
    """Runs CFG cleanup, mem2reg, GVN/CSE, LICM, expression flag inlining, constant/copy prop, and DCE.

    Returns ``(optimized_c, metrics, structured_ir_bundle_or_None)``.
    """
    parsed = _parse_c_function(c_code)
    if parsed is None:
        return c_code, {"skipped": 1}, None

    header_lines, blocks, _ = parsed
    returns_double = any(ln.strip().startswith("double ") for ln in header_lines[:2])
    raw_stmts = sum(len(b.stmts) for b in blocks)
    blocks_before = len(blocks)

    blocks = _cleanup_cfg(blocks, returns_double)
    promoted_slots, slot_rewrites = _promote_stack_slots(blocks)
    tracked_vars: Set[str] = _TRACKED_SET | promoted_slots

    dead_flags_total = 0
    dead_assigns_total = 0
    prop_edits_total = 0
    gvn_hits_total = 0
    flag_inlines_total = 0
    licm_hoisted_total = 0
    phi_nodes_placed = 0
    mba_simplified_total = 0
    opaque_pruned_total = 0

    for idx_iter in range(4):
        blocks = _cleanup_cfg(blocks, returns_double)
        if idx_iter == 0:
            for blk_m in blocks:
                for st_i, st_raw in enumerate(blk_m.stmts):
                    if any(op in st_raw for op in ("^", "&", "|", "~")):
                        m_as = _SIMPLE_ASSIGN_RE.match(st_raw)
                        if m_as:
                            lhs_m, rhs_m = m_as.group(1), m_as.group(2).strip()
                            simp_m = simplify_mba_expression(rhs_m)
                            if simp_m != rhs_m and _is_pure_rhs(simp_m):
                                blk_m.stmts[st_i] = f"{lhs_m} = {simp_m}"
                                mba_simplified_total += 1
                if (
                    blk_m.term_kind == "cbranch"
                    and blk_m.term_cond
                    and "0xffffffff" not in blk_m.term_cond.lower()
                    and "aether_" not in blk_m.term_cond
                    and any(op in blk_m.term_cond for op in ("^", "%", "&", "|", "*"))
                ):
                    op_eval = detect_opaque_predicate(blk_m.term_cond)
                    if op_eval.get("is_opaque"):
                        if op_eval["static_truth_value"] is True:
                            blk_m.term_kind = "goto"
                            blk_m.term_cond = ""
                        else:
                            blk_m.term_kind = "fall"
                            blk_m.term_cond = ""
                            blk_m.term_target = ""
                        opaque_pruned_total += 1
        p_edits = _forward_const_and_copy_prop(blocks, tracked_vars)
        fi = _inline_flag_comparisons(blocks, tracked_vars)
        if fi > 0:
            for blk_fi in blocks:
                if (
                    blk_fi.term_kind == "cbranch"
                    and blk_fi.term_cond
                    and "0xffffffff" not in blk_fi.term_cond.lower()
                    and "aether_" not in blk_fi.term_cond
                    and any(op in blk_fi.term_cond for op in ("^", "%", "&", "|", "*"))
                ):
                    op_eval2 = detect_opaque_predicate(blk_fi.term_cond)
                    if op_eval2.get("is_opaque"):
                        if op_eval2["static_truth_value"] is True:
                            blk_fi.term_kind = "goto"
                            blk_fi.term_cond = ""
                        else:
                            blk_fi.term_kind = "fall"
                            blk_fi.term_cond = ""
                            blk_fi.term_target = ""
                        opaque_pruned_total += 1
        gv, phis_cnt, _ = _gvn_cse_over_domtree(blocks, tracked_vars)
        if phis_cnt > phi_nodes_placed:
            phi_nodes_placed = phis_cnt
        lh = _hoist_loop_invariants(blocks, returns_double, tracked_vars) if idx_iter == 0 else 0
        df, da = _backward_liveness_dce(blocks, returns_double, tracked_vars)
        prop_edits_total += p_edits
        flag_inlines_total += fi
        gvn_hits_total += gv
        licm_hoisted_total += lh
        dead_flags_total += df
        dead_assigns_total += da
        if p_edits == 0 and df == 0 and da == 0 and fi == 0 and gv == 0 and lh == 0:
            break
    blocks = _cleanup_cfg(blocks, returns_double)

    active_slots = sorted(
        sv for sv in promoted_slots if any(sv in st for b in blocks for st in b.stmts)
    )
    out_lines: List[str] = []
    inserted_slots = False
    for hl in header_lines:
        if active_slots and not inserted_slots and hl.strip().startswith(("xmm0 =", "xmm1 =")):
            out_lines.append("    int64_t " + ", ".join(f"{sv} = 0" for sv in active_slots) + ";")
            inserted_slots = True
        out_lines.append(hl)
    if active_slots and not inserted_slots:
        out_lines.append("    int64_t " + ", ".join(f"{sv} = 0" for sv in active_slots) + ";")
    for i, b in enumerate(blocks):
        if i == 0 and b.label:
            out_lines.append(f"{b.label}: ; /* entry */")
        elif b.label:
            tag = "switch case" if b.pinned_label else "bb"
            out_lines.append(f"{b.label}: ; /* {tag} */")
        for st in b.stmts:
            out_lines.append(f"    {st};" if not st.endswith((";", "}")) else f"    {st}")
        if b.term_kind == "return":
            out_lines.append(f"    return {b.term_ret};")
        elif b.term_kind == "goto":
            out_lines.append(f"    if (1) goto {b.term_target};")
        elif b.term_kind == "cbranch":
            out_lines.append(f"    if ({b.term_cond}) goto {b.term_target};")
    out_lines.append("}")

    opt_stmts = sum(len(b.stmts) for b in blocks)
    metrics = {
        "raw_stmts": raw_stmts,
        "opt_stmts": opt_stmts,
        "blocks_before": blocks_before,
        "blocks_after": len(blocks),
        "stack_slots_promoted": len(promoted_slots),
        "stack_slot_rewrites": slot_rewrites,
        "dead_flags_removed": dead_flags_total,
        "dead_assigns_removed": dead_assigns_total,
        "prop_edits": prop_edits_total,
        "gvn_hits": gvn_hits_total,
        "flag_inlines": flag_inlines_total,
        "licm_hoisted": licm_hoisted_total,
        "phi_nodes_placed": phi_nodes_placed,
        "mba_simplified": mba_simplified_total,
        "opaque_pruned": opaque_pruned_total,
    }
    names, edges, block_defs = _compute_cfg_edges_and_defs(blocks, tracked_vars)
    final_ssa = build_ssa_for_cfg_blocks(names, edges, block_defs, names[0]) if names else {}
    ir_bundle = {
        "header_lines": header_lines,
        "blocks": blocks,
        "promoted_slots": active_slots,
        "returns_double": returns_double,
        "ssa": final_ssa,
        "metrics": metrics,
    }
    return "\n".join(out_lines), metrics, ir_bundle


def optimize_lifted_c_via_ssa(c_code: str) -> Tuple[str, Dict[str, int]]:
    """Runs iterative CFG cleanup, stack-slot mem2reg, Cytron SSA GVN/CSE, LICM, flag inlining, constant/copy prop, and DCE."""
    opt, metrics, _ = optimize_lifted_c_to_ir_bundle(c_code)
    return opt, metrics


def optimize_lifted_c(c_code: str) -> str:
    """Convenience wrapper returning optimized C source."""
    opt, _, _ = optimize_lifted_c_to_ir_bundle(c_code)
    return opt
