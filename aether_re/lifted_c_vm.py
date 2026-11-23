"""Pre-Compiled Lifted C VM & Deterministic Scalar/SIMD Helpers (v7.0.0).

Eliminates per-vector C line splitting, regex cleaning, label indexing, and
recursive callee closure allocation inside differential behavioral verification.
"""

from __future__ import annotations

import ctypes
import math
import re
import struct
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

_ALL_CANON_REGS: Tuple[str, ...] = (
    "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_XMM_REGS: Tuple[str, ...] = tuple(f"xmm{i}" for i in range(16))
_XMM_HI_REGS: Tuple[str, ...] = tuple(f"xmm{i}_hi" for i in range(16))
_ARM64_REGS: Tuple[str, ...] = tuple(f"x{i}" for i in range(31))

_AST_LHS_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+|-)?=")
_AST_NORM_REGS: set[str] = {
    *_ALL_CANON_REGS,
    *_XMM_REGS,
    *_XMM_HI_REGS,
    *_ARM64_REGS,
    "cmp_lhs",
    "cmp_rhs",
}
_SLOT_VAR_RE = re.compile(r"\baether_slot_[A-Za-z0-9_]+\b")
_ULL_SUFFIX_RE = re.compile(r"\b(0x[0-9a-fA-F]+|\d+)U?LL\b")

_PY_EXEC_CACHE: Dict[str, Any] = {}
_PY_EVAL_CACHE: Dict[str, Any] = {}
_PROGRAM_CACHE: Dict[str, "CompiledLiftedProgram"] = {}
_CALLEE_CACHE: Dict[int, Dict[str, Any]] = {}
_VM_TLS = threading.local()


def _to_int64(val: int) -> int:
    return ctypes.c_int64(val).value


def _fast_i64(val: int) -> int:
    v = int(val) & 0xFFFFFFFFFFFFFFFF
    return v - 0x10000000000000000 if (v & 0x8000000000000000) else v


def _i32(val: int) -> int:
    return ctypes.c_int32(int(val)).value


def _u32(val: int) -> int:
    return val & 0xFFFFFFFF


def _u8(val: int) -> int:
    return val & 0xFF


def _i8(val: int) -> int:
    return ctypes.c_int8(int(val) & 0xFF).value


def _i16(val: int) -> int:
    return ctypes.c_int16(int(val) & 0xFFFF).value


def _bt_cf(val: int, bit: int, mask: int) -> int:
    return 0 if ((int(val) >> (int(bit) & int(mask))) & 1) else 1


def _bit_mask(bit: int, mask: int) -> int:
    return 1 << (int(bit) & int(mask))


def _tolower_ascii(c: int) -> int:
    b = int(c) & 0xFF
    return b + 32 if 65 <= b <= 90 else b


def _f64_to_bits(val: float) -> int:
    return struct.unpack("<q", struct.pack("<d", float(val)))[0]


def _bits_to_f64(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<q", _to_int64(int(bits))))[0]


def _f64_comisd(a_bits: int, b_bits: int) -> int:
    a = _bits_to_f64(a_bits)
    b = _bits_to_f64(b_bits)
    if math.isnan(a) or math.isnan(b):
        return -1
    if a == b:
        return 1
    if a > b:
        return 2
    return 0


def _pcmpeqb64(a: int, b: int) -> int:
    out = 0
    for i in range(8):
        if ((a >> (i * 8)) & 0xFF) == ((b >> (i * 8)) & 0xFF):
            out |= 0xFF << (i * 8)
    return _to_int64(out)


def _pmaxud64(a: int, b: int) -> int:
    lo = max(a & 0xFFFFFFFF, b & 0xFFFFFFFF)
    hi = max((a >> 32) & 0xFFFFFFFF, (b >> 32) & 0xFFFFFFFF)
    return _to_int64((hi << 32) | lo)


def _paddd64(a: int, b: int) -> int:
    lo = ((a & 0xFFFFFFFF) + (b & 0xFFFFFFFF)) & 0xFFFFFFFF
    hi = (((a >> 32) & 0xFFFFFFFF) + ((b >> 32) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return _to_int64((hi << 32) | lo)


def _pmulld64(a: int, b: int) -> int:
    lo = ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & 0xFFFFFFFF
    hi = (((a >> 32) & 0xFFFFFFFF) * ((b >> 32) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return _to_int64((hi << 32) | lo)


def _paddb64(a: int, b: int) -> int:
    out = 0
    for i in range(8):
        out |= ((((a >> (i * 8)) & 0xFF) + ((b >> (i * 8)) & 0xFF)) & 0xFF) << (i * 8)
    return _to_int64(out)


def _f32_add(a_bits: int, b_bits: int) -> int:
    fa = struct.unpack("<f", struct.pack("<I", int(a_bits) & 0xFFFFFFFF))[0]
    fb = struct.unpack("<f", struct.pack("<I", int(b_bits) & 0xFFFFFFFF))[0]
    return struct.unpack("<I", struct.pack("<f", fa + fb))[0]


def _f32_mul(a_bits: int, b_bits: int) -> int:
    fa = struct.unpack("<f", struct.pack("<I", int(a_bits) & 0xFFFFFFFF))[0]
    fb = struct.unpack("<f", struct.pack("<I", int(b_bits) & 0xFFFFFFFF))[0]
    return struct.unpack("<I", struct.pack("<f", fa * fb))[0]


def _pcmpeqd64(a: int, b: int) -> int:
    lo = 0xFFFFFFFF if (a & 0xFFFFFFFF) == (b & 0xFFFFFFFF) else 0
    hi = 0xFFFFFFFF if ((a >> 32) & 0xFFFFFFFF) == ((b >> 32) & 0xFFFFFFFF) else 0
    return _to_int64(lo | (hi << 32))


def _psubd64(a: int, b: int) -> int:
    lo = ((a & 0xFFFFFFFF) - (b & 0xFFFFFFFF)) & 0xFFFFFFFF
    hi = (((a >> 32) & 0xFFFFFFFF) - ((b >> 32) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return _to_int64(lo | (hi << 32))


def _pshufd128(lo: int, hi: int, imm8: int) -> Tuple[int, int]:
    lanes = [lo & 0xFFFFFFFF, (lo >> 32) & 0xFFFFFFFF, hi & 0xFFFFFFFF, (hi >> 32) & 0xFFFFFFFF]
    n0 = lanes[imm8 & 3]
    n1 = lanes[(imm8 >> 2) & 3]
    n2 = lanes[(imm8 >> 4) & 3]
    n3 = lanes[(imm8 >> 6) & 3]
    return _to_int64(n0 | (n1 << 32)), _to_int64(n2 | (n3 << 32))


def _f64_to_i32(bits: int) -> int:
    d = _bits_to_f64(bits)
    if not math.isfinite(d) or d >= 2147483648.0 or d < -2147483648.0:
        return 0x80000000
    return _u32(int(d))


def _i32_to_f64(i_val: int) -> int:
    return _f64_to_bits(float(_i32(i_val)))


def _f32_to_f64(u32_bits: int) -> int:
    f_val = struct.unpack("<f", struct.pack("<I", int(u32_bits) & 0xFFFFFFFF))[0]
    return _f64_to_bits(float(f_val))


def _f64_max(a: int, b: int) -> int:
    return a if _bits_to_f64(a) > _bits_to_f64(b) else b


def _f64_min(a: int, b: int) -> int:
    return a if _bits_to_f64(a) < _bits_to_f64(b) else b


def _f64_add(a: int, b: int) -> int:
    return _f64_to_bits(_bits_to_f64(a) + _bits_to_f64(b))


def _f64_sub(a: int, b: int) -> int:
    return _f64_to_bits(_bits_to_f64(a) - _bits_to_f64(b))


def _f64_mul(a: int, b: int) -> int:
    return _f64_to_bits(_bits_to_f64(a) * _bits_to_f64(b))


def _f64_div(a: int, b: int) -> int:
    fb = _bits_to_f64(b)
    if fb == 0.0:
        return _f64_to_bits(float("nan"))
    return _f64_to_bits(_bits_to_f64(a) / fb)


def _safe_f64_pow(a: float, b: float) -> float:
    try:
        return float(math.pow(a, b))
    except OverflowError:
        return float("inf")
    except ValueError:
        return float("nan")


def _compile_exec_cached(src: str) -> Any:
    code = _PY_EXEC_CACHE.get(src)
    if code is None:
        if len(_PY_EXEC_CACHE) > 20000:
            _PY_EXEC_CACHE.clear()
        code = compile(src, "<aether_c_stmt>", "exec")
        _PY_EXEC_CACHE[src] = code
    return code


def _compile_eval_cached(src: str) -> Any:
    code = _PY_EVAL_CACHE.get(src)
    if code is None:
        if len(_PY_EVAL_CACHE) > 20000:
            _PY_EVAL_CACHE.clear()
        code = compile(src, "<aether_c_cond>", "eval")
        _PY_EVAL_CACHE[src] = code
    return code


def _clean_c_stmt(s: str) -> str:
    s = (
        s.replace("(int64_t)", "")
        .replace("(uint64_t)", "")
        .replace("0xffLL", "0xff")
        .replace("0xffffLL", "0xffff")
    )
    return _ULL_SUFFIX_RE.sub(r"\1", s)


@dataclass(frozen=True)
class CompiledLiftedProgram:
    returns_double: bool
    takes_double_arg0: bool
    slot_vars: Tuple[str, ...]
    ops: Tuple[Tuple[Any, ...], ...]


def _compile_lifted_program(c_code: str) -> CompiledLiftedProgram:
    cached = _PROGRAM_CACHE.get(c_code)
    if cached is not None:
        return cached

    lines = [ln.strip() for ln in c_code.splitlines()]
    returns_double = any(ln.startswith("double ") for ln in lines[:4])
    sig_line = lines[0] if lines else ""
    takes_double_arg0 = "double xmm0_arg" in sig_line
    slot_vars = tuple(_SLOT_VAR_RE.findall("\n".join(lines[:16])))

    label_to_op_idx: Dict[str, int] = {}
    raw_ops: List[Tuple[Any, ...]] = []
    for ln in lines:
        if (
            not ln
            or ln.startswith("int64_t ")
            or ln.startswith("double ")
            or ln.startswith("uint8_t ")
            or ln.startswith("/*")
            or ln == "}"
        ):
            continue
        if ln.startswith("L_") and ":" in ln:
            lbl = ln.split(":", 1)[0].strip()
            label_to_op_idx[lbl] = len(raw_ops)
            continue
        if ln == "return rax;":
            raw_ops.append(("ret_rax",))
            continue
        if ln == "return aether_bits_to_f64(xmm0);":
            raw_ops.append(("ret_xmm0",))
            continue
        if ln.startswith("return ") and ln.endswith(";"):
            expr_s = ln[7:-1].strip()
            raw_ops.append(("ret_expr", _compile_eval_cached(_clean_c_stmt(expr_s))))
            continue
        if ln.startswith("if (") and ("goto " in ln or ") {" in ln):
            if ") goto " in ln:
                cond_str = ln[4 : ln.index(") goto")].strip()
                target_lbl = ln[ln.index("goto ") + 5 : ln.rindex(";")].strip()
                raw_ops.append(("br", _compile_eval_cached(_clean_c_stmt(cond_str)), target_lbl))
                continue
            if ") {" in ln and ln.endswith("}"):
                cond_str = ln[4 : ln.index(") {")].strip()
                body_str = ln[ln.index(") {") + 3 : -1].strip()
                compiled_body: List[Tuple[Any, Optional[str]]] = []
                for st in (s.strip() for s in body_str.split(";") if s.strip()):
                    m_lhs = _AST_LHS_ASSIGN_RE.match(st)
                    norm_var = (
                        m_lhs.group(1)
                        if m_lhs and (m_lhs.group(1) in _AST_NORM_REGS or m_lhs.group(1).startswith("aether_slot_"))
                        else None
                    )
                    compiled_body.append((_compile_exec_cached(_clean_c_stmt(st)), norm_var))
                raw_ops.append(("cond_exec", _compile_eval_cached(_clean_c_stmt(cond_str)), tuple(compiled_body)))
                continue

        compiled_stmts: List[Tuple[Any, Optional[str]]] = []
        for st in (s.strip() for s in ln.split(";") if s.strip()):
            m_lhs = _AST_LHS_ASSIGN_RE.match(st)
            norm_var = (
                m_lhs.group(1)
                if m_lhs and (m_lhs.group(1) in _AST_NORM_REGS or m_lhs.group(1).startswith("aether_slot_"))
                else None
            )
            compiled_stmts.append((_compile_exec_cached(_clean_c_stmt(st)), norm_var))
        raw_ops.append(("exec", tuple(compiled_stmts)))

    resolved_ops: List[Tuple[Any, ...]] = []
    end_idx = len(raw_ops)
    for op in raw_ops:
        if op[0] == "br":
            resolved_ops.append(("br", op[1], label_to_op_idx.get(op[2], end_idx)))
        else:
            resolved_ops.append(op)

    prog = CompiledLiftedProgram(
        returns_double=returns_double,
        takes_double_arg0=takes_double_arg0,
        slot_vars=slot_vars,
        ops=tuple(resolved_ops),
    )
    if len(_PROGRAM_CACHE) > 4096:
        _PROGRAM_CACHE.clear()
    _PROGRAM_CACHE[c_code] = prog
    return prog


_STATIC_BASE_ENV: Dict[str, Any] = {
    **{r: 0 for r in _ALL_CANON_REGS},
    **{xr: 0 for xr in _XMM_REGS},
    **{xh: 0 for xh in _XMM_HI_REGS},
    **{ar: 0 for ar in _ARM64_REGS},
    "cmp_lhs": 0,
    "cmp_rhs": 0,
    "_aether_div_rem": 0,
    "_aether_imul_hi": 0,
    "_aether_xmm_hi": 0,
    "_aether_sp": 0,
    "_aether_saved_sp": 0,
    "aether_u32": _u32,
    "aether_i32": _i32,
    "aether_i16": _i16,
    "aether_i8": _i8,
    "aether_bt_cf": _bt_cf,
    "aether_bit_mask": _bit_mask,
    "aether_set_byte": lambda reg, cond: _to_int64((int(reg) & ~0xFF) | (1 if cond else 0)),
    "aether_sscanf": lambda *args: 0,
    "aether_abort": lambda *args: 0,
    "aether_printf": lambda *args: 0,
    "aether_isalpha": lambda c: 1 if (0 <= (int(c) & 0xFF) < 128 and chr(int(c) & 0xFF).isalpha()) else 0,
    "aether_isdigit": lambda c: 1 if (0 <= (int(c) & 0xFF) < 128 and chr(int(c) & 0xFF).isdigit()) else 0,
    "aether_isspace": lambda c: 1 if (0 <= (int(c) & 0xFF) < 128 and chr(int(c) & 0xFF).isspace()) else 0,
    "aether_isxdigit": lambda c: 1 if ((int(c) & 0xFF) in b"0123456789abcdefABCDEF") else 0,
    "aether_fn_ptr": lambda r_rva: _to_int64(int(r_rva)),
    "aether_pcmpeqb64": _pcmpeqb64,
    "aether_tolower": lambda c: _to_int64(_tolower_ascii(int(c))),
    "aether_pow": lambda a, b: _safe_f64_pow(float(a), float(b)),
    "aether_fmod": lambda a, b: math.fmod(float(a), float(b)) if float(b) != 0.0 else float("nan"),
    "aether_pmaxud64": _pmaxud64,
    "aether_paddd64": _paddd64,
    "aether_pmulld64": _pmulld64,
    "aether_paddb64": _paddb64,
    "aether_f32_add": _f32_add,
    "aether_f32_mul": _f32_mul,
    "aether_pcmpeqd64": _pcmpeqd64,
    "aether_psubd64": _psubd64,
    "aether_f64_to_bits": _f64_to_bits,
    "aether_bits_to_f64": _bits_to_f64,
    "aether_f64_comisd": _f64_comisd,
    "aether_f64_to_i32": _f64_to_i32,
    "aether_i32_to_f64": _i32_to_f64,
    "aether_f32_to_f64": _f32_to_f64,
    "aether_f64_max": _f64_max,
    "aether_f64_min": _f64_min,
    "aether_f64_add": _f64_add,
    "aether_f64_sub": _f64_sub,
    "aether_f64_mul": _f64_mul,
    "aether_f64_div": _f64_div,
    "aether_crt_fn_ptr": lambda kid: _to_int64(0x1A000 + int(kid)),
    "aether_tzcnt32": lambda v: 32 if (int(v) & 0xFFFFFFFF) == 0 else (((int(v) & 0xFFFFFFFF) & -(int(v) & 0xFFFFFFFF)).bit_length() - 1),
    "aether_tzcnt64": lambda v: 64 if (int(v) & 0xFFFFFFFFFFFFFFFF) == 0 else (((int(v) & 0xFFFFFFFFFFFFFFFF) & -(int(v) & 0xFFFFFFFFFFFFFFFF)).bit_length() - 1),
    "aether_fcall_f64": lambda *args: 0.0,
    "aether_cfcall_f64": lambda *args: 0.0,
}


def _get_callee_dispatch(c_fn_table: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    key = hash(frozenset((k, v.get("c_code", "")) for k, v in c_fn_table.items()))
    cached = _CALLEE_CACHE.get(key)
    if cached is not None:
        return cached
    dispatch: Dict[str, Any] = {}
    for c_sym, meta in c_fn_table.items():
        def _make_callee(m: Dict[str, Any]):
            c_src = m["c_code"]
            takes_d0 = bool(m.get("takes_double_arg0"))
            takes_d1 = bool(m.get("takes_double_arg1"))
            ret_d = bool(m.get("returns_double"))

            def _call_fn(a0: Any, a1: Any, a2: Any, a3: Any) -> Any:
                ctx = _VM_TLS.ctx
                caller_env = ctx["env"]
                c_p0 = _f64_to_bits(float(a0)) if takes_d0 else int(caller_env["xmm0"])
                c_p1 = _f64_to_bits(float(a1)) if takes_d1 else int(caller_env["xmm1"])
                out_bits = execute_lifted_c_ast(
                    c_src,
                    0 if takes_d0 else int(a0),
                    0 if takes_d1 else int(a1),
                    int(a2),
                    int(a3),
                    mem_arena=ctx["arena"],
                    xmm0_bits=c_p0,
                    xmm1_bits=c_p1,
                    c_fn_table=ctx["c_fn_table"],
                    ro_table_fns=ctx["ro_table_fns"],
                    vtable_arena_addrs=ctx["vtable_arena_addrs"],
                    rva_to_c_sym=ctx["rva_to_c_sym"],
                    rw_data_base=ctx["rw_data_base"],
                    ro_arena_addrs=ctx["ro_arena_addrs"],
                    halt_info=ctx["halt_info"],
                    _stack_base=max(0x1E800, int(caller_env["rsp"]) - 8),
                    _depth=ctx["depth"] + 1,
                )
                return _bits_to_f64(out_bits) if ret_d else _to_int64(out_bits)

            return _call_fn

        dispatch[c_sym] = _make_callee(meta)
    if len(_CALLEE_CACHE) > 256:
        _CALLEE_CACHE.clear()
    _CALLEE_CACHE[key] = dispatch
    return dispatch


def execute_lifted_c_ast(
    c_code: str,
    rcx: int,
    rdx: int,
    r8: int,
    r9: int,
    mem_arena: Optional[Any] = None,
    *,
    xmm0_bits: int = 0,
    xmm1_bits: int = 0,
    c_fn_table: Optional[Dict[str, Dict[str, Any]]] = None,
    ro_table_fns: Optional[Dict[str, List[int]]] = None,
    vtable_arena_addrs: Optional[Dict[int, int]] = None,
    rva_to_c_sym: Optional[Dict[int, str]] = None,
    rw_data_base: int = 0,
    ro_arena_addrs: Optional[Dict[int, int]] = None,
    halt_info: Optional[Dict[str, bool]] = None,
    _stack_base: int = 0x4E000,
    _depth: int = 0,
    arena_factory: Any = None,
) -> int:
    """Executes pre-compiled lifted C operations directly in a deterministic VM."""
    if _depth >= 24:
        return 0
    if mem_arena is not None:
        arena = mem_arena
    elif arena_factory is not None:
        arena = arena_factory()
    else:
        raise ValueError("mem_arena_or_factory_required")

    prog = _compile_lifted_program(c_code)
    env: Dict[str, Any] = dict(_STATIC_BASE_ENV)
    for sv in prog.slot_vars:
        env[sv] = 0

    env.update({
        "rcx": 0 if prog.takes_double_arg0 else _to_int64(rcx),
        "rdx": _to_int64(rdx),
        "r8": _to_int64(r8),
        "r9": _to_int64(r9),
        "xmm0_arg": _bits_to_f64(xmm0_bits),
        "xmm0": _to_int64(xmm0_bits),
        "xmm1_arg": _bits_to_f64(xmm1_bits),
        "xmm1": _to_int64(xmm1_bits),
        "rsp": _stack_base,
        "aether_stack_base": lambda: _stack_base,
        "aether_mem_read": lambda addr, width: arena.read(int(addr), int(width)),
        "aether_mem_write": lambda addr, width, val: arena.write(int(addr), int(width), int(val)),
        "aether_malloc": lambda sz: _to_int64(arena.alloc(int(sz))),
        "aether_free": lambda ptr: _to_int64(arena.free(int(ptr))),
        "aether_realloc": lambda ptr, sz: _to_int64(arena.realloc(int(ptr), int(sz))),
        "aether_calloc": lambda n, sz: _to_int64(arena.alloc(max(1, (int(n) & 0xFFFFFFFF) * (int(sz) & 0xFFFFFFFF)))),
        "aether_rep_stos": lambda d, v, c, w: _to_int64(arena.c_rep_stos(int(d), int(v), int(c), int(w))),
        "aether_strlen": lambda ptr: _to_int64(arena.c_strlen(int(ptr))),
        "aether_strcmp": lambda p1, p2: _to_int64(arena.c_strcmp(int(p1), int(p2))),
        "aether_strncmp": lambda p1, p2, n: _to_int64(arena.c_strncmp(int(p1), int(p2), int(n))),
        "aether_strcpy": lambda dst, src: _to_int64(arena.c_strcpy(int(dst), int(src))),
        "aether_strrchr": lambda s, ch: _to_int64(arena.c_strrchr(int(s), int(ch))),
        "aether_sprintf": lambda buf, fmt, a1, a2, a3: _to_int64(arena.c_sprintf(int(buf), int(fmt), int(a1), int(a2), int(a3))),
        "aether_strtod": lambda s_ptr, end_ptr: _bits_to_f64(arena.c_strtod(int(s_ptr), int(end_ptr))),
        "aether_memcpy": lambda dst, src, sz: _to_int64(arena.c_memcpy(int(dst), int(src), int(sz))),
        "aether_memset": lambda dst, val, sz: _to_int64(arena.c_memset(int(dst), int(val), int(sz))),
        "aether_vtable_ptr": lambda vt_rva: _to_int64((vtable_arena_addrs or {}).get(int(vt_rva), 0)),
        "aether_data_ptr": lambda d_rva: _to_int64(0x1B000 + (int(d_rva) - rw_data_base)) if rw_data_base > 0 else 0,
        "aether_ro_ptr": lambda r_rva: _to_int64((ro_arena_addrs or {}).get(int(r_rva), 0)),
        "aether_icall": lambda fp, a0, a1, a2, a3: (
            _to_int64(arena.alloc(int(a0))) if int(fp) == 0x1A001 else
            (_to_int64(arena.free(int(a0))) if int(fp) == 0x1A002 else
            (_to_int64(arena.realloc(int(a0), int(a1))) if int(fp) == 0x1A003 else 0))
        ),
    })

    if ro_table_fns:
        for t_fn_name, t_vals in ro_table_fns.items():
            env[t_fn_name] = (lambda vals: lambda idx: vals[int(idx)] if 0 <= int(idx) < len(vals) else 0)(t_vals)

    def _exec_udiv64(hi: Any, lo: Any, d: Any) -> int:
        ud = int(d) & 0xFFFFFFFFFFFFFFFF
        if ud == 0:
            env["_aether_div_rem"] = 0
            return 0
        un = ((int(hi) & 0xFFFFFFFFFFFFFFFF) << 64) | (int(lo) & 0xFFFFFFFFFFFFFFFF)
        env["_aether_div_rem"] = _to_int64(un % ud)
        return _to_int64(un // ud)

    def _exec_udiv32(hi: Any, lo: Any, d: Any) -> int:
        ud = int(d) & 0xFFFFFFFF
        if ud == 0:
            env["_aether_div_rem"] = 0
            return 0
        un = ((int(hi) & 0xFFFFFFFF) << 32) | (int(lo) & 0xFFFFFFFF)
        env["_aether_div_rem"] = _u32(un % ud)
        return _u32(un // ud)

    def _exec_imul32(a: Any, b: Any) -> int:
        p = _i32(int(a)) * _i32(int(b))
        env["_aether_imul_hi"] = _u32(p >> 32)
        return _u32(p)

    def _exec_imul64(a: Any, b: Any) -> int:
        p = int(a) * int(b)
        env["_aether_imul_hi"] = _to_int64((p >> 64) & 0xFFFFFFFFFFFFFFFF)
        return _to_int64(p & 0xFFFFFFFFFFFFFFFF)

    def _exec_umul32(a: Any, b: Any) -> int:
        p = (int(a) & 0xFFFFFFFF) * (int(b) & 0xFFFFFFFF)
        env["_aether_imul_hi"] = _u32(p >> 32)
        return _u32(p)

    def _exec_umul64(a: Any, b: Any) -> int:
        p = (int(a) & 0xFFFFFFFFFFFFFFFF) * (int(b) & 0xFFFFFFFFFFFFFFFF)
        env["_aether_imul_hi"] = _to_int64((p >> 64) & 0xFFFFFFFFFFFFFFFF)
        return _to_int64(p & 0xFFFFFFFFFFFFFFFF)

    def _exec_pshufd(lo: Any, hi: Any, imm8: Any) -> int:
        n_lo, n_hi = _pshufd128(int(lo), int(hi), int(imm8))
        env["_aether_xmm_hi"] = n_hi
        return n_lo

    env["aether_udiv64"] = _exec_udiv64
    env["aether_udiv32"] = _exec_udiv32
    env["aether_imul32"] = _exec_imul32
    env["aether_imul64"] = _exec_imul64
    env["aether_umul32"] = _exec_umul32
    env["aether_umul64"] = _exec_umul64
    env["aether_pshufd"] = _exec_pshufd

    if c_fn_table:
        env.update(_get_callee_dispatch(c_fn_table))

    def _vcall_helper(fn_ptr: Any, a0: Any, a1: Any, a2: Any, a3: Any) -> int:
        sym = (rva_to_c_sym or {}).get(int(fn_ptr))
        if sym and sym in env:
            return _to_int64(int(env[sym](a0, a1, a2, a3)))
        return 0

    env["aether_vcall"] = _vcall_helper

    prev_ctx = getattr(_VM_TLS, "ctx", None)
    _VM_TLS.ctx = {
        "arena": arena,
        "env": env,
        "c_fn_table": c_fn_table,
        "ro_table_fns": ro_table_fns,
        "vtable_arena_addrs": vtable_arena_addrs,
        "rva_to_c_sym": rva_to_c_sym,
        "rw_data_base": rw_data_base,
        "ro_arena_addrs": ro_arena_addrs,
        "halt_info": halt_info,
        "depth": _depth,
    }
    try:
        ops = prog.ops
        n_ops = len(ops)
        pc = 0
        steps = 0
        builtins_ns = {"__builtins__": {}}
        while pc < n_ops and steps < 4000:
            op = ops[pc]
            kind = op[0]
            steps += 1
            if kind == "exec":
                for st_code, norm_var in op[1]:
                    exec(st_code, builtins_ns, env)
                    if norm_var is not None:
                        env[norm_var] = _fast_i64(env[norm_var])
                pc += 1
            elif kind == "br":
                if eval(op[1], builtins_ns, env):
                    pc = op[2]
                else:
                    pc += 1
            elif kind == "ret_rax":
                return _fast_i64(int(env["rax"]))
            elif kind == "ret_xmm0":
                return _fast_i64(int(env["xmm0"]))
            elif kind == "ret_expr":
                return _fast_i64(int(eval(op[1], builtins_ns, env)))
            elif kind == "cond_exec":
                if eval(op[1], builtins_ns, env):
                    for st_code, norm_var in op[2]:
                        exec(st_code, builtins_ns, env)
                        if norm_var is not None:
                            env[norm_var] = _fast_i64(env[norm_var])
                pc += 1
        if halt_info is not None and steps >= 4000 and pc < n_ops:
            halt_info["fuel_exhausted"] = True
        return _fast_i64(int(env["xmm0"] if prog.returns_double else env["rax"]))
    finally:
        _VM_TLS.ctx = prev_ctx
