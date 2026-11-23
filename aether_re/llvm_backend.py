"""Phase III Native LLVM IR Backend, O3 PassManager, Win64 COFF Emitter & MCJIT Engine.

Lowers optimized CFG/SSA functions from ``ir_optimizer`` into strongly-typed
``llvmlite.ir`` modules, validates with LLVM's C++ IR verifier, runs LLVM's
NewPassManager at optimization level ``O3`` (``mem2reg``, ``sroa``, ``instcombine``,
``gvn``, ``sccp``, ``licm``, ``loop-vectorize``), emits Win64 COFF ``.obj`` files,
and supports live native x86-64 CPU execution via LLVM MCJIT.
"""

from __future__ import annotations

import ast
import ctypes
import math
import re
import struct
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import llvmlite.binding as llvm
import llvmlite.ir as ir

from aether_re.ir_optimizer import _parse_c_function

_LLVM_INITIALIZED = False


def _ensure_llvm_init() -> None:
    global _LLVM_INITIALIZED
    if not _LLVM_INITIALIZED:
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        _LLVM_INITIALIZED = True


_I64 = ir.IntType(64)
_I32 = ir.IntType(32)
_I16 = ir.IntType(16)
_I8 = ir.IntType(8)
_I1 = ir.IntType(1)
_I128 = ir.IntType(128)
_F64 = ir.DoubleType()
_F32 = ir.FloatType()
_VOID = ir.VoidType()

_TRACKED_LOCALS: Tuple[str, ...] = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    "xmm0_hi", "xmm1_hi", "xmm2_hi", "xmm3_hi", "xmm4_hi", "xmm5_hi", "xmm6_hi", "xmm7_hi",
    "xmm8_hi", "xmm9_hi", "xmm10_hi", "xmm11_hi", "xmm12_hi", "xmm13_hi", "xmm14_hi", "xmm15_hi",
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    "cmp_lhs", "cmp_rhs", "_aether_saved_sp",
)

# Helper prototypes for runtime / arena external symbols: (arg_types, ret_type)
_EXT_HELPER_SIGS: Dict[str, Tuple[Tuple[ir.Type, ...], ir.Type]] = {
    "aether_stack_base": ((), _I64),
    "aether_get_sp": ((), _I64),
    "aether_set_sp": ((_I64,), _I64),
    "aether_abort": ((), _I64),
    "aether_mem_read": ((_I64, _I64), _I64),
    "aether_mem_write": ((_I64, _I64, _I64), _VOID),
    "aether_malloc": ((_I64,), _I64),
    "aether_free": ((_I64,), _I64),
    "aether_realloc": ((_I64, _I64), _I64),
    "aether_calloc": ((_I64, _I64), _I64),
    "aether_memcpy": ((_I64, _I64, _I64), _I64),
    "aether_memset": ((_I64, _I64, _I64), _I64),
    "aether_rep_stos": ((_I64, _I64, _I64, _I64), _I64),
    "aether_strlen": ((_I64,), _I64),
    "aether_strcmp": ((_I64, _I64), _I64),
    "aether_strncmp": ((_I64, _I64, _I64), _I64),
    "aether_strcpy": ((_I64, _I64), _I64),
    "aether_strrchr": ((_I64, _I64), _I64),
    "aether_sprintf": ((_I64, _I64, _I64, _I64, _I64), _I64),
    "aether_sscanf": ((_I64, _I64, _I64, _I64), _I64),
    "aether_printf": ((_I64, _I64, _I64, _I64), _I64),
    "aether_strtod": ((_I64, _I64), _F64),
    "aether_pow": ((_F64, _F64), _F64),
    "aether_fmod": ((_F64, _F64), _F64),
    "aether_isalpha": ((_I64,), _I64),
    "aether_isdigit": ((_I64,), _I64),
    "aether_isspace": ((_I64,), _I64),
    "aether_isxdigit": ((_I64,), _I64),
    "aether_tolower": ((_I64,), _I64),
    "aether_ro_ptr": ((_I64,), _I64),
    "aether_data_ptr": ((_I64,), _I64),
    "aether_fn_ptr": ((_I64,), _I64),
    "aether_vtable_ptr": ((_I64,), _I64),
    "aether_crt_fn_ptr": ((_I64,), _I64),
    "aether_vcall": ((_I64, _I64, _I64, _I64, _I64), _I64),
    "aether_icall": ((_I64, _I64, _I64, _I64, _I64), _I64),
    "aether_fcall_f64": ((_I64, _I64, _I64, _I64, _I64, _I64, _I64, _I64, _I64), _F64),
    "aether_cfcall_f64": ((_I64, _I64, _I64, _I64, _I64, _I64, _I64, _I64, _I64), _F64),
    "aether_pmaxud64": ((_I64, _I64), _I64),
    "aether_pcmpeqd64": ((_I64, _I64), _I64),
    "aether_psubd64": ((_I64, _I64), _I64),
    "aether_pcmpeqb64": ((_I64, _I64), _I64),
}

_U64_MASK = 0xFFFFFFFFFFFFFFFF
_LL_SUFFIX_RE = re.compile(r"\b(0x[0-9a-fA-F]+|\d+)U?LL\b")
_IDENT_SCAN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
_AST_EVAL_CACHE: Dict[str, ast.AST] = {}


def _clean_expr_for_ast(expr: str) -> str:
    s = (
        expr.replace("(int64_t)", "")
        .replace("(uint64_t)", "")
        .replace("0xffLL", "0xff")
        .replace("0xffffLL", "0xffff")
    )
    return _LL_SUFFIX_RE.sub(r"\1", s).strip()


def _parse_ast_eval_cached(cleaned_expr: str) -> ast.AST:
    cached = _AST_EVAL_CACHE.get(cleaned_expr)
    if cached is None:
        if len(_AST_EVAL_CACHE) > 16384:
            _AST_EVAL_CACHE.clear()
        cached = ast.parse(cleaned_expr, mode="eval").body
        _AST_EVAL_CACHE[cleaned_expr] = cached
    return cached


def _i64_const(val: int) -> ir.Constant:
    v = int(val) & _U64_MASK
    if v & (1 << 63):
        v -= 1 << 64
    return ir.Constant(_I64, v)


def _is_u64_masked(node: ast.AST) -> Optional[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitAnd):
        if isinstance(node.right, ast.Constant) and node.right.value == _U64_MASK:
            return node.left
        if isinstance(node.left, ast.Constant) and node.left.value == _U64_MASK:
            return node.right
    return None


class _FunctionLowerer:
    """Lowers one parsed `_IRBlock` CFG into `llvmlite.ir.Function` SSA IR."""

    def __init__(
        self,
        module: ir.Module,
        fn: ir.Function,
        fn_sigs: Dict[str, Tuple[bool, bool, bool]],
        globals_map: Dict[str, ir.GlobalVariable],
        ext_cache: Dict[str, ir.Function],
        returns_double: bool,
        takes_double_arg0: bool,
        takes_double_arg1: bool,
        extra_slots: List[str],
        *,
        inline_direct_memory: bool = False,
    ) -> None:
        self.module = module
        self.fn = fn
        self.fn_sigs = fn_sigs
        self.globals_map = globals_map
        self.ext_cache = ext_cache
        self.returns_double = returns_double
        self.takes_double_arg0 = takes_double_arg0
        self.takes_double_arg1 = takes_double_arg1
        self.extra_slots = extra_slots
        self.inline_direct_memory = inline_direct_memory
        self.allocas: Dict[str, ir.AllocaInstr] = {}
        self.builder: ir.IRBuilder
        self._block_counter = 0

    def _get_ext(self, name: str, arg_types: Tuple[ir.Type, ...], ret_type: ir.Type) -> ir.Function:
        if name in self.ext_cache:
            return self.ext_cache[name]
        if name in self.module.globals:
            g = self.module.globals[name]
            if isinstance(g, ir.Function):
                self.ext_cache[name] = g
                return g
        f_ty = ir.FunctionType(ret_type, list(arg_types))
        ext = ir.Function(self.module, f_ty, name=name)
        self.ext_cache[name] = ext
        return ext

    def _get_cttz(self, bits: int) -> ir.Function:
        iname = f"llvm.cttz.i{bits}"
        if iname in self.ext_cache:
            return self.ext_cache[iname]
        if iname in self.module.globals:
            g = self.module.globals[iname]
            if isinstance(g, ir.Function):
                self.ext_cache[iname] = g
                return g
        ity = ir.IntType(bits)
        fn = ir.Function(self.module, ir.FunctionType(ity, [ity, _I1]), name=iname)
        self.ext_cache[iname] = fn
        return fn

    def _ensure_i64(self, val: ir.Value) -> ir.Value:
        if val.type == _I64:
            return val
        if val.type == _F64:
            return self.builder.bitcast(val, _I64)
        if val.type == _I1:
            return self.builder.zext(val, _I64)
        if isinstance(val.type, ir.IntType):
            if val.type.width < 64:
                return self.builder.sext(val, _I64)
            return self.builder.trunc(val, _I64)
        return _i64_const(0)

    def _ensure_f64(self, val: ir.Value) -> ir.Value:
        if val.type == _F64:
            return val
        if val.type == _I64:
            return self.builder.bitcast(val, _F64)
        return self.builder.bitcast(self._ensure_i64(val), _F64)

    def _ensure_i1(self, val: ir.Value) -> ir.Value:
        if val.type == _I1:
            return val
        if val.type == _F64:
            return self.builder.fcmp_ordered("!=", val, ir.Constant(_F64, 0.0))
        return self.builder.icmp_signed("!=", self._ensure_i64(val), _i64_const(0))

    def _eval_ast(self, node: ast.AST) -> ir.Value:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, float):
                return ir.Constant(_F64, node.value)
            if isinstance(node.value, bool):
                return _i64_const(1 if node.value else 0)
            if isinstance(node.value, int):
                return _i64_const(node.value)
            return _i64_const(0)

        if isinstance(node, ast.Name):
            ident = node.id
            if ident == "_aether_sp":
                return self.builder.call(self._get_ext("aether_get_sp", (), _I64), [])
            if ident in self.allocas:
                return self.builder.load(self.allocas[ident])
            if ident in self.globals_map:
                return self.builder.load(self.globals_map[ident])
            if ident == "xmm0_arg":
                return self.fn.args[0] if self.takes_double_arg0 else ir.Constant(_F64, 0.0)
            if ident == "xmm1_arg":
                return self.fn.args[1] if self.takes_double_arg1 else ir.Constant(_F64, 0.0)
            return _i64_const(0)

        if isinstance(node, ast.UnaryOp):
            operand = self._ensure_i64(self._eval_ast(node.operand))
            if isinstance(node.op, ast.USub):
                return self.builder.neg(operand)
            if isinstance(node.op, ast.UAdd):
                return operand
            if isinstance(node.op, ast.Invert):
                return self.builder.xor(operand, _i64_const(-1))
            if isinstance(node.op, ast.Not):
                c = self.builder.icmp_signed("==", operand, _i64_const(0))
                return self.builder.zext(c, _I64)
            return operand

        if isinstance(node, ast.BinOp):
            lhs = self._ensure_i64(self._eval_ast(node.left))
            rhs = self._ensure_i64(self._eval_ast(node.right))
            op = node.op
            if isinstance(op, ast.Add):
                return self.builder.add(lhs, rhs)
            if isinstance(op, ast.Sub):
                return self.builder.sub(lhs, rhs)
            if isinstance(op, ast.Mult):
                return self.builder.mul(lhs, rhs)
            if isinstance(op, ast.BitAnd):
                return self.builder.and_(lhs, rhs)
            if isinstance(op, ast.BitOr):
                return self.builder.or_(lhs, rhs)
            if isinstance(op, ast.BitXor):
                return self.builder.xor(lhs, rhs)
            if isinstance(op, ast.LShift):
                return self.builder.shl(lhs, self.builder.and_(rhs, _i64_const(63)))
            if isinstance(op, ast.RShift):
                # Logical right shift if LHS was zero-extended u32, else arithmetic
                if isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Name) and node.left.func.id == "aether_u32":
                    return self.builder.lshr(lhs, self.builder.and_(rhs, _i64_const(63)))
                return self.builder.ashr(lhs, self.builder.and_(rhs, _i64_const(63)))
            if isinstance(op, (ast.FloorDiv, ast.Div)):
                safe_r = self.builder.select(self.builder.icmp_signed("==", rhs, _i64_const(0)), _i64_const(1), rhs)
                return self.builder.sdiv(lhs, safe_r)
            if isinstance(op, ast.Mod):
                safe_r = self.builder.select(self.builder.icmp_signed("==", rhs, _i64_const(0)), _i64_const(1), rhs)
                return self.builder.srem(lhs, safe_r)
            return lhs

        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                res = _i64_const(1)
                for v in node.values:
                    b = self._ensure_i1(self._eval_ast(v))
                    res = self.builder.and_(res, self.builder.zext(b, _I64))
                return self.builder.icmp_signed("!=", res, _i64_const(0))
            if isinstance(node.op, ast.Or):
                res = _i64_const(0)
                for v in node.values:
                    b = self._ensure_i1(self._eval_ast(v))
                    res = self.builder.or_(res, self.builder.zext(b, _I64))
                return self.builder.icmp_signed("!=", res, _i64_const(0))

        if isinstance(node, ast.Compare):
            left_node = node.left
            right_node = node.comparators[0]
            op = node.ops[0]
            u_l = _is_u64_masked(left_node)
            u_r = _is_u64_masked(right_node)
            is_unsigned = u_l is not None or u_r is not None
            lhs = self._ensure_i64(self._eval_ast(u_l if u_l is not None else left_node))
            rhs = self._ensure_i64(self._eval_ast(u_r if u_r is not None else right_node))
            if isinstance(op, ast.Eq):
                return self.builder.icmp_signed("==", lhs, rhs)
            if isinstance(op, ast.NotEq):
                return self.builder.icmp_signed("!=", lhs, rhs)
            if isinstance(op, ast.Lt):
                return self.builder.icmp_unsigned("<", lhs, rhs) if is_unsigned else self.builder.icmp_signed("<", lhs, rhs)
            if isinstance(op, ast.LtE):
                return self.builder.icmp_unsigned("<=", lhs, rhs) if is_unsigned else self.builder.icmp_signed("<=", lhs, rhs)
            if isinstance(op, ast.Gt):
                return self.builder.icmp_unsigned(">", lhs, rhs) if is_unsigned else self.builder.icmp_signed(">", lhs, rhs)
            if isinstance(op, ast.GtE):
                return self.builder.icmp_unsigned(">=", lhs, rhs) if is_unsigned else self.builder.icmp_signed(">=", lhs, rhs)
            return ir.Constant(_I1, 0)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            fname = node.func.id
            args = node.args
            return self._lower_call(fname, args)

        return _i64_const(0)

    def _lower_call(self, fname: str, arg_nodes: List[ast.AST]) -> ir.Value:
        # 1. Native LLVM bit-width casts & intrinsics
        if fname == "aether_u32" and len(arg_nodes) == 1:
            v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            return self.builder.zext(self.builder.trunc(v, _I32), _I64)
        if fname == "aether_i32" and len(arg_nodes) == 1:
            v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            return self.builder.sext(self.builder.trunc(v, _I32), _I64)
        if fname == "aether_i16" and len(arg_nodes) == 1:
            v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            return self.builder.sext(self.builder.trunc(v, _I16), _I64)
        if fname == "aether_i8" and len(arg_nodes) == 1:
            v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            return self.builder.sext(self.builder.trunc(v, _I8), _I64)
        if fname == "aether_u8" and len(arg_nodes) == 1:
            v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            return self.builder.and_(v, _i64_const(0xFF))
        if fname == "aether_bt_cf" and len(arg_nodes) == 3:
            v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            b = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            m = self._ensure_i64(self._eval_ast(arg_nodes[2]))
            sh = self.builder.and_(b, m)
            bit = self.builder.and_(self.builder.lshr(v, sh), _i64_const(1))
            is_zero = self.builder.icmp_signed("==", bit, _i64_const(0))
            return self.builder.select(is_zero, _i64_const(1), _i64_const(0))
        if fname == "aether_bit_mask" and len(arg_nodes) == 2:
            b = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            m = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            return self.builder.shl(_i64_const(1), self.builder.and_(b, m))
        if fname == "aether_set_byte" and len(arg_nodes) == 2:
            reg = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            cond = self._ensure_i1(self._eval_ast(arg_nodes[1]))
            return self.builder.or_(self.builder.and_(reg, _i64_const(~0xFF)), self.builder.zext(cond, _I64))
        if fname == "aether_tzcnt32" and len(arg_nodes) == 1:
            v = self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[0])), _I32)
            ct = self.builder.call(self._get_cttz(32), [v, ir.Constant(_I1, 0)])
            return self.builder.zext(ct, _I64)
        if fname == "aether_tzcnt64" and len(arg_nodes) == 1:
            v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            return self.builder.call(self._get_cttz(64), [v, ir.Constant(_I1, 0)])

        # 2. Native IEEE-754 float ops
        if fname == "aether_f64_to_bits" and len(arg_nodes) == 1:
            return self._ensure_i64(self._eval_ast(arg_nodes[0]))
        if fname == "aether_bits_to_f64" and len(arg_nodes) == 1:
            return self._ensure_f64(self._eval_ast(arg_nodes[0]))
        if fname == "aether_i32_to_f64" and len(arg_nodes) == 1:
            v32 = self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[0])), _I32)
            return self.builder.bitcast(self.builder.sitofp(v32, _F64), _I64)
        if fname == "aether_f64_to_i32" and len(arg_nodes) == 1:
            d = self._ensure_f64(self._eval_ast(arg_nodes[0]))
            return self.builder.sext(self.builder.fptosi(d, _I32), _I64)
        if fname == "aether_f32_to_f64" and len(arg_nodes) == 1:
            f32_bits = self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[0])), _I32)
            d = self.builder.fpext(self.builder.bitcast(f32_bits, _F32), _F64)
            return self.builder.bitcast(d, _I64)
        if fname in ("aether_f64_add", "aether_f64_sub", "aether_f64_mul", "aether_f64_div") and len(arg_nodes) == 2:
            da = self._ensure_f64(self._eval_ast(arg_nodes[0]))
            db = self._ensure_f64(self._eval_ast(arg_nodes[1]))
            if fname == "aether_f64_add":
                r = self.builder.fadd(da, db)
            elif fname == "aether_f64_sub":
                r = self.builder.fsub(da, db)
            elif fname == "aether_f64_mul":
                r = self.builder.fmul(da, db)
            else:
                r = self.builder.fdiv(da, db)
            return self.builder.bitcast(r, _I64)
        if fname in ("aether_f64_max", "aether_f64_min") and len(arg_nodes) == 2:
            da = self._ensure_f64(self._eval_ast(arg_nodes[0]))
            db = self._ensure_f64(self._eval_ast(arg_nodes[1]))
            pred = ">" if fname == "aether_f64_max" else "<"
            c = self.builder.fcmp_ordered(pred, da, db)
            return self.builder.bitcast(self.builder.select(c, da, db), _I64)
        if fname == "aether_f64_comisd" and len(arg_nodes) == 2:
            da = self._ensure_f64(self._eval_ast(arg_nodes[0]))
            db = self._ensure_f64(self._eval_ast(arg_nodes[1]))
            is_uno = self.builder.fcmp_unordered("uno", da, db)
            is_eq = self.builder.fcmp_ordered("==", da, db)
            is_gt = self.builder.fcmp_ordered(">", da, db)
            gt_or_lt = self.builder.select(is_gt, _i64_const(2), _i64_const(0))
            eq_sel = self.builder.select(is_eq, _i64_const(1), gt_or_lt)
            return self.builder.select(is_uno, _i64_const(-1), eq_sel)

        # 3. Native 128-bit & 64-bit mul/div + pshufd SIMD
        if fname in ("aether_imul64", "aether_umul64") and len(arg_nodes) == 2:
            a = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            b = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            a128 = self.builder.sext(a, _I128) if fname == "aether_imul64" else self.builder.zext(a, _I128)
            b128 = self.builder.sext(b, _I128) if fname == "aether_imul64" else self.builder.zext(b, _I128)
            prod = self.builder.mul(a128, b128)
            hi = self.builder.trunc(self.builder.lshr(prod, ir.Constant(_I128, 64)), _I64)
            self.builder.store(hi, self.globals_map["_aether_imul_hi"])
            return self.builder.trunc(prod, _I64)
        if fname in ("aether_imul32", "aether_umul32") and len(arg_nodes) == 2:
            a32 = self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[0])), _I32)
            b32 = self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[1])), _I32)
            a64 = self.builder.sext(a32, _I64) if fname == "aether_imul32" else self.builder.zext(a32, _I64)
            b64 = self.builder.sext(b32, _I64) if fname == "aether_imul32" else self.builder.zext(b32, _I64)
            prod = self.builder.mul(a64, b64)
            hi32 = self.builder.zext(self.builder.trunc(self.builder.lshr(prod, _i64_const(32)), _I32), _I64)
            self.builder.store(hi32, self.globals_map["_aether_imul_hi"])
            return self.builder.zext(self.builder.trunc(prod, _I32), _I64)
        if fname == "aether_udiv64" and len(arg_nodes) == 3:
            hi = self.builder.zext(self._ensure_i64(self._eval_ast(arg_nodes[0])), _I128)
            lo = self.builder.zext(self._ensure_i64(self._eval_ast(arg_nodes[1])), _I128)
            d = self._ensure_i64(self._eval_ast(arg_nodes[2]))
            is_zero = self.builder.icmp_signed("==", d, _i64_const(0))
            safe_d = self.builder.zext(self.builder.select(is_zero, _i64_const(1), d), _I128)
            num = self.builder.or_(self.builder.shl(hi, ir.Constant(_I128, 64)), lo)
            q = self.builder.trunc(self.builder.udiv(num, safe_d), _I64)
            r = self.builder.trunc(self.builder.urem(num, safe_d), _I64)
            self.builder.store(self.builder.select(is_zero, _i64_const(0), r), self.globals_map["_aether_div_rem"])
            return self.builder.select(is_zero, _i64_const(0), q)
        if fname == "aether_udiv32" and len(arg_nodes) == 3:
            hi = self.builder.zext(self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[0])), _I32), _I64)
            lo = self.builder.zext(self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[1])), _I32), _I64)
            d32 = self.builder.zext(self.builder.trunc(self._ensure_i64(self._eval_ast(arg_nodes[2])), _I32), _I64)
            is_zero = self.builder.icmp_signed("==", d32, _i64_const(0))
            safe_d = self.builder.select(is_zero, _i64_const(1), d32)
            num = self.builder.or_(self.builder.shl(hi, _i64_const(32)), lo)
            q = self.builder.zext(self.builder.trunc(self.builder.udiv(num, safe_d), _I32), _I64)
            r = self.builder.zext(self.builder.trunc(self.builder.urem(num, safe_d), _I32), _I64)
            self.builder.store(self.builder.select(is_zero, _i64_const(0), r), self.globals_map["_aether_div_rem"])
            return self.builder.select(is_zero, _i64_const(0), q)
        if fname == "aether_pshufd" and len(arg_nodes) == 3:
            lo = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            hi = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            imm = 0
            if isinstance(arg_nodes[2], ast.Constant) and isinstance(arg_nodes[2].value, int):
                imm = int(arg_nodes[2].value) & 0xFF
            v2 = ir.Constant(ir.VectorType(_I64, 2), ir.Undefined)
            v2 = self.builder.insert_element(v2, lo, ir.Constant(_I32, 0))
            v2 = self.builder.insert_element(v2, hi, ir.Constant(_I32, 1))
            v4 = self.builder.bitcast(v2, ir.VectorType(_I32, 4))
            mask = ir.Constant(
                ir.VectorType(_I32, 4),
                [imm & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3],
            )
            shuf = self.builder.shuffle_vector(v4, ir.Constant(ir.VectorType(_I32, 4), ir.Undefined), mask)
            out2 = self.builder.bitcast(shuf, ir.VectorType(_I64, 2))
            new_lo = self.builder.extract_element(out2, ir.Constant(_I32, 0))
            new_hi = self.builder.extract_element(out2, ir.Constant(_I32, 1))
            self.builder.store(new_hi, self.globals_map["_aether_xmm_hi"])
            return new_lo

        # 3b. Native LLVM SIMD Vector IR for packed integer helpers (zero helper-call overhead)
        if fname == "aether_pcmpeqb64" and len(arg_nodes) == 2:
            a = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            b = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            va = self.builder.bitcast(a, ir.VectorType(_I8, 8))
            vb = self.builder.bitcast(b, ir.VectorType(_I8, 8))
            cmp_v = self.builder.icmp_unsigned("==", va, vb)
            mask_v = self.builder.sext(cmp_v, ir.VectorType(_I8, 8))
            return self.builder.bitcast(mask_v, _I64)
        if fname == "aether_pcmpeqd64" and len(arg_nodes) == 2:
            a = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            b = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            va = self.builder.bitcast(a, ir.VectorType(_I32, 2))
            vb = self.builder.bitcast(b, ir.VectorType(_I32, 2))
            cmp_v = self.builder.icmp_unsigned("==", va, vb)
            mask_v = self.builder.sext(cmp_v, ir.VectorType(_I32, 2))
            return self.builder.bitcast(mask_v, _I64)
        if fname == "aether_pmaxud64" and len(arg_nodes) == 2:
            a = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            b = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            va = self.builder.bitcast(a, ir.VectorType(_I32, 2))
            vb = self.builder.bitcast(b, ir.VectorType(_I32, 2))
            gt_v = self.builder.icmp_unsigned(">", va, vb)
            max_v = self.builder.select(gt_v, va, vb)
            return self.builder.bitcast(max_v, _I64)
        if fname == "aether_psubd64" and len(arg_nodes) == 2:
            a = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            b = self._ensure_i64(self._eval_ast(arg_nodes[1]))
            va = self.builder.bitcast(a, ir.VectorType(_I32, 2))
            vb = self.builder.bitcast(b, ir.VectorType(_I32, 2))
            return self.builder.bitcast(self.builder.sub(va, vb), _I64)

        # 3c. Optional null-guarded direct native pointer memory load/store (inline_direct_memory=True)
        if self.inline_direct_memory and fname == "aether_mem_read" and len(arg_nodes) == 2:
            addr = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            w_node = arg_nodes[1]
            width = int(w_node.value) if isinstance(w_node, ast.Constant) and isinstance(w_node.value, int) else 8
            if width in (1, 2, 4, 8):
                self._block_counter += 1
                mid = self._block_counter
                ok_bb = self.fn.append_basic_block(f"mem_r_ok_{mid}")
                null_bb = self.fn.append_basic_block(f"mem_r_null_{mid}")
                done_bb = self.fn.append_basic_block(f"mem_r_done_{mid}")
                is_nz = self.builder.icmp_signed("!=", addr, _i64_const(0))
                self.builder.cbranch(is_nz, ok_bb, null_bb)
                self.builder.position_at_end(ok_bb)
                elem_ty = _I8 if width == 1 else (_I16 if width == 2 else (_I32 if width == 4 else _I64))
                ptr_v = self.builder.inttoptr(addr, elem_ty.as_pointer())
                raw_ld = self.builder.load(ptr_v)
                val_ok = raw_ld if elem_ty == _I64 else self.builder.zext(raw_ld, _I64)
                self.builder.branch(done_bb)
                self.builder.position_at_end(null_bb)
                self.builder.branch(done_bb)
                self.builder.position_at_end(done_bb)
                phi = self.builder.phi(_I64)
                phi.add_incoming(val_ok, ok_bb)
                phi.add_incoming(_i64_const(0), null_bb)
                return phi
        if self.inline_direct_memory and fname == "aether_mem_write" and len(arg_nodes) == 3:
            addr = self._ensure_i64(self._eval_ast(arg_nodes[0]))
            w_node = arg_nodes[1]
            val = self._ensure_i64(self._eval_ast(arg_nodes[2]))
            width = int(w_node.value) if isinstance(w_node, ast.Constant) and isinstance(w_node.value, int) else 8
            if width in (1, 2, 4, 8):
                self._block_counter += 1
                mid = self._block_counter
                ok_bb = self.fn.append_basic_block(f"mem_w_ok_{mid}")
                done_bb = self.fn.append_basic_block(f"mem_w_done_{mid}")
                is_nz = self.builder.icmp_signed("!=", addr, _i64_const(0))
                self.builder.cbranch(is_nz, ok_bb, done_bb)
                self.builder.position_at_end(ok_bb)
                elem_ty = _I8 if width == 1 else (_I16 if width == 2 else (_I32 if width == 4 else _I64))
                ptr_v = self.builder.inttoptr(addr, elem_ty.as_pointer())
                val_st = val if elem_ty == _I64 else self.builder.trunc(val, elem_ty)
                self.builder.store(val_st, ptr_v)
                self.builder.branch(done_bb)
                self.builder.position_at_end(done_bb)
                return _i64_const(0)

        # 4. Internal/exported function call or switch table tbl_*
        if fname in self.fn_sigs:
            callee = self.module.globals.get(fname)
            if isinstance(callee, ir.Function):
                c_ret_f64, c_p0_f64, c_p1_f64 = self.fn_sigs[fname]
                cargs: List[ir.Value] = []
                for idx_a, an in enumerate(arg_nodes[:4]):
                    av = self._eval_ast(an)
                    if idx_a == 0 and c_p0_f64:
                        cargs.append(self._ensure_f64(av))
                    elif idx_a == 1 and c_p1_f64:
                        cargs.append(self._ensure_f64(av))
                    else:
                        cargs.append(self._ensure_i64(av))
                while len(cargs) < 4:
                    idx_a = len(cargs)
                    if (idx_a == 0 and c_p0_f64) or (idx_a == 1 and c_p1_f64):
                        cargs.append(ir.Constant(_F64, 0.0))
                    else:
                        cargs.append(_i64_const(0))
                return self.builder.call(callee, cargs)

        if fname.startswith("tbl_"):
            tbl_fn = self.module.globals.get(fname)
            if isinstance(tbl_fn, ir.Function) and len(arg_nodes) == 1:
                idx_v = self._ensure_i64(self._eval_ast(arg_nodes[0]))
                return self.builder.call(tbl_fn, [idx_v])

        # 5. External runtime helper symbol
        if fname in _EXT_HELPER_SIGS:
            arg_tys, ret_ty = _EXT_HELPER_SIGS[fname]
            ext = self._get_ext(fname, arg_tys, ret_ty)
            cargs = []
            for idx_a, exp_ty in enumerate(arg_tys):
                av = self._eval_ast(arg_nodes[idx_a]) if idx_a < len(arg_nodes) else _i64_const(0)
                cargs.append(self._ensure_f64(av) if exp_ty == _F64 else self._ensure_i64(av))
            return self.builder.call(ext, cargs)

        # Generic fallback: all i64 args -> i64
        gen_arg_tys = tuple(_I64 for _ in arg_nodes)
        ext = self._get_ext(fname, gen_arg_tys, _I64)
        cargs = [self._ensure_i64(self._eval_ast(an)) for an in arg_nodes]
        return self.builder.call(ext, cargs)

    def _lower_single_stmt(self, stmt: str) -> None:
        st = stmt.strip()
        if not st:
            return
        if st.startswith("if (") and ") {" in st and st.endswith("}"):
            cond_s = _clean_expr_for_ast(st[4 : st.index(") {")].strip())
            body_s = st[st.index(") {") + 3 : -1].strip()
            cond_val = self._ensure_i1(self._eval_ast(_parse_ast_eval_cached(cond_s)))
            self._block_counter += 1
            cid = self._block_counter
            then_bb = self.fn.append_basic_block(f"cmov_then_{cid}")
            cont_bb = self.fn.append_basic_block(f"cmov_cont_{cid}")
            self.builder.cbranch(cond_val, then_bb, cont_bb)
            self.builder.position_at_end(then_bb)
            for sub_s in [x.strip() for x in body_s.split(";") if x.strip()]:
                self._lower_single_stmt(sub_s)
            if not self.builder.block.is_terminated:
                self.builder.branch(cont_bb)
            self.builder.position_at_end(cont_bb)
            return

        # Compound assign: lhs += rhs or lhs -= rhs
        m_cmp = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\+=|-=)\s*(.+)$", st)
        if m_cmp:
            lhs, op, rhs = m_cmp.group(1), m_cmp.group(2), _clean_expr_for_ast(m_cmp.group(3))
            ptr = self.allocas.get(lhs) or self.globals_map.get(lhs)
            if ptr is not None:
                cur_v = self.builder.load(ptr)
                rv = self._ensure_i64(self._eval_ast(_parse_ast_eval_cached(rhs)))
                nv = self.builder.add(cur_v, rv) if op == "+=" else self.builder.sub(cur_v, rv)
                self.builder.store(nv, ptr)
            return

        # Simple assign: lhs = rhs
        m_as = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", st)
        if m_as:
            lhs, rhs = m_as.group(1), _clean_expr_for_ast(m_as.group(2))
            rv = self._ensure_i64(self._eval_ast(_parse_ast_eval_cached(rhs)))
            if lhs == "_aether_sp":
                self.builder.call(self._get_ext("aether_set_sp", (_I64,), _I64), [rv])
                return
            ptr = self.allocas.get(lhs) or self.globals_map.get(lhs)
            if ptr is not None:
                self.builder.store(rv, ptr)
            return

        # Bare expression statement (e.g. aether_mem_write(...))
        cleaned = _clean_expr_for_ast(st)
        self._eval_ast(_parse_ast_eval_cached(cleaned))

    def lower(self, blocks: List[Any]) -> None:
        entry_bb = self.fn.append_basic_block("alloc_entry")
        self.builder = ir.IRBuilder(entry_bb)

        # Prune allocas to only variables used in blocks plus ABI arg/return slots
        used_vars: set[str] = {"rax", "rcx", "rdx", "r8", "r9"}
        if self.returns_double or self.takes_double_arg0 or self.takes_double_arg1:
            used_vars.add("xmm0")
            used_vars.add("xmm1")
        for b in blocks:
            for st in b.stmts:
                used_vars.update(_IDENT_SCAN_RE.findall(st))
            if b.term_cond:
                used_vars.update(_IDENT_SCAN_RE.findall(b.term_cond))
            if b.term_ret:
                used_vars.update(_IDENT_SCAN_RE.findall(b.term_ret))
        for vname in _TRACKED_LOCALS:
            if vname in used_vars:
                self.allocas[vname] = self.builder.alloca(_I64, name=vname)
        for sv in self.extra_slots:
            self.allocas[sv] = self.builder.alloca(_I64, name=sv)

        zero = _i64_const(0)
        for vname, ptr in self.allocas.items():
            if vname == "rcx" and not self.takes_double_arg0:
                self.builder.store(self.fn.args[0], ptr)
            elif vname == "rdx" and not self.takes_double_arg1:
                self.builder.store(self.fn.args[1], ptr)
            elif vname == "r8":
                self.builder.store(self.fn.args[2], ptr)
            elif vname == "r9":
                self.builder.store(self.fn.args[3], ptr)
            elif vname == "xmm0" and self.takes_double_arg0:
                self.builder.store(self.builder.bitcast(self.fn.args[0], _I64), ptr)
            elif vname == "xmm1" and self.takes_double_arg1:
                self.builder.store(self.builder.bitcast(self.fn.args[1], _I64), ptr)
            elif vname == "_aether_saved_sp":
                gsp_fn = self._get_ext("aether_get_sp", (), _I64)
                self.builder.store(self.builder.call(gsp_fn, []), ptr)
            elif vname == "rsp":
                sb_fn = self._get_ext("aether_stack_base", (), _I64)
                self.builder.store(self.builder.call(sb_fn, []), ptr)
            else:
                self.builder.store(zero, ptr)

        # Create LLVM basic blocks for every IRBlock
        ir_bbs: List[ir.Block] = []
        lbl_to_bb: Dict[str, ir.Block] = {}
        for idx, b in enumerate(blocks):
            bb_name = b.label or f"{b.name}_{idx}"
            ir_bb = self.fn.append_basic_block(bb_name)
            ir_bbs.append(ir_bb)
            if b.label:
                lbl_to_bb[b.label] = ir_bb

        if ir_bbs:
            self.builder.branch(ir_bbs[0])
        else:
            self.builder.ret(ir.Constant(_F64, 0.0) if self.returns_double else zero)
            return

        for idx, b in enumerate(blocks):
            self.builder.position_at_end(ir_bbs[idx])
            for st in b.stmts:
                self._lower_single_stmt(st)
            if self.builder.block.is_terminated:
                continue

            fall_bb = ir_bbs[idx + 1] if idx + 1 < len(ir_bbs) else None
            if b.term_kind == "return":
                if self.returns_double:
                    ret_v = self._ensure_f64(self.builder.load(self.allocas["xmm0"]))
                else:
                    ret_v = self._ensure_i64(self.builder.load(self.allocas["rax"]))
                self.builder.ret(ret_v)
            elif b.term_kind == "goto":
                tgt_bb = lbl_to_bb.get(b.term_target) or fall_bb
                if tgt_bb is not None:
                    self.builder.branch(tgt_bb)
                else:
                    self.builder.ret(ir.Constant(_F64, 0.0) if self.returns_double else zero)
            elif b.term_kind == "cbranch":
                tgt_bb = lbl_to_bb.get(b.term_target)
                cond_s = _clean_expr_for_ast(b.term_cond)
                cond_v = self._ensure_i1(self._eval_ast(_parse_ast_eval_cached(cond_s)))
                if tgt_bb is not None and fall_bb is not None:
                    self.builder.cbranch(cond_v, tgt_bb, fall_bb)
                elif tgt_bb is not None:
                    self.builder.branch(tgt_bb)
                elif fall_bb is not None:
                    self.builder.branch(fall_bb)
                else:
                    self.builder.ret(ir.Constant(_F64, 0.0) if self.returns_double else zero)
            else:
                if fall_bb is not None:
                    self.builder.branch(fall_bb)
                else:
                    ret_v = (
                        self._ensure_f64(self.builder.load(self.allocas["xmm0"]))
                        if self.returns_double
                        else self._ensure_i64(self.builder.load(self.allocas["rax"]))
                    )
                    self.builder.ret(ret_v)

        # Ensure every basic block in LLVM IR has a valid terminator (verifier contract)
        for bb in self.fn.basic_blocks:
            if not bb.is_terminated:
                self.builder.position_at_end(bb)
                self.builder.ret(ir.Constant(_F64, 0.0) if self.returns_double else zero)


def build_llvm_module_from_records(
    records_list: List[Dict[str, Any]],
    *,
    ro_table_fns_map: Optional[Dict[str, List[int]]] = None,
    unresolved_rvas: Optional[List[int]] = None,
    rva_to_symbol: Optional[Dict[int, str]] = None,
    module_name: str = "reconstructed_twin",
    inline_direct_memory: bool = False,
) -> Tuple[ir.Module, Dict[str, Any]]:
    """Builds an LLVM IR module lowering all reconstructed functions and switch tables."""
    _ensure_llvm_init()
    mod = ir.Module(name=module_name)
    mod.triple = llvm.get_default_triple()

    globals_map: Dict[str, ir.GlobalVariable] = {}
    for gname in ("_aether_div_rem", "_aether_imul_hi", "_aether_xmm_hi"):
        gv = ir.GlobalVariable(mod, _I64, name=gname)
        gv.linkage = "internal"
        gv.initializer = _i64_const(0)
        globals_map[gname] = gv

    ext_cache: Dict[str, ir.Function] = {}

    # Emit switch jump-table helper functions directly as LLVM constant array lookups
    if ro_table_fns_map:
        for t_name, t_vals in sorted(ro_table_fns_map.items()):
            arr_vals = [_i64_const(v) for v in (t_vals or [0])]
            arr_ty = ir.ArrayType(_I64, len(arr_vals))
            arr_gv = ir.GlobalVariable(mod, arr_ty, name=f"__data_{t_name}")
            arr_gv.linkage = "internal"
            arr_gv.global_constant = True
            arr_gv.initializer = ir.Constant(arr_ty, arr_vals)

            tfn = ir.Function(mod, ir.FunctionType(_I64, [_I64]), name=t_name)
            tfn.linkage = "internal"
            bb_entry = tfn.append_basic_block("entry")
            bb_ok = tfn.append_basic_block("in_bounds")
            bb_oob = tfn.append_basic_block("out_of_bounds")
            b = ir.IRBuilder(bb_entry)
            idx_v = tfn.args[0]
            cond_ge = b.icmp_signed(">=", idx_v, _i64_const(0))
            cond_lt = b.icmp_signed("<", idx_v, _i64_const(len(t_vals)))
            b.cbranch(b.and_(cond_ge, cond_lt), bb_ok, bb_oob)
            b.position_at_end(bb_ok)
            ptr = b.gep(arr_gv, [_i64_const(0), idx_v], inbounds=True)
            b.ret(b.load(ptr))
            b.position_at_end(bb_oob)
            b.ret(_i64_const(0))

    # Pre-declare all defined internal/exported functions
    fn_sigs: Dict[str, Tuple[bool, bool, bool]] = {}
    for rec in records_list:
        c_ident = rec["c_ident"]
        ret_f64 = bool(rec.get("returns_double"))
        p0_f64 = bool(rec.get("takes_double_arg0"))
        p1_f64 = bool(rec.get("takes_double_arg1"))
        fn_sigs[c_ident] = (ret_f64, p0_f64, p1_f64)
        ret_ty = _F64 if ret_f64 else _I64
        arg_tys = [
            _F64 if p0_f64 else _I64,
            _F64 if p1_f64 else _I64,
            _I64,
            _I64,
        ]
        if c_ident not in mod.globals:
            ir.Function(mod, ir.FunctionType(ret_ty, arg_tys), name=c_ident)

    # Stub any unresolved external code RVAs cleanly
    if unresolved_rvas and rva_to_symbol:
        for un_rva in sorted(unresolved_rvas):
            sym_name = rva_to_symbol.get(un_rva, f"sub_{un_rva:x}")
            if sym_name not in fn_sigs and sym_name not in mod.globals:
                fn_sigs[sym_name] = (False, False, False)
                ufn = ir.Function(mod, ir.FunctionType(_I64, [_I64, _I64, _I64, _I64]), name=sym_name)
                ubb = ufn.append_basic_block("entry")
                ir.IRBuilder(ubb).ret(_i64_const(0))

    lowered_count = 0
    errors: List[str] = []
    for rec in records_list:
        c_ident = rec["c_ident"]
        c_code = rec["c_code"]
        ir_fn = mod.globals[c_ident]
        ir_bundle = rec.get("ir_bundle")
        if ir_bundle and ir_bundle.get("blocks"):
            header_lines = ir_bundle["header_lines"]
            blocks = ir_bundle["blocks"]
        else:
            parsed = _parse_c_function(c_code)
            if parsed is None:
                bb = ir_fn.append_basic_block("entry")
                b = ir.IRBuilder(bb)
                b.ret(ir.Constant(_F64, 0.0) if rec.get("returns_double") else _i64_const(0))
                continue
            header_lines, blocks, _ = parsed
        extra_slots = sorted(set(re.findall(r"\baether_slot_[A-Za-z0-9_]+\b", "\n".join(header_lines))))
        try:
            lowerer = _FunctionLowerer(
                mod,
                ir_fn,
                fn_sigs,
                globals_map,
                ext_cache,
                bool(rec.get("returns_double")),
                bool(rec.get("takes_double_arg0")),
                bool(rec.get("takes_double_arg1")),
                extra_slots,
                inline_direct_memory=inline_direct_memory,
            )
            lowerer.lower(blocks)
            lowered_count += 1
        except Exception as exc:
            errors.append(f"{c_ident}: {exc}")
            if not ir_fn.basic_blocks:
                bb = ir_fn.append_basic_block("fallback")
                ir.IRBuilder(bb).ret(ir.Constant(_F64, 0.0) if rec.get("returns_double") else _i64_const(0))

    return mod, {
        "lowered_functions": lowered_count,
        "total_functions": len(records_list),
        "lowering_errors": errors,
        "fn_sigs": fn_sigs,
    }


def compile_project_to_llvm_ir(
    records_list: List[Dict[str, Any]],
    out_ir_dir: Path,
    *,
    ro_table_fns_map: Optional[Dict[str, List[int]]] = None,
    unresolved_rvas: Optional[List[int]] = None,
    rva_to_symbol: Optional[Dict[int, str]] = None,
    opt_level: int = 3,
    inline_direct_memory: bool = False,
) -> Dict[str, Any]:
    """Emits LLVM IR (.ll), verifies it, runs LLVM O3 PassBuilder, and emits Win64 COFF (.obj)."""
    _ensure_llvm_init()
    out_ir_dir.mkdir(parents=True, exist_ok=True)
    mod, build_meta = build_llvm_module_from_records(
        records_list,
        ro_table_fns_map=ro_table_fns_map,
        unresolved_rvas=unresolved_rvas,
        rva_to_symbol=rva_to_symbol,
        inline_direct_memory=inline_direct_memory,
    )

    raw_ll_path = out_ir_dir / "reconstructed_project.ll"
    o3_ll_path = out_ir_dir / "reconstructed_project_o3.ll"
    obj_path = out_ir_dir / "reconstructed_project.obj"

    raw_ir_str = str(mod)
    raw_ll_path.write_text(raw_ir_str, encoding="utf-8")

    verified = False
    verify_error: Optional[str] = None
    o3_ir_str = ""
    coff_bytes = 0

    try:
        lm = llvm.parse_assembly(raw_ir_str)
        lm.verify()
        verified = True

        tm = llvm.Target.from_default_triple().create_target_machine(
            opt=opt_level, codemodel="default"
        )
        pto = llvm.create_pipeline_tuning_options(speed_level=opt_level, size_level=0)
        pb = llvm.create_pass_builder(tm, pto)
        mpm = pb.getModulePassManager()
        mpm.run(lm, pb)

        o3_ir_str = str(lm)
        o3_ll_path.write_text(o3_ir_str, encoding="utf-8")

        obj_data = tm.emit_object(lm)
        obj_path.write_bytes(obj_data)
        coff_bytes = len(obj_data)
    except Exception as exc:
        verify_error = str(exc)

    return {
        "llvm_ir_verified": verified,
        "llvm_o3_functions": build_meta["lowered_functions"] if verified else 0,
        "total_functions": build_meta["total_functions"],
        "lowering_errors": build_meta["lowering_errors"],
        "verify_error": verify_error,
        "fn_sigs": build_meta["fn_sigs"],
        "o3_ir_text": o3_ir_str,
        "raw_ll_path": str(raw_ll_path),
        "o3_ll_path": str(o3_ll_path) if verified else None,
        "obj_path": str(obj_path) if coff_bytes > 0 else None,
        "coff_obj_bytes": coff_bytes,
    }


# ---------------------------------------------------------------------------
# Process-wide pinned MCJIT runtime trampoline callbacks (ctypes callbacks GC-safe)
# ---------------------------------------------------------------------------

_MCJIT_RUNTIME_CTX: Dict[str, Any] = {
    "arena": None,
    "stack_base": 0x4E000,
    "sp": 0,
    "ro_addrs": {},
    "vt_addrs": {},
    "rw_base": 0,
    "rva_to_sym": {},
    "ee": None,
    "fn_sigs": {},
}
_MCJIT_PINNED_CBS: Dict[str, Any] = {}


def _ensure_mcjit_symbols_registered() -> None:
    if _MCJIT_PINNED_CBS:
        return
    _ensure_llvm_init()

    def _ctx_arena():
        return _MCJIT_RUNTIME_CTX["arena"]

    @ctypes.CFUNCTYPE(ctypes.c_int64)
    def cb_stack_base() -> int:
        sp = int(_MCJIT_RUNTIME_CTX.get("sp") or 0)
        if sp:
            return max(0x1E800, sp - 8)
        return int(_MCJIT_RUNTIME_CTX["stack_base"])

    @ctypes.CFUNCTYPE(ctypes.c_int64)
    def cb_get_sp() -> int:
        return int(_MCJIT_RUNTIME_CTX.get("sp") or 0)

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_set_sp(sp: int) -> int:
        _MCJIT_RUNTIME_CTX["sp"] = int(sp)
        return int(sp)

    @ctypes.CFUNCTYPE(ctypes.c_int64)
    def cb_abort() -> int:
        return 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_mem_read(addr: int, width: int) -> int:
        a = _ctx_arena()
        return a.read(int(addr), int(width)) if a is not None else 0

    @ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_mem_write(addr: int, width: int, val: int) -> None:
        a = _ctx_arena()
        if a is not None:
            a.write(int(addr), int(width), int(val))

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_malloc(sz: int) -> int:
        a = _ctx_arena()
        return a.alloc(int(sz)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_free(ptr: int) -> int:
        a = _ctx_arena()
        return a.free(int(ptr)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_realloc(ptr: int, sz: int) -> int:
        a = _ctx_arena()
        return a.realloc(int(ptr), int(sz)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_calloc(n: int, sz: int) -> int:
        a = _ctx_arena()
        return a.alloc(max(1, (int(n) & 0xFFFFFFFF) * (int(sz) & 0xFFFFFFFF))) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_memcpy(dst: int, src: int, sz: int) -> int:
        a = _ctx_arena()
        return a.c_memcpy(int(dst), int(src), int(sz)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_memset(dst: int, val: int, sz: int) -> int:
        a = _ctx_arena()
        return a.c_memset(int(dst), int(val), int(sz)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_rep_stos(d: int, v: int, c: int, w: int) -> int:
        a = _ctx_arena()
        return a.c_rep_stos(int(d), int(v), int(c), int(w)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_strlen(ptr: int) -> int:
        a = _ctx_arena()
        return a.c_strlen(int(ptr)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_strcmp(p1: int, p2: int) -> int:
        a = _ctx_arena()
        return a.c_strcmp(int(p1), int(p2)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_strncmp(p1: int, p2: int, n: int) -> int:
        a = _ctx_arena()
        return a.c_strncmp(int(p1), int(p2), int(n)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_strcpy(dst: int, src: int) -> int:
        a = _ctx_arena()
        return a.c_strcpy(int(dst), int(src)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_strrchr(s: int, ch: int) -> int:
        a = _ctx_arena()
        return a.c_strrchr(int(s), int(ch)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_sprintf(buf: int, fmt: int, a1: int, a2: int, a3: int) -> int:
        a = _ctx_arena()
        return a.c_sprintf(int(buf), int(fmt), int(a1), int(a2), int(a3)) if a is not None else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_zero4(a0: int, a1: int, a2: int, a3: int) -> int:
        return 0

    @ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_int64, ctypes.c_int64)
    def cb_strtod(s_ptr: int, end_ptr: int) -> float:
        a = _ctx_arena()
        if a is None:
            return 0.0
        bits = a.c_strtod(int(s_ptr), int(end_ptr))
        return struct.unpack("<d", struct.pack("<q", bits))[0]

    @ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_double, ctypes.c_double)
    def cb_pow(x: float, y: float) -> float:
        try:
            return float(math.pow(x, y))
        except Exception:
            return float("nan")

    @ctypes.CFUNCTYPE(ctypes.c_double, ctypes.c_double, ctypes.c_double)
    def cb_fmod(x: float, y: float) -> float:
        return math.fmod(x, y) if y != 0.0 else float("nan")

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_isalpha(c: int) -> int:
        b = int(c) & 0xFF
        return 1 if (0 <= b < 128 and chr(b).isalpha()) else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_isdigit(c: int) -> int:
        b = int(c) & 0xFF
        return 1 if (0 <= b < 128 and chr(b).isdigit()) else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_isspace(c: int) -> int:
        b = int(c) & 0xFF
        return 1 if (0 <= b < 128 and chr(b).isspace()) else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_isxdigit(c: int) -> int:
        return 1 if ((int(c) & 0xFF) in b"0123456789abcdefABCDEF") else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_tolower(c: int) -> int:
        b = int(c) & 0xFF
        return b + 32 if 65 <= b <= 90 else b

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_ro_ptr(rva: int) -> int:
        return int(_MCJIT_RUNTIME_CTX["ro_addrs"].get(int(rva), 0))

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_data_ptr(rva: int) -> int:
        base = int(_MCJIT_RUNTIME_CTX["rw_base"])
        return 0x1B000 + (int(rva) - base) if base > 0 else 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_fn_ptr(rva: int) -> int:
        return int(rva)

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_vtable_ptr(vt_rva: int) -> int:
        return int(_MCJIT_RUNTIME_CTX["vt_addrs"].get(int(vt_rva), 0))

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def cb_crt_fn_ptr(kid: int) -> int:
        return 0x1A000 + int(kid)

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_vcall(fp: int, a0: int, a1: int, a2: int, a3: int) -> int:
        sym = _MCJIT_RUNTIME_CTX["rva_to_sym"].get(int(fp))
        ee = _MCJIT_RUNTIME_CTX["ee"]
        if sym and ee is not None:
            addr = ee.get_function_address(sym)
            if addr:
                fn_c = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)(addr)
                return int(fn_c(a0, a1, a2, a3))
        return 0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_icall(fp: int, a0: int, a1: int, a2: int, a3: int) -> int:
        a = _ctx_arena()
        if int(fp) == 0x1A001:
            return a.alloc(int(a0)) if a is not None else 0
        if int(fp) == 0x1A002:
            return a.free(int(a0)) if a is not None else 0
        if int(fp) == 0x1A003:
            return a.realloc(int(a0), int(a1)) if a is not None else 0
        sym = _MCJIT_RUNTIME_CTX["rva_to_sym"].get(int(fp))
        ee = _MCJIT_RUNTIME_CTX["ee"]
        if sym and ee is not None:
            addr = ee.get_function_address(sym)
            if addr:
                fn_c = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)(addr)
                return int(fn_c(a0, a1, a2, a3))
        return 0

    @ctypes.CFUNCTYPE(
        ctypes.c_double,
        ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64,
        ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64,
    )
    def cb_fcall9(fn_ptr: int, x0: int, x1: int, x2: int, x3: int, x4: int, x5: int, x6: int, x7: int) -> float:
        def _b2d(b: int) -> float:
            return struct.unpack("<d", struct.pack("<q", ctypes.c_int64(b).value))[0]
        if int(fn_ptr) == 0x1A004:
            try:
                return float(math.pow(_b2d(x0), _b2d(x1)))
            except Exception:
                return float("nan")
        if int(fn_ptr) == 0x1A005:
            d1 = _b2d(x1)
            return math.fmod(_b2d(x0), d1) if d1 != 0.0 else float("nan")
        sym = _MCJIT_RUNTIME_CTX["rva_to_sym"].get(int(fn_ptr))
        ee = _MCJIT_RUNTIME_CTX["ee"]
        if sym and ee is not None:
            addr = ee.get_function_address(sym)
            if addr:
                fn_d = ctypes.CFUNCTYPE(
                    ctypes.c_double,
                    ctypes.c_double, ctypes.c_double, ctypes.c_double, ctypes.c_double,
                )(addr)
                return float(fn_d(_b2d(x0), _b2d(x1), _b2d(x2), _b2d(x3)))
        return 0.0

    @ctypes.CFUNCTYPE(
        ctypes.c_double,
        ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64,
        ctypes.c_int64, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64,
    )
    def cb_cfcall9(fn_ptr: int, ctx: int, x1: int, x2: int, x3: int, x4: int, x5: int, x6: int, x7: int) -> float:
        def _b2d(b: int) -> float:
            return struct.unpack("<d", struct.pack("<q", ctypes.c_int64(b).value))[0]
        sym = _MCJIT_RUNTIME_CTX["rva_to_sym"].get(int(fn_ptr))
        ee = _MCJIT_RUNTIME_CTX["ee"]
        if sym and ee is not None:
            addr = ee.get_function_address(sym)
            if addr:
                fn_d = ctypes.CFUNCTYPE(
                    ctypes.c_double,
                    ctypes.c_int64, ctypes.c_double, ctypes.c_double, ctypes.c_double,
                )(addr)
                return float(fn_d(int(ctx), _b2d(x1), _b2d(x2), _b2d(x3)))
        return 0.0

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_pmaxud64(a: int, b: int) -> int:
        al, bl = a & 0xFFFFFFFF, b & 0xFFFFFFFF
        ah, bh = (a >> 32) & 0xFFFFFFFF, (b >> 32) & 0xFFFFFFFF
        v = (al if al > bl else bl) | ((ah if ah > bh else bh) << 32)
        return v - (1 << 64) if (v & (1 << 63)) else v

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_pcmpeqd64(a: int, b: int) -> int:
        al, bl = a & 0xFFFFFFFF, b & 0xFFFFFFFF
        ah, bh = (a >> 32) & 0xFFFFFFFF, (b >> 32) & 0xFFFFFFFF
        v = (0xFFFFFFFF if al == bl else 0) | ((0xFFFFFFFF if ah == bh else 0) << 32)
        return v - (1 << 64) if (v & (1 << 63)) else v

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_psubd64(a: int, b: int) -> int:
        al = ((a & 0xFFFFFFFF) - (b & 0xFFFFFFFF)) & 0xFFFFFFFF
        ah = (((a >> 32) & 0xFFFFFFFF) - ((b >> 32) & 0xFFFFFFFF)) & 0xFFFFFFFF
        v = al | (ah << 32)
        return v - (1 << 64) if (v & (1 << 63)) else v

    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def cb_pcmpeqb64(a: int, b: int) -> int:
        out = 0
        for i in range(8):
            if ((a >> (i * 8)) & 0xFF) == ((b >> (i * 8)) & 0xFF):
                out |= 0xFF << (i * 8)
        return out - (1 << 64) if (out & (1 << 63)) else out

    mapping = {
        "aether_stack_base": cb_stack_base,
        "aether_get_sp": cb_get_sp,
        "aether_set_sp": cb_set_sp,
        "aether_abort": cb_abort,
        "aether_mem_read": cb_mem_read,
        "aether_mem_write": cb_mem_write,
        "aether_malloc": cb_malloc,
        "aether_free": cb_free,
        "aether_realloc": cb_realloc,
        "aether_calloc": cb_calloc,
        "aether_memcpy": cb_memcpy,
        "aether_memset": cb_memset,
        "aether_rep_stos": cb_rep_stos,
        "aether_strlen": cb_strlen,
        "aether_strcmp": cb_strcmp,
        "aether_strncmp": cb_strncmp,
        "aether_strcpy": cb_strcpy,
        "aether_strrchr": cb_strrchr,
        "aether_sprintf": cb_sprintf,
        "aether_sscanf": cb_zero4,
        "aether_printf": cb_zero4,
        "aether_strtod": cb_strtod,
        "aether_pow": cb_pow,
        "aether_fmod": cb_fmod,
        "aether_isalpha": cb_isalpha,
        "aether_isdigit": cb_isdigit,
        "aether_isspace": cb_isspace,
        "aether_isxdigit": cb_isxdigit,
        "aether_tolower": cb_tolower,
        "aether_ro_ptr": cb_ro_ptr,
        "aether_data_ptr": cb_data_ptr,
        "aether_fn_ptr": cb_fn_ptr,
        "aether_vtable_ptr": cb_vtable_ptr,
        "aether_crt_fn_ptr": cb_crt_fn_ptr,
        "aether_vcall": cb_vcall,
        "aether_icall": cb_icall,
        "aether_fcall_f64": cb_fcall9,
        "aether_cfcall_f64": cb_cfcall9,
        "aether_pmaxud64": cb_pmaxud64,
        "aether_pcmpeqd64": cb_pcmpeqd64,
        "aether_psubd64": cb_psubd64,
        "aether_pcmpeqb64": cb_pcmpeqb64,
    }
    for name, cb in mapping.items():
        _MCJIT_PINNED_CBS[name] = cb
        ptr = ctypes.cast(cb, ctypes.c_void_p).value
        if ptr:
            llvm.add_symbol(name, ptr)


class MCJITSession:
    """Native x86-64 LLVM O3 JIT execution engine bound to `_MemoryArena`."""

    def __init__(
        self,
        o3_ir_text: str,
        fn_sigs: Dict[str, Tuple[bool, bool, bool]],
        *,
        ro_arena_addrs: Optional[Dict[int, int]] = None,
        vtable_arena_addrs: Optional[Dict[int, int]] = None,
        rw_data_base: int = 0,
        rva_to_c_sym: Optional[Dict[int, str]] = None,
    ) -> None:
        _ensure_mcjit_symbols_registered()
        self.fn_sigs = fn_sigs
        self.ro_arena_addrs = ro_arena_addrs or {}
        self.vtable_arena_addrs = vtable_arena_addrs or {}
        self.rw_data_base = rw_data_base
        self.rva_to_c_sym = rva_to_c_sym or {}

        lm = llvm.parse_assembly(o3_ir_text)
        lm.verify()
        tm = llvm.Target.from_default_triple().create_target_machine()
        self.ee = llvm.create_mcjit_compiler(lm, tm)
        self.ee.finalize_object()
        self._tm = tm

    def invoke(
        self,
        fn_name: str,
        rcx: int,
        rdx: int,
        r8: int,
        r9: int,
        *,
        mem_arena: Any = None,
        xmm0_bits: int = 0,
        xmm1_bits: int = 0,
        stack_base: int = 0x4E000,
    ) -> int:
        addr = self.ee.get_function_address(fn_name)
        if not addr:
            raise KeyError(f"Function {fn_name!r} not found in MCJIT module")

        ret_f64, p0_f64, p1_f64 = self.fn_sigs.get(fn_name, (False, False, False))
        _MCJIT_RUNTIME_CTX["arena"] = mem_arena
        _MCJIT_RUNTIME_CTX["stack_base"] = stack_base
        _MCJIT_RUNTIME_CTX["sp"] = 0
        _MCJIT_RUNTIME_CTX["ro_addrs"] = self.ro_arena_addrs
        _MCJIT_RUNTIME_CTX["vt_addrs"] = self.vtable_arena_addrs
        _MCJIT_RUNTIME_CTX["rw_base"] = self.rw_data_base
        _MCJIT_RUNTIME_CTX["rva_to_sym"] = self.rva_to_c_sym
        _MCJIT_RUNTIME_CTX["ee"] = self.ee

        c_ret = ctypes.c_double if ret_f64 else ctypes.c_int64
        c_p0 = ctypes.c_double if p0_f64 else ctypes.c_int64
        c_p1 = ctypes.c_double if p1_f64 else ctypes.c_int64
        cfunc = ctypes.CFUNCTYPE(c_ret, c_p0, c_p1, ctypes.c_int64, ctypes.c_int64)(addr)

        a0: Any = struct.unpack("<d", struct.pack("<q", ctypes.c_int64(xmm0_bits).value))[0] if p0_f64 else int(rcx)
        a1: Any = struct.unpack("<d", struct.pack("<q", ctypes.c_int64(xmm1_bits).value))[0] if p1_f64 else int(rdx)
        res = cfunc(a0, a1, int(r8), int(r9))
        if ret_f64:
            return struct.unpack("<q", struct.pack("<d", float(res)))[0]
        return ctypes.c_int64(int(res)).value

    def close(self) -> None:
        _MCJIT_RUNTIME_CTX["arena"] = None
        _MCJIT_RUNTIME_CTX["ee"] = None
        if hasattr(self, "ee") and self.ee is not None:
            self.ee.close()
            self.ee = None
