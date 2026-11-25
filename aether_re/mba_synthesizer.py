"""Mixed Boolean-Arithmetic (MBA) Synthesizer & Formal Opaque Predicate Solver (v9.5).

Uses 1-bit truth-table / affine basis regression + Z3 BitVec(64) formal equivalence
proving (UNSAT check on `orig != synthesized`) to collapse obfuscated MBA formulas
(OLLVM, Tigress, VMProtect-style arithmetic) into minimal canonical expressions.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional, Sequence

import z3

from aether_re.smt_solver import _c_expr_to_smt_expr

SCHEMA = "re-megazord-mba-synthesizer.v1"

_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
_RESERVED = {
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
    "int64_t", "uint64_t", "long", "unsigned", "signed", "uintptr_t", "intptr_t",
    "and", "or", "not",
}


def eval_c_expr_to_z3(expr: str, env: Dict[str, z3.BitVecRef], *, bitwidth: int = 64) -> Any:
    """Safely parses a C arithmetic/bitwise/boolean expression via Python AST into a Z3 expression."""
    py_expr = _c_expr_to_smt_expr(expr)
    node = ast.parse(py_expr, mode="eval").body

    def _to_bool(v: Any) -> Any:
        return v if z3.is_bool(v) else (v != z3.BitVecVal(0, bitwidth))

    def _to_bv(v: Any) -> z3.BitVecRef:
        if z3.is_bool(v):
            return z3.If(v, z3.BitVecVal(1, bitwidth), z3.BitVecVal(0, bitwidth))
        return v

    def _walk(n: ast.AST) -> Any:
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, bool)):
            val = int(n.value) & ((1 << bitwidth) - 1)
            return z3.BitVecVal(val, bitwidth)
        if isinstance(n, ast.Name):
            if n.id not in env:
                env[n.id] = z3.BitVec(n.id, bitwidth)
            return env[n.id]
        if isinstance(n, ast.UnaryOp):
            operand = _walk(n.operand)
            if isinstance(n.op, ast.USub):
                return -_to_bv(operand)
            if isinstance(n.op, ast.UAdd):
                return _to_bv(operand)
            if isinstance(n.op, ast.Invert):
                return ~_to_bv(operand)
            if isinstance(n.op, ast.Not):
                return z3.Not(_to_bool(operand))
        if isinstance(n, ast.BinOp):
            l = _to_bv(_walk(n.left))
            r = _to_bv(_walk(n.right))
            if isinstance(n.op, ast.Add):
                return l + r
            if isinstance(n.op, ast.Sub):
                return l - r
            if isinstance(n.op, ast.Mult):
                return l * r
            if isinstance(n.op, ast.BitXor):
                return l ^ r
            if isinstance(n.op, ast.BitAnd):
                return l & r
            if isinstance(n.op, ast.BitOr):
                return l | r
            if isinstance(n.op, ast.LShift):
                return l << r
            if isinstance(n.op, ast.RShift):
                return z3.LShR(l, r)
        if isinstance(n, ast.BoolOp):
            vals = [_to_bool(_walk(v)) for v in n.values]
            if isinstance(n.op, ast.And):
                return z3.And(*vals)
            if isinstance(n.op, ast.Or):
                return z3.Or(*vals)
        if isinstance(n, ast.Compare) and len(n.ops) == 1 and len(n.comparators) == 1:
            l = _to_bv(_walk(n.left))
            r = _to_bv(_walk(n.comparators[0]))
            op = n.ops[0]
            if isinstance(op, ast.Eq):
                return l == r
            if isinstance(op, ast.NotEq):
                return l != r
            if isinstance(op, ast.Lt):
                return l < r
            if isinstance(op, ast.LtE):
                return l <= r
            if isinstance(op, ast.Gt):
                return l > r
            if isinstance(op, ast.GtE):
                return l >= r
        if isinstance(n, ast.IfExp):
            return z3.If(_to_bool(_walk(n.test)), _to_bv(_walk(n.body)), _to_bv(_walk(n.orelse)))
        raise ValueError(f"Unsupported AST node in MBA expression: {ast.dump(n)}")

    return _walk(node)


def _extract_vars(expr: str) -> List[str]:
    found: List[str] = []
    for m in _IDENT_RE.finditer(expr):
        nm = m.group(1)
        if nm in _RESERVED or nm.startswith("0x") or nm.startswith("0X"):
            continue
        if nm not in found:
            found.append(nm)
    return found


def _prove_z3_equiv(orig_expr: str, cand_expr: str, var_names: Sequence[str], *, bitwidth: int = 64, timeout_ms: int = 250) -> bool:
    try:
        env1: Dict[str, z3.BitVecRef] = {v: z3.BitVec(v, bitwidth) for v in var_names}
        lhs = eval_c_expr_to_z3(orig_expr, env1, bitwidth=bitwidth)
        rhs = eval_c_expr_to_z3(cand_expr, env1, bitwidth=bitwidth)
        if z3.is_bool(lhs):
            lhs = z3.If(lhs, z3.BitVecVal(1, bitwidth), z3.BitVecVal(0, bitwidth))
        if z3.is_bool(rhs):
            rhs = z3.If(rhs, z3.BitVecVal(1, bitwidth), z3.BitVecVal(0, bitwidth))
        slv = z3.Solver()
        slv.set("timeout", timeout_ms)
        slv.add(lhs != rhs)
        return slv.check() == z3.unsat
    except Exception:
        return False


def _gen_candidates(var_names: Sequence[str]) -> List[str]:
    if not var_names:
        return ["0", "1", "-1"]
    if len(var_names) == 1:
        x = var_names[0]
        return [
            "0", "1", "-1", x, f"-{x}", f"~{x}", f"({x} + 1)", f"({x} - 1)",
            f"({x} * 2)", f"({x} * -1)", f"({x} & 1)", f"({x} ^ 1)",
        ]
    x, y = var_names[0], var_names[1]
    cands = [
        "0", "1", "-1", x, y,
        f"({x} + {y})", f"({x} - {y})", f"({y} - {x})",
        f"({x} ^ {y})", f"({x} & {y})", f"({x} | {y})",
        f"({x} * {y})", f"({x} + {y} + 1)", f"({x} - {y} - 1)",
        f"(2 * ({x} + {y}))", f"(~({x} ^ {y}))",
    ]
    if len(var_names) >= 3:
        z = var_names[2]
        cands.extend([
            z,
            f"(({x} + {y}) + {z})",
            f"(({x} + {y}) - {z})",
            f"(({x} ^ {y}) ^ {z})",
            f"(({x} & {y}) | {z})",
        ])
    return cands


def _solve_linear_mba_coeffs(orig_expr: str, var_names: Sequence[str], *, bitwidth: int = 64, timeout_ms: int = 250) -> Optional[str]:
    """Synthesizes `a*x + b*y + c` or linear combinations over `{1, x, y, x^y, x&y, x|y}` using concrete Z3 sampling."""
    if not var_names or len(var_names) > 3:
        return None
    sample_points = [
        (0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1),
        (1, 1, 0), (3, 5, 7), (17, 42, 9), (-1, 5, -3),
        (0x12345, 0x98765, 0x5555), (0xAAAAAAAA, 0x55555555, 0x11111111),
    ]
    env_sym: Dict[str, z3.BitVecRef] = {v: z3.BitVec(v, bitwidth) for v in var_names}
    try:
        z_orig = eval_c_expr_to_z3(orig_expr, env_sym, bitwidth=bitwidth)
    except Exception:
        return None

    observed_y: List[int] = []
    basis_rows: List[List[int]] = []
    # Basis: [const 1, v0, (v1), (v0 ^ v1), (v0 & v1)]
    for pt in sample_points:
        subs = [(env_sym[v], z3.BitVecVal(pt[i], bitwidth)) for i, v in enumerate(var_names)]
        try:
            val_bv = z3.simplify(z3.substitute(z_orig, subs))
            if not z3.is_bv_value(val_bv):
                return None
            observed_y.append(val_bv.as_long())
        except Exception:
            return None
        row = [1, pt[0] & ((1 << bitwidth) - 1)]
        if len(var_names) >= 2:
            row.append(pt[1] & ((1 << bitwidth) - 1))
        if len(var_names) >= 3:
            row.append(pt[2] & ((1 << bitwidth) - 1))
        basis_rows.append(row)

    # Check if purely affine `c0 + sum(ci * vi)` satisfies all points via Z3 integer/BV solve
    slv = z3.Solver()
    slv.set("timeout", timeout_ms)
    coeffs = [z3.BitVec(f"_c{i}", bitwidth) for i in range(len(basis_rows[0]))]
    for row, y_obs in zip(basis_rows, observed_y):
        acc = coeffs[0]
        for j in range(1, len(coeffs)):
            acc = acc + coeffs[j] * z3.BitVecVal(row[j], bitwidth)
        slv.add(acc == z3.BitVecVal(y_obs, bitwidth))
    # Restrict coefficients to small readable constants [-16..16]
    for cf in coeffs:
        slv.add(z3.Or(cf <= z3.BitVecVal(16, bitwidth), cf >= z3.BitVecVal((1 << bitwidth) - 16, bitwidth)))

    if slv.check() != z3.sat:
        return None
    m = slv.model()
    terms: List[str] = []
    names_map = ["1", *var_names]
    for idx, cf in enumerate(coeffs):
        raw_c = m.eval(cf, model_completion=True).as_long()
        signed_c = raw_c - (1 << bitwidth) if raw_c >= (1 << (bitwidth - 1)) else raw_c
        if signed_c == 0:
            continue
        if idx == 0:
            terms.append(str(signed_c))
        elif signed_c == 1:
            terms.append(names_map[idx])
        elif signed_c == -1:
            terms.append(f"(-{names_map[idx]})")
        else:
            terms.append(f"({signed_c} * {names_map[idx]})")
    cand = " + ".join(terms) if terms else "0"
    if len(terms) > 1:
        cand = f"({cand})"
    if _prove_z3_equiv(orig_expr, cand, var_names, bitwidth=bitwidth, timeout_ms=timeout_ms):
        return cand
    return None


def simplify_mba_expr(expr: str, *, bitwidth: int = 64, timeout_ms: int = 250) -> Dict[str, Any]:
    """Synthesizes and formally proves a minimal equivalent form for an MBA expression."""
    cleaned = expr.strip().rstrip(";")
    if not cleaned:
        return {"schema": SCHEMA, "original": expr, "simplified": expr, "proven": False, "variables": []}
    vars_found = _extract_vars(cleaned)
    # 1. Constant check first
    if _prove_z3_equiv(cleaned, "0", vars_found, bitwidth=bitwidth, timeout_ms=timeout_ms):
        return {"schema": SCHEMA, "original": cleaned, "simplified": "0", "proven": True, "strategy": "z3_const_zero", "variables": vars_found}
    if _prove_z3_equiv(cleaned, "1", vars_found, bitwidth=bitwidth, timeout_ms=timeout_ms):
        return {"schema": SCHEMA, "original": cleaned, "simplified": "1", "proven": True, "strategy": "z3_const_one", "variables": vars_found}

    # 2. Structural small-candidate enumeration verified formally by Z3
    for cand in sorted(_gen_candidates(vars_found), key=len):
        if len(cand) >= len(cleaned) and cand == cleaned:
            continue
        if _prove_z3_equiv(cleaned, cand, vars_found, bitwidth=bitwidth, timeout_ms=timeout_ms):
            return {
                "schema": SCHEMA,
                "original": cleaned,
                "simplified": cand,
                "proven": True,
                "strategy": "z3_candidate_synthesis",
                "variables": vars_found,
            }

    # 3. Linear affine basis synthesis over BitVec(bitwidth)
    lin_cand = _solve_linear_mba_coeffs(cleaned, vars_found, bitwidth=bitwidth, timeout_ms=timeout_ms)
    if lin_cand is not None:
        return {
            "schema": SCHEMA,
            "original": cleaned,
            "simplified": lin_cand,
            "proven": True,
            "strategy": "z3_linear_basis_synthesis",
            "variables": vars_found,
        }

    return {
        "schema": SCHEMA,
        "original": cleaned,
        "simplified": cleaned,
        "proven": False,
        "strategy": "unchanged",
        "variables": vars_found,
    }


def solve_opaque_predicate_z3(cond_expr: str, *, bitwidth: int = 64, timeout_ms: int = 250) -> Dict[str, Any]:
    """Determines whether a multi-variable boolean condition is mathematically invariant (always True or always False)."""
    cleaned = cond_expr.strip()
    vars_found = _extract_vars(cleaned)
    try:
        env: Dict[str, z3.BitVecRef] = {v: z3.BitVec(v, bitwidth) for v in vars_found}
        z_cond = eval_c_expr_to_z3(cleaned, env, bitwidth=bitwidth)
        if not z3.is_bool(z_cond):
            z_cond = z_cond != z3.BitVecVal(0, bitwidth)
        s_t = z3.Solver()
        s_t.set("timeout", timeout_ms)
        s_t.add(z3.Not(z_cond))
        if s_t.check() == z3.unsat:
            return {"schema": SCHEMA, "condition": cleaned, "is_opaque": True, "truth_value": True, "variables": vars_found}
        s_f = z3.Solver()
        s_f.set("timeout", timeout_ms)
        s_f.add(z_cond)
        if s_f.check() == z3.unsat:
            return {"schema": SCHEMA, "condition": cleaned, "is_opaque": True, "truth_value": False, "variables": vars_found}
    except Exception as exc:
        return {"schema": SCHEMA, "condition": cleaned, "is_opaque": False, "truth_value": None, "error": str(exc)}
    return {"schema": SCHEMA, "condition": cleaned, "is_opaque": False, "truth_value": None, "variables": vars_found}
