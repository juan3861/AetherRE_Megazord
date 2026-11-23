"""Bounded SMT constraints with a restricted expression grammar.

SAT/UNSAT describe the entire accepted model. Invalid input is ERROR;
solver exhaustion is UNKNOWN. Neither is converted into a proof.
Integer division follows SMT integer arithmetic, with nonzero divisors.
Bitvector arithmetic and comparisons use Z3's signed word semantics.
"""
from __future__ import annotations

import ast
import functools
import gc
import re
import threading
from typing import Any, Sequence

SCHEMA = "smt-solver-report.v1"
try:
    import z3
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False

_THREAD_Z3 = threading.local()
_Z3_ALLOC_LOCK = threading.Lock()
_Z3_ALLOC_COUNT = 0


def _maybe_gc_z3(force: bool = False) -> None:
    global _Z3_ALLOC_COUNT
    if force:
        gc.collect()
        return
    with _Z3_ALLOC_LOCK:
        _Z3_ALLOC_COUNT += 1
        should_collect = (_Z3_ALLOC_COUNT % 32) == 0
    if should_collect:
        gc.collect(0)


def _new_z3_context() -> Any | None:
    """Creates a fresh z3.Context, recovering once via GC if Z3 returns a null context."""
    for attempt in range(2):
        try:
            ctx = z3.Context()
            if getattr(ctx, "ctx", None):
                return ctx
        except (OSError, z3.Z3Exception):
            pass
        if attempt == 0:
            gc.collect()
    return None


def _get_thread_opaque_context() -> Any | None:
    """Returns a thread-local Z3 context recycled every 64 queries for opaque-predicate sweeps."""
    ctx = getattr(_THREAD_Z3, "ctx", None)
    uses = int(getattr(_THREAD_Z3, "uses", 0))
    if ctx is None or uses >= 64:
        _THREAD_Z3.ctx = None
        _THREAD_Z3.uses = 0
        if ctx is not None:
            del ctx
            gc.collect(0)
        ctx = _new_z3_context()
        if ctx is None:
            return None
        _THREAD_Z3.ctx = ctx
    _THREAD_Z3.uses = int(getattr(_THREAD_Z3, "uses", 0)) + 1
    return ctx


def _solve_in_context(
    constraints: Sequence[str],
    context: Any,
    report: dict[str, Any],
    *,
    bitvector_width: int | None,
    timeout_ms: int,
    resource_limit: int,
) -> dict[str, Any]:
    solver = z3.Solver(ctx=context)
    solver.set(timeout=timeout_ms, rlimit=resource_limit, random_seed=0)
    variables: dict[str, Any] = {}
    guards: list[Any] = []
    model: Any = None

    def variable(name, boolean=False):
        if name.startswith("_") or len(name) > 128:
            raise ValueError("invalid_variable_name")
        if name not in variables:
            variables[name] = (
                z3.Bool(name, ctx=context) if boolean else
                z3.BitVec(name, bitvector_width, ctx=context) if bitvector_width else z3.Int(name, ctx=context)
            )
        value = variables[name]
        if boolean != z3.is_bool(value):
            raise ValueError("variable_sort_conflict")
        return value

    def translate(node, boolean=False):
        if isinstance(node, ast.Constant):
            if type(node.value) is bool:
                return z3.BoolVal(node.value, ctx=context)
            if type(node.value) is int and node.value.bit_length() <= 256:
                return z3.BitVecVal(node.value, bitvector_width, ctx=context) if bitvector_width else z3.IntVal(node.value, ctx=context)
            raise ValueError("unsupported_literal")
        if isinstance(node, ast.Name):
            return variable(node.id, boolean)
        if isinstance(node, ast.BoolOp):
            values = [translate(v, True) for v in node.values]
            return z3.And(*values) if isinstance(node.op, ast.And) else z3.Or(*values)
        if isinstance(node, ast.UnaryOp):
            value = translate(node.operand, isinstance(node.op, ast.Not))
            if isinstance(node.op, ast.Not):
                return z3.Not(value)
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.UAdd):
                return value
            if isinstance(node.op, ast.Invert) and bitvector_width:
                return ~value
            raise ValueError("unsupported_unary_operation")
        if isinstance(node, ast.BinOp):
            left, right = translate(node.left), translate(node.right)
            op = node.op
            if isinstance(op, ast.Add):
                return left + right
            if isinstance(op, ast.Sub):
                return left - right
            if isinstance(op, ast.Mult):
                return left * right
            if isinstance(op, (ast.Div, ast.FloorDiv, ast.Mod)):
                guards.append(right != 0)
                return left % right if isinstance(op, ast.Mod) else left / right
            if isinstance(op, ast.Pow):
                if (bitvector_width or not isinstance(node.right, ast.Constant)
                        or type(node.right.value) is not int or not 0 <= node.right.value <= 16):
                    raise ValueError("unsupported_power")
                return left ** node.right.value
            if bitvector_width:
                if isinstance(op, ast.BitXor):
                    return left ^ right
                if isinstance(op, ast.BitAnd):
                    return left & right
                if isinstance(op, ast.BitOr):
                    return left | right
                if isinstance(op, (ast.LShift, ast.RShift)):
                    guards.append(right >= 0)
                    return left << right if isinstance(op, ast.LShift) else left >> right
            raise ValueError("unsupported_binary_operation")
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            boolean_comparison = any(
                isinstance(n, ast.Constant) and type(n.value) is bool
                or isinstance(n, ast.Name) and n.id in variables and z3.is_bool(variables[n.id])
                for n in operands
            )
            values = [translate(n, boolean_comparison) for n in operands]
            comparisons = []
            for left, op, right in zip(values, node.ops, values[1:]):
                if isinstance(op, ast.Eq):
                    comparisons.append(left == right)
                elif isinstance(op, ast.NotEq):
                    comparisons.append(left != right)
                elif isinstance(op, ast.Lt):
                    comparisons.append(left < right)
                elif isinstance(op, ast.LtE):
                    comparisons.append(left <= right)
                elif isinstance(op, ast.Gt):
                    comparisons.append(left > right)
                elif isinstance(op, ast.GtE):
                    comparisons.append(left >= right)
                else:
                    raise ValueError("unsupported_comparison")
            return z3.And(*comparisons)
        # No attributes, indexing, comprehensions, or calls reach Python eval.
        raise ValueError("unsupported_expression")

    try:
        for index, text in enumerate(constraints):
            try:
                if not isinstance(text, str) or not text.strip() or len(text) > 4096:
                    raise ValueError("invalid_expression_length")
                tree = ast.parse(text, mode="eval")
                if sum(1 for _ in ast.walk(tree)) > 256:
                    raise ValueError("expression_complexity_exceeded")
                expr = translate(tree.body, True)
                if not z3.is_bool(expr):
                    raise ValueError("constraint_must_be_boolean")
                solver.add(expr)
                report["total_constraints_parsed"] += 1
            except (ValueError, SyntaxError, TypeError, RecursionError, z3.Z3Exception) as exc:
                report["errors"].append({"index": index, "code": str(exc)[:200]})
        report["variables_count"] = len(variables)
        if report["errors"]:
            report["error"] = "constraint_rejected"
            return report
        solver.add(*guards)
        report["complete_input"] = True
        report["timeout_ms"] = timeout_ms
        report["resource_limit"] = resource_limit
        report["arithmetic_domain"] = "signed_bitvector" if bitvector_width else "smt_integer"
        checked = solver.check()
        if checked == z3.unknown:
            report.update(status="UNKNOWN", reason_unknown=solver.reason_unknown())
            return report
        if checked == z3.unsat:
            report.update(status="UNSAT", is_satisfiable=False)
            return report
        if checked != z3.sat:
            report.update(status="UNKNOWN", reason_unknown="unrecognized_solver_result")
            return report
        model = solver.model()
        witness = {}
        for name, value in variables.items():
            observed = model.eval(value, model_completion=True)
            if z3.is_bool(value):
                witness[name] = z3.is_true(observed)
            else:
                witness[name] = observed.as_long()
        report.update(status="SAT", is_satisfiable=True, model=witness)
        return report
    finally:
        variables.clear()
        guards.clear()
        model = None
        solver = None


def _base_report(total_constraints: int) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "engine": "z3-theorem-prover", "status": "ERROR",
        "is_satisfiable": None, "model": {}, "total_constraints_received": total_constraints,
        "total_constraints_parsed": 0, "variables_count": 0,
        "complete_input": False, "errors": [],
    }


def solve_constraints_smt(
    constraints: Sequence[str], *,
    bitvector_width: int | None = None,
    timeout_ms: int = 1000,
    resource_limit: int = 500000,
) -> dict[str, Any]:
    if not _HAS_Z3:
        report = _base_report(0)
        report["error"] = "z3_not_installed"
        return report
    if (isinstance(constraints, (str, bytes)) or not isinstance(constraints, (list, tuple))
            or not 1 <= len(constraints) <= 1000):
        report = _base_report(0)
        report["error"] = "invalid_constraint_collection"
        return report
    report = _base_report(len(constraints))
    if (type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000
            or type(resource_limit) is not int or not 1 <= resource_limit <= 10000000
            or (bitvector_width is not None and
                (type(bitvector_width) is not int or not 1 <= bitvector_width <= 256))):
        report["error"] = "invalid_solver_budget_or_width"
        return report
    # A request owns its context: unrelated prior AST allocation must not
    # perturb a bounded query's solver strategy or share mutable state.
    context = _new_z3_context()
    if context is None:
        report.update(status="UNKNOWN", reason_unknown="z3_context_init_failed")
        return report
    try:
        return _solve_in_context(
            constraints,
            context,
            report,
            bitvector_width=bitvector_width,
            timeout_ms=timeout_ms,
            resource_limit=resource_limit,
        )
    except (OSError, z3.Z3Exception) as exc:
        report.update(status="UNKNOWN", is_satisfiable=None, reason_unknown=f"z3_runtime_error:{type(exc).__name__}")
        return report
    finally:
        context = None
        _maybe_gc_z3()


_SMT_ULL_RE = re.compile(r"\b(0x[0-9a-fA-F]+|\d+)U?LL\b")


def _c_expr_to_smt_expr(expr: str) -> str:
    s = expr.strip()
    s = s.replace("(int64_t)", "").replace("(uint64_t)", "").replace("(long long)", "").replace("(unsigned long long)", "")
    s = _SMT_ULL_RE.sub(r"\1", s)
    s = s.replace("&&", " and ").replace("||", " or ")
    s = re.sub(r"(?<![=!<>])!(?!=)", " not ", s)
    return s


@functools.lru_cache(maxsize=1024)
def _prove_opaque_predicate_bv64_cached(smt_cond: str, timeout_ms: int) -> tuple[bool, bool | None, str]:
    ctx = _get_thread_opaque_context()
    if ctx is None:
        return (False, None, "z3_context_init_failed")
    try:
        res_true = _solve_in_context(
            [f"not ({smt_cond})"], ctx, _base_report(1),
            bitvector_width=64, timeout_ms=timeout_ms, resource_limit=200000,
        )
        if res_true.get("status") == "UNSAT":
            return (True, True, "TAUTOLOGY_UNSAT")
        res_false = _solve_in_context(
            [smt_cond], ctx, _base_report(1),
            bitvector_width=64, timeout_ms=timeout_ms, resource_limit=200000,
        )
        if res_false.get("status") == "UNSAT":
            return (True, False, "CONTRADICTION_UNSAT")
        return (False, None, str(res_false.get("status", "UNKNOWN")))
    except (OSError, z3.Z3Exception) as exc:
        _THREAD_Z3.ctx = None
        _THREAD_Z3.uses = 0
        return (False, None, f"z3_runtime_error:{type(exc).__name__}")


def prove_opaque_predicate_bv64(condition_str: str, *, timeout_ms: int = 150) -> dict[str, Any]:
    """Proves whether a C/Python boolean expression is a 64-bit bitvector tautology or contradiction via Z3."""
    if not _HAS_Z3:
        return {"proved": False, "truth_value": None, "status": "z3_unavailable"}
    smt_cond = _c_expr_to_smt_expr(condition_str)
    proved, truth_value, status = _prove_opaque_predicate_bv64_cached(smt_cond, int(timeout_ms))
    return {"proved": proved, "truth_value": truth_value, "status": status}


def prove_bv64_equivalence(expr_a: str, expr_b: str, *, timeout_ms: int = 250) -> dict[str, Any]:
    """Proves two 64-bit integer expressions are semantically identical across all 2^64 inputs via Z3."""
    if not _HAS_Z3:
        return {"proved_equivalent": False, "status": "z3_unavailable"}
    pa = _c_expr_to_smt_expr(expr_a)
    pb = _c_expr_to_smt_expr(expr_b)
    ctx = _get_thread_opaque_context()
    if ctx is None:
        return {"proved_equivalent": False, "status": "z3_context_init_failed"}
    try:
        res = _solve_in_context(
            [f"({pa}) != ({pb})"], ctx, _base_report(1),
            bitvector_width=64, timeout_ms=timeout_ms, resource_limit=300000,
        )
    except (OSError, z3.Z3Exception) as exc:
        _THREAD_Z3.ctx = None
        _THREAD_Z3.uses = 0
        return {"proved_equivalent": False, "status": f"z3_runtime_error:{type(exc).__name__}"}
    if res.get("status") == "UNSAT":
        return {"proved_equivalent": True, "status": "PROVED_EQUIVALENT"}
    if res.get("status") == "SAT":
        return {"proved_equivalent": False, "status": "COUNTEREXAMPLE", "counterexample": res.get("model", {})}
    return {"proved_equivalent": False, "status": res.get("status", "UNKNOWN")}
