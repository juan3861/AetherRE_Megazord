"""Reverse Engineering Graph (REG) — Symbolic Path Feasibility & Constraint Evaluator.

Verificação leve e determinística de satisfatibilidade (SMT-lite / Interval Arithmetic):
  1. Avalia conjunções de restrições relacionais (==, !=, <, <=, >, >=) sobre caminhos de execução;
  2. Refinamento de domínios intervalares [min, max] para detecção de caminhos inviáveis (UNSAT);
  3. Identificação de código morto e bifurcações contraditórias em CFGs.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

SCHEMA = "constraint-feasibility-report.v1"

INT_MAX = 2**63 - 1
INT_MIN = -(2**63)


def parse_constraint(raw_constraint: str) -> tuple[str, str, int] | None:
    """Extrai (variável, operador, constante) de expressões como 'x > 10' ou 'eax == 0x20'."""
    pattern = re.compile(r"^\s*([a-zA-Z_]\w*)\s*(==|!=|<=|>=|<|>)\s*(0x[0-9a-fA-F]+|-?\d+)\s*$")
    m = pattern.match(raw_constraint.strip())
    if not m:
        return None
    var, op, val_str = m.group(1), m.group(2), m.group(3)
    val = int(val_str, 16) if val_str.lower().startswith("0x") else int(val_str)
    return var, op, val


def evaluate_path_feasibility(constraints: Sequence[str]) -> dict[str, Any]:
    """Use the strict SMT backend; intervals remain diagnostic metadata.

    The legacy API keeps a signed 64-bit input domain. Unsupported input and
    solver exhaustion never produce a feasible model.
    """
    import ast
    from aether_re.smt_solver import solve_constraints_smt
    domains: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    valid_collection = isinstance(constraints,(list,tuple)) and all(isinstance(c,str) for c in constraints)
    if valid_collection:
        for text in constraints:
            try:
                tree = ast.parse(text,mode="eval")
                names.update(n.id for n in ast.walk(tree) if isinstance(n,ast.Name))
            except (SyntaxError,RecursionError):
                pass
            parsed = parse_constraint(text)
            if parsed is None:
                continue
            name,op,number = parsed
            domain = domains.setdefault(name,{"min":INT_MIN,"max":INT_MAX,"excluded":[]})
            if op == "==":
                domain["min"],domain["max"] = max(domain["min"],number),min(domain["max"],number)
            elif op == "!=": domain["excluded"].append(number)
            elif op == ">": domain["min"] = max(domain["min"],number+1)
            elif op == ">=": domain["min"] = max(domain["min"],number)
            elif op == "<": domain["max"] = min(domain["max"],number-1)
            elif op == "<=": domain["max"] = min(domain["max"],number)
    bounded = list(constraints) if valid_collection else constraints
    if valid_collection:
        bounded += [f"{name} >= {INT_MIN}" for name in sorted(names)]
        bounded += [f"{name} <= {INT_MAX}" for name in sorted(names)]
    solved = solve_constraints_smt(bounded)
    return {
        "schema":SCHEMA, "is_feasible":solved["is_satisfiable"], "status":solved["status"],
        "total_constraints_evaluated":len(constraints) if solved["complete_input"] else 0,
        "variable_domains":domains,
        "satisfying_model":solved["model"] if solved["status"]=="SAT" else None,
        "contradiction":{"variable":None,"reason":"Intervalo contraditório ou restrições SMT incompatíveis"} if solved["status"]=="UNSAT" else None,
        "solver":solved, "arithmetic_domain":"signed_integer64_inputs",
    }
