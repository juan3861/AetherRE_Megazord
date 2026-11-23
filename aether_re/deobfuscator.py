"""Reverse Engineering Graph (REG) — MBA Deobfuscation & Opaque Predicate Pruner.

Engenharia de desofuscação baseada em regras algébricas (estilo D-MBA / Tigress / OLLVM):
  1. Simplificação de expressões Mixed Boolean-Arithmetic (MBA);
  2. Detecção de predicados opacos (Opaque Predicates - Bogus Control Flow);
  3. Poda determinística de arestas mortas e blocos básicos inalcançáveis no CFG.
"""

from __future__ import annotations

import re
from typing import Any, Sequence

from aether_re.smt_solver import prove_opaque_predicate_bv64

SCHEMA = "deobfuscation-report.v1"

# Padrões canônicos de simplificação MBA
MBA_RULES: list[tuple[re.Pattern[str], str]] = [
    # (x ^ y) + 2*(x & y) => x + y
    (re.compile(r"\(([\w]+)\s*\^\s*([\w]+)\)\s*\+\s*2\s*\*\s*\(\1\s*&\s*\2\)"), r"(\1 + \2)"),
    (re.compile(r"2\s*\*\s*\(([\w]+)\s*&\s*([\w]+)\)\s*\+\s*\(\1\s*\^\s*\2\)"), r"(\1 + \2)"),
    # (x | y) - (x ^ y) => x & y
    (re.compile(r"\(([\w]+)\s*\|\s*([\w]+)\)\s*-\s*\(\1\s*\^\s*\2\)"), r"(\1 & \2)"),
    # (x | y) + (x & y) => x + y
    (re.compile(r"\(([\w]+)\s*\|\s*([\w]+)\)\s*\+\s*\(\1\s*&\s*\2\)"), r"(\1 + \2)"),
    (re.compile(r"\(([\w]+)\s*&\s*([\w]+)\)\s*\+\s*\(\1\s*\|\s*\2\)"), r"(\1 + \2)"),
    # x ^ ~x ou ~x ^ x => -1
    (re.compile(r"([\w]+)\s*\^\s*~(?:\1|\(\1\))"), "-1"),
    (re.compile(r"~([\w]+)\s*\^\s*\1"), "-1"),
    # x & ~x => 0
    (re.compile(r"([\w]+)\s*&\s*~(?:\1|\(\1\))"), "0"),
    (re.compile(r"~([\w]+)\s*&\s*\1"), "0"),
    # x ^ x => 0
    (re.compile(r"\b([\w]+)\s*\^\s*\1\b"), "0"),
    # x - (-y) => x + y
    (re.compile(r"([\w]+)\s*-\s*\(-([\w]+)\)"), r"\1 + \2"),
    # Identidades com zero
    (re.compile(r"\b([\w]+)\s*\^\s*0\b"), r"\1"),
    (re.compile(r"\b0\s*\^\s*([\w]+)\b"), r"\1"),
    (re.compile(r"\b([\w]+)\s*\|\s*0\b"), r"\1"),
    (re.compile(r"\b0\s*\|\s*([\w]+)\b"), r"\1"),
    (re.compile(r"\b([\w]+)\s*\*\s*0\b"), "0"),
    (re.compile(r"\b0\s*\*\s*([\w]+)\b"), "0"),
    (re.compile(r"\b([\w]+)\s*&\s*0\b"), "0"),
    (re.compile(r"\b0\s*&\s*([\w]+)\b"), "0"),
]

# Padrões de Predicados Opacos clássicos de Bogus Control Flow (OLLVM / Tigress)
OPAQUE_PATTERNS: list[tuple[re.Pattern[str], bool, str]] = [
    # y * (y + 1) % 2 == 0  -> Sempre Verdadeiro
    (re.compile(r"\(?([\w]+)\s*\*\s*\(\1\s*\+\s*1\)\)?\s*%\s*2\s*==\s*0"), True, "paridade_consecutivos"),
    # y * (y + 1) % 2 != 0  -> Sempre Falso
    (re.compile(r"\(?([\w]+)\s*\*\s*\(\1\s*\+\s*1\)\)?\s*%\s*2\s*!=\s*0"), False, "paridade_consecutivos_negada"),
    # (x | 1) % 2 != 0 -> Sempre Verdadeiro (ímpar forçado)
    (re.compile(r"\(([\w]+)\s*\|\s*1\)\s*%\s*2\s*!=\s*0"), True, "bit0_impar_garantido"),
    # (x | 1) % 2 == 0 -> Sempre Falso
    (re.compile(r"\(([\w]+)\s*\|\s*1\)\s*%\s*2\s*==\s*0"), False, "bit0_impar_negado"),
    # x*x >= 0 -> Sempre Verdadeiro
    (re.compile(r"([\w]+)\s*\*\s*\1\s*>=\s*0"), True, "quadrado_positivo"),
    # x == x -> Sempre Verdadeiro
    (re.compile(r"([\w]+)\s*==\s*\1"), True, "tautologia_identidade"),
    # x != x -> Sempre Falso
    (re.compile(r"([\w]+)\s*!=\s*\1"), False, "contradicao_identidade"),
    # Comparações de literais
    (re.compile(r"(\d+)\s*==\s*(\d+)"), None, "literal_eq"),
    (re.compile(r"(\d+)\s*!=\s*(\d+)"), None, "literal_neq"),
    (re.compile(r"(\d+)\s*<\s*(\d+)"), None, "literal_lt"),
    (re.compile(r"(\d+)\s*>\s*(\d+)"), None, "literal_gt"),
]


def simplify_mba_expression(expr: str, max_passes: int = 5) -> str:
    """Aplica iterativamente regras de simplificação algébrica MBA."""
    current = expr.strip()
    for _ in range(max_passes):
        changed = False
        for pat, repl in MBA_RULES:
            new_expr = pat.sub(repl, current)
            if new_expr != current:
                current = new_expr
                changed = True
        if not changed:
            break
    # Remove espaços duplos
    return re.sub(r"\s+", " ", current).strip()


def detect_opaque_predicate(condition_str: str) -> dict[str, Any]:
    """Detecta se uma condição de desvio é um predicado opaco (invariante constante)."""
    clean_cond = re.sub(r"\s+", " ", condition_str.strip())

    for pat, static_val, rule_name in OPAQUE_PATTERNS:
        m = pat.search(clean_cond)
        if m:
            if static_val is not None:
                return {
                    "is_opaque": True,
                    "static_truth_value": static_val,
                    "rule": rule_name,
                    "original_condition": condition_str,
                }
            # Avaliação de literais
            v1, v2 = int(m.group(1)), int(m.group(2))
            if rule_name == "literal_eq":
                val = (v1 == v2)
            elif rule_name == "literal_neq":
                val = (v1 != v2)
            elif rule_name == "literal_lt":
                val = (v1 < v2)
            else:
                val = (v1 > v2)
            return {
                "is_opaque": True,
                "static_truth_value": val,
                "rule": rule_name,
                "original_condition": condition_str,
            }

    # Simplifica via MBA antes de desistir
    simplified = simplify_mba_expression(clean_cond)
    if simplified in {"1", "true", "True"}:
        return {"is_opaque": True, "static_truth_value": True, "rule": "mba_reduction_true", "original_condition": condition_str}
    if simplified in {"0", "false", "False"}:
        return {"is_opaque": True, "static_truth_value": False, "rule": "mba_reduction_false", "original_condition": condition_str}

    # Fallback formal via Z3 bitvector-64 quando há álgebra suspeita (sem chamadas externas)
    if (
        len(simplified) <= 128
        and "aether_" not in simplified
        and any(op in simplified for op in ("^", "%", "&", "|", "*"))
        and any(cmp_op in simplified for cmp_op in ("==", "!=", "<", ">"))
    ):
        z3_res = prove_opaque_predicate_bv64(simplified, timeout_ms=150)
        if z3_res.get("proved"):
            return {
                "is_opaque": True,
                "static_truth_value": bool(z3_res["truth_value"]),
                "rule": f"z3_{z3_res['status'].lower()}",
                "original_condition": condition_str,
            }

    return {"is_opaque": False, "static_truth_value": None, "rule": "dynamic", "original_condition": condition_str}


def prune_dead_cfg_branches(
    nodes: Sequence[str],
    edges: Sequence[tuple[str, str]],
    branch_conditions: list[dict[str, Any]],
    entry: str | None = None,
) -> dict[str, Any]:
    """Identifica predicados opacos nas bifurcações e poda arestas mortas e nós inalcançáveis."""
    node_set = set(nodes)
    edge_set = set(edges)
    pruned_edges: list[tuple[str, str]] = []
    detected_opaques: list[dict[str, Any]] = []

    for bc in branch_conditions:
        src = bc.get("branch_node")
        true_dst = bc.get("true_target")
        false_dst = bc.get("false_target")
        cond = bc.get("condition", "")

        eval_res = detect_opaque_predicate(cond)
        if eval_res["is_opaque"]:
            static_val = eval_res["static_truth_value"]
            dead_edge: tuple[str, str] | None = None
            if static_val is True and false_dst:
                # O desvio falso nunca ocorre
                dead_edge = (src, false_dst)
            elif static_val is False and true_dst:
                # O desvio verdadeiro nunca ocorre
                dead_edge = (src, true_dst)

            if dead_edge and dead_edge in edge_set:
                edge_set.remove(dead_edge)
                pruned_edges.append(dead_edge)
                detected_opaques.append({
                    "branch_node": src,
                    "dead_edge": dead_edge,
                    "condition": cond,
                    "always_branch_to": true_dst if static_val else false_dst,
                    "rule": eval_res["rule"],
                })

    # Recalcula nós alcançáveis se houver entry point
    unreachable_nodes: list[str] = []
    if entry and entry in node_set:
        adj: dict[str, list[str]] = {n: [] for n in node_set}
        for s, d in edge_set:
            if s in adj and d in node_set:
                adj[s].append(d)

        reachable = set()
        stack = [entry]
        reachable.add(entry)
        while stack:
            u = stack.pop()
            for v in adj[u]:
                if v not in reachable:
                    reachable.add(v)
                    stack.append(v)
        unreachable_nodes = sorted(node_set - reachable)
        # Remove nós e arestas inalcançáveis
        node_set = reachable
        edge_set = {(s, d) for s, d in edge_set if s in reachable and d in reachable}

    return {
        "schema": SCHEMA,
        "original_nodes_count": len(nodes),
        "original_edges_count": len(edges),
        "pruned_edges_count": len(pruned_edges),
        "pruned_edges": pruned_edges,
        "unreachable_nodes_count": len(unreachable_nodes),
        "unreachable_nodes": unreachable_nodes,
        "clean_nodes_count": len(node_set),
        "clean_edges_count": len(edge_set),
        "clean_edges": sorted(edge_set),
        "opaque_predicates": detected_opaques,
    }
