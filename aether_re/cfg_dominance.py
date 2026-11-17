"""Reverse Engineering Graph (REG) — Control Flow Graph (CFG) Dominance & Loop Recovery.

Implementa análise de dominância e recuperação estrutural de laços sobre CFGs:
  1. Árvore de Dominância e Dominadores Imediatos (idom) via Cooper-Harvey-Kennedy
     / Lengauer-Tarjan (O(N·D), determinístico e iterativo);
  2. Fronteira de Dominância (Dominance Frontier - DF) para construção de forma SSA;
  3. Recuperação de laços naturais (Natural Loops) a partir de back-edges;
  4. Detecção de redutibilidade de fluxo de controle (Reducible vs Irreducible CFG).

Reúso: quando ``networkx`` está presente, utiliza ``immediate_dominators`` e
``dominance_frontiers`` do NetworkX com fallback autônomo puro-Python testado.
"""

from __future__ import annotations

from typing import Any, Sequence

try:  # pragma: no cover
    import networkx as _nx  # type: ignore
except Exception:  # pragma: no cover
    _nx = None

SCHEMA = "cfg-dominance-report.v1"


def _build_predecessors_and_successors(
    nodes: Sequence[str], edges: Sequence[tuple[str, str]]
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    preds: dict[str, list[str]] = {n: [] for n in nodes}
    succs: dict[str, list[str]] = {n: [] for n in nodes}
    for s, d in edges:
        if s in succs and d in preds:
            succs[s].append(d)
            preds[d].append(s)
    return preds, succs


def compute_immediate_dominators_pure(
    nodes: Sequence[str], edges: Sequence[tuple[str, str]], entry: str
) -> dict[str, str | None]:
    """Algoritmo de Cooper-Harvey-Kennedy para Dominadores Imediatos (idom).

    Iterativo, sem recursão, amplamente utilizado em compiladores modernos (LLVM style).
    """
    node_set = list(dict.fromkeys(nodes))
    if entry not in node_set:
        return {n: None for n in node_set}

    preds, succs = _build_predecessors_and_successors(node_set, edges)

    # 1. Obter ordem RPO (Reverse Post-Order) a partir do entry
    visited: set[str] = set()
    post_order: list[str] = []
    # DFS iterativo para post-order
    call_stack: list[tuple[str, int]] = [(entry, 0)]
    visited.add(entry)

    while call_stack:
        u, idx = call_stack[-1]
        children = succs.get(u, [])
        if idx < len(children):
            call_stack[-1] = (u, idx + 1)
            nxt = children[idx]
            if nxt not in visited:
                visited.add(nxt)
                call_stack.append((nxt, 0))
        else:
            post_order.append(u)
            call_stack.pop()

    rpo = list(reversed(post_order))
    rpo_idx = {n: i for i, n in enumerate(rpo)}

    # Nós alcançáveis a partir de entry
    idom: dict[str, str | None] = {n: None for n in node_set}
    idom[entry] = entry

    def intersect(b1: str, b2: str) -> str:
        f1, f2 = b1, b2
        while f1 != f2:
            while rpo_idx[f1] > rpo_idx[f2]:
                par = idom[f1]
                if par is None or par == f1:
                    break
                f1 = par
            while rpo_idx[f2] > rpo_idx[f1]:
                par = idom[f2]
                if par is None or par == f2:
                    break
                f2 = par
            if f1 == idom.get(f1) and f2 == idom.get(f2) and f1 != f2:
                break
        return f1

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry:
                continue
            pred_list = [p for p in preds[b] if idom[p] is not None]
            if not pred_list:
                continue
            new_idom = pred_list[0]
            for p in pred_list[1:]:
                new_idom = intersect(p, new_idom)
            if idom[b] != new_idom:
                idom[b] = new_idom
                changed = True

    return idom


def compute_immediate_dominators(
    nodes: Sequence[str], edges: Sequence[tuple[str, str]], entry: str
) -> dict[str, str | None]:
    node_set = list(dict.fromkeys(nodes))
    if entry not in node_set:
        return {n: None for n in node_set}
    if _nx is not None:
        try:
            g = _nx.DiGraph()
            g.add_nodes_from(node_set)
            g.add_edges_from((s, d) for s, d in edges if s in g and d in g)
            raw_idom = _nx.immediate_dominators(g, entry)
            res = {n: raw_idom.get(n) for n in node_set}
            res[entry] = entry
            return res
        except Exception:
            pass
    return compute_immediate_dominators_pure(node_set, edges, entry)


def compute_dominance_frontier(
    nodes: Sequence[str], edges: Sequence[tuple[str, str]], idoms: dict[str, str | None]
) -> dict[str, list[str]]:
    """Calcula a fronteira de dominância (DF) para cada nó."""
    node_set = list(dict.fromkeys(nodes))
    preds, _ = _build_predecessors_and_successors(node_set, edges)
    df: dict[str, set[str]] = {n: set() for n in node_set}

    for b in node_set:
        pred_list = preds.get(b, [])
        if len(pred_list) >= 2:
            for p in pred_list:
                runner = p
                b_idom = idoms.get(b)
                while runner and runner != b_idom and runner in idoms:
                    df[runner].add(b)
                    if idoms[runner] == runner or idoms[runner] is None:
                        break
                    runner = idoms[runner]

    return {n: sorted(df[n]) for n in node_set}


def _is_dominating(a: str, b: str, idoms: dict[str, str | None]) -> bool:
    """Verifica se 'a' domina 'b' navegando idom(b)."""
    curr: str | None = b
    while curr is not None:
        if curr == a:
            return True
        parent = idoms.get(curr)
        if parent == curr:
            break
        curr = parent
    return False


def find_natural_loops(
    nodes: Sequence[str], edges: Sequence[tuple[str, str]], idoms: dict[str, str | None]
) -> list[dict[str, Any]]:
    """Identifica laços naturais a partir de back-edges (arestas tail -> head onde head domina tail)."""
    node_set = list(dict.fromkeys(nodes))
    preds, _ = _build_predecessors_and_successors(node_set, edges)
    loops: list[dict[str, Any]] = []

    for s, d in edges:
        if s not in node_set or d not in node_set:
            continue
        if _is_dominating(d, s, idoms):
            # Encontrou back-edge: d é o header do laço, s é o tail
            header, tail = d, s
            loop_nodes = {header}
            if tail != header:
                loop_nodes.add(tail)
                stack = [tail]
                while stack:
                    curr = stack.pop()
                    for p in preds.get(curr, []):
                        if p not in loop_nodes:
                            loop_nodes.add(p)
                            stack.append(p)
            loops.append({
                "header": header,
                "tail": tail,
                "back_edge": [tail, header],
                "nodes": sorted(loop_nodes),
                "size": len(loop_nodes),
            })
    loops.sort(key=lambda x: (x["header"], x["tail"]))
    return loops


def analyze_cfg_structure(
    nodes: Sequence[str], edges: Sequence[tuple[str, str]], entry: str
) -> dict[str, Any]:
    """Análise estrutural completa de CFG: Dominância, DF, Laços Naturais e Redutibilidade."""
    node_set = list(dict.fromkeys(nodes))
    idoms = compute_immediate_dominators(node_set, edges, entry)
    df = compute_dominance_frontier(node_set, edges, idoms)
    loops = find_natural_loops(node_set, edges, idoms)

    # Detecção de redutibilidade: se todos os laços são naturais e alcançáveis
    # Em CFG irredutível há ciclos com múltiplos pontos de entrada (sem dominador único)
    is_reducible = True
    for lp in loops:
        hdr = lp["header"]
        for n in lp["nodes"]:
            if n != hdr:
                preds, _ = _build_predecessors_and_successors(node_set, edges)
                for p in preds.get(n, []):
                    if p not in lp["nodes"] and p != hdr:
                        is_reducible = False
                        break

    # Árvore de dominância: filhos de cada nó na dominância
    dom_tree: dict[str, list[str]] = {n: [] for n in node_set}
    for n, parent in idoms.items():
        if parent and parent != n and parent in dom_tree:
            dom_tree[parent].append(n)
    for n in dom_tree:
        dom_tree[n].sort()

    return {
        "schema": SCHEMA,
        "entry_point": entry,
        "total_nodes": len(node_set),
        "total_edges": len(edges),
        "is_reducible": is_reducible,
        "immediate_dominators": idoms,
        "dominance_frontiers": df,
        "dominator_tree_children": dom_tree,
        "natural_loops_count": len(loops),
        "natural_loops": loops,
    }
