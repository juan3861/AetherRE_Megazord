"""Reverse Engineering Graph (AetherRE) — Graph Analytics & Complexity Profiling.

Métricas topológicas sobre Callgraphs/CFGs:
  1. Complexidade ciclomática de McCabe  M = E - N + 2P  (P = componentes fracamente conexos);
  2. Componentes fortemente conexos (recursão mútua) e auto-laços;
  3. Centralidade de grau e hubs.

Reuso antes de reimplementação: quando ``networkx`` está disponível (perfil angr,
pinado por hash em ``requirements-angr.lock``) os algoritmos dele são usados.
No perfil core (sem networkx) há fallback puro-Python **iterativo** (sem recursão,
imune a RecursionError em grafos profundos). O backend usado é reportado.
"""

from __future__ import annotations

from typing import Any, Sequence

try:  # pragma: no cover - depende do perfil instalado
    import networkx as _nx  # type: ignore
except Exception:  # pragma: no cover
    _nx = None

SCHEMA = "graph-analytics-report.v1"


def graph_backend() -> str:
    return "networkx" if _nx is not None else "pure-python"


def compute_cyclomatic_complexity(nodes_count: int, edges_count: int, connected_components: int = 1) -> int:
    """McCabe: M = E - N + 2P (mínimo 1)."""
    if nodes_count <= 0:
        return 1
    return max(1, edges_count - nodes_count + 2 * max(1, connected_components))


def _adjacency(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> dict[str, list[str]]:
    adj: dict[str, list[str]] = {n: [] for n in nodes}
    for src, dst in edges:
        if src in adj and dst in adj:
            adj[src].append(dst)
    return adj


def _tarjan_iterative(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> list[list[str]]:
    """Tarjan SCC iterativo O(V+E), sem recursão."""
    adj = _adjacency(nodes, edges)
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []
    counter = 0
    for root in sorted(adj):
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            v, i = work[-1]
            if i == 0 and v not in index:
                index[v] = low[v] = counter
                counter += 1
                stack.append(v)
                on_stack.add(v)
            succ = adj[v]
            if i < len(succ):
                work[-1] = (v, i + 1)
                w = succ[i]
                if w not in index:
                    work.append((w, 0))
                elif w in on_stack:
                    low[v] = min(low[v], index[w])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index[v]:
                comp: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                sccs.append(sorted(comp))
    return sccs


def _weak_components_pure(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> int:
    parent = {n: n for n in nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for src, dst in edges:
        if src in parent and dst in parent:
            ra, rb = find(src), find(dst)
            if ra != rb:
                parent[ra] = rb
    return len({find(n) for n in nodes})


def find_strongly_connected_components(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> list[list[str]]:
    node_list = list(dict.fromkeys(nodes))
    if _nx is not None:
        g = _nx.DiGraph()
        g.add_nodes_from(node_list)
        g.add_edges_from((s, d) for s, d in edges if s in g and d in g)
        return sorted((sorted(c) for c in _nx.strongly_connected_components(g)), key=lambda c: c[0])
    return sorted(_tarjan_iterative(node_list, edges), key=lambda c: c[0])


def count_weak_components(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> int:
    node_list = list(dict.fromkeys(nodes))
    if not node_list:
        return 0
    if _nx is not None:
        g = _nx.DiGraph()
        g.add_nodes_from(node_list)
        g.add_edges_from((s, d) for s, d in edges if s in g and d in g)
        return _nx.number_weakly_connected_components(g)
    return _weak_components_pure(node_list, edges)


def compute_centrality_and_degrees(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> dict[str, dict[str, Any]]:
    node_set = list(dict.fromkeys(nodes))
    in_deg = {n: 0 for n in node_set}
    out_deg = {n: 0 for n in node_set}
    for src, dst in edges:
        if src in out_deg and dst in in_deg:
            out_deg[src] += 1
            in_deg[dst] += 1
    denom = max(1, len(node_set) - 1)
    return {
        n: {
            "in_degree": in_deg[n],
            "out_degree": out_deg[n],
            "total_degree": in_deg[n] + out_deg[n],
            "degree_centrality": round((in_deg[n] + out_deg[n]) / (2.0 * denom), 4),
        }
        for n in node_set
    }


def analyze_callgraph_topology(nodes: dict[str, Any], edges: Sequence[tuple[str, str]], entry_point: str | None = None) -> dict[str, Any]:
    names = list(nodes.keys())
    valid_edges = [(s, d) for s, d in edges if s in nodes and d in nodes]
    n_count, e_count = len(names), len(valid_edges)
    sccs = find_strongly_connected_components(names, valid_edges)
    weak = count_weak_components(names, valid_edges)
    recursive_groups = [c for c in sccs if len(c) > 1]
    self_loops = sorted({s for s, d in valid_edges if s == d})
    centrality = compute_centrality_and_degrees(names, valid_edges)
    ranked = sorted(centrality.items(), key=lambda kv: (kv[1]["degree_centrality"], kv[1]["out_degree"], kv[0]), reverse=True)
    return {
        "schema": SCHEMA,
        "backend": graph_backend(),
        "metrics": {
            "nodes_count": n_count,
            "edges_count": e_count,
            "weakly_connected_components": weak,
            "cyclomatic_complexity": compute_cyclomatic_complexity(n_count, e_count, weak),
            "strongly_connected_components": len(sccs),
            "recursive_cycles_count": len(recursive_groups),
            "self_loops_count": len(self_loops),
            "density": round(e_count / (n_count * (n_count - 1)), 4) if n_count > 1 else 0.0,
        },
        "top_hubs": [{"name": k, **v} for k, v in ranked[:10]],
        "recursive_groups": recursive_groups[:5],
        "self_loops": self_loops[:10],
    }
