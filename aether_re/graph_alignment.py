"""Reverse Engineering Graph (AetherRE) — Bipartite Function Alignment.

Pareamento 1-para-1 de funções entre dois binários (problema de atribuição),
na linha do QBinDiff (Quarkslab), usando afinidade composta:
  - similaridade SimHash 64-bit (normalização PalmTree);
  - similaridade topológica (in/out-degree);
  - compatibilidade de papel semântico (rótulos SymLM-light).

Reuso: com ``networkx`` disponível usa ``max_weight_matching`` (Edmonds/blossom,
ótimo exato para peso máximo). Sem networkx (perfil core), usa fallback guloso,
explicitamente reportado como ``greedy-fallback`` (não-ótimo).

"identical" só é declarado quando os SimHashes são exatamente iguais
(ou, sem SimHash, quando os nomes coincidem); o resto é "modified".
"""

from __future__ import annotations

from typing import Any

from aether_re.function_simhash import simhash_similarity
from aether_re.semantic_labeler import infer_function_role

try:  # pragma: no cover
    import networkx as _nx  # type: ignore
except Exception:  # pragma: no cover
    _nx = None

SCHEMA = "graph-alignment-report.v1"


def _role(fn: dict[str, Any]) -> str:
    return fn.get("inferred_role") or infer_function_role(name=fn.get("name", ""))["inferred_category"]


def compute_affinity_score(fa: dict[str, Any], fb: dict[str, Any], *, w_simhash: float = 0.60, w_topo: float = 0.25, w_role: float = 0.15) -> float:
    sh_a, sh_b = fa.get("simhash", ""), fb.get("simhash", "")
    if sh_a and sh_b:
        sim_hash = simhash_similarity(sh_a, sh_b)
    else:
        sim_hash = 1.0 if fa.get("name") and fa.get("name") == fb.get("name") else 0.4
    in_a, out_a = fa.get("in_degree", 0), fa.get("out_degree", 0)
    in_b, out_b = fb.get("in_degree", 0), fb.get("out_degree", 0)
    max_deg = max(1, in_a + out_a, in_b + out_b)
    sim_topo = max(0.0, 1.0 - (abs(in_a - in_b) + abs(out_a - out_b)) / (2.0 * max_deg))
    sim_role = 1.0 if _role(fa) == _role(fb) else 0.3
    return round(w_simhash * sim_hash + w_topo * sim_topo + w_role * sim_role, 4)


def _is_identical(fa: dict[str, Any], fb: dict[str, Any]) -> bool:
    sh_a, sh_b = fa.get("simhash", ""), fb.get("simhash", "")
    if sh_a and sh_b:
        return sh_a.lower() == sh_b.lower()
    return bool(fa.get("name")) and fa.get("name") == fb.get("name")


def align_bipartite_graphs(functions_a: dict[str, dict[str, Any]], functions_b: dict[str, dict[str, Any]], *, threshold: float = 0.50) -> dict[str, Any]:
    names_a, names_b = sorted(functions_a), sorted(functions_b)
    candidates: list[tuple[float, str, str]] = []
    for na in names_a:
        fa = {"name": na, **functions_a[na]}
        for nb in names_b:
            fb = {"name": nb, **functions_b[nb]}
            score = compute_affinity_score(fa, fb)
            if score >= threshold:
                candidates.append((score, na, nb))

    pairs: list[tuple[str, str, float]] = []
    if _nx is not None and candidates:
        algorithm = "networkx-max-weight-matching"
        g = _nx.Graph()
        for score, na, nb in candidates:
            g.add_edge(("A", na), ("B", nb), weight=score)
        for u, v in _nx.max_weight_matching(g, maxcardinality=False):
            a, b = (u, v) if u[0] == "A" else (v, u)
            pairs.append((a[1], b[1], g[u][v]["weight"]))
    else:
        algorithm = "greedy-fallback" if candidates else "none"
        used_a: set[str] = set()
        used_b: set[str] = set()
        for score, na, nb in sorted(candidates, key=lambda c: (-c[0], c[1], c[2])):
            if na not in used_a and nb not in used_b:
                used_a.add(na)
                used_b.add(nb)
                pairs.append((na, nb, score))

    pairs.sort(key=lambda p: (-p[2], p[0]))
    matched_pairs = []
    for na, nb, score in pairs:
        fa, fb = {"name": na, **functions_a[na]}, {"name": nb, **functions_b[nb]}
        matched_pairs.append({
            "function_a": na,
            "function_b": nb,
            "score": score,
            "status": "identical" if _is_identical(fa, fb) else "modified",
            "simhash_a": fa.get("simhash", ""),
            "simhash_b": fb.get("simhash", ""),
        })
    ma = {p["function_a"] for p in matched_pairs}
    mb = {p["function_b"] for p in matched_pairs}
    return {
        "schema": SCHEMA,
        "algorithm": algorithm,
        "matched_pairs": matched_pairs,
        "unmatched_a": [n for n in names_a if n not in ma],
        "unmatched_b": [n for n in names_b if n not in mb],
        "total_matches": len(matched_pairs),
        "total_weight": round(sum(p["score"] for p in matched_pairs), 4),
        "alignment_quality": round(sum(p["score"] for p in matched_pairs) / len(matched_pairs), 4) if matched_pairs else 0.0,
        "identical_count": sum(p["status"] == "identical" for p in matched_pairs),
        "modified_count": sum(p["status"] == "modified" for p in matched_pairs),
    }
