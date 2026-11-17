"""Unit tests for Reverse Engineering Graph — Graph Analytics & Complexity Profiling."""

from __future__ import annotations

import pytest

from aether_re.graph_analytics import (
    SCHEMA,
    _tarjan_iterative,
    _weak_components_pure,
    analyze_callgraph_topology,
    compute_centrality_and_degrees,
    compute_cyclomatic_complexity,
    count_weak_components,
    find_strongly_connected_components,
    graph_backend,
)


def test_compute_cyclomatic_complexity():
    # Sem nós -> 1
    assert compute_cyclomatic_complexity(0, 0, 1) == 1

    # Grafo linear simples: A -> B -> C (N=3, E=2, P=1) => 2 - 3 + 2*1 = 1
    assert compute_cyclomatic_complexity(3, 2, 1) == 1

    # Grafo com bifurcação (if/else): A -> B, A -> C, B -> D, C -> D (N=4, E=4, P=1) => 4 - 4 + 2 = 2
    assert compute_cyclomatic_complexity(4, 4, 1) == 2

    # Dois componentes independentes (P=2), linear em cada: A->B, C->D (N=4, E=2, P=2) => 2 - 4 + 4 = 2
    assert compute_cyclomatic_complexity(4, 2, 2) == 2


def test_tarjan_scc_dag_no_cycles():
    nodes = ["main", "foo", "bar"]
    edges = [("main", "foo"), ("foo", "bar")]
    sccs = _tarjan_iterative(nodes, edges)
    # Em DAG, cada nó é um SCC isolado
    assert len(sccs) == 3
    assert all(len(c) == 1 for c in sccs)


def test_tarjan_scc_mutual_recursion_cycle():
    nodes = ["f1", "f2", "f3", "isolated"]
    edges = [("f1", "f2"), ("f2", "f3"), ("f3", "f1")]
    sccs = _tarjan_iterative(nodes, edges)
    sizes = sorted(len(c) for c in sccs)
    assert sizes == [1, 3]  # isolated (1) e {f1, f2, f3} (3)
    rec_group = [c for c in sccs if len(c) == 3][0]
    assert sorted(rec_group) == ["f1", "f2", "f3"]


def test_weak_components_pure():
    nodes = ["a", "b", "c", "d", "e"]
    edges = [("a", "b"), ("b", "c"), ("d", "e")]
    # Dois componentes fracos: {a, b, c} e {d, e}
    assert _weak_components_pure(nodes, edges) == 2
    assert count_weak_components(nodes, edges) == 2


def test_compute_centrality_and_degrees():
    nodes = ["hub", "leaf1", "leaf2"]
    edges = [("hub", "leaf1"), ("hub", "leaf2")]
    deg = compute_centrality_and_degrees(nodes, edges)
    assert deg["hub"]["out_degree"] == 2
    assert deg["hub"]["in_degree"] == 0
    assert deg["hub"]["total_degree"] == 2
    assert deg["leaf1"]["in_degree"] == 1
    assert deg["leaf1"]["out_degree"] == 0


def test_analyze_callgraph_topology_full():
    nodes = {
        "main": {"address": "0x1000"},
        "crypto_init": {"address": "0x1100"},
        "encrypt_block": {"address": "0x1200"},
        "helper_rec_a": {"address": "0x1300"},
        "helper_rec_b": {"address": "0x1400"},
    }
    edges = [
        ("main", "crypto_init"),
        ("main", "encrypt_block"),
        ("encrypt_block", "encrypt_block"),  # auto-laço
        ("main", "helper_rec_a"),
        ("helper_rec_a", "helper_rec_b"),
        ("helper_rec_b", "helper_rec_a"),  # ciclo recursivo
    ]
    res = analyze_callgraph_topology(nodes, edges, entry_point="main")
    assert res["schema"] == SCHEMA
    assert res["backend"] in ("networkx", "pure-python")
    metrics = res["metrics"]
    assert metrics["nodes_count"] == 5
    assert metrics["edges_count"] == 6
    assert metrics["self_loops_count"] == 1
    assert metrics["recursive_cycles_count"] >= 1
    assert res["self_loops"] == ["encrypt_block"]
    assert len(res["top_hubs"]) >= 1
    assert res["top_hubs"][0]["name"] == "main"
