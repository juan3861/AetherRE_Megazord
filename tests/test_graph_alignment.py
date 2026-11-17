"""Unit tests for Reverse Engineering Graph — Bipartite Function Alignment."""

from __future__ import annotations

import pytest

from aether_re.graph_alignment import (
    SCHEMA,
    align_bipartite_graphs,
    compute_affinity_score,
)


def test_affinity_score_identical_functions():
    sh = "a1b2c3d4e5f60718"
    fa = {"name": "crypto_aes", "simhash": sh, "in_degree": 2, "out_degree": 4, "inferred_role": "crypto"}
    fb = {"name": "sub_401000", "simhash": sh, "in_degree": 2, "out_degree": 4, "inferred_role": "crypto"}
    score = compute_affinity_score(fa, fb)
    # SimHash = 1.0 (0.60), Topo = 1.0 (0.25), Role = 1.0 (0.15) => 1.0000
    assert score == 1.0


def test_affinity_score_divergent_functions():
    fa = {"name": "parse_header", "simhash": "0000000000000000", "in_degree": 1, "out_degree": 10, "inferred_role": "parsing"}
    fb = {"name": "draw_window", "simhash": "ffffffffffffffff", "in_degree": 8, "out_degree": 0, "inferred_role": "gui"}
    score = compute_affinity_score(fa, fb)
    assert score < 0.50


def test_align_bipartite_graphs_perfect_match():
    funcs_a = {
        "fn_alpha": {"simhash": "1111222233334444", "in_degree": 1, "out_degree": 2, "inferred_role": "math"},
        "fn_beta": {"simhash": "5555666677778888", "in_degree": 3, "out_degree": 1, "inferred_role": "crypto"},
    }
    funcs_b = {
        "sub_100": {"simhash": "1111222233334444", "in_degree": 1, "out_degree": 2, "inferred_role": "math"},
        "sub_200": {"simhash": "5555666677778888", "in_degree": 3, "out_degree": 1, "inferred_role": "crypto"},
    }
    res = align_bipartite_graphs(funcs_a, funcs_b, threshold=0.50)
    assert res["schema"] == SCHEMA
    assert res["total_matches"] == 2
    assert res["identical_count"] == 2
    assert res["modified_count"] == 0
    assert res["unmatched_a"] == []
    assert res["unmatched_b"] == []


def test_align_bipartite_graphs_with_modified_and_unmatched():
    funcs_a = {
        "f_common": {"simhash": "aaaaaaaaaaaaaaaa", "in_degree": 2, "out_degree": 2, "inferred_role": "net"},
        "f_mod": {"simhash": "bbbbbbbbbbbbbbbb", "in_degree": 1, "out_degree": 1, "inferred_role": "crypto"},
        "f_removed": {"simhash": "0000000011111111", "in_degree": 0, "out_degree": 1, "inferred_role": "util"},
    }
    # Na versão B, f_mod teve SimHash levemente alterado (1 bit de distância)
    # 'bbbbbbbbbbbbbbba' difere de 'bbbbbbbbbbbbbbbb' por pouquíssimos bits
    funcs_b = {
        "f_common": {"simhash": "aaaaaaaaaaaaaaaa", "in_degree": 2, "out_degree": 2, "inferred_role": "net"},
        "f_mod_v2": {"simhash": "bbbbbbbbbbbbbbba", "in_degree": 1, "out_degree": 1, "inferred_role": "crypto"},
        "f_added": {"simhash": "ffffffff00000000", "in_degree": 5, "out_degree": 0, "inferred_role": "ui"},
    }
    res = align_bipartite_graphs(funcs_a, funcs_b, threshold=0.60)
    assert res["total_matches"] == 2
    assert res["identical_count"] == 1  # f_common
    assert res["modified_count"] == 1   # f_mod <-> f_mod_v2
    assert "f_removed" in res["unmatched_a"]
    assert "f_added" in res["unmatched_b"]
