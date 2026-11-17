"""Unit tests for Reverse Engineering Graph — CFG Dominance & Natural Loop Recovery."""

from __future__ import annotations

import pytest

from aether_re.cfg_dominance import (
    SCHEMA,
    analyze_cfg_structure,
    compute_dominance_frontier,
    compute_immediate_dominators,
    compute_immediate_dominators_pure,
    find_natural_loops,
)


def test_immediate_dominators_linear_flow():
    nodes = ["entry", "bb1", "bb2", "bb3"]
    edges = [("entry", "bb1"), ("bb1", "bb2"), ("bb2", "bb3")]
    idoms = compute_immediate_dominators(nodes, edges, "entry")
    assert idoms["entry"] == "entry"
    assert idoms["bb1"] == "entry"
    assert idoms["bb2"] == "bb1"
    assert idoms["bb3"] == "bb2"


def test_immediate_dominators_diamond_join():
    # entry -> left, entry -> right, left -> join, right -> join
    nodes = ["entry", "left", "right", "join"]
    edges = [("entry", "left"), ("entry", "right"), ("left", "join"), ("right", "join")]
    idoms = compute_immediate_dominators(nodes, edges, "entry")
    assert idoms["left"] == "entry"
    assert idoms["right"] == "entry"
    # Ambos os caminhos convergem em join a partir de entry -> idom(join) == entry
    assert idoms["join"] == "entry"

    df = compute_dominance_frontier(nodes, edges, idoms)
    # join é ponto de convergência: está na DF de left e right
    assert "join" in df["left"]
    assert "join" in df["right"]
    assert df["entry"] == []


def test_find_natural_loops_single_and_nested():
    # Loop 1: hdr -> body -> hdr (back-edge body -> hdr)
    nodes = ["entry", "hdr", "body", "exit"]
    edges = [("entry", "hdr"), ("hdr", "body"), ("body", "hdr"), ("hdr", "exit")]
    idoms = compute_immediate_dominators(nodes, edges, "entry")
    loops = find_natural_loops(nodes, edges, idoms)
    assert len(loops) == 1
    assert loops[0]["header"] == "hdr"
    assert loops[0]["tail"] == "body"
    assert sorted(loops[0]["nodes"]) == ["body", "hdr"]


def test_analyze_cfg_structure_full():
    nodes = ["entry", "bb_if", "bb_then", "bb_else", "bb_loop_hdr", "bb_loop_body", "bb_exit"]
    edges = [
        ("entry", "bb_if"),
        ("bb_if", "bb_then"),
        ("bb_if", "bb_else"),
        ("bb_then", "bb_loop_hdr"),
        ("bb_else", "bb_loop_hdr"),
        ("bb_loop_hdr", "bb_loop_body"),
        ("bb_loop_body", "bb_loop_hdr"),  # back-edge
        ("bb_loop_hdr", "bb_exit"),
    ]
    rep = analyze_cfg_structure(nodes, edges, "entry")
    assert rep["schema"] == SCHEMA
    assert rep["entry_point"] == "entry"
    assert rep["is_reducible"] is True
    assert rep["natural_loops_count"] == 1
    assert rep["natural_loops"][0]["header"] == "bb_loop_hdr"
    assert "bb_exit" in rep["dominator_tree_children"]["bb_loop_hdr"]
