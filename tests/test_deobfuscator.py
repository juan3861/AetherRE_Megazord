"""Unit tests for Reverse Engineering Graph — MBA Deobfuscation & Opaque Predicates."""

from __future__ import annotations

import pytest

from aether_re.deobfuscator import (
    SCHEMA,
    detect_opaque_predicate,
    prune_dead_cfg_branches,
    simplify_mba_expression,
)


def test_simplify_mba_expression():
    # Regra: (x ^ y) + 2*(x & y) => (x + y)
    assert simplify_mba_expression("(a ^ b) + 2*(a & b)") == "(a + b)"

    # Regra: (x | y) - (x ^ y) => (x & y)
    assert simplify_mba_expression("(x | y) - (x ^ y)") == "(x & y)"

    # Identidades com zero
    assert simplify_mba_expression("foo ^ 0") == "foo"
    assert simplify_mba_expression("bar * 0") == "0"

    # Auto-XOR
    assert simplify_mba_expression("reg ^ reg") == "0"


def test_detect_opaque_predicate_bogus_control_flow():
    # y * (y + 1) % 2 == 0 sempre verdadeiro
    res1 = detect_opaque_predicate("y * (y + 1) % 2 == 0")
    assert res1["is_opaque"] is True
    assert res1["static_truth_value"] is True
    assert res1["rule"] == "paridade_consecutivos"

    # (x | 1) % 2 == 0 sempre falso
    res2 = detect_opaque_predicate("(x | 1) % 2 == 0")
    assert res2["is_opaque"] is True
    assert res2["static_truth_value"] is False

    # Identidade óbvia
    res3 = detect_opaque_predicate("z == z")
    assert res3["is_opaque"] is True
    assert res3["static_truth_value"] is True

    # Condição dinâmica normal (não-opaca)
    res4 = detect_opaque_predicate("eax > 100")
    assert res4["is_opaque"] is False
    assert res4["static_truth_value"] is None


def test_prune_dead_cfg_branches():
    nodes = ["entry", "opaque_branch", "true_dest", "dead_false_dest", "exit"]
    edges = [
        ("entry", "opaque_branch"),
        ("opaque_branch", "true_dest"),
        ("opaque_branch", "dead_false_dest"),
        ("true_dest", "exit"),
        ("dead_false_dest", "exit"),
    ]
    # O predicado no opaque_branch é sempre verdadeiro -> dead_false_dest torna-se aresta morta
    branch_conditions = [
        {
            "branch_node": "opaque_branch",
            "true_target": "true_dest",
            "false_target": "dead_false_dest",
            "condition": "x * (x + 1) % 2 == 0",
        }
    ]

    report = prune_dead_cfg_branches(nodes, edges, branch_conditions, entry="entry")
    assert report["schema"] == SCHEMA
    assert report["pruned_edges_count"] == 1
    assert ("opaque_branch", "dead_false_dest") in report["pruned_edges"]
    assert "dead_false_dest" in report["unreachable_nodes"]
    assert len(report["opaque_predicates"]) == 1
