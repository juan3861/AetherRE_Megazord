"""Unit tests for Reverse Engineering Graph — Symbolic Path Feasibility & Constraints."""

from __future__ import annotations

import pytest

from aether_re.symbolic_constraints import (
    SCHEMA,
    evaluate_path_feasibility,
    parse_constraint,
)


def test_parse_constraint():
    assert parse_constraint("x > 10") == ("x", ">", 10)
    assert parse_constraint("eax == 0x20") == ("eax", "==", 32)
    assert parse_constraint("count <= -5") == ("count", "<=", -5)
    assert parse_constraint("invalid format") is None


def test_evaluate_path_feasibility_sat():
    constraints = ["x > 10", "x < 20", "x != 15", "y == 42"]
    rep = evaluate_path_feasibility(constraints)
    assert rep["schema"] == SCHEMA
    assert rep["is_feasible"] is True
    assert rep["status"] == "SAT"
    model = rep["satisfying_model"]
    assert 10 < model["x"] < 20
    assert model["x"] != 15
    assert model["y"] == 42


def test_evaluate_path_feasibility_unsat_interval():
    # x > 10 e x < 5 é impossível (UNSAT)
    constraints = ["x > 10", "x < 5"]
    rep = evaluate_path_feasibility(constraints)
    assert rep["is_feasible"] is False
    assert rep["status"] == "UNSAT"
    assert "Intervalo contraditório" in rep["contradiction"]["reason"]


def test_evaluate_path_feasibility_unsat_excluded():
    # x == 10 e x != 10 é impossível (UNSAT)
    constraints = ["x == 10", "x != 10"]
    rep = evaluate_path_feasibility(constraints)
    assert rep["is_feasible"] is False
    assert rep["status"] == "UNSAT"


def test_unparsed_constraint_cannot_be_silently_removed():
    report = evaluate_path_feasibility(["x == 1", "broken ???"])
    assert report["status"] == "ERROR"
    assert report["is_feasible"] is None
    assert report["satisfying_model"] is None


def test_all_values_excluded_is_unsat_not_out_of_bounds_witness():
    report = evaluate_path_feasibility(["x >= 0", "x <= 1", "x != 0", "x != 1"])
    assert report["status"] == "UNSAT"
    assert report["satisfying_model"] is None


def test_nonlinear_path_constraints_are_actually_enforced():
    report = evaluate_path_feasibility(["x > 0", "x * x == 49"])
    assert report["status"] == "SAT"
    assert report["satisfying_model"]["x"] == 7


def test_path_query_isolated_from_previous_z3_context_history():
    import z3
    for index in range(4):
        unrelated = [z3.Int(f"unrelated_{index}_{j}") for j in range(index * 25)]
        report = evaluate_path_feasibility(["x > 0", "x * x == 49"])
        assert report["status"] == "SAT", report["solver"]
        assert report["satisfying_model"]["x"] == 7
