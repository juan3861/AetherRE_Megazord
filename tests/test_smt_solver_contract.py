from aether_re.smt_solver import solve_constraints_smt


def test_invalid_constraint_never_proves_satisfiability_of_partial_input():
    result = solve_constraints_smt(["x == 1", "invalid syntax???"])
    assert result["status"] == "ERROR"
    assert result["is_satisfiable"] is None
    assert result["model"] == {}


def test_attributes_and_function_calls_cannot_execute_effects(tmp_path):
    marker = tmp_path / "effect.txt"
    expression = f"__import__('pathlib').Path({str(marker)!r}).write_text('effect') == 6"
    result = solve_constraints_smt([expression])
    assert result["status"] == "ERROR"
    assert not marker.exists()


def test_nonlinear_witness_satisfies_every_constraint():
    result = solve_constraints_smt(["x > 0", "x * x == 49", "x + y == 10"])
    assert result["status"] == "SAT"
    assert result["model"]["x"] == 7
    assert result["model"]["y"] == 3
    assert result["total_constraints_parsed"] == 3


def test_unsigned_bitwise_operations_keep_word_width():
    result = solve_constraints_smt(["x == 255", "(x + 1) == 0", "(x ^ 15) == 240"], bitvector_width=8)
    assert result["status"] == "SAT"
    assert result["model"]["x"] == 255


def test_real_solver_resource_exhaustion_is_unknown_not_unsat():
    result = solve_constraints_smt(["x > 10", "x < 20"], resource_limit=1)
    assert result["status"] == "UNKNOWN"
    assert result["is_satisfiable"] is None
    assert result["reason_unknown"]


def test_boolean_constraints_have_boolean_witnesses():
    result = solve_constraints_smt(["enabled and (x == 4)", "not blocked"])
    assert result["status"] == "SAT"
    assert result["model"]["enabled"] is True
    assert result["model"]["blocked"] is False


def test_division_by_zero_does_not_generate_a_spurious_witness():
    result = solve_constraints_smt(["x == 0", "10 / x == 2"])
    assert result["status"] == "UNSAT"


def test_blank_constraints_are_invalid_not_silently_dropped():
    result = solve_constraints_smt(["x == 1", " "])
    assert result["status"] == "ERROR"
    assert result["is_satisfiable"] is None
