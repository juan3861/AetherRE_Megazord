import json
from argparse import Namespace

from aether_re.symbolic import validate_symbolic_result, write_symbolic_report
from megazord import cmd_symbolic_validate


def _result(**overrides):
    document = {
        "schema": "symbolic-exploration.v1",
        "run_id": "sym-1",
        "target_sha256": "a" * 64,
        "engine": "angr",
        "objective": "find divergent return",
        "status": "sat",
        "states_explored": 12,
        "paths": [{"path_id": "p1", "status": "sat", "input_sha256": "b" * 64, "note": "bounded counterexample"}],
        "timeout_s": 30,
        "memory_limit_mb": 512,
        "executed_in_lab": False,
    }
    document.update(overrides)
    return document


def test_symbolic_valid_sat_is_reviewable_counterexample_not_universal_proof():
    report = validate_symbolic_result(_result())
    assert report["status"] == "complete"
    assert report["conclusion"] == "counterexample_found"
    assert report["summary"]["review_required"] is True
    assert report["summary"]["universal_proof"] is False
    assert report["paths"][0]["input_sha256"] == "b" * 64


def test_symbolic_unsat_and_timeout_are_not_proofs():
    unsat = validate_symbolic_result(_result(status="unsat", paths=[]))
    assert unsat["status"] == "complete"
    assert unsat["conclusion"] == "not_proven"
    timeout = validate_symbolic_result(_result(status="timeout", paths=[]))
    assert timeout["conclusion"] == "timeout"
    assert timeout["summary"]["universal_proof"] is False


def test_symbolic_rejects_schema_budgets_and_lab_attestation():
    bad = _result(schema="wrong.v1", timeout_s=0, executed_in_lab=True)
    report = validate_symbolic_result(bad)
    codes = {item["code"] for item in report["errors"]}
    assert report["status"] == "invalid"
    assert {"schema_invalid", "positive_budget_invalid", "lab_proof_id_required"} <= codes


def test_symbolic_rejects_malformed_optional_lab_attestation_even_when_not_executed():
    report = validate_symbolic_result(_result(lab_proof_id=123))
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "lab_proof_id_invalid"


def test_symbolic_rejects_duplicate_paths_and_invalid_hashes():
    paths = [
        {"path_id": "p1", "status": "sat", "input_sha256": "not-a-hash"},
        {"path_id": "p1", "status": "unsat"},
    ]
    report = validate_symbolic_result(_result(paths=paths))
    codes = {item["code"] for item in report["errors"]}
    assert report["status"] == "invalid"
    assert {"path_input_hash_invalid", "path_id_duplicate"} <= codes


def test_symbolic_rejects_path_budget_without_processing_unbounded_payload():
    report = validate_symbolic_result(_result(paths=[]), max_paths=True)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "max_paths_invalid"


def test_symbolic_cli_materializes_unreadable_and_scalar_diagnostics(tmp_path):
    out = tmp_path / "missing.json"
    code = cmd_symbolic_validate(Namespace(input=str(tmp_path / "nope.json"), out=str(out), max_paths=100))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["errors"][0]["code"] == "input_unreadable"

    scalar = tmp_path / "scalar.json"
    scalar.write_text("42", encoding="utf-8")
    scalar_out = tmp_path / "scalar-report.json"
    code = cmd_symbolic_validate(Namespace(input=str(scalar), out=str(scalar_out), max_paths=100))
    report = json.loads(scalar_out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["errors"][0]["code"] == "result_must_be_object"


def test_symbolic_report_writer_is_deterministic_json(tmp_path):
    report = validate_symbolic_result(_result())
    out = tmp_path / "report.json"
    write_symbolic_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == "symbolic-exploration.v1"
