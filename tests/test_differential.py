import json
import hashlib
from argparse import Namespace

from aether_re.differential import compare_observations, reduce_counterexample
from megazord import cmd_differential_compare


def test_differential_compare_finds_effect_and_exception_counterexamples():
    report = compare_observations(
        [{"input": "x", "output": 1, "effects": ["write:a"], "exception": None}, {"input": "bad", "output": None, "effects": [], "exception": "ValueError"}],
        [{"input": "x", "output": 1, "effects": [], "exception": None}],
    )
    assert report["status"] == "counterexamples_found"
    assert report["summary"]["mismatches"] == 2
    assert {item["kind"] for item in report["mismatches"]} == {"behavior_mismatch", "missing_reconstruction"}
    expected = hashlib.sha256(b'"x"').hexdigest()
    assert all(item["input_sha256"] and item["reproduction_id"] == f"ce-{item['input_sha256']}" for item in report["mismatches"])
    assert report["mismatches"][0]["input_sha256"] == expected


def test_differential_counterexample_identity_is_stable_for_nested_input():
    original = [{"input": {"b": 2, "a": [True, None]}, "output": "old"}]
    reconstructed = [{"input": {"a": [True, None], "b": 2}, "output": "new"}]
    first = compare_observations(original, reconstructed)
    second = compare_observations(original, reconstructed)
    assert first["status"] == "counterexamples_found"
    assert first["mismatches"][0]["reproduction_id"] == second["mismatches"][0]["reproduction_id"]


def test_counterexample_reducer_minimizes_with_external_boolean_oracle():
    original = {"noise": ["discard", "this"], "payload": "xxFAILxx", "unused": True}

    def oracle(candidate):
        return "FAIL" in json.dumps(candidate, sort_keys=True)

    report = reduce_counterexample(original, oracle, max_attempts=200)
    assert report["status"] == "reduced"
    assert report["reduced"] == {"payload": "FAIL"}
    assert report["reduced_identity"]["reproduction_id"].startswith("ce-")
    assert report["attempts"] <= 200


def test_counterexample_reducer_fails_closed_for_non_failure_and_bad_oracle():
    not_failed = reduce_counterexample({"input": "ok"}, lambda value: False)
    assert not_failed["status"] == "not_a_counterexample"
    assert not_failed["errors"][0]["code"] == "oracle_did_not_confirm_failure"
    bad = reduce_counterexample("boom", lambda value: "yes")
    assert bad["status"] == "invalid"
    assert bad["errors"][0]["code"] == "failure_oracle_must_return_bool"


def test_differential_compare_rejects_duplicate_or_malformed_inputs():
    duplicate = compare_observations([{"input": "x", "output": 1}, {"input": "x", "output": 2}], [{"input": "x", "output": 1}])
    assert duplicate["status"] == "invalid"
    assert duplicate["errors"][0]["code"] == "duplicate_observation_input"
    malformed = compare_observations([{"output": 1}], [{"input": "x", "output": 1}])
    assert malformed["status"] == "invalid"
    assert malformed["errors"][0]["code"] == "observation_input_missing"
    budget = compare_observations([], [], max_observations=0)
    assert budget["status"] == "invalid"
    assert budget["errors"][0]["code"] == "max_observations_invalid"


def test_differential_cli_rejects_unreadable_input_without_traceback(tmp_path):
    original = tmp_path / "original.json"
    reconstructed = tmp_path / "reconstructed.json"
    out = tmp_path / "report.json"
    original.write_text("{", encoding="utf-8")
    reconstructed.write_text(json.dumps([]), encoding="utf-8")
    code = cmd_differential_compare(Namespace(original=str(original), reconstructed=str(reconstructed), out=str(out), max_observations=10))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"
