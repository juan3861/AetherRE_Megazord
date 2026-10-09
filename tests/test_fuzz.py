import json
from argparse import Namespace

import pytest

from aether_re.fuzz import generate_mutations
from megazord import cmd_fuzz_seeds


def test_fuzz_mutations_are_deterministic_bounded_and_nonexecuting():
    first = generate_mutations([b"abcdef"], budget=2, max_size=4)
    second = generate_mutations([b"abcdef"], budget=2, max_size=4)
    assert first == second
    assert len(first) == 2
    assert all(item["size"] <= 4 and item["sha256"] for item in first)
    assert all(item["seed_sha256"] for item in first)


def test_fuzz_mutator_rejects_unbounded_configuration():
    with pytest.raises(ValueError, match="budget_must_be_nonnegative"):
        generate_mutations([b"abc"], budget=-1)
    with pytest.raises(ValueError, match="max_size_must_be_positive"):
        generate_mutations([b"abc"], max_size=0)


def test_fuzz_cli_rejects_malformed_json_without_traceback(tmp_path):
    source = tmp_path / "seeds.json"
    out = tmp_path / "report.json"
    source.write_text("{", encoding="utf-8")
    code = cmd_fuzz_seeds(Namespace(input=str(source), out=str(out), budget=10, max_size=16))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"


def test_fuzz_cli_publishes_provenance_without_execution(tmp_path):
    source = tmp_path / "seeds.json"
    out = tmp_path / "report.json"
    source.write_text(json.dumps({"seeds": ["616263"]}), encoding="utf-8")
    code = cmd_fuzz_seeds(Namespace(input=str(source), out=str(out), budget=2, max_size=16))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0
    assert report["status"] == "generated"
    assert report["executed_targets"] is False
    assert report["mutations"][0]["seed_sha256"]


def test_fuzz_cli_rejects_valid_json_with_wrong_shape(tmp_path):
    source = tmp_path / "seeds.json"
    out = tmp_path / "report.json"
    source.write_text(json.dumps({"not_seeds": []}), encoding="utf-8")
    code = cmd_fuzz_seeds(Namespace(input=str(source), out=str(out), budget=10, max_size=16))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["errors"][0]["code"] == "input_shape_invalid"
