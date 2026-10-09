import copy
import json
from argparse import Namespace

from aether_re.profile_comparison import compare_binary_profiles
from megazord import cmd_compare_binary_profiles


def _evaluation(recall=1.0):
    tp = round(2 * recall)
    score = {"expected": 2, "observed": 2, "true_positive": tp, "false_positive": 2 - tp, "false_negative": 2 - tp, "precision": recall, "recall": recall, "f1": recall}
    return {
        "schema": "corpus-binary-evaluation.v1",
        "status": "complete",
        "manifest_sha256": "a" * 64,
        "executed_targets": False,
        "projects": [{"id": "owned-c", "family": "owned", "language": "c", "split": "holdout", "build_kind": "shared_library", "binary_sha256": "b" * 64, "symbols": copy.deepcopy(score), "symbol_candidates": copy.deepcopy(score), "relations": {"status": "measured", **copy.deepcopy(score)}}],
    }


def test_profile_comparison_measures_regression_on_same_manifest():
    baseline = _evaluation(1.0)
    candidate = _evaluation(0.5)
    candidate["projects"][0]["binary_sha256"] = "c" * 64
    report = compare_binary_profiles(baseline, candidate)
    assert report["status"] == "complete"
    assert report["summary"]["symbol_recall"] == {"compared": 1, "mean_delta": -0.5, "regressed": 1, "improved": 0, "unchanged": 0}
    assert report["projects"][0]["relations"]["recall"]["delta"] == -0.5
    assert report["executed_targets"] is False


def test_profile_comparison_rejects_mismatched_or_duplicated_identity():
    baseline = _evaluation()
    candidate = _evaluation()
    candidate["manifest_sha256"] = "d" * 64
    assert compare_binary_profiles(baseline, candidate)["errors"][0]["code"] == "manifest_hash_mismatch"
    candidate = _evaluation()
    candidate["projects"].append(copy.deepcopy(candidate["projects"][0]))
    report = compare_binary_profiles(baseline, candidate)
    assert report["status"] == "invalid"
    assert any(error["code"] == "project_duplicate" for error in report["errors"])


def test_profile_comparison_rejects_false_complete_and_invalid_scores():
    candidate = _evaluation()
    candidate["status"] = "partial"
    assert compare_binary_profiles(_evaluation(), candidate)["status"] == "invalid"
    candidate = _evaluation()
    candidate["projects"][0]["symbols"]["recall"] = True
    report = compare_binary_profiles(_evaluation(), candidate)
    assert report["status"] == "invalid"
    assert any(error["code"] == "score_invalid" for error in report["errors"])
    candidate = _evaluation()
    candidate["projects"][0]["symbols"]["true_positive"] = 1
    report = compare_binary_profiles(_evaluation(), candidate)
    assert report["status"] == "invalid"
    assert any(error["code"] == "score_counts_inconsistent" for error in report["errors"])


def test_profile_comparison_preserves_unmeasured_relations():
    candidate = _evaluation()
    candidate["projects"][0]["relations"] = {"status": "not_measured", "expected": 2}
    report = compare_binary_profiles(_evaluation(), candidate)
    assert report["status"] == "complete"
    assert report["summary"]["relations_compared"] == 0
    assert report["projects"][0]["relations"]["status"] == "not_comparable"


def test_profile_comparison_cli_rejects_unreadable_input(tmp_path):
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    out = tmp_path / "comparison.json"
    baseline.write_text("{", encoding="utf-8")
    candidate.write_text(json.dumps(_evaluation()), encoding="utf-8")
    code = cmd_compare_binary_profiles(Namespace(baseline=str(baseline), candidate=str(candidate), out=str(out)))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
