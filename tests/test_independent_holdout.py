from pathlib import Path

from aether_re.corpus_eval import evaluate_corpus_source


ROOT = Path(__file__).resolve().parents[1]


def test_manual_holdout_corpus_is_hash_bound_and_generator_independent():
    manifest = ROOT / "corpus" / "independent_holdout_v1" / "manifest.json"
    report = evaluate_corpus_source(manifest)
    assert report["status"] == "complete"
    assert report["oracle_provenance"] == "manual_author_holdout; independent_from_bootstrap_generator"
    assert len(report["projects"]) == 2
    assert all(item["split"] == "holdout" for item in report["projects"])
    assert all(item["symbols"]["recall"] == 1.0 for item in report["projects"])
    assert all(item["relations"]["recall"] == 1.0 for item in report["projects"])
    assert all(len(item["source_sha256"]) == 64 and len(item["oracle_sha256"]) == 64 for item in report["projects"])


def test_manual_holdout_v2_covers_python_and_c_with_hash_bound_oracles():
    manifest = ROOT / "corpus" / "independent_holdout_v2" / "manifest.json"
    report = evaluate_corpus_source(manifest)
    assert report["status"] == "complete"
    assert report["oracle_provenance"] == "manual_author_holdout_v2; independent_from_bootstrap_generator"
    assert {item["language"] for item in report["projects"]} == {"python", "c"}
    assert all(item["symbols"]["recall"] == 1.0 for item in report["projects"])
    assert all(item["relations"]["recall"] == 1.0 for item in report["projects"])


def test_manual_holdout_v3_expands_hash_bound_split_without_external_claim():
    manifest = ROOT / "corpus" / "independent_holdout_v3" / "manifest.json"
    report = evaluate_corpus_source(manifest)
    assert report["status"] == "complete"
    assert report["oracle_provenance"] == "manual_author_holdout_v3; independent_from_bootstrap_generator; no_external_project"
    assert len(report["projects"]) == 6
    assert {item["language"] for item in report["projects"]} == {"python", "c"}
    assert sum(item["language"] == "c" for item in report["projects"]) == 4
    assert all(item["split"] == "holdout" for item in report["projects"])
    assert all(item["symbols"]["recall"] == 1.0 and item["relations"]["recall"] == 1.0 for item in report["projects"])
