"""Regression checks for the materialized, commit-bound Juliet external subset."""

import json
from pathlib import Path

from aether_re.corpus import validate_corpus_builds
from aether_re.corpus_eval import evaluate_corpus_source


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "corpus" / "external_juliet_cwe_v1" / "manifest.json"


def test_external_juliet_subset_is_hash_bound_and_oracle_separated():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema"] == "re-megazord-corpus.v1"
    assert manifest["source_commit"] == "f88433e3443648a17671398797a04ea1f8e1a274"
    assert manifest["count"] == 10
    assert len({item["family"] for item in manifest["projects"]}) == 10
    assert all(item["authorization"] == "external_authorized" for item in manifest["projects"])
    assert all(item["provenance"]["oracle_independent"] is True for item in manifest["projects"])
    assert all(not item["oracle"].startswith(item["id"] + "/") for item in manifest["projects"])
    report = evaluate_corpus_source(MANIFEST)
    assert report["status"] == "complete"
    assert len(report["projects"]) == 10
    assert all(item["symbols"]["recall"] == 1.0 for item in report["projects"])
    assert all(item["split"] == "holdout" for item in report["projects"])


def test_external_juliet_build_is_fail_closed_without_native_worker():
    report = validate_corpus_builds(MANIFEST)
    assert report["status"] == "partial"
    assert report["manifest_errors"] == []
    assert len(report["results"]) == 10
    assert all(item["status"] == "unavailable" for item in report["results"])
    assert all(item["reason"] == "compiler_not_found" for item in report["results"])
