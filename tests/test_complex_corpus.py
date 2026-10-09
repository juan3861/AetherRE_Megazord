"""F03 complex fixtures: integrity and compilation, not independent accuracy."""

import hashlib
import json
from pathlib import Path

import pytest

from aether_re.corpus import validate_corpus_builds
from aether_re.corpus_eval import evaluate_corpus_source
from tools.complex_corpus import generate_complex_corpus


def test_complex_corpus_is_ten_owned_multifile_nonblind_projects(tmp_path: Path):
    root = tmp_path / "complex"
    manifest = generate_complex_corpus(root)
    assert manifest["count"] == 10
    assert len({item["family"] for item in manifest["projects"]}) == 10
    assert {item["split"] for item in manifest["projects"]} == {"development", "calibration"}
    assert all(item["authorization"] == "owned_synthetic" and len(item["artifacts"]) >= 4 for item in manifest["projects"])
    assert "NOT independent ground truth" in manifest["provenance"]
    build = validate_corpus_builds(root / "manifest.json")
    assert build["status"] == "complete"
    assert all(item["compiled_files"] >= 3 for item in build["results"])
    source = evaluate_corpus_source(root / "manifest.json")
    assert source["status"] == "complete"
    assert len(source["projects"]) == 10
    assert source["groups"]["calibration:python"]["relation_recall"] < 1.0
    with pytest.raises(FileExistsError):
        generate_complex_corpus(root)


def test_complex_corpus_rejects_tampered_auxiliary_file_before_scoring(tmp_path: Path):
    root = tmp_path / "complex"
    manifest = generate_complex_corpus(root)
    project = manifest["projects"][0]
    readme = root / project["id"] / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "tamper\n", encoding="utf-8")
    build = validate_corpus_builds(root / "manifest.json")
    source = evaluate_corpus_source(root / "manifest.json")
    assert build["status"] == source["status"] == "invalid"
    assert {error["code"] for error in build["manifest_errors"]} >= {"artifact_hash_mismatch"}
    assert {error["code"] for error in source["errors"]} >= {"artifact_hash_mismatch"}
    assert len(source["projects"]) == 9


def test_complex_corpus_compiles_declared_python_modules_not_just_main(tmp_path: Path):
    root = tmp_path / "complex"
    manifest = generate_complex_corpus(root)
    project = manifest["projects"][0]
    support = root / project["id"] / "src" / "support.py"
    support.write_text("def broken(:\n", encoding="utf-8")
    manifest["projects"][0]["artifacts"] = [
        {**entry, "sha256": hashlib.sha256(support.read_bytes()).hexdigest()} if entry["path"].endswith("support.py") else entry
        for entry in project["artifacts"]
    ]
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    build = validate_corpus_builds(root / "manifest.json")
    assert build["status"] == "partial"
    assert build["manifest_errors"] == []
    assert build["results"][0]["status"] == "failed"
    assert build["results"][0]["compile_failures"]


def test_source_evaluator_fails_closed_when_manifest_hash_is_removed(tmp_path: Path):
    root = tmp_path / "complex"
    manifest = generate_complex_corpus(root)
    manifest["projects"][0].pop("source_sha256")
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    report = evaluate_corpus_source(root / "manifest.json")
    assert report["status"] == "invalid"
    assert any(error["code"] == "source_hash_missing_or_invalid" for error in report["errors"])
    assert len(report["projects"]) == 9
