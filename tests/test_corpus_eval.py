import json
import hashlib
import os
import shutil
import pytest
from pathlib import Path

from aether_re.corpus_eval import _candidate_function_names, _measured_relation_scores, _pdb_function_names_for_sources, evaluate_corpus_binaries, evaluate_corpus_source, write_corpus_evaluation
from tools.bootstrap_corpus import generate_corpus


def test_corpus_source_evaluation_is_explicitly_synthetic_and_split_aware(tmp_path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    report = evaluate_corpus_source(root / "manifest.json")
    assert report["schema"] == "corpus-source-evaluation.v1"
    assert report["status"] == "complete"
    assert len(report["projects"]) == 20
    assert set(report["groups"]) == {"development:python", "development:c", "calibration:python", "calibration:c", "holdout:python", "holdout:c"}
    assert "não independente" in report["oracle_provenance"]
    # The primary relation metric is restricted to unique local function edges;
    # unresolved/module-level candidates stay visible in the audit companion.
    holdout = [item for item in report["projects"] if item["split"] == "holdout"]
    assert all(item["relations"]["recall"] == 1.0 for item in holdout)
    assert all("relation_candidates" in item for item in report["projects"])
    assert all("compile_context" in item for item in report["projects"])
    out = tmp_path / "evaluation.json"
    write_corpus_evaluation(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == report["schema"]


def test_measured_relation_score_keeps_count_and_samples_separate():
    result = _measured_relation_scores({("main", "helper")}, {"method": "static", "unique_relations": [{"caller": "main", "callee": "helper"}, {"caller": "main", "callee": "external"}]})
    assert result["observed"] == 2
    assert result["true_positive"] == 1
    assert result["false_positive"] == 1
    assert result["observed_relations"] == [["main", "external"], ["main", "helper"]]


def test_symbol_candidate_metric_excludes_undefined_objects_and_zero_sized_runtime_stubs():
    structure = {
        "format": "ELF64",
        "symbols": [
            {"name": "clamp", "type": 2, "size": 42, "section_index": 8},
            {"name": "exported_theta", "type": 2, "size": 27, "section_index": 8},
            {"name": "register_tm_clones", "type": 2, "size": 0, "section_index": 8},
            {"name": "__cxa_finalize", "type": 0, "size": 0, "section_index": 0},
            {"name": "completed.0", "type": 1, "size": 1, "section_index": 19},
        ],
    }
    assert _candidate_function_names(structure) == {"clamp", "exported_theta"}


def test_pdb_source_metric_uses_debug_provenance_not_oracle_name_intersection():
    report = {
        "symbols": [
            {"name": "owned_main", "source_file": r"D:\repo\sample\src\main.c", "is_static": False},
            {"name": "private_helper", "source_file": r"D:\repo\sample\src\main.c", "is_static": True},
            {"name": "support_noise", "source_file": r"D:\repo\sample\support\io.c"},
            {"name": "crt_noise", "source_file": r"D:\toolchain\crt\startup.cpp"},
            {"name": "unattributed"},
        ]
    }

    assert _pdb_function_names_for_sources(report, ["sample/src/main.c"], external_only=True) == {"owned_main"}


def test_corpus_binary_evaluation_verifies_hash_and_keeps_relations_unmeasured(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    source = root / "src" / "main.c"
    source.parent.mkdir()
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    oracle = root / "oracle.json"
    oracle.write_text(json.dumps({"expected_symbols": ["getRegisterPointerVar"], "expected_relations": [["main", "helper"]]}), encoding="utf-8")
    ghidra_home = os.environ.get("GHIDRA_HOME")
    fixture = (
        Path(ghidra_home)
        / "docs"
        / "GhidraClass"
        / "ExerciseFiles"
        / "Advanced"
        / "globalRegVars.so"
        if ghidra_home
        else None
    )
    if fixture is None or not fixture.is_file():
        pytest.skip("fixture ELF do Ghidra ausente; configure GHIDRA_HOME")
    output_root = tmp_path / "build"
    output_root.mkdir()
    binary = output_root / "sample.elf"
    shutil.copyfile(fixture, binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    oracle_digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"projects": [{"id": "sample_c", "language": "c", "family": "fixture", "split": "holdout", "source": "src/main.c", "source_sha256": source_digest, "oracle": "oracle.json", "oracle_sha256": oracle_digest}]}), encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    build = output_root / "build_report.json"
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "manifest_sha256": manifest_digest, "output_dir": str(output_root), "results": [{"id": "sample_c", "status": "succeeded", "output": str(binary), "output_sha256": digest, "source_sha256": source_digest}]}), encoding="utf-8")
    report = evaluate_corpus_binaries(manifest, build)
    assert report["status"] == "complete"
    assert report["projects"][0]["symbols"]["recall"] == 1.0
    assert "symbol_candidates" in report["projects"][0]
    assert report["projects"][0]["relations"]["status"] == "not_measured"
    assert report["executed_targets"] is False


def test_corpus_binary_evaluation_rejects_output_hash_tamper(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "manifest.json").write_text(json.dumps({"projects": []}), encoding="utf-8")
    build = tmp_path / "build.json"
    build.write_text(json.dumps({"schema": "wrong", "output_dir": str(tmp_path), "results": []}), encoding="utf-8")
    report = evaluate_corpus_binaries(root / "manifest.json", build)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "build_report_invalid"


def test_corpus_binary_evaluation_rejects_duplicate_manifest_id_before_scoring(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"projects": [{"id": "same", "language": "c"}, {"id": "same", "language": "c"}]}), encoding="utf-8")
    build = tmp_path / "build.json"
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "results": []}), encoding="utf-8")
    report = evaluate_corpus_binaries(manifest, build)
    assert report["status"] == "invalid"
    assert report["errors"] == [{"code": "duplicate_manifest_project_id", "id": "same"}]


def test_corpus_binary_evaluation_rejects_invalid_auxiliary_artifact_without_crashing(tmp_path):
    root = tmp_path / "corpus"
    root.mkdir()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"projects": [{"id": "sample", "language": "c", "artifacts": "not-a-list"}]}), encoding="utf-8")
    build = tmp_path / "build.json"
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "results": []}), encoding="utf-8")

    report = evaluate_corpus_binaries(manifest, build)

    assert report["status"] == "invalid"
    assert report["errors"] == [{"code": "artifacts_invalid", "id": "sample"}]


def test_corpus_binary_evaluation_rejects_source_tamper_after_build(tmp_path: Path):
    root = tmp_path / "corpus"
    root.mkdir()
    source = root / "main.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    oracle = root / "oracle.json"
    oracle.write_text(json.dumps({"expected_symbols": [], "expected_relations": []}), encoding="utf-8")
    output_root = tmp_path / "build"
    output_root.mkdir()
    binary = output_root / "sample.elf"
    binary.write_bytes(b"not-an-elf")
    manifest = root / "manifest.json"
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    oracle_digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
    manifest.write_text(json.dumps({"projects": [{"id": "sample_c", "language": "c", "family": "fixture", "split": "holdout", "source": "main.c", "source_sha256": source_digest, "oracle": "oracle.json", "oracle_sha256": oracle_digest}]}), encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    original_source_digest = source_digest
    source.write_text("int main(void) { return 1; }\n", encoding="utf-8")
    build = output_root / "build_report.json"
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "manifest_sha256": manifest_digest, "output_dir": str(output_root), "results": [{"id": "sample_c", "status": "succeeded", "output": str(binary), "output_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "source_sha256": original_source_digest}]}), encoding="utf-8")
    report = evaluate_corpus_binaries(manifest, build)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "source_hash_mismatch"


def test_corpus_binary_evaluation_rejects_symlink_output_root(tmp_path: Path):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "manifest.json").write_text(json.dumps({"projects": []}), encoding="utf-8")
    real_output = tmp_path / "real-output"
    real_output.mkdir()
    linked_output = tmp_path / "linked-output"
    try:
        linked_output.symlink_to(real_output, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")
    build = tmp_path / "build.json"
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "manifest_sha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(), "output_dir": str(linked_output), "results": []}), encoding="utf-8")
    report = evaluate_corpus_binaries(root / "manifest.json", build)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "output_root_invalid"


def test_corpus_binary_evaluation_rejects_manifest_tamper_after_build(tmp_path: Path):
    root = tmp_path / "corpus"
    root.mkdir()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"projects": []}), encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    manifest.write_text(json.dumps({"projects": [], "tampered": True}), encoding="utf-8")
    output_root = tmp_path / "build"
    output_root.mkdir()
    build = output_root / "build.json"
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "manifest_sha256": manifest_digest, "output_dir": str(output_root), "results": []}), encoding="utf-8")
    report = evaluate_corpus_binaries(manifest, build)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "manifest_hash_mismatch"


def test_corpus_source_evaluation_rejects_manifest_source_traversal(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["projects"][0]["source"] = "../outside.c"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = evaluate_corpus_source(manifest)
    assert report["status"] == "invalid"
    assert any(error["code"] == "source_invalid" for error in report["errors"])


def test_corpus_source_evaluation_does_not_treat_empty_manifest_as_complete(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"projects": []}), encoding="utf-8")
    report = evaluate_corpus_source(manifest)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "manifest_invalid"


def test_corpus_source_evaluation_rejects_duplicate_project_ids(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["projects"][1]["id"] = data["projects"][0]["id"]
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = evaluate_corpus_source(manifest)
    assert report["status"] == "invalid"
    assert any(error["code"] == "duplicate_project_id" for error in report["errors"])


def test_corpus_source_evaluation_rejects_source_oracle_hash_tamper(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    first = data["projects"][0]
    (root / first["source"]).write_text((root / first["source"]).read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    report = evaluate_corpus_source(manifest)
    assert report["status"] == "invalid"
    assert any(error["code"] == "source_hash_mismatch" for error in report["errors"])


def test_corpus_binary_evaluation_rejects_duplicate_build_results(tmp_path: Path):
    root = tmp_path / "corpus"
    root.mkdir()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"projects": []}), encoding="utf-8")
    output_root = tmp_path / "build"
    output_root.mkdir()
    build = output_root / "build.json"
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "manifest_sha256": manifest_digest, "output_dir": str(output_root), "results": [{"id": "same", "status": "failed"}, {"id": "same", "status": "failed"}]}), encoding="utf-8")
    report = evaluate_corpus_binaries(manifest, build)
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "duplicate_build_result_id"


def test_corpus_binary_evaluation_requires_both_dia_paths(tmp_path: Path):
    root = tmp_path / "corpus"
    root.mkdir()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"projects": []}), encoding="utf-8")
    build = tmp_path / "build.json"
    build.write_text(json.dumps({"schema": "corpus-native-build.v1", "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "output_dir": str(tmp_path), "results": []}), encoding="utf-8")
    report = evaluate_corpus_binaries(manifest, build, dia_helper=tmp_path / "dia.exe")
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "pdb_dia_configuration_incomplete"
    assert report["executed_targets"] is False


def test_pdb_reader_fails_closed_without_explicit_tools(tmp_path: Path):
    from aether_re.pdb_dia import extract_pdb_symbols

    pdb = tmp_path / "sample.pdb"
    pdb.write_bytes(b"not-a-pdb")
    report = extract_pdb_symbols(pdb, helper_path=tmp_path / "missing-helper.exe", dia_dll=tmp_path / "missing-msdia140.dll")
    assert report["status"] == "unavailable"
    assert report["code"] == "helper_invalid"
    assert report["executed_target"] is False
