import json
from pathlib import Path

from tools.bootstrap_corpus import generate_corpus
from aether_re.corpus import build_c_corpus_msvc, build_c_corpus_wsl, validate_corpus_builds


def test_corpus_build_validation_is_explicit_about_capabilities(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    report = validate_corpus_builds(root / "manifest.json")
    assert report["schema"] == "corpus-build-validation.v1"
    statuses = {item["status"] for item in report["results"]}
    assert "succeeded" in statuses
    assert "unavailable" in statuses or "queued" in statuses
    assert not any(item["status"] == "failed" for item in report["results"])


def test_corpus_validation_fails_closed_on_hash_tamper_and_split_leak(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    first = manifest["projects"][0]
    (root / first["source"]).write_text("tampered = True\n", encoding="utf-8")
    manifest["projects"][1]["split"] = "holdout"  # same family as project 0
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = validate_corpus_builds(manifest_path)
    assert report["status"] == "invalid"
    codes = {item["code"] for item in report["manifest_errors"]}
    assert {"source_hash_mismatch", "family_split_leak"} <= codes
    assert any(item["status"] == "invalid" for item in report["results"])


def test_native_corpus_build_rejects_output_inside_corpus(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    report = build_c_corpus_wsl(root / "manifest.json", root / "native-output")
    assert report["status"] == "invalid"
    assert report["issues"][0]["code"] == "output_inside_corpus"
    assert report["executed_targets"] is False


def test_native_corpus_build_rejects_tampered_manifest_before_worker(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["projects"][0]["authorization"] = "unknown"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = build_c_corpus_wsl(manifest, tmp_path / "native-output")
    assert report["status"] == "invalid"
    assert any(issue["code"] == "authorization_missing" for issue in report["issues"])
    assert report["executed_targets"] is False


def test_native_corpus_build_does_not_turn_manifest_id_into_output_traversal(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["projects"][0]["id"] = "../escaped"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = build_c_corpus_wsl(manifest, tmp_path / "native-output")
    assert report["status"] == "invalid"
    assert report["executed_targets"] is False


def test_native_corpus_build_rejects_unbounded_optimization_profile(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    report = build_c_corpus_wsl(root / "manifest.json", tmp_path / "native-output", opt_level="-Ofast")
    assert report["status"] == "invalid"
    assert report["issues"][0]["code"] == "optimization_invalid"
    assert report["executed_targets"] is False


def test_corpus_manifest_accepts_owned_c_shared_library_but_rejects_unknown_kind(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest = root / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    c_project = next(item for item in data["projects"] if item["language"] == "c")
    c_project["build_kind"] = "shared_library"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = validate_corpus_builds(manifest)
    assert not any(item["code"] == "build_kind_invalid" for item in report["manifest_errors"])
    c_project["build_kind"] = "arbitrary_shell"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = build_c_corpus_wsl(manifest, tmp_path / "build")
    assert report["status"] == "invalid"
    assert any(item["code"] == "build_kind_invalid" for item in report["issues"])
    assert report["executed_targets"] is False


def test_external_authorized_profile_requires_provenance_and_independence(tmp_path: Path):
    from aether_re.corpus import validate_corpus_builds
    import json

    generate_corpus(tmp_path / "corpus")
    manifest_path = tmp_path / "corpus" / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    project = data["projects"][0]
    project["authorization"] = "external_authorized"
    independent_oracle = tmp_path / "corpus" / "independent_oracle_review.json"
    independent_oracle.write_text(json.dumps({"review": "adjudicated outside source"}), encoding="utf-8")
    import hashlib
    project["provenance"] = {
        "origin": "https://authorized.example/project",
        "license": "MIT",
        "authorization_ref": "AUTH-2026-001",
        "oracle_method": "independent reviewer + execution trace",
        "oracle_independent": True,
        "oracle_artifact": independent_oracle.name,
        "oracle_artifact_sha256": hashlib.sha256(independent_oracle.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    report = validate_corpus_builds(manifest_path)
    assert report["manifest_errors"] == []
    assert report["authorization_profiles"] == ["owned_synthetic", "external_authorized", "local_authorized"]

    project.pop("provenance")
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    invalid = validate_corpus_builds(manifest_path)
    assert any(error["code"] == "external_provenance_missing" for error in invalid["manifest_errors"])

    project["provenance"] = {"origin": "x", "license": "MIT", "authorization_ref": "AUTH", "oracle_method": "review", "oracle_independent": True, "oracle_artifact": project["oracle"], "oracle_artifact_sha256": "0" * 64}
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    invalid_separate = validate_corpus_builds(manifest_path)
    assert any(error["code"] == "external_oracle_not_separate" for error in invalid_separate["manifest_errors"])




def test_msvc_worker_rejects_manifest_build_source_escape(tmp_path: Path, monkeypatch):
    import aether_re.corpus as corpus_module

    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest_path = root / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    project = next(item for item in data["projects"] if item["language"] == "c")
    project["build_sources"] = [project["source"], "../outside.c"]
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    compiler = tmp_path / "cl.exe"
    vcvarsall = tmp_path / "vcvarsall.bat"
    compiler.write_text("stub", encoding="utf-8")
    vcvarsall.write_text("@echo off", encoding="utf-8")
    support = tmp_path / "support"
    support.mkdir()
    for name in ("std_testcase.h", "std_testcase_io.h", "io.c", "std_thread.c"):
        (support / name).write_text("", encoding="utf-8")

    monkeypatch.setattr(
        corpus_module,
        "run_bounded",
        lambda *args, **kwargs: {"returncode": 0, "stdout": "Compiler Version 19", "stderr": "", "timed_out": False},
    )
    report = build_c_corpus_msvc(
        manifest_path,
        tmp_path / "msvc-output",
        compiler_path=compiler,
        vcvarsall_path=vcvarsall,
        support_dir=support,
    )
    rejected = next(item for item in report["results"] if item["id"] == project["id"])
    assert rejected["status"] == "invalid"
    assert rejected["reason"] == "build_sources_invalid"
    assert rejected["executed_target"] is False


def test_msvc_corpus_worker_fails_closed_without_explicit_compiler(tmp_path: Path):
    root = tmp_path / "corpus"
    generate_corpus(root)
    report = build_c_corpus_msvc(
        root / "manifest.json",
        tmp_path / "msvc-output",
        compiler_path=tmp_path / "missing-cl.exe",
        vcvarsall_path=tmp_path / "missing-vcvarsall.bat",
        support_dir=tmp_path / "missing-support",
    )
    assert report["status"] == "unavailable"
    assert report["issues"][0]["code"] == "compiler_invalid"
    assert report["executed_targets"] is False


def test_local_authorized_profile_requires_separate_authorization_and_oracle_artifacts(tmp_path: Path):
    import hashlib
    import json

    root = tmp_path / "corpus"
    generate_corpus(root)
    manifest_path = root / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    project = data["projects"][0]
    project["authorization"] = "local_authorized"
    oracle_artifact = root / "oracle_review_local.json"
    oracle_artifact.write_text(json.dumps({"review": "source-project tests and API inventory; independent of bootstrap"}), encoding="utf-8")
    authorization_artifact = root / "authorization_local.json"
    authorization_artifact.write_text(json.dumps({"authorization_ref": "USER_LOCAL_PROJECT_2026", "scope": "static analysis only"}), encoding="utf-8")
    project["provenance"] = {
        "origin": "local user-owned snapshot",
        "license": "user-owned-internal",
        "authorization_ref": "USER_LOCAL_PROJECT_2026",
        "oracle_method": "source-project tests and API inventory",
        "oracle_independent": True,
        "oracle_artifact": oracle_artifact.name,
        "oracle_artifact_sha256": hashlib.sha256(oracle_artifact.read_bytes()).hexdigest(),
        "authorization_artifact": authorization_artifact.name,
        "authorization_artifact_sha256": hashlib.sha256(authorization_artifact.read_bytes()).hexdigest(),
    }
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    report = validate_corpus_builds(manifest_path)
    assert report["manifest_errors"] == []
    assert "local_authorized" in report["authorization_profiles"]

    authorization_artifact.write_text("tampered", encoding="utf-8")
    invalid = validate_corpus_builds(manifest_path)
    assert any(error["code"] == "local_authorization_artifact_hash_mismatch" for error in invalid["manifest_errors"])

