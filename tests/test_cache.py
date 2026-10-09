from pathlib import Path

import json
import pytest

from aether_re.cache import analysis_cache_key, verify_manifest


def test_cache_key_is_content_and_config_addressed(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"same")
    first = analysis_cache_key(target, config={"deep": True})
    second = analysis_cache_key(target, config={"deep": True})
    third = analysis_cache_key(target, config={"deep": False})
    assert first == second
    assert first != third
    target.write_bytes(b"changed")
    assert analysis_cache_key(target, config={"deep": True}) != first


def test_verify_manifest_detects_tampered_artifact(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    snapshot = run / "input.snapshot"
    snapshot.write_bytes(target.read_bytes())
    artifact = run / "report.json"
    artifact.write_text("{}", encoding="utf-8")
    key = analysis_cache_key(target, config={"deep": True})
    manifest = {"schema": "evidence-manifest.v1", "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(), "metadata": {"cache_key": key}, "files": [{"path": "input.snapshot", "sha256": __import__("hashlib").sha256(snapshot.read_bytes()).hexdigest(), "size": snapshot.stat().st_size}, {"path": "report.json", "sha256": __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()}]}
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_manifest(run / "manifest.json", target, expected_cache_key=key)[0] is True
    artifact.write_text("tampered", encoding="utf-8")
    ok, errors = verify_manifest(run / "manifest.json", target, expected_cache_key=key)
    assert ok is False
    assert "hash_mismatch:report.json" in errors


def test_verify_manifest_rejects_path_escape(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    manifest = {
        "schema": "evidence-manifest.v1",
        "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        "files": [{"path": "../outside.txt", "sha256": __import__("hashlib").sha256(outside.read_bytes()).hexdigest()}],
    }
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    ok, errors = verify_manifest(run / "manifest.json", target)
    assert ok is False
    assert "path_escape:../outside.txt" in errors


def test_verify_manifest_rejects_malformed_file_list(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest = {
        "schema": "evidence-manifest.v1",
        "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        "files": {"report.json": "not-a-list"},
        "metadata": "not-a-dict",
    }
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    ok, errors = verify_manifest(run / "manifest.json", target)
    assert ok is False
    assert "files_invalid" in errors
    assert "metadata_invalid" in errors


def test_verify_manifest_rejects_scalar_manifest_and_duplicate_paths(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest_path = run / "manifest.json"
    manifest_path.write_text(json.dumps(["not-an-object"]), encoding="utf-8")
    ok, errors = verify_manifest(manifest_path, target)
    assert ok is False
    assert errors == ["manifest_not_object"]

    artifact = run / "report.json"
    artifact.write_text("{}", encoding="utf-8")
    digest = __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()
    valid_target = __import__("hashlib").sha256(target.read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "evidence-manifest.v1",
                "target_sha256": valid_target,
                "files": [{"path": "report.json", "sha256": digest}, {"path": "report.json", "sha256": digest}],
            }
        ),
        encoding="utf-8",
    )
    ok, errors = verify_manifest(manifest_path, target)
    assert ok is False
    assert "duplicate_path:report.json" in errors


def test_verify_manifest_rejects_invalid_target_hash(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest = {
        "schema": "evidence-manifest.v1",
        "target_sha256": "not-a-hash",
        "files": [],
    }
    manifest_path = run / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    ok, errors = verify_manifest(manifest_path, target)
    assert ok is False
    assert {"target_hash_invalid", "target_hash_mismatch"} <= set(errors)


def test_verify_manifest_rejects_duplicate_json_keys_at_any_depth(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest_path = run / "manifest.json"
    target_hash = __import__("hashlib").sha256(target.read_bytes()).hexdigest()
    # Duplicate values are deliberately identical: ordinary json.loads silently
    # collapses them, which makes the signed/hashed interpretation ambiguous.
    manifest_path.write_text(
        '{"schema":"evidence-manifest.v1","schema":"evidence-manifest.v1",'
        f'"target_sha256":"{target_hash}","metadata":{{"x":1,"x":1}},"files":[]}}',
        encoding="utf-8",
    )

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert errors == ["manifest_invalid:DuplicateJSONKeyError"]


def test_verify_manifest_rejects_hardlinked_artifact(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "report.json"
    artifact.write_text("trusted", encoding="utf-8")
    external_alias = tmp_path / "external-alias.json"
    try:
        external_alias.hardlink_to(artifact)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    manifest = {
        "schema": "evidence-manifest.v1",
        "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        "files": [{"path": "report.json", "sha256": __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()}],
    }
    manifest_path = run / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert "artifact_hardlink:report.json" in errors


def test_verify_manifest_rejects_reparse_or_symlink_intermediate_component(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    real_dir = run / "real"
    real_dir.mkdir()
    artifact = real_dir / "report.json"
    artifact.write_text("trusted", encoding="utf-8")
    alias_dir = run / "alias"
    try:
        alias_dir.symlink_to(real_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")
    manifest = {
        "schema": "evidence-manifest.v1",
        "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        "files": [{"path": "alias/report.json", "sha256": __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()}],
    }
    manifest_path = run / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert "artifact_reparse:alias/report.json" in errors


def test_verify_manifest_rejects_junction_component(tmp_path: Path, monkeypatch):
    from aether_re import cache

    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    junction = run / "junction"
    junction.mkdir()
    artifact = junction / "report.json"
    artifact.write_text("trusted", encoding="utf-8")
    manifest = {
        "schema": "evidence-manifest.v1",
        "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        "files": [{"path": "junction/report.json", "sha256": __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()}],
    }
    manifest_path = run / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(cache.os.path, "isjunction", lambda path: Path(path) == junction, raising=False)

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert "artifact_reparse:junction/report.json" in errors


def test_verify_manifest_rejects_invalid_utf8_without_raising(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest_path = run / "manifest.json"
    manifest_path.write_bytes(b"\xff\xfe")

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert errors == ["manifest_invalid:UnicodeDecodeError"]


def test_verify_manifest_rejects_excessive_json_nesting_without_raising(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest_path = run / "manifest.json"
    manifest_path.write_text('{"metadata":' + '{"x":' * 10000 + "0" + "}" * 10000 + "}", encoding="utf-8")

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert errors == ["manifest_invalid:RecursionError"]


@pytest.mark.parametrize("metadata", [None, [], "malformed", 7])
def test_verify_manifest_rejects_null_or_malformed_metadata(tmp_path: Path, metadata):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest_path = run / "manifest.json"
    manifest_path.write_text(
        json.dumps({"schema": "evidence-manifest.v1", "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(), "metadata": metadata, "files": []}),
        encoding="utf-8",
    )

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert "metadata_invalid" in errors


def test_verify_manifest_rejects_internally_consistent_snapshot_for_different_target(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"actual target")
    run = tmp_path / "run"
    run.mkdir()
    snapshot = run / "input.snapshot"
    snapshot.write_bytes(b"different but consistently manifested")
    manifest_path = run / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "schema": "evidence-manifest.v1",
            "target_sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
            "files": [{"path": "input.snapshot", "sha256": __import__("hashlib").sha256(snapshot.read_bytes()).hexdigest(), "size": snapshot.stat().st_size}],
        }),
        encoding="utf-8",
    )

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert "input_snapshot_target_hash_mismatch" in errors


def test_verify_manifest_requires_input_snapshot_and_real_size(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    snapshot = run / "input.snapshot"
    snapshot.write_bytes(target.read_bytes())
    target_hash = __import__("hashlib").sha256(target.read_bytes()).hexdigest()
    manifest_path = run / "manifest.json"

    manifest_path.write_text(json.dumps({"schema": "evidence-manifest.v1", "target_sha256": target_hash, "files": []}), encoding="utf-8")
    ok, errors = verify_manifest(manifest_path, target)
    assert ok is False
    assert "input_snapshot_missing" in errors

    manifest_path.write_text(
        json.dumps({"schema": "evidence-manifest.v1", "target_sha256": target_hash, "files": [{"path": "input.snapshot", "sha256": target_hash}]}),
        encoding="utf-8",
    )
    ok, errors = verify_manifest(manifest_path, target)
    assert ok is False
    assert "input_snapshot_size_invalid" in errors


def test_verify_manifest_rejects_manifest_above_byte_limit_without_parsing(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    manifest_path = run / "manifest.json"
    manifest_path.write_bytes(b" " * (16 * 1024 * 1024 + 1))

    ok, errors = verify_manifest(manifest_path, target)

    assert ok is False
    assert errors == ["manifest_size_limit_exceeded"]
