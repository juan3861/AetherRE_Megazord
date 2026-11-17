import json
from pathlib import Path
import pytest

from aether_re.evidence import build_manifest, write_manifest_atomic, sha256_file
from aether_re.homologation import audit_run_package
from aether_re.lock import RunLock


def _package(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"MZsynthetic")
    run = tmp_path / "run"
    run.mkdir()
    (run / "input.snapshot").write_bytes(target.read_bytes())
    (run / "pseudo_source.c").write_text("/* pseudo */\n", encoding="utf-8")
    (run / "findings.md").write_text("# findings\n", encoding="utf-8")
    (run / "strings.txt").write_text("hello\n", encoding="utf-8")
    (run / "report.json").write_text(json.dumps({"target_sha256": sha256_file(target)}), encoding="utf-8")
    (run / "checkpoint.json").write_text(json.dumps({"schema": "analysis-checkpoint.v1", "status": "succeeded", "stage": "persisted"}), encoding="utf-8")
    write_manifest_atomic(build_manifest(target, run, metadata={"cache_key": "test"}), run / "manifest.json")
    return target, run


def test_homologation_accepts_intact_package_and_rejects_tamper(tmp_path):
    target, run = _package(tmp_path)
    report = audit_run_package(run, target=target)
    assert report["status"] == "pass"
    (run / "strings.txt").write_text("tampered\n", encoding="utf-8")
    rejected = audit_run_package(run, target=target)
    assert rejected["status"] == "fail"
    assert any(item["code"] == "hash_mismatch" for item in rejected["issues"])


def test_homologation_rejects_active_lock_and_manifest_escape(tmp_path):
    target, run = _package(tmp_path)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"].append({"path": "../outside", "sha256": "0" * 64})
    (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run / "run.lock").write_text("active", encoding="utf-8")
    report = audit_run_package(run, target=target)
    codes = {item["code"] for item in report["issues"]}
    assert report["status"] == "fail"
    assert {"path_escape", "run_lock_present"} <= codes


def test_homologation_rejects_duplicate_or_missing_manifest_entries(tmp_path):
    target, run = _package(tmp_path)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append(dict(manifest["files"][0]))
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    duplicate = audit_run_package(run, target=target)
    assert duplicate["status"] == "fail"
    assert any(item["code"] == "manifest_duplicate_path" for item in duplicate["issues"])

    missing_root = tmp_path / "missing"
    missing_root.mkdir()
    target, run = _package(missing_root)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"] = [item for item in manifest["files"] if item.get("path") != "findings.md"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    missing = audit_run_package(run, target=target)
    assert missing["status"] == "fail"
    assert any(item["code"] == "manifest_required_artifact_missing" for item in missing["issues"])


def test_homologation_rejects_unlisted_regular_artifact(tmp_path):
    target, run = _package(tmp_path)
    (run / "unexpected.bin").write_bytes(b"not in manifest")
    report = audit_run_package(run, target=target)
    assert report["status"] == "fail"
    assert any(item["code"] == "manifest_unlisted_artifact" for item in report["issues"])


def test_homologation_rejects_duplicate_json_keys(tmp_path):
    target, run = _package(tmp_path)
    manifest_path = run / "manifest.json"
    body = manifest_path.read_text(encoding="utf-8")
    body = body.replace('"schema": "evidence-manifest.v1",', '"schema": "evidence-manifest.v1",\n  "schema": "evidence-manifest.v1",', 1)
    manifest_path.write_text(body, encoding="utf-8")

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "json_duplicate_key" for item in report["issues"])


def test_homologation_rejects_nested_control_named_unlisted_artifact(tmp_path):
    target, run = _package(tmp_path)
    nested = run / "comparative"
    nested.mkdir()
    (nested / "manifest.json").write_text('{"kind":"nested"}', encoding="utf-8")
    (nested / "run.lock").write_text("not a root run lock", encoding="utf-8")

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    unlisted = {item["path"] for item in report["issues"] if item["code"] == "manifest_unlisted_artifact"}
    assert {"comparative/manifest.json", "comparative/run.lock"} <= unlisted


def test_homologation_accepts_manifested_nested_control_named_artifacts(tmp_path):
    target, run = _package(tmp_path)
    nested = run / "comparative"
    nested.mkdir()
    (nested / "manifest.json").write_text('{"kind":"nested"}', encoding="utf-8")
    (nested / "run.lock").write_text("not a root run lock", encoding="utf-8")
    write_manifest_atomic(build_manifest(target, run, metadata={"cache_key": "test"}), run / "manifest.json")

    report = audit_run_package(run, target=target)

    assert report["status"] == "pass"


def test_homologation_rejects_hardlinked_artifact(tmp_path):
    target, run = _package(tmp_path)
    manifest = (run / "manifest.json").read_bytes()
    outside_alias = tmp_path / "outside-strings.txt"
    outside_alias.hardlink_to(run / "strings.txt")
    (run / "manifest.json").write_bytes(manifest)

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "artifact_hardlink" for item in report["issues"])


def test_homologation_rejects_junction_component(tmp_path, monkeypatch):
    target, run = _package(tmp_path)
    nested = run / "linked"
    nested.mkdir()
    (nested / "evidence.txt").write_text("evidence", encoding="utf-8")
    write_manifest_atomic(build_manifest(target, run, metadata={"cache_key": "test"}), run / "manifest.json")

    if not hasattr(Path, "is_junction"):
        pytest.skip("Path.is_junction is unavailable on this Python")
    monkeypatch.setattr(Path, "is_junction", lambda path: path == nested)

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "artifact_symlink" for item in report["issues"])


@pytest.mark.parametrize(
    ("payload", "expected_detail"),
    [
        (b"\xff\xfe", "UnicodeDecodeError"),
        (b'{"schema":"evidence-manifest.v1","metadata":' + b'{"x":' * 10000 + b"0" + b"}" * 10000 + b',"files":[]}', "RecursionError"),
    ],
    ids=["invalid-utf8", "deep-nesting"],
)
def test_homologation_rejects_unreadable_or_deep_json_without_raising(tmp_path, payload, expected_detail):
    target, run = _package(tmp_path)
    (run / "manifest.json").write_bytes(payload)

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "json_invalid" and item["detail"] == expected_detail for item in report["issues"])


@pytest.mark.parametrize("metadata", [None, [], "malformed", 7])
def test_homologation_rejects_null_or_malformed_manifest_metadata(tmp_path, metadata):
    target, run = _package(tmp_path)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"] = metadata
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "manifest_metadata_invalid" for item in report["issues"])


def test_homologation_accepts_active_lock_only_for_matching_owned_run_lock(tmp_path):
    target, run = _package(tmp_path)
    lock = RunLock(run / "run.lock")
    lock.acquire()

    try:
        report = audit_run_package(run, target=target, active_lock=lock)
    finally:
        assert lock.release() is True

    assert report["status"] == "pass"
    assert report["run_lock_state"] == "expected_active"
    assert any(check["name"] == "active_lock_expected" and check["verified"] is True for check in report["checks"])
    assert not any(check["name"] == "lock_released" for check in report["checks"])
    assert not any(warning["code"] == "run_lock_owner_not_independently_verified" for warning in report["warnings"])


def test_homologation_rejects_active_lock_without_owned_token(tmp_path):
    target, run = _package(tmp_path)
    (run / "run.lock").write_text('{"pid": 1, "owner_token": "fake"}', encoding="utf-8")
    unowned = RunLock(run / "run.lock")

    report = audit_run_package(run, target=target, active_lock=unowned)

    assert report["status"] == "fail"
    assert report["run_lock_state"] == "active_rejected"
    assert any(item["code"] == "run_lock_owner_mismatch" for item in report["issues"])


@pytest.mark.parametrize("tampered_payload", [{"pid": 1}, {"pid": 1, "owner_token": "different"}])
def test_homologation_rejects_missing_or_divergent_active_lock_owner_token(tmp_path, tampered_payload):
    target, run = _package(tmp_path)
    lock = RunLock(run / "run.lock")
    lock.acquire()
    original = lock.path.read_bytes()
    lock.path.write_text(json.dumps(tampered_payload), encoding="utf-8")

    try:
        report = audit_run_package(run, target=target, active_lock=lock)
        assert report["status"] == "fail"
        assert report["run_lock_state"] == "active_rejected"
        assert any(item["code"] == "run_lock_owner_mismatch" for item in report["issues"])
    finally:
        lock.path.write_bytes(original)
        assert lock.release() is True


def test_homologation_rejects_internally_consistent_snapshot_for_different_target(tmp_path):
    target, run = _package(tmp_path)
    snapshot = run / "input.snapshot"
    snapshot.write_bytes(b"different but consistently manifested")
    write_manifest_atomic(build_manifest(target, run, metadata={"cache_key": "test"}), run / "manifest.json")

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "snapshot_target_hash_mismatch" for item in report["issues"])


def test_homologation_rejects_target_hardlink(tmp_path):
    target, run = _package(tmp_path)
    alias = tmp_path / "target-alias.bin"
    try:
        alias.hardlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    report = audit_run_package(run, target=alias)

    assert report["status"] == "fail"
    assert any(item["code"] == "target_hardlink" for item in report["issues"])


def test_homologation_rejects_manifest_above_byte_limit_without_parsing(tmp_path):
    target, run = _package(tmp_path)
    (run / "manifest.json").write_bytes(b" " * (16 * 1024 * 1024 + 1))

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "manifest_size_limit_exceeded" for item in report["issues"])


def test_homologation_requires_manifested_snapshot_size(tmp_path):
    target, run = _package(tmp_path)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    snapshot_entry = next(entry for entry in manifest["files"] if entry.get("path") == "input.snapshot")
    snapshot_entry.pop("size")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "snapshot_size_invalid" for item in report["issues"])


def test_homologation_rejects_reparse_target_path_before_hashing(tmp_path, monkeypatch):
    target, run = _package(tmp_path)
    monkeypatch.setattr(
        "aether_re.homologation._has_link_or_reparse_component",
        lambda path: Path(path) == target,
    )

    report = audit_run_package(run, target=target)

    assert report["status"] == "fail"
    assert any(item["code"] == "target_link" for item in report["issues"])


def test_homologate_cli_verifies_released_and_active_locks(tmp_path, monkeypatch):
    import sys
    import megazord

    target, run = _package(tmp_path)
    out = tmp_path / "homologation.json"

    monkeypatch.setattr(sys, "argv", ["megazord.py", "homologate", str(run), "--target", str(target), "--out", str(out)])
    assert megazord.main() == 0
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "pass"

    lock = RunLock(run / "run.lock")
    lock.acquire()
    try:
        monkeypatch.setattr(sys, "argv", ["megazord.py", "homologate", str(run), "--target", str(target), "--out", str(out)])
        assert megazord.main() == 2
        assert any(i["code"] == "run_lock_present" for i in json.loads(out.read_text(encoding="utf-8"))["issues"])

        monkeypatch.setattr(
            sys,
            "argv",
            ["megazord.py", "homologate", str(run), "--target", str(target), "--active-lock-token", lock._owner_token, "--out", str(out)],
        )
        assert megazord.main() == 0
        active_report = json.loads(out.read_text(encoding="utf-8"))
        assert active_report["status"] == "pass"
        assert active_report["run_lock_state"] == "expected_active"

        monkeypatch.setattr(
            sys,
            "argv",
            ["megazord.py", "homologate", str(run), "--target", str(target), "--active-lock-token", "wrong-token", "--out", str(out)],
        )
        assert megazord.main() == 2
        assert any(i["code"] == "run_lock_owner_mismatch" for i in json.loads(out.read_text(encoding="utf-8"))["issues"])
    finally:
        assert lock.release() is True

