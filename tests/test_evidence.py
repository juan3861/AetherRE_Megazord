import json
import errno
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest

from aether_re.evidence import SnapshotCancelled, build_manifest, create_verified_snapshot, sha256_file, write_manifest_atomic


def test_manifest_hashes_artifacts_and_target(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    artifact = run_dir / "artifact.txt"
    artifact.write_text("evidence", encoding="utf-8")
    manifest = build_manifest(target, run_dir, metadata={"run": "unit"})
    assert manifest["schema"] == "evidence-manifest.v1"
    assert manifest["target_sha256"] == sha256_file(target)
    assert {item["path"] for item in manifest["files"]} == {"artifact.txt"}


def test_manifest_excludes_ephemeral_angr_rtdb_but_keeps_worker_report(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "angr_report.json").write_text('{"status":"complete"}', encoding="utf-8")
    volatile = run_dir / "intake" / "objects" / "sample_angr_rtdb"
    volatile.mkdir(parents=True)
    (volatile / "data.mdb").write_bytes(b"mutable analysis cache")

    manifest = build_manifest(target, run_dir)

    paths = {item["path"] for item in manifest["files"]}
    assert "angr_report.json" in paths
    assert not any("_angr_rtdb" in path for path in paths)


def test_manifest_write_is_atomic_and_valid_json(tmp_path: Path):
    path = tmp_path / "manifest.json"
    write_manifest_atomic({"schema": "test", "ok": True}, path)
    assert json.loads(path.read_text(encoding="utf-8"))["ok"] is True
    assert not list(tmp_path.glob(".manifest.json.*.tmp"))


def test_create_verified_snapshot_copies_and_hashes(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"stable")
    destination = tmp_path / "run" / "input.snapshot"
    observed = create_verified_snapshot(source, destination)
    assert destination.read_bytes() == b"stable"
    assert observed == sha256_file(source)


def test_create_verified_snapshot_rejects_mismatch(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"stable")
    destination = tmp_path / "run" / "input.snapshot"

    try:
        create_verified_snapshot(source, destination, expected_sha256="0" * 64)
    except ValueError as exc:
        assert str(exc) == "source_changed_during_snapshot"
    else:
        raise AssertionError("snapshot mismatch was accepted")
    assert not destination.exists()


def test_snapshot_is_create_only_and_does_not_overwrite(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"new")
    destination = tmp_path / "existing.bin"
    destination.write_bytes(b"original")
    try:
        create_verified_snapshot(source, destination)
    except ValueError as exc:
        assert str(exc) == "snapshot_destination_not_create_only"
    else:
        raise AssertionError("existing snapshot was overwritten")
    assert destination.read_bytes() == b"original"


def test_snapshot_rejects_generic_reparse_point_in_source_path(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"content")
    destination = tmp_path / "run" / "input.snapshot"
    monkeypatch.setattr(
        "aether_re.evidence._is_link_or_reparse_point",
        lambda path: Path(path) == source,
    )

    with pytest.raises(ValueError, match="source_must_be_regular_file"):
        create_verified_snapshot(source, destination)

    assert not destination.exists()


def test_snapshot_budget_rejects_growth_and_leaves_no_partial_file(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abcdef")
    destination = tmp_path / "run" / "input.snapshot"
    try:
        create_verified_snapshot(source, destination, max_bytes=3)
    except ValueError as exc:
        assert str(exc) == "source_size_budget_exceeded"
    else:
        raise AssertionError("oversize source accepted")
    assert not destination.exists()


def test_snapshot_racing_publishers_cannot_overwrite_each_other(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"proof" * 1024)
    destination = tmp_path / "run" / "input.snapshot"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _snapshot_result(source, destination), range(2)))
    assert sorted(results) == ["created", "snapshot_destination_not_create_only"]
    assert destination.read_bytes() == source.read_bytes()
    assert not list(destination.parent.glob(".input.snapshot.*.tmp"))


def _snapshot_result(source: Path, destination: Path) -> str:
    try:
        create_verified_snapshot(source, destination)
        return "created"
    except ValueError as exc:
        return str(exc)


def test_snapshot_fsync_failure_leaves_no_published_input(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"proof")
    destination = tmp_path / "run" / "input.snapshot"
    def fail_fsync(_fd):
        raise OSError("simulated_disk_failure")
    monkeypatch.setattr("aether_re.evidence.os.fsync", fail_fsync)
    with pytest.raises(OSError, match="simulated_disk_failure"):
        create_verified_snapshot(source, destination)
    assert not destination.exists()
    assert not list(destination.parent.glob(".input.snapshot.*.tmp"))


def test_snapshot_simulated_disk_full_leaves_no_partial_input_and_recovers(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"proof" * 4096)
    destination = tmp_path / "run" / "input.snapshot"
    real_fdopen = __import__("aether_re.evidence", fromlist=["os"]).os.fdopen

    class FailingWriter:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            return self.handle.__exit__(*args)

        def write(self, _chunk):
            raise OSError(errno.ENOSPC, "simulated disk full")

        def flush(self):
            return self.handle.flush()

        def fileno(self):
            return self.handle.fileno()

    monkeypatch.setattr("aether_re.evidence.os.fdopen", lambda fd, *args, **kwargs: FailingWriter(real_fdopen(fd, *args, **kwargs)))
    with pytest.raises(OSError) as failure:
        create_verified_snapshot(source, destination)
    assert failure.value.errno == errno.ENOSPC
    assert not destination.exists()
    assert not list(destination.parent.glob(".input.snapshot.*.tmp"))
    monkeypatch.setattr("aether_re.evidence.os.fdopen", real_fdopen)
    assert create_verified_snapshot(source, destination) == sha256_file(source)


def test_snapshot_cancellation_is_fail_closed_and_retryable(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"proof" * 4096)
    destination = tmp_path / "run" / "input.snapshot"
    calls = 0

    def cancel_after_start():
        nonlocal calls
        calls += 1
        return calls >= 2

    with pytest.raises(SnapshotCancelled, match="snapshot_cancelled"):
        create_verified_snapshot(source, destination, cancel_check=cancel_after_start)
    assert not destination.exists()
    assert not list(destination.parent.glob(".input.snapshot.*.tmp"))
    assert create_verified_snapshot(source, destination) == sha256_file(source)


def test_manifest_rejects_missing_or_non_directory_inputs(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run_file = tmp_path / "run.txt"
    run_file.write_text("not a directory", encoding="utf-8")
    try:
        build_manifest(target, run_file)
    except ValueError as exc:
        assert str(exc) == "run_dir_must_be_regular_directory"
    else:
        raise AssertionError("file run directory was accepted")
    try:
        build_manifest(tmp_path / "missing.bin", tmp_path)
    except ValueError as exc:
        assert str(exc) == "target_must_be_regular_file"
    else:
        raise AssertionError("missing target was accepted")


def test_manifest_rejects_non_serializable_metadata(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    try:
        build_manifest(target, run, metadata={"bad": object()})
    except ValueError as exc:
        assert str(exc) == "metadata_not_serializable"
    else:
        raise AssertionError("non-serializable metadata was accepted")


def test_manifest_rejects_hardlinked_artifacts(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "evidence.txt"
    artifact.write_text("evidence", encoding="utf-8")
    alias = tmp_path / "outside-alias.txt"
    alias.hardlink_to(artifact)

    with pytest.raises(ValueError, match="hardlinked_artifact_not_allowed"):
        build_manifest(target, run)


def test_manifest_rejects_hardlinked_target(tmp_path: Path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    target_alias = tmp_path / "target-alias.bin"
    target_alias.hardlink_to(target)
    run = tmp_path / "run"
    run.mkdir()

    with pytest.raises(ValueError, match="target_hardlink_not_allowed"):
        build_manifest(target, run)


def test_manifest_rejects_junction_component(tmp_path: Path, monkeypatch):
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    run = tmp_path / "run"
    run.mkdir()
    nested = run / "linked"
    nested.mkdir()
    (nested / "evidence.txt").write_text("evidence", encoding="utf-8")

    real_is_junction = getattr(Path, "is_junction", None)
    if real_is_junction is None:
        pytest.skip("Path.is_junction is unavailable on this Python")
    monkeypatch.setattr(Path, "is_junction", lambda path: path == nested)

    with pytest.raises(ValueError, match="linked_artifact_not_allowed"):
        build_manifest(target, run)
