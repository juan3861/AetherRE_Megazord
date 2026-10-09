from concurrent.futures import ThreadPoolExecutor
import errno
import json
import stat
from pathlib import Path

import pytest

from aether_re.project_inventory import inventory_project
from aether_re.project_snapshot import create_project_snapshot, verify_project_snapshot
from aether_re.evidence import SnapshotCancelled


def test_project_snapshot_copies_scoped_files_and_detects_tamper(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("value = 1\n", encoding="utf-8")
    (source / "vendor").mkdir()
    (source / "vendor" / "ignored.py").write_text("secret = 1\n", encoding="utf-8")
    destination = tmp_path / "snapshot"
    created = create_project_snapshot(source, destination)
    assert created["status"] == "created"
    assert created["scope"] == "partial"
    assert created["file_count"] == 1
    assert (destination / "files" / "main.py").read_bytes() == (source / "main.py").read_bytes()
    assert not (destination / "files" / "vendor").exists()
    assert verify_project_snapshot(destination, expected_manifest_sha256=created["manifest_sha256"])["status"] == "pass"
    (destination / "files" / "main.py").write_text("value = 2\n", encoding="utf-8")
    checked = verify_project_snapshot(destination, expected_manifest_sha256=created["manifest_sha256"])
    assert checked["status"] == "fail"
    assert any(item["code"] == "snapshot_hash_mismatch" for item in checked["issues"])


def test_project_snapshot_rejects_live_source_change_and_cleans_stage(tmp_path: Path, monkeypatch):
    source = tmp_path / "project"
    source.mkdir()
    target = source / "main.py"
    target.write_text("value = 1\n", encoding="utf-8")
    destination = tmp_path / "snapshot"
    calls = 0
    def changing_inventory(root, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            target.write_text("value = 2\n", encoding="utf-8")
        return inventory_project(root, **kwargs)
    monkeypatch.setattr("aether_re.project_snapshot.inventory_project", changing_inventory)
    with pytest.raises(ValueError, match="source_changed_during_project_snapshot"):
        create_project_snapshot(source, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".snapshot.*.stage"))


def test_project_snapshot_create_only_and_manifest_hash(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("pass\n", encoding="utf-8")
    destination = tmp_path / "snapshot"
    created = create_project_snapshot(source, destination)
    with pytest.raises(ValueError, match="snapshot_destination_not_create_only"):
        create_project_snapshot(source, destination)
    bad_hash = "0" * 64
    assert bad_hash != created["manifest_sha256"]
    checked = verify_project_snapshot(destination, expected_manifest_sha256=bad_hash)
    assert checked["status"] == "fail"
    assert any(item["code"] == "manifest_hash_mismatch" for item in checked["issues"])


def test_project_snapshot_rejects_destination_inside_source(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="snapshot_destination_inside_source"):
        create_project_snapshot(source, source / "output" / "snapshot")


def test_project_snapshot_rejects_symlinked_source(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("pass\n", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(source, target_is_directory=True)
    except OSError:
        pytest.skip("symlink capability unavailable")
    with pytest.raises(ValueError, match="snapshot_source_invalid"):
        create_project_snapshot(link, tmp_path / "snapshot")


def test_project_snapshot_empty_scope_is_rejected(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "large.bin").write_bytes(b"x" * 100)
    with pytest.raises(ValueError, match="snapshot_empty_scope"):
        create_project_snapshot(source, tmp_path / "snapshot", max_file_bytes=10)


def test_project_snapshot_concurrent_publish_has_one_owner_and_is_retryable(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("pass\n", encoding="utf-8")
    destination = tmp_path / "snapshot"

    def attempt(_index):
        try:
            return create_project_snapshot(source, destination)["status"]
        except Exception as exc:  # competing owner is an expected contract outcome
            return type(exc).__name__ + ":" + str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert results.count("created") == 1
    assert any("RunLockError:run_locked:" in value or "ValueError:snapshot_destination_not_create_only" in value for value in results)
    assert verify_project_snapshot(destination)["status"] == "pass"
    assert not list(tmp_path.glob(".snapshot.*.stage"))


def test_project_snapshot_simulated_disk_full_cleans_stage_and_recovers(tmp_path: Path, monkeypatch):
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("pass\n", encoding="utf-8")
    destination = tmp_path / "snapshot"
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
        create_project_snapshot(source, destination)
    assert failure.value.errno == errno.ENOSPC
    assert not destination.exists()
    assert not list(tmp_path.glob(".snapshot.*.stage"))
    assert not (tmp_path / ".snapshot.snapshot.lock").exists()
    monkeypatch.setattr("aether_re.evidence.os.fdopen", real_fdopen)
    assert create_project_snapshot(source, destination)["status"] == "created"


def test_project_snapshot_simulated_disk_full_after_partial_write(tmp_path: Path, monkeypatch):
    source = tmp_path / "project"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"x" * (256 * 1024))
    destination = tmp_path / "snapshot"
    real_fdopen = __import__("aether_re.evidence", fromlist=["os"]).os.fdopen

    class PartialFailWriter:
        def __init__(self, handle):
            self.handle = handle
            self.failed = False
        def __enter__(self):
            self.handle.__enter__()
            return self
        def __exit__(self, *args):
            return self.handle.__exit__(*args)
        def write(self, chunk):
            if not self.failed:
                self.failed = True
                self.handle.write(chunk[:max(1, len(chunk) // 2)])
                raise OSError(errno.ENOSPC, "simulated disk full after partial write")
            return self.handle.write(chunk)
        def flush(self):
            return self.handle.flush()
        def fileno(self):
            return self.handle.fileno()

    monkeypatch.setattr("aether_re.evidence.os.fdopen", lambda fd, *args, **kwargs: PartialFailWriter(real_fdopen(fd, *args, **kwargs)))
    with pytest.raises(OSError) as failure:
        create_project_snapshot(source, destination)
    assert failure.value.errno == errno.ENOSPC
    assert not destination.exists()
    assert not list(tmp_path.glob(".snapshot.*.stage"))
    assert not (tmp_path / ".snapshot.snapshot.lock").exists()
    monkeypatch.setattr("aether_re.evidence.os.fdopen", real_fdopen)
    assert create_project_snapshot(source, destination)["status"] == "created"


def test_project_snapshot_cancellation_cleans_stage_and_recovers(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    for index in range(3):
        (source / f"file_{index}.py").write_text(f"value = {index}\n", encoding="utf-8")
    destination = tmp_path / "snapshot"
    calls = 0

    def cancel_after_first_file():
        nonlocal calls
        calls += 1
        return calls >= 3

    with pytest.raises(SnapshotCancelled, match="snapshot_cancelled"):
        create_project_snapshot(source, destination, cancel_check=cancel_after_first_file)
    assert not destination.exists()
    assert not list(tmp_path.glob(".snapshot.*.stage"))
    assert not (tmp_path / ".snapshot.snapshot.lock").exists()
    assert create_project_snapshot(source, destination)["status"] == "created"


def test_project_snapshot_recovers_orphan_stage_after_worker_kill(tmp_path: Path):
    """A hard process kill leaves an orphan stage; the next owner cleans it before retry."""
    import subprocess
    import sys
    import time

    source = tmp_path / "project"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"x" * (4 * 1024 * 1024))
    destination = tmp_path / "snapshot"
    script = f"""
import time
from pathlib import Path
import aether_re.evidence as evidence
from aether_re.project_snapshot import create_project_snapshot
real_fsync = evidence.os.fsync
fsync_calls = [0]
def slow_fsync(fd):
    fsync_calls[0] += 1
    if fsync_calls[0] >= 2:
        time.sleep(30)
    return real_fsync(fd)
evidence.os.fsync = slow_fsync
create_project_snapshot(Path(r'{source}'), Path(r'{destination}'))
"""
    # The venv can use a launcher; select the base interpreter so the child
    # process itself is the one that gets terminated.
    child_python = getattr(sys, '_base_executable', sys.executable) if sys.platform == 'win32' else sys.executable
    child = subprocess.Popen([child_python, '-c', script], cwd=str(Path(__file__).parents[1]))
    stage = None
    deadline = time.time() + 10
    while time.time() < deadline:
        stages = list(tmp_path.glob(".snapshot.*.stage"))
        if stages:
            stage = stages[0]
            break
        time.sleep(0.05)
    assert stage is not None
    # child_python is the real base interpreter above, not the venv launcher.
    # Kill that direct process instead of invoking taskkill: on this host the
    # taskkill command can hang and let the worker publish the destination.
    # The direct kill is portable and leaves the orphan stage observable.
    child.kill()
    child.wait(timeout=10)
    assert not destination.exists()
    assert stage.exists()
    recovered = create_project_snapshot(source, destination)
    assert recovered["status"] == "created"
    assert not stage.exists()
    assert verify_project_snapshot(destination)["status"] == "pass"




def test_project_snapshot_local_seal_is_read_only_and_detects_tamper(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("value = 1\n", encoding="utf-8")
    destination = tmp_path / "sealed"

    created = create_project_snapshot(source, destination, immutable=True)
    assert created["status"] == "created"
    assert created["sealed"] is True
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["immutability"]["sealed"] is True
    assert verify_project_snapshot(destination, require_sealed=True)["status"] == "pass"

    for path in destination.rglob("*"):
        if path.is_file():
            assert not path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

    target = destination / "files" / "main.py"
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    target.write_text("value = 2\n", encoding="utf-8")
    checked = verify_project_snapshot(destination, require_sealed=True)
    assert checked["status"] == "fail"
    assert any(item["code"] == "snapshot_hash_mismatch" for item in checked["issues"])
    assert any(item["code"] == "snapshot_not_read_only" for item in checked["issues"])


def test_project_snapshot_concurrent_publish_stress_16_workers(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    for index in range(4):
        (source / f"file_{index}.py").write_text(f"value = {index}\n", encoding="utf-8")
    destination = tmp_path / "snapshot"

    def attempt(_index):
        try:
            return ("created", create_project_snapshot(source, destination)["status"])
        except Exception as exc:
            return (type(exc).__name__, str(exc))

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))

    assert sum(1 for kind, value in results if kind == "created" and value == "created") == 1
    assert all(kind in {"created", "RunLockError", "ValueError"} for kind, _ in results)
    assert verify_project_snapshot(destination)["status"] == "pass"
    assert not list(tmp_path.glob(".snapshot.*.stage"))


