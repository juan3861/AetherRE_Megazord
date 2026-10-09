import json
import os
from pathlib import Path

import pytest

from aether_re.lock import RunLock, RunLockError


def test_run_lock_exclusive_and_release(tmp_path: Path):
    path = tmp_path / "run.lock"
    first = RunLock(path)
    first.acquire()
    second = RunLock(path)
    with pytest.raises(RunLockError):
        second.acquire()
    first.release()
    second.acquire()
    second.release()
    assert not path.exists()


def test_run_lock_persists_owner_token_and_does_not_release_replaced_lock(tmp_path: Path):
    path = tmp_path / "run.lock"
    lock = RunLock(path)
    lock.acquire()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload.get("owner_token"), str)
    assert len(payload["owner_token"]) == 32
    path.write_text(json.dumps({"pid": os.getpid(), "owner_token": "other"}), encoding="utf-8")
    assert lock.verify_owner() is False
    assert lock.release() is False
    assert path.exists()


def test_run_lock_verifies_its_live_owner_token_and_confirms_release(tmp_path: Path):
    path = tmp_path / "run.lock"
    lock = RunLock(path)
    lock.acquire()

    assert lock.verify_owner() is True
    assert lock.release() is True
    assert not path.exists()
    assert lock.verify_owner() is False
    assert lock.release() is False


def test_run_lock_recovers_dead_owner(tmp_path: Path):
    path = tmp_path / "run.lock"
    path.write_text(json.dumps({"pid": 999999999, "host": "test"}), encoding="utf-8")
    lock = RunLock(path)
    lock.acquire()
    assert json.loads(path.read_text(encoding="utf-8"))["pid"] == os.getpid()
    lock.release()


def test_run_lock_failed_fsync_does_not_strand_lock_and_recovers(tmp_path: Path, monkeypatch):
    path = tmp_path / "run.lock"
    real_fsync = os.fsync

    def fail_fsync(_fd):
        raise OSError(28, "simulated disk full")

    monkeypatch.setattr("aether_re.lock.os.fsync", fail_fsync)
    with pytest.raises(OSError, match="simulated disk full"):
        RunLock(path).acquire()
    assert not path.exists()
    monkeypatch.setattr("aether_re.lock.os.fsync", real_fsync)
    lock = RunLock(path)
    lock.acquire()
    lock.release()
    assert not path.exists()
