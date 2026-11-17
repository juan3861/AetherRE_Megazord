"""Campaign cleanup must terminate its waits and refuse incomplete evidence."""
import hashlib
import itertools
import subprocess

import pytest

from aether_re import validation_campaign as module


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("taskkill", 5), OSError("unavailable")])
def test_taskkill_failure_still_attempts_direct_kill(monkeypatch, error):
    class Process:
        pid = 123456
        killed = False

        def kill(self):
            self.killed = True

    proc = Process()

    def taskkill(*args, **kwargs):
        assert kwargs.get("timeout") is not None, "taskkill needs a deadline"
        raise error

    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module.subprocess, "run", taskkill)
    module._kill_tree(proc)
    assert proc.killed


@pytest.mark.parametrize("scenario", ["unreaped", "unreaped_capture_complete", "capture_incomplete"])
def test_campaign_records_incomplete_cleanup_as_failure(tmp_path, monkeypatch, scenario):
    class Process:
        pid = 123456
        returncode = None if scenario.startswith("unreaped") else 0
        stdout = object()
        stderr = object()

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            assert timeout is not None, "reaping needs a deadline"
            if scenario.startswith("unreaped"):
                raise subprocess.TimeoutExpired("owned", timeout)
            return self.returncode

    class CaptureThread:
        def __init__(self, *, target, args, kwargs, **options):
            self.options = options
            self.kwargs = kwargs

        def start(self):
            if self.kwargs["key"] == "stdout" or scenario == "unreaped_capture_complete":
                data = b"OK_CODE\n" if self.kwargs["key"] == "stdout" else b""
                self.kwargs["state"][self.kwargs["key"]] = {
                    "data": data, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                }

        def join(self, timeout=None):
            assert timeout is not None
            assert self.options.get("daemon") is True, "blocked capture must not hold interpreter open"

        def is_alive(self):
            return self.kwargs["key"] == "stderr" and scenario != "unreaped_capture_complete"

    proc = Process()
    launches = []
    def launch(*args, **kwargs):
        launches.append(args)
        return proc
    monkeypatch.setattr(module.subprocess, "Popen", launch)
    monkeypatch.setattr(module.threading, "Thread", CaptureThread)
    monkeypatch.setattr(module, "_kill_tree", lambda p: None)
    ticks = itertools.count()
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    case = module.CampaignCase("owned", "timeout", ("owned",), 0, ("OK_CODE",), 1)
    next_case = module.CampaignCase("must-not-launch", "tamper", ("owned",), 0, ("OK_CODE",), 1)
    report = module.run_validation_campaign([case, next_case], root=tmp_path, output=tmp_path / "r.json")
    row = report["cases"][0]
    assert row["status"] == "failed"
    assert row["capture_complete"] == (scenario == "unreaped_capture_complete")
    assert row["cleanup_complete"] == (not scenario.startswith("unreaped"))
    assert row["outcome_code"] == ("timeout" if scenario.startswith("unreaped") else "capture_incomplete")
    assert row["matched_codes"] == ["OK_CODE"]
    assert len(launches) == 1
    assert report["execution"]["unexecuted_case_ids"] == ["must-not-launch"]
    assert report["execution"]["requested_cases"] == 2
    assert report["execution"]["executed_cases"] == 1
