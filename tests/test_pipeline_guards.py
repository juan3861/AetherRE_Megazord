import json
from pathlib import Path

import pytest

from aether_re.pipeline import run_megazord


def test_pipeline_preserves_disk_failure_reason(tmp_path: Path, monkeypatch):
    target = tmp_path / "input.bin"
    target.write_bytes(b"not-a-real-binary")
    out = tmp_path / "run"
    monkeypatch.setattr("aether_re.pipeline.has_free_disk", lambda *_args: False)
    with pytest.raises(OSError, match="insufficient_disk_space"):
        run_megazord(target, out_dir=out, use_adapters=False, deep=False)
    checkpoint = json.loads((out / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["status"] == "failed"
    assert checkpoint["error"] == "insufficient_disk_space"
    assert not (out / "run.lock").exists()


def test_pipeline_rejects_artifact_changed_after_manifest_publication(tmp_path: Path, monkeypatch):
    target = tmp_path / "input.bin"
    target.write_bytes(b"MZ" + b"\x00" * 126)
    out = tmp_path / "run"
    publish = __import__("aether_re.pipeline", fromlist=["write_manifest_atomic"]).write_manifest_atomic

    def publish_then_tamper(manifest, path):
        publish(manifest, path)
        (path.parent / "strings.txt").write_bytes(b"tampered after manifest\n")

    monkeypatch.setattr("aether_re.pipeline.write_manifest_atomic", publish_then_tamper)
    with pytest.raises(RuntimeError, match="published_manifest_invalid"):
        run_megazord(target, out_dir=out, use_adapters=False, deep=False)

    checkpoint = json.loads((out / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["status"] == "failed"
    assert checkpoint["error"] == "published_manifest_invalid"
    assert not (out / "run.lock").exists()


def test_pipeline_rejects_nested_unlisted_control_named_artifact(tmp_path: Path, monkeypatch):
    target = tmp_path / "input.bin"
    target.write_bytes(b"MZ" + b"\x00" * 126)
    out = tmp_path / "run"
    publish = __import__("aether_re.pipeline", fromlist=["write_manifest_atomic"]).write_manifest_atomic

    def publish_then_add_nested_manifest(manifest, path):
        publish(manifest, path)
        nested = path.parent / "comparative" / "manifest.json"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_text('{"schema":"nested-unlisted"}', encoding="utf-8")

    monkeypatch.setattr("aether_re.pipeline.write_manifest_atomic", publish_then_add_nested_manifest)
    with pytest.raises(RuntimeError, match="published_package_invalid"):
        run_megazord(target, out_dir=out, use_adapters=False, deep=False)

    checkpoint = json.loads((out / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["status"] == "failed"
    assert checkpoint["error"] == "published_package_invalid"


def test_pipeline_refuses_preexisting_snapshot_with_unbound_bytes(tmp_path: Path):
    target = tmp_path / "input.bin"
    target.write_bytes(b"MZ" + b"\x00" * 126)
    out = tmp_path / "run"
    out.mkdir()
    (out / "input.snapshot").write_bytes(b"different bytes")

    with pytest.raises(FileExistsError, match="input_snapshot_already_exists"):
        run_megazord(target, out_dir=out, use_adapters=False, deep=False)

    checkpoint = json.loads((out / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["status"] == "failed"
    assert checkpoint["error"] == "input_snapshot_already_exists"


def test_pipeline_rejects_reparse_output_path_before_resolving_it(tmp_path: Path, monkeypatch):
    target = tmp_path / "input.bin"
    target.write_bytes(b"MZ" + b"\x00" * 126)
    out = tmp_path / "requested-reparse-output"

    def mark_requested_output_as_reparse(path: Path) -> bool:
        return Path(path) == out

    monkeypatch.setattr("aether_re.pipeline._has_link_or_reparse_component", mark_requested_output_as_reparse)
    with pytest.raises(ValueError, match="output_path_contains_link_or_reparse"):
        run_megazord(target, out_dir=out, use_adapters=False, deep=False)

    assert not out.exists()


def test_pipeline_rejects_hardlinked_target_before_analysis(tmp_path: Path):
    target = tmp_path / "input.bin"
    target.write_bytes(b"MZ" + b"\x00" * 126)
    alias = tmp_path / "input-alias.bin"
    alias.hardlink_to(target)
    out = tmp_path / "run"

    with pytest.raises(ValueError, match="target_hardlink_not_allowed"):
        run_megazord(alias, out_dir=out, use_adapters=False, deep=False)

    assert not out.exists()


def test_pipeline_audits_published_package_while_holding_run_lock(tmp_path: Path, monkeypatch):
    from aether_re import pipeline
    from aether_re.lock import RunLock

    target = tmp_path / "input.bin"
    target.write_bytes(b"MZ" + b"\x00" * 126)
    out = tmp_path / "run"
    real_audit = pipeline.audit_run_package
    observed: dict[str, object] = {}

    def audit_during_lock(run_dir: Path, **kwargs):
        observed["lock_present"] = (Path(run_dir) / "run.lock").is_file()
        observed["active_lock_owned"] = isinstance(kwargs.get("active_lock"), RunLock) and kwargs["active_lock"].verify_owner()
        observed["active_lock_path"] = kwargs["active_lock"].path if kwargs.get("active_lock") else None
        return real_audit(run_dir, **kwargs)

    monkeypatch.setattr(pipeline, "audit_run_package", audit_during_lock)
    pipeline.run_megazord(target, out_dir=out, use_adapters=False, deep=False)

    assert observed == {"lock_present": True, "active_lock_owned": True, "active_lock_path": out / "run.lock"}
    assert not (out / "run.lock").exists()


def test_pipeline_fails_closed_when_owned_run_lock_release_reports_false(tmp_path: Path, monkeypatch):
    from aether_re import pipeline
    from aether_re.lock import RunLock

    target = tmp_path / "input.bin"
    target.write_bytes(b"MZ" + b"\x00" * 126)
    out = tmp_path / "run"
    instances: list[RunLock] = []

    class FalseReleaseRunLock(RunLock):
        def __init__(self, path: Path):
            super().__init__(path)
            instances.append(self)

        def release(self) -> bool:
            return False

    monkeypatch.setattr(pipeline, "RunLock", FalseReleaseRunLock)

    try:
        with pytest.raises(RuntimeError, match="run_lock_release_failed"):
            pipeline.run_megazord(target, out_dir=out, use_adapters=False, deep=False)
    finally:
        for lock in instances:
            RunLock.release(lock)

    assert instances
    assert not (out / "run.lock").exists()
