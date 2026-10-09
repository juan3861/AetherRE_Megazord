import json
from pathlib import Path

from aether_re.checkpoint import read_checkpoint, write_checkpoint


def test_checkpoint_roundtrip_and_replacement(tmp_path: Path):
    path = tmp_path / "checkpoint.json"
    write_checkpoint(path, {"status": "running", "step": 1})
    write_checkpoint(path, {"status": "succeeded", "step": 2})
    assert read_checkpoint(path) == {"status": "succeeded", "step": 2}
    assert not list(tmp_path.glob(".checkpoint.json.*.tmp"))


def test_corrupt_checkpoint_is_not_executed(tmp_path: Path):
    path = tmp_path / "checkpoint.json"
    path.write_text("{truncated", encoding="utf-8")
    assert read_checkpoint(path) is None
