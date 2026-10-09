import json
from pathlib import Path

import pytest

from aether_re.custody_release import capture_custody_snapshot


def _git(root: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_custody_snapshot_records_git_file_hashes_and_explicit_exclusions(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Custody Test")
    (root / "tracked.py").write_text("print('tracked')\n", encoding="utf-8")
    _git(root, "add", "tracked.py")
    _git(root, "commit", "-m", "baseline")
    (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    (root / ".env").write_text("TOKEN=do-not-copy\n", encoding="utf-8")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "cached.pyc").write_bytes(b"cache")
    (root / "object.obj").write_bytes(b"build")

    output_dir = tmp_path / "evidence"
    report = capture_custody_snapshot(root, output_dir)

    assert report["schema"] == "custody-snapshot.v1"
    assert report["git"]["head"]
    assert report["git"]["branch"] in {"master", "main"}
    files = {entry["path"]: entry for entry in report["files"]}
    assert files["tracked.py"]["git_classification"] == "tracked"
    assert files["untracked.txt"]["git_classification"] == "untracked"
    assert len(files["tracked.py"]["sha256"]) == 64
    assert files[".env"]["secret_candidate"] is True
    assert files[".env"]["content_copied"] is False
    excluded = {entry["path"]: entry for entry in report["excluded"]}
    assert excluded["__pycache__/cached.pyc"]["reason"] == "cache_directory"
    assert excluded["object.obj"]["reason"] == "build_artifact_extension"
    assert (output_dir / "custody-snapshot.v1.json").is_file()
    written = json.loads((output_dir / "custody-snapshot.v1.json").read_text(encoding="utf-8"))
    assert written["inventory_sha256"] == report["inventory_sha256"]


def test_custody_snapshot_is_create_only_and_refuses_output_inside_source(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "file.txt").write_text("data", encoding="utf-8")
    output_dir = tmp_path / "evidence"

    capture_custody_snapshot(root, output_dir)
    with pytest.raises(FileExistsError, match="custody_snapshot_destination_exists"):
        capture_custody_snapshot(root, output_dir)
    with pytest.raises(ValueError, match="custody_snapshot_destination_inside_source"):
        capture_custody_snapshot(root, root / "evidence")
