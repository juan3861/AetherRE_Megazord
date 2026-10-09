import json
from pathlib import Path

import pytest

from aether_re.ghidra_provenance import (
    _load_json_strict,
    validate_candidate_boundary,
    verify_file_manifest,
)


def _write_manifest(root: Path, manifest_path: Path) -> str:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": len(data),
                    "sha256": __import__("hashlib").sha256(data).hexdigest(),
                }
            )
    rows.sort(key=lambda row: row["path"])
    payload = {
        "schema": "distribution-files.v1",
        "root": str(root.resolve()),
        "file_count": len(rows),
        "total_bytes": sum(row["size"] for row in rows),
        "tree_sha256": __import__("hashlib").sha256(
            json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "files": rows,
    }
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return __import__("hashlib").sha256(manifest_path.read_bytes()).hexdigest()


def test_distribution_manifest_rehashes_exact_tree_and_detects_extra_file(tmp_path: Path):
    root = tmp_path / "dist"
    root.mkdir()
    (root / "Utility.jar").write_bytes(b"jar")
    (root / "module.bin").write_bytes(b"module")
    manifest = tmp_path / "files.json"
    expected_manifest_sha256 = _write_manifest(root, manifest)

    result = verify_file_manifest(root, manifest, expected_manifest_sha256)
    assert result["verified"] is True
    assert result["file_count"] == 2

    (root / "unexpected.bin").write_bytes(b"tamper")
    with pytest.raises(ValueError, match="tree_mismatch|file_set_mismatch"):
        verify_file_manifest(root, manifest, expected_manifest_sha256)


def test_distribution_manifest_rejects_unsafe_or_duplicate_relative_paths(tmp_path: Path):
    root = tmp_path / "dist"
    root.mkdir()
    manifest = tmp_path / "files.json"
    payload = {
        "schema": "distribution-files.v1",
        "root": str(root.resolve()),
        "file_count": 1,
        "total_bytes": 0,
        "tree_sha256": "0" * 64,
        "files": [{"path": "../escape.bin", "size": 0, "sha256": "0" * 64}],
    }
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    digest = __import__("hashlib").sha256(manifest.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="unsafe_manifest_path"):
        verify_file_manifest(root, manifest, digest)


def test_candidate_boundary_never_accepts_self_promotion():
    candidate = {
        "qualification": {
            "classification": "candidate-not-qualified",
            "worker_eligible": False,
            "worker_qualified": False,
            "independent_review": None,
            "gate_passed": False,
            "blockers": ["external qualification required"],
        }
    }
    assert validate_candidate_boundary(candidate) is True

    candidate["qualification"]["worker_eligible"] = True
    with pytest.raises(ValueError, match="candidate_self_promotion_rejected"):
        validate_candidate_boundary(candidate)

    candidate["qualification"]["worker_eligible"] = False
    candidate["qualification"]["gate_passed_extra"] = False
    with pytest.raises(ValueError, match="qualification_keys_invalid"):
        validate_candidate_boundary(candidate)


def test_manifest_counts_require_plain_integers_not_booleans(tmp_path: Path):
    root = tmp_path / "dist"
    root.mkdir()
    (root / "one.bin").write_bytes(b"x")
    manifest = tmp_path / "files.json"
    _write_manifest(root, manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["file_count"] = True
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    digest = __import__("hashlib").sha256(manifest.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="manifest_counts_invalid"):
        verify_file_manifest(root, manifest, digest)


def test_strict_json_loader_rejects_duplicate_keys(tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate_json_key"):
        _load_json_strict(path)
