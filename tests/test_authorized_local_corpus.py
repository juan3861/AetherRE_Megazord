import json
from pathlib import Path

import pytest

from aether_re.corpus import validate_corpus_builds
from tools.authorized_local_corpus import materialize_local_corpus


def _fake_snapshot(tmp_path: Path) -> Path:
    snapshot = tmp_path / "snapshot"
    files = snapshot / "files"
    for relative, content in {
        "omniroute/__init__.py": "__all__ = ['OmniRoute']\nclass OmniRoute: pass\n",
        "router/canonical/__init__.py": "__all__ = ['CanonicalRequest']\nclass CanonicalRequest: pass\n",
        "oasys_rlm/rlm/__init__.py": "__all__ = ['RLM']\nclass RLM: pass\n",
        "tests/test_omniroute.py": "def test_omniroute(): pass\n",
        "tests/test_omniroute_equivalence.py": "def test_equivalence(): pass\n",
        "tests/test_canonical_ir.py": "def test_ir(): pass\n",
        "tests/test_canonical_ir_contract_coverage.py": "def test_contract(): pass\n",
        "oasys_rlm/tests/test_imports.py": "def test_imports(): pass\n",
        "oasys_rlm/tests/test_rlm_query.py": "def test_query(): pass\n",
    }.items():
        path = files / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    snapshot.mkdir(exist_ok=True)
    (snapshot / "manifest.json").write_text(
        json.dumps({"schema": "project-snapshot.v1", "source_root": "C:/owned/project", "inventory_status": "complete"}),
        encoding="utf-8",
    )
    return snapshot


def test_authorized_local_corpus_materializes_hash_bound_projects(tmp_path: Path):
    snapshot = _fake_snapshot(tmp_path)
    out = tmp_path / "corpus"
    manifest = materialize_local_corpus(snapshot, out, authorization_ref="AUTH-TEST-001")
    assert manifest["count"] == 3
    assert all(item["authorization"] == "local_authorized" for item in manifest["projects"])
    report = validate_corpus_builds(out / "manifest.json")
    assert report["status"] == "complete"
    assert report["manifest_errors"] == []
    assert all(item["status"] == "succeeded" for item in report["results"])

    authorization = out / "authorization" / "local_rotor_snapshot_authorization.json"
    authorization.write_text("tampered", encoding="utf-8")
    invalid = validate_corpus_builds(out / "manifest.json")
    assert any(error["code"] == "local_authorization_artifact_hash_mismatch" for error in invalid["manifest_errors"])


def test_authorized_local_corpus_refuses_overwrite(tmp_path: Path):
    snapshot = _fake_snapshot(tmp_path)
    out = tmp_path / "corpus"
    materialize_local_corpus(snapshot, out, authorization_ref="AUTH-TEST-002")
    with pytest.raises(FileExistsError):
        materialize_local_corpus(snapshot, out, authorization_ref="AUTH-TEST-003")
