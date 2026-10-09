
import json
from pathlib import Path

from tools.bootstrap_corpus import generate_corpus
from tools.blind_release import create_blind_release, verify_blind_release


def test_blind_release_withholds_oracles_and_verifies_commitments(tmp_path: Path):
    corpus = tmp_path / "corpus"
    release = tmp_path / "release"
    escrow = tmp_path / "escrow"
    generate_corpus(corpus)
    report = create_blind_release(corpus / "manifest.json", release, escrow)
    assert report["status"] == "complete"
    public = json.loads((release / "manifest.blind.json").read_text(encoding="utf-8"))
    assert public["blind_holdout"] is True
    assert all("oracle" not in project and "oracle_sha256" not in project for project in public["projects"])
    assert not any(path.is_file() and "oracle" in path.name.lower() for path in release.rglob("*") if path.name != "manifest.blind.json")
    verified = verify_blind_release(release / "manifest.blind.json", escrow / "manifest.escrow.json")
    assert verified["status"] == "pass"
    first_source = release / public["projects"][0]["source"]
    first_source.write_text(first_source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    tampered = verify_blind_release(release / "manifest.blind.json", escrow / "manifest.escrow.json")
    assert tampered["status"] == "invalid"
    assert any(issue["code"] == "source_hash_mismatch" for issue in tampered["issues"])
