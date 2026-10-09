import json
import os
import stat
from pathlib import Path

from aether_re.custody import create_custody_receipt, verify_custody_receipt


def test_custody_receipt_commits_artifacts_and_verifies(tmp_path: Path):
    artifact = tmp_path / "snapshot.manifest"
    artifact.write_text("root=abc\n", encoding="utf-8")
    receipt = tmp_path / "receipt.json"
    created = create_custody_receipt({"snapshot_manifest": artifact}, receipt, metadata={"phase": "F02"}, immutable=True)
    assert created["status"] == "created"
    assert created["verification"]["status"] == "pass"
    assert created["custody"]["external_anchor"] is False
    verified = verify_custody_receipt(receipt, require_sealed=True, expected_artifacts={"snapshot_manifest": artifact})
    assert verified["status"] == "pass"
    os.chmod(receipt, receipt.stat().st_mode | stat.S_IWUSR)


def test_custody_receipt_detects_artifact_tamper(tmp_path: Path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"original")
    receipt = tmp_path / "receipt.json"
    assert create_custody_receipt({"target": artifact}, receipt)["status"] == "created"
    artifact.write_bytes(b"tampered")
    verified = verify_custody_receipt(receipt)
    assert verified["status"] == "fail"
    assert any(issue["code"] == "artifact_hash_mismatch" for issue in verified["issues"])


def test_custody_receipt_chain_and_destination_are_fail_closed(tmp_path: Path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("v1", encoding="utf-8")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    assert create_custody_receipt({"a": artifact}, first)["status"] == "created"
    chained = create_custody_receipt({"a": artifact}, second, previous_receipt=first)
    assert chained["status"] == "created"
    data = json.loads(second.read_text(encoding="utf-8"))
    assert data["previous_receipt_sha256"]
    assert create_custody_receipt({"a": artifact}, second)["status"] == "invalid"


def test_custody_receipt_detects_seal_relaxation(tmp_path: Path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"sealed")
    receipt = tmp_path / "receipt.json"
    assert create_custody_receipt({"artifact": artifact}, receipt, immutable=True)["status"] == "created"
    os.chmod(receipt, receipt.stat().st_mode | stat.S_IWUSR)
    verified = verify_custody_receipt(receipt, require_sealed=True)
    assert verified["status"] == "fail"
    assert any(issue["code"] == "receipt_not_read_only" for issue in verified["issues"])
