import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aether_re.release_certification import certify_release, sign_review
from megazord import main


def _manifest(root):
    gates = []
    for index in range(13):
        path = root / f"F{index:02d}.evidence"
        payload = f"gate-{index}".encode("ascii")
        artifact = root / f"F{index:02d}.artifact"
        artifact.write_bytes(payload)
        gate_evidence = {
            "schema": "gate-evidence.v1",
            "gate": f"F{index:02d}",
            "status": "QUITADA",
            "gate_passed": True,
            "integrity_errors": [],
            "blocking_gates": [],
            "artifacts": [{"path": artifact.name, "sha256": hashlib.sha256(payload).hexdigest()}],
        }
        path.write_text(json.dumps(gate_evidence), encoding="utf-8")
        gates.append({"gate": f"F{index:02d}", "status": "QUITADA", "evidence_path": path.name,
                      "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return {
        "schema": "release-manifest.v1",
        "commit": "a" * 40,
        "toolchain_lock_sha256": "b" * 64,
        "corpus_lock_sha256": "c" * 64,
        "gates": gates,
    }


def _reviewer_material():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return private, {"schema": "review-trust-map.v1", "reviewers": {"auditor-b": {"ed25519_public_key": public}}}


def test_certification_requires_a_trusted_independent_ed25519_review(tmp_path):
    manifest = _manifest(tmp_path)
    private, trust = _reviewer_material()
    review = sign_review(manifest, reviewer="auditor-b", producer="builder-a", private_key=private)

    report = certify_release(manifest, review, trust, release_root=tmp_path)
    assert report["schema"] == "release-certification.v1"
    assert report["status"] == "PARCIALMENTE_QUITADA"
    assert report["certified"] is False
    assert "external_vm_attestation_required_for_f08_f09" in {error["code"] for error in report["errors"]}


def test_certification_rejects_self_review_tampering_and_non_quitada_gate(tmp_path):
    manifest = _manifest(tmp_path)
    private, trust = _reviewer_material()
    self_review = sign_review(manifest, reviewer="builder-a ", producer="builder-a", private_key=private)
    report = certify_release(manifest, self_review, trust, release_root=tmp_path)
    assert report["certified"] is False
    assert "self_review_forbidden" in {error["code"] for error in report["errors"]}

    review = sign_review(manifest, reviewer="auditor-b", producer="builder-a", private_key=private)
    tampered = json.loads(json.dumps(manifest))
    tampered["gates"][0]["status"] = "PARCIALMENTE_QUITADA"
    report = certify_release(tampered, review, trust, release_root=tmp_path)
    assert report["certified"] is False
    assert "review_manifest_hash_mismatch" in {error["code"] for error in report["errors"]}

    review["signature"] = "00" * 64
    report = certify_release(manifest, review, trust, release_root=tmp_path)
    assert report["certified"] is False
    assert "review_signature_invalid" in {error["code"] for error in report["errors"]}


def test_certification_does_not_trust_a_status_only_gate_evidence_file(tmp_path):
    manifest = _manifest(tmp_path)
    evidence_path = tmp_path / manifest["gates"][0]["evidence_path"]
    evidence_path.write_text(json.dumps({"status": "pass", "gate_passed": True}), encoding="utf-8")
    manifest["gates"][0]["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    private, trust = _reviewer_material()
    review = sign_review(manifest, reviewer="auditor-b", producer="builder-a", private_key=private)

    report = certify_release(manifest, review, trust, release_root=tmp_path)

    assert report["certified"] is False
    assert "manifest_gate_evidence_contract_invalid" in {error["code"] for error in report["errors"]}


def test_certification_rejects_duplicate_gate_evidence_json_keys(tmp_path):
    manifest = _manifest(tmp_path)
    evidence_path = tmp_path / manifest["gates"][0]["evidence_path"]
    evidence_text = evidence_path.read_text(encoding="utf-8")
    evidence_path.write_text(
        evidence_text.replace(
            '"status": "QUITADA"',
            '"status": "PARCIALMENTE_QUITADA", "status": "QUITADA"',
            1,
        ),
        encoding="utf-8",
    )
    manifest["gates"][0]["evidence_sha256"] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    private, trust = _reviewer_material()
    review = sign_review(manifest, reviewer="auditor-b", producer="builder-a", private_key=private)

    report = certify_release(manifest, review, trust, release_root=tmp_path)

    assert report["certified"] is False
    assert "manifest_gate_evidence_contract_invalid" in {error["code"] for error in report["errors"]}


def test_certification_rehashes_artifacts_referenced_by_gate_evidence(tmp_path):
    manifest = _manifest(tmp_path)
    (tmp_path / "F03.artifact").write_bytes(b"tampered")
    private, trust = _reviewer_material()
    review = sign_review(manifest, reviewer="auditor-b", producer="builder-a", private_key=private)

    report = certify_release(manifest, review, trust, release_root=tmp_path)

    assert report["certified"] is False
    assert "manifest_gate_artifact_hash_mismatch" in {error["code"] for error in report["errors"]}


def test_release_certify_cli_loads_external_key_and_trust_map(tmp_path, monkeypatch):
    manifest = _manifest(tmp_path)
    private, trust = _reviewer_material()
    review = sign_review(manifest, reviewer="auditor-b", producer="builder-a", private_key=private)
    manifest_path = tmp_path / "manifest.json"
    review_path = tmp_path / "review.json"
    trust_path = tmp_path / "trust.json"
    output = tmp_path / "certificate.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    review_path.write_text(json.dumps(review), encoding="utf-8")
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    monkeypatch.setattr("sys.argv", [
        "megazord.py", "release-certify", "--manifest", str(manifest_path), "--review", str(review_path),
        "--trust-map", str(trust_path), "--release-root", str(tmp_path), "--out", str(output),
    ])
    assert main() == 3
    assert json.loads(output.read_text(encoding="utf-8"))["certified"] is False
