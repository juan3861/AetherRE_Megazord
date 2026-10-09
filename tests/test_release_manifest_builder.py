import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from aether_re.release_builder import ReleaseManifestBuildError, build_release_manifest
from aether_re.release_certification import certify_release, validate_release_manifest


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _material_gate(root: Path, gate: str) -> str:
    artifact = root / "artifacts" / f"{gate}.bin"
    artifact.parent.mkdir(exist_ok=True)
    payload = f"material proof for {gate}".encode("ascii")
    artifact.write_bytes(payload)
    evidence = {
        "schema": "gate-evidence.v1",
        "gate": gate,
        "status": "QUITADA",
        "gate_passed": True,
        "integrity_errors": [],
        "blocking_gates": [],
        "artifacts": [
            {"path": f"artifacts/{gate}.bin", "sha256": _sha256(payload)},
        ],
    }
    relative = f"gates/{gate}.json"
    path = root / relative
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(evidence), encoding="utf-8")
    return relative


def _material_release(root: Path) -> list[str]:
    return [_material_gate(root, f"F{index:02d}") for index in range(13)]


def _build(root: Path, paths: list[str], **overrides):
    arguments = {
        "commit": "a" * 40,
        "toolchain_lock_sha256": "b" * 64,
        "corpus_lock_sha256": "c" * 64,
        "gate_evidence_paths": paths,
    }
    arguments.update(overrides)
    return build_release_manifest(root, **arguments)


def test_builder_rehashes_thirteen_material_gates_and_emits_validator_compatible_manifest(tmp_path):
    paths = list(reversed(_material_release(tmp_path)))

    manifest = _build(tmp_path, paths)

    assert manifest["schema"] == "release-manifest.v1"
    assert [item["gate"] for item in manifest["gates"]] == [f"F{index:02d}" for index in range(13)]
    assert manifest["gates"][3]["evidence_sha256"] == _sha256((tmp_path / "gates/F03.json").read_bytes())
    assert validate_release_manifest(manifest, release_root=tmp_path) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commit", "not-a-commit"),
        ("toolchain_lock_sha256", "f" * 63),
        ("corpus_lock_sha256", "g" * 64),
    ],
)
def test_builder_rejects_invalid_commit_and_lock_hashes(tmp_path, field, value):
    paths = _material_release(tmp_path)

    with pytest.raises(ReleaseManifestBuildError, match=f"^{field}_invalid$"):
        _build(tmp_path, paths, **{field: value})


def test_builder_rejects_duplicate_or_incomplete_gate_sets(tmp_path):
    paths = _material_release(tmp_path)

    with pytest.raises(ReleaseManifestBuildError, match="^gate_evidence_count_invalid$"):
        _build(tmp_path, paths[:-1])

    duplicate_gate = tmp_path / "gates/F11-duplicate.json"
    duplicate_gate.write_bytes((tmp_path / "gates/F11.json").read_bytes())
    with pytest.raises(ReleaseManifestBuildError, match="^gate_identity_duplicate$"):
        _build(tmp_path, paths[:-1] + ["gates/F11-duplicate.json"])


def test_builder_rejects_non_textual_and_duplicate_evidence_paths(tmp_path):
    paths = _material_release(tmp_path)

    non_textual = list(paths)
    non_textual[0] = ["not", "a", "path"]
    with pytest.raises(ReleaseManifestBuildError, match="^gate_evidence_path_invalid$"):
        _build(tmp_path, non_textual)

    duplicate = list(paths)
    duplicate[-1] = duplicate[0]
    with pytest.raises(ReleaseManifestBuildError, match="^gate_evidence_path_duplicate$"):
        _build(tmp_path, duplicate)


@pytest.mark.parametrize("mutation", ["status", "gate_passed", "integrity", "blocker"])
def test_builder_rejects_non_quitada_or_blocked_gate_evidence(tmp_path, mutation):
    paths = _material_release(tmp_path)
    target = tmp_path / "gates/F08.json"
    evidence = json.loads(target.read_text(encoding="utf-8"))
    if mutation == "status":
        evidence["status"] = "PARCIALMENTE_QUITADA"
    elif mutation == "gate_passed":
        evidence["gate_passed"] = False
    elif mutation == "integrity":
        evidence["integrity_errors"] = ["tamper"]
    else:
        evidence["blocking_gates"] = ["external_vm"]
    target.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ReleaseManifestBuildError, match="^gate_evidence_contract_invalid$"):
        _build(tmp_path, paths)


def test_builder_rehashes_artifacts_instead_of_trusting_declared_digest(tmp_path):
    paths = _material_release(tmp_path)
    (tmp_path / "artifacts/F04.bin").write_bytes(b"tampered after evidence")

    with pytest.raises(ReleaseManifestBuildError, match="^gate_artifact_hash_mismatch$"):
        _build(tmp_path, paths)


def test_builder_rejects_release_inventory_used_as_gate_evidence_artifact(tmp_path):
    paths = _material_release(tmp_path)
    inventory = {
        "schema": "release-inventory.v1",
        "certification_status": "NOT_CERTIFIED",
        "promoted_gates": [],
        "gate_truth_recalculated": False,
        "manifest_built": False,
        "release_manifest_generated": False,
        "gate_claims": [{"gate": "F00", "claimed_status": "QUITADA", "verified": False}],
    }
    artifact_path = tmp_path / "artifacts/F00-inventory.bin"
    artifact_path.write_text(json.dumps(inventory), encoding="utf-8")
    evidence_path = tmp_path / paths[0]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["artifacts"] = [
        {"path": "artifacts/F00-inventory.bin", "sha256": _sha256(artifact_path.read_bytes())}
    ]
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ReleaseManifestBuildError, match="^gate_artifact_release_inventory_forbidden$"):
        _build(tmp_path, paths)


def test_builder_keeps_accepting_other_json_artifacts(tmp_path):
    paths = _material_release(tmp_path)
    artifact_path = tmp_path / "artifacts/F01-report.json"
    artifact_path.write_text(json.dumps({"schema": "analysis-report.v1", "finding_count": 0}), encoding="utf-8")
    evidence_path = tmp_path / "gates/F01.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["artifacts"] = [
        {"path": "artifacts/F01-report.json", "sha256": _sha256(artifact_path.read_bytes())}
    ]
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    manifest = _build(tmp_path, paths)

    assert manifest["schema"] == "release-manifest.v1"
    assert manifest["gates"][1]["gate"] == "F01"


@pytest.mark.parametrize("bad_path", ["../F00.json", "C:/outside/F00.json"])
def test_builder_rejects_traversal_and_absolute_evidence_paths(tmp_path, bad_path):
    paths = _material_release(tmp_path)
    paths[0] = bad_path

    with pytest.raises(ReleaseManifestBuildError, match="^gate_evidence_path_invalid$"):
        _build(tmp_path, paths)


def test_builder_rejects_symlinked_evidence_and_artifacts(tmp_path):
    paths = _material_release(tmp_path)
    real_evidence = tmp_path / "gates/F00.json"
    link_evidence = tmp_path / "gates/F00-link.json"
    try:
        link_evidence.symlink_to(real_evidence)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")

    paths[0] = "gates/F00-link.json"
    with pytest.raises(ReleaseManifestBuildError, match="^gate_evidence_path_invalid$"):
        _build(tmp_path, paths)

    paths[0] = "gates/F00.json"
    real_artifact = tmp_path / "artifacts/F00.bin"
    linked_artifact = tmp_path / "artifacts/F00-link.bin"
    linked_artifact.symlink_to(real_artifact)
    evidence = json.loads(real_evidence.read_text(encoding="utf-8"))
    evidence["artifacts"][0]["path"] = "artifacts/F00-link.bin"
    real_evidence.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(ReleaseManifestBuildError, match="^gate_artifact_path_invalid$"):
        _build(tmp_path, paths)


def _create_directory_junction(link: Path, target: Path) -> None:
    if os.name != "nt":
        pytest.skip("directory junction coverage is Windows-specific")
    result = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("directory junction creation is unavailable on this host")


def test_builder_rejects_evidence_reached_through_directory_junction(tmp_path):
    paths = _material_release(tmp_path)
    junction = tmp_path / "gates-alias"
    _create_directory_junction(junction, tmp_path / "gates")
    paths[0] = "gates-alias/F00.json"

    with pytest.raises(ReleaseManifestBuildError, match="^gate_evidence_path_invalid$"):
        _build(tmp_path, paths)


def test_certifier_rejects_evidence_reached_through_directory_junction(tmp_path):
    paths = _material_release(tmp_path)
    manifest = _build(tmp_path, paths)
    junction = tmp_path / "gates-alias"
    _create_directory_junction(junction, tmp_path / "gates")
    manifest["gates"][0]["evidence_path"] = "gates-alias/F00.json"

    report = certify_release(
        manifest,
        {"status": "pass"},
        {"status": "pass"},
        release_root=tmp_path,
    )

    assert "manifest_gate_evidence_hash_mismatch" in {error["code"] for error in report["errors"]}


def test_material_manifest_never_promotes_textual_review_vm_or_worm_status(tmp_path):
    """Hashed status prose is not an external signature, VM, or WORM proof."""
    manifest = _build(tmp_path, _material_release(tmp_path))

    report = certify_release(
        manifest,
        {"status": "pass", "signature": "pass"},
        {"status": "pass", "worm": True},
        release_root=tmp_path,
    )

    codes = {error["code"] for error in report["errors"]}
    assert report["certified"] is False
    assert report["status"] == "PARCIALMENTE_QUITADA"
    assert "review_schema_invalid" in codes
    assert "reviewer_untrusted" in codes
    assert "review_signature_invalid" in codes
    assert "external_vm_attestation_required_for_f08_f09" in codes
    assert "external_worm_attestation_required" in codes

