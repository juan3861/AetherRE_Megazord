import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aether_re.profile_certification import certify_static_profile


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _material_case(root: Path) -> dict:
    corpus_refs = {}
    for split in ("development", "calibration", "blind"):
        path = root / "corpus" / f"{split}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"independent-{split}".encode())
        corpus_refs[f"{split}_ref"] = f"corpus/{split}.bin"
        corpus_refs[f"{split}_hash"] = _sha(path)

    worker = root / "tools" / "worker.exe"
    worker.parent.mkdir(parents=True)
    worker.write_bytes(b"pinned-worker-v1")

    observations = root / "results" / "observations.json"
    observations.parent.mkdir(parents=True)
    observations.write_text('{"cases": 100}', encoding="utf-8")

    oracle = root / "oracle" / "attestation.json"
    oracle.parent.mkdir(parents=True)
    oracle_payload = {
        "schema": "oracle-independence-claim.v1",
        "profile_id": "wasm",
        "producer_identity": "megazord-team",
        "oracle_owner_identity": "independent-lab",
        "blind_corpus_sha256": corpus_refs["blind_hash"],
        "sealed_before_evaluation": True,
        "oracle_access": "withheld_until_evaluation_complete",
    }
    private = Ed25519PrivateKey.generate()
    signature = base64.b64encode(private.sign(_canonical(oracle_payload))).decode("ascii")
    oracle.write_text(json.dumps({
        "schema": "signed-oracle-independence-attestation.v1",
        "payload": oracle_payload,
        "signature": {
            "key_id": "independent-lab-2026",
            "algorithm": "Ed25519",
            "signature_b64": signature,
        },
    }, sort_keys=True), encoding="utf-8")
    public_key = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    trust_map = {
        "schema": "profile-oracle-trust-map.v1",
        "keys": [{
            "key_id": "independent-lab-2026",
            "algorithm": "Ed25519",
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
            "oracle_owner_identity": "independent-lab",
            "active": True,
        }],
    }

    evidence_ref = "results/observations.json"
    measurements = {
        "entities": {
            "status": "measured", "metric_type": "classification",
            "true_positive": 90, "false_positive": 5, "false_negative": 5,
            "denominator": 100, "precision": 90 / 95, "recall": 90 / 95,
            "thresholds": {"min_precision": 0.9, "min_recall": 0.9},
            "evidence_refs": [evidence_ref],
        },
        "relations": {
            "status": "measured", "metric_type": "classification",
            "true_positive": 80, "false_positive": 10, "false_negative": 10,
            "denominator": 100, "precision": 80 / 90, "recall": 80 / 90,
            "thresholds": {"min_precision": 0.8, "min_recall": 0.8},
            "evidence_refs": [evidence_ref],
        },
        "abstention": {
            "status": "measured", "metric_type": "abstention",
            "abstained": 4, "denominator": 100, "rate": 0.04,
            "thresholds": {"max_rate": 0.1},
            "evidence_refs": [evidence_ref],
        },
        "calibration": {
            "status": "measured", "metric_type": "calibration",
            "denominator": 100, "brier_score": 0.08, "ece": 0.04,
            "thresholds": {"max_brier_score": 0.15, "max_ece": 0.1},
            "evidence_refs": [evidence_ref],
        },
        "reproducibility": {
            "status": "measured", "metric_type": "reproducibility",
            "matching_runs": 2, "denominator": 2, "rate": 1.0,
            "thresholds": {"min_rate": 1.0, "min_runs": 2},
            "evidence_refs": [evidence_ref],
        },
    }
    return {
        "profile_scope": {"schema": "profile-scope.v1", "profile_id": "wasm"},
        "corpus": corpus_refs,
        "workers": {"workers": [{
            "name": "worker", "executable_ref": "tools/worker.exe",
            "executable_sha256": _sha(worker), "version": "1.0",
            "license_spdx": "MIT", "invocation": ["tools/worker.exe", "--json"],
        }]},
        "evaluation": {
            "oracle_independent": True,
            "oracle_attestation": {
                "ref": "oracle/attestation.json", "sha256": _sha(oracle),
            },
            "evidence_refs": [evidence_ref],
            "artifacts": [{"ref": evidence_ref, "sha256": _sha(observations)}],
            "limitations": ["packed inputs are outside this certificate"],
            **measurements,
        },
        "baseline": {"regressions": []},
        "evidence_root": root,
        "external_trust_map": trust_map,
    }


def _codes(result: dict) -> set[str]:
    return {item["code"] for item in result["errors"]}


def test_material_certificate_rehashes_bound_evidence_and_can_quit(tmp_path):
    case = _material_case(tmp_path)

    result = certify_static_profile(**case)

    assert result["status"] == "QUITADA"
    assert result["errors"] == []
    assert result["verified_artifact_count"] == 6
    assert result["limitations"] == ["packed inputs are outside this certificate"]


def test_legacy_call_without_evidence_root_stays_fail_closed(tmp_path):
    case = _material_case(tmp_path)
    case.pop("evidence_root")

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "profile_evidence_root_missing" in _codes(result)


@pytest.mark.parametrize("hostile_ref", ["../outside.bin", "C:/outside.bin", "/outside.bin"])
def test_evidence_refs_cannot_escape_root(tmp_path, hostile_ref):
    case = _material_case(tmp_path)
    case["evaluation"]["evidence_refs"] = [hostile_ref]

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "evidence_ref_unsafe" in _codes(result)


def test_evidence_refs_reject_symlinks(tmp_path):
    case = _material_case(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = tmp_path / "results" / "linked.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    case["evaluation"]["evidence_refs"] = ["results/linked.json"]
    case["evaluation"]["artifacts"].append({"ref": "results/linked.json", "sha256": _sha(outside)})

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "evidence_ref_symlink" in _codes(result)


@pytest.mark.parametrize("target", ["corpus", "worker", "evidence"])
def test_material_hash_mismatch_blocks_certificate(tmp_path, target):
    case = _material_case(tmp_path)
    if target == "corpus":
        (tmp_path / "corpus" / "blind.bin").write_bytes(b"tampered")
        expected = "corpus_hash_mismatch"
    elif target == "worker":
        (tmp_path / "tools" / "worker.exe").write_bytes(b"tampered")
        expected = "worker_executable_hash_mismatch"
    else:
        (tmp_path / "results" / "observations.json").write_bytes(b"tampered")
        expected = "evidence_hash_mismatch"

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert expected in _codes(result)


def test_boolean_oracle_claim_without_material_attestation_is_insufficient(tmp_path):
    case = _material_case(tmp_path)
    case["evaluation"].pop("oracle_attestation")

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "independent_oracle_attestation_missing" in _codes(result)


def test_material_oracle_json_without_external_trust_stays_fail_closed(tmp_path):
    case = _material_case(tmp_path)
    case.pop("external_trust_map")

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "external_oracle_trust_map_missing" in _codes(result)


def test_invalid_oracle_signature_is_rejected(tmp_path):
    case = _material_case(tmp_path)
    oracle = tmp_path / case["evaluation"]["oracle_attestation"]["ref"]
    envelope = json.loads(oracle.read_text(encoding="utf-8"))
    envelope["signature"]["signature_b64"] = base64.b64encode(b"x" * 64).decode("ascii")
    oracle.write_text(json.dumps(envelope, sort_keys=True), encoding="utf-8")
    case["evaluation"]["oracle_attestation"]["sha256"] = _sha(oracle)

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "independent_oracle_signature_invalid" in _codes(result)


def test_oracle_key_controlled_by_producer_is_not_independent(tmp_path):
    case = _material_case(tmp_path)
    case["external_trust_map"]["keys"][0]["oracle_owner_identity"] = "megazord-team"

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "independent_oracle_signer_invalid" in _codes(result)


def test_trust_map_path_inside_evidence_root_is_rejected(tmp_path):
    case = _material_case(tmp_path)
    trust_path = tmp_path / "oracle" / "trust-map.json"
    trust_path.write_text(json.dumps(case.pop("external_trust_map")), encoding="utf-8")
    case["external_trust_map"] = trust_path

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert "external_oracle_trust_map_not_external" in _codes(result)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda e: e["entities"].update(denominator=0), "entities_measurement_invalid"),
        (lambda e: e["entities"].pop("thresholds"), "entities_measurement_invalid"),
        (lambda e: e["entities"]["thresholds"].update(min_precision=0.99), "entities_threshold_failed"),
        (lambda e: e.update(limitations=[]), "limitations_missing"),
        (lambda e: e["abstention"]["thresholds"].update(max_rate=0.01), "abstention_threshold_failed"),
    ],
)
def test_typed_metrics_require_denominators_thresholds_and_limitations(tmp_path, mutation, expected):
    case = _material_case(tmp_path)
    mutation(case["evaluation"])

    result = certify_static_profile(**case)

    assert result["status"] == "NAO_COMPROVADA"
    assert expected in _codes(result)
