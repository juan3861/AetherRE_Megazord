import json
from argparse import Namespace

from aether_re.claims import validate_claims
from megazord import cmd_claims_validate


def test_claim_validation_rejects_missing_and_accepts_explicit_support():
    report = validate_claims(
        [{"statement": "safe", "state": "confirmed", "evidence_ids": ["e1"]}, {"statement": "invented", "state": "confirmed", "evidence_ids": ["missing"]}],
        [{"evidence_id": "e1", "supports": True}],
    )
    assert report["summary"] == {"total": 2, "supported": 1, "inconclusive": 0, "unsupported": 1}
    assert report["claims"][1]["review_required"] is True


def test_claim_validation_strict_mode_requires_evidence_provenance():
    claims = [{"statement": "observed", "state": "confirmed", "evidence_ids": ["ev-1"]}]
    weak = [{"evidence_id": "ev-1", "supports": True}]
    report = validate_claims(claims, weak, strict_evidence=True)
    assert report["summary"]["unsupported"] == 1
    assert report["strict_evidence"] is True


def test_claim_validation_surfaces_strict_contract_failure_even_without_references():
    # A malformed provenance record must not disappear simply because no
    # claim happens to reference its ID.  The nested contract remains the
    # detailed diagnostic; the claim report is invalid for machine gates.
    report = validate_claims([], [{"evidence_id": "orphan", "supports": True}], strict_evidence=True)
    assert report["status"] == "invalid"
    assert report["evidence_contract"]["status"] == "invalid"
    assert any(item["code"] == "evidence_contract_invalid" for item in report["errors"])


def test_claim_validation_propagates_unbound_strict_artifact_hash():
    claims = [{"statement": "observed", "state": "confirmed", "evidence_ids": ["ev-1"]}]
    evidence = [
        {
            "evidence_id": "ev-1",
            "run_id": "run-1",
            "input_hash": "a" * 64,
            "producer": {"name": "native", "version": "1"},
            "method": "static-test",
            "validation_status": "observed",
            "supports": True,
            "target_identity": {"format": "PE"},
            "source_span": {"module": "main.c", "line": 4},
            "raw_artifact_hash": "b" * 64,
            "assumptions": [],
            "limits": ["static"],
            "dependencies": [],
        }
    ]

    for manifest in (None, {"files": []}):
        report = validate_claims(claims, evidence, strict_evidence=True, evidence_manifest=manifest)
        assert report["status"] == "invalid"
        assert any(item["code"] == "evidence_contract_invalid" for item in report["errors"])
        assert any(item["code"] == "raw_artifact_not_in_manifest" for item in report["evidence_contract"]["errors"])


def test_claim_validation_rejects_duplicate_evidence_and_malformed_shapes():
    report = validate_claims(
        [{"statement": "ambiguous", "state": "confirmed", "evidence_ids": ["e1"]}],
        [{"evidence_id": "e1", "supports": True}, {"evidence_id": "e1", "supports": False}],
    )
    assert report["status"] == "invalid"
    assert report["summary"]["unsupported"] == 1
    assert any(item["code"] == "duplicate_evidence_id" for item in report["errors"])
    malformed = validate_claims([{"statement": "bad", "evidence_ids": "e1"}], [{"evidence_id": "e1", "supports": True}])
    assert malformed["status"] == "invalid"
    assert malformed["errors"][0]["code"] == "claim_evidence_ids_must_be_list"


def test_claim_validation_does_not_ignore_counterevidence():
    report = validate_claims(
        [{"statement": "contradicted", "state": "confirmed", "evidence_ids": ["e1"], "counterevidence_ids": ["e2"]}],
        [{"evidence_id": "e1", "supports": True}, {"evidence_id": "e2", "supports": True}],
    )
    assert report["claims"][0]["verdict"] == "unsupported"
    assert report["claims"][0]["review_required"] is True


def test_claim_validation_does_not_promote_explicitly_unsupported_evidence():
    report = validate_claims(
        [{"statement": "malicious promotion", "state": "confirmed", "evidence_ids": ["ev-1"]}],
        [{"evidence_id": "ev-1", "supports": True, "validation_status": "unsupported"}],
    )
    assert report["claims"][0]["verdict"] == "unsupported"
    assert report["claims"][0]["review_required"] is True


def test_claim_validation_rejects_non_list_inputs():
    report = validate_claims({}, [])  # type: ignore[arg-type]
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "claims_and_evidence_must_be_lists"


def test_claims_cli_rejects_unreadable_input_without_traceback(tmp_path):
    claims = tmp_path / "claims.json"
    evidence = tmp_path / "evidence.json"
    out = tmp_path / "report.json"
    claims.write_text("{", encoding="utf-8")
    evidence.write_text(json.dumps([]), encoding="utf-8")
    code = cmd_claims_validate(Namespace(claims=str(claims), evidence=str(evidence), out=str(out), strict_evidence=False, manifest=None))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert report["errors"][0]["code"] == "input_unreadable"


def test_claims_cli_strict_gate_rejects_orphan_invalid_provenance(tmp_path):
    claims = tmp_path / "claims.json"
    evidence = tmp_path / "evidence.json"
    out = tmp_path / "report.json"
    claims.write_text(json.dumps([]), encoding="utf-8")
    evidence.write_text(json.dumps([{"evidence_id": "orphan", "supports": True}]), encoding="utf-8")
    code = cmd_claims_validate(Namespace(claims=str(claims), evidence=str(evidence), out=str(out), strict_evidence=True, manifest=None))
    report = json.loads(out.read_text(encoding="utf-8"))
    assert code == 2
    assert report["status"] == "invalid"
    assert any(item["code"] == "evidence_contract_invalid" for item in report["errors"])
