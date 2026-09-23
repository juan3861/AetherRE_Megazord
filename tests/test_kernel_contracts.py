import pytest

from aether_re.kernel_contracts import (
    ArtifactRef,
    AuthorizationPolicy,
    ContractError,
    DerivationRecord,
    EpistemicState,
    IntakeLimits,
    canonical_json,
    sha256_canonical,
)


def test_canonical_json_is_order_independent_and_rejects_nan() -> None:
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert sha256_canonical({"a": 1, "b": 2}) == sha256_canonical({"b": 2, "a": 1})
    with pytest.raises(ContractError, match="canonical_json_invalid"):
        canonical_json({"score": float("nan")})


def test_authorization_and_limits_fail_closed() -> None:
    policy = AuthorizationPolicy.from_dict({
        "schema": "authorization-policy.v1", "basis": "owner",
        "principal": "local-user", "scope": ["static-analysis"],
    })
    assert policy.allows("static-analysis")
    with pytest.raises(ContractError, match="authorization_scope_invalid"):
        AuthorizationPolicy.from_dict({
            "schema": "authorization-policy.v1", "basis": "owner",
            "principal": "x", "scope": [],
        })
    with pytest.raises(ContractError, match="intake_limit_invalid:max_files"):
        IntakeLimits.from_dict({"max_files": True})
    assert {item.value for item in EpistemicState} == {
        "EXACT", "VERIFIED_RECONSTRUCTION", "PROBABILISTIC_INFERENCE", "HYPOTHESIS", "UNKNOWN",
    }


def test_authorization_rejects_dynamic_execution_when_static_only() -> None:
    policy = AuthorizationPolicy.from_dict({
        "case_owner": "owner", "allow_static": True, "allow_dynamic": False,
    })
    assert policy.allow_static is True
    assert policy.allow_dynamic is False
    assert policy.allows("static-analysis")
    assert not policy.allows("dynamic-execution")


def _artifact() -> dict[str, object]:
    return {
        "schema": "artifact-ref.v1", "artifact_id": "sha256:" + "a" * 64,
        "sha256": "a" * 64, "size": 3, "media_type": "application/octet-stream",
        "object_path": "objects/sha256/aa/" + "a" * 64, "origin": "input.bin",
        "authorization_sha256": "b" * 64,
    }


def test_artifact_and_derivation_reject_bad_hash_and_confidence() -> None:
    artifact = _artifact()
    assert ArtifactRef.from_dict(artifact).size == 3
    record = {
        "schema": "derivation-record.v1", "derivation_id": "derive-1",
        "product": artifact, "parents": [artifact["artifact_id"]],
        "producer": {"name": "intake", "version": "1"}, "method": "snapshot",
        "epistemic_state": "EXACT", "confidence": None, "limitations": [],
    }
    assert DerivationRecord.from_dict(record).epistemic_state is EpistemicState.EXACT
    record["confidence"] = 0.9
    with pytest.raises(ContractError, match="confidence_forbidden"):
        DerivationRecord.from_dict(record)


def test_inference_requires_parent_evidence_and_bounded_confidence() -> None:
    with pytest.raises(ContractError, match="parents_required"):
        DerivationRecord.from_dict({
            "derivation_id": "d1", "artifact_id": "a1",
            "epistemic_state": "PROBABILISTIC_INFERENCE",
            "confidence": 0.8, "parents": [], "losses": ["symbol names stripped"],
        })
    with pytest.raises(ContractError, match="confidence_invalid"):
        DerivationRecord.from_dict({
            "derivation_id": "d1", "artifact_id": "a1",
            "epistemic_state": "PROBABILISTIC_INFERENCE",
            "confidence": 1.1, "parents": ["evidence-1"], "losses": [],
        })


def test_contracts_reject_unknown_fields_and_duplicate_strings() -> None:
    with pytest.raises(ContractError, match="artifact_schema_invalid"):
        ArtifactRef.from_dict({**_artifact(), "extra": "not admitted"})
    with pytest.raises(ContractError, match="derivation_parents_invalid"):
        DerivationRecord.from_dict({
            "derivation_id": "d1", "artifact_id": "a1", "epistemic_state": "HYPOTHESIS",
            "confidence": None, "parents": ["p1", "p1"], "losses": [],
        })


def test_public_constructors_fail_closed_for_invalid_values() -> None:
    direct_policy = AuthorizationPolicy(
        schema="authorization-policy.v1", basis="owner", principal="owner", scope=("static-analysis",),
    )
    assert direct_policy.allow_static is True
    assert direct_policy.allow_dynamic is False
    with pytest.raises(ContractError, match="intake_limit_invalid:max_files"):
        IntakeLimits(max_files=0)
    with pytest.raises(ContractError, match="authorization_scope_invalid"):
        AuthorizationPolicy(
            schema="authorization-policy.v1", basis="owner", principal="owner", scope=(),
        )
    with pytest.raises(ContractError, match="artifact_hash_invalid"):
        ArtifactRef(
            schema="artifact-ref.v1", artifact_id="sha256:not-a-hash", sha256="not-a-hash",
            size=0, media_type="application/octet-stream", object_path="objects/item",
            origin="input.bin", authorization_sha256="b" * 64,
        )
    with pytest.raises(ContractError, match="parents_required"):
        DerivationRecord(
            schema="derivation-record.compact.v1", derivation_id="d1", artifact_id="a1",
            epistemic_state=EpistemicState.HYPOTHESIS, confidence=None, parents=(),
        )


@pytest.mark.parametrize("object_path", ["C:/escape", "C:relative", "//server/share/object", "objects/a:b", "objects/\x00item"])
def test_artifact_rejects_windows_absolute_or_unsafe_paths(object_path: str) -> None:
    artifact = _artifact()
    artifact["object_path"] = object_path
    with pytest.raises(ContractError, match="artifact_path_invalid"):
        ArtifactRef.from_dict(artifact)
