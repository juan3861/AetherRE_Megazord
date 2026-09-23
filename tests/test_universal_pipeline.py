from __future__ import annotations

import json
from pathlib import Path

import pytest

from aether_re.kernel_contracts import EpistemicState
from aether_re.pipeline import CasePolicy, run_universal_case


def test_universal_case_routes_fixture_and_preserves_unknown(tmp_path: Path) -> None:
    target = tmp_path / "sample.wasm"
    target.write_bytes(b"\x00asm\x01\x00\x00\x00")

    report = run_universal_case(target, tmp_path / "out", CasePolicy.static_only())

    assert report.profile == "wasm"
    assert report.target_sha256
    assert all(
        item.evidence_refs
        for item in report.observations
        if item.epistemic_state != EpistemicState.UNKNOWN
    )
    assert any(item.epistemic_state == EpistemicState.UNKNOWN for item in report.observations)
    assert report.graph["abstentions"] == [
        {
            "kind": "original-source",
            "value": "not-established",
            "epistemic_state": "UNKNOWN",
            "evidence_refs": [],
            "losses": ["static evidence cannot recover original source identity"],
        }
    ]
    assert report.dynamic_status == "not_requested"
    assert report.original_source_recovered is False
    persisted = json.loads((tmp_path / "out" / "case_report.json").read_text(encoding="utf-8"))
    assert persisted["profile"] == "wasm"


def test_universal_case_fails_closed_when_profile_is_unknown(tmp_path: Path) -> None:
    target = tmp_path / "opaque.bin"
    target.write_bytes(b"not a certified executable profile")

    report = run_universal_case(target, tmp_path / "out", CasePolicy.static_only())

    assert report.profile == "opaque-static"
    assert report.certification_status == "abstained"
    assert report.original_source_recovered is False
    assert any(item.epistemic_state == EpistemicState.UNKNOWN for item in report.observations)
    assert report.graph["abstentions"]


def test_pipeline_has_no_optional_lab_policy_import() -> None:
    source = Path(__file__).parents[1] / "aether_re" / "pipeline.py"
    assert "from aether_re.lab_policy import" not in source.read_text(encoding="utf-8")


def test_dynamic_request_without_vm_proof_is_refused_before_execution(tmp_path: Path) -> None:
    target = tmp_path / "sample.wasm"
    target.write_bytes(b"\x00asm\x01\x00\x00\x00")

    with pytest.raises(ValueError, match="dynamic_vm_proof_required"):
        run_universal_case(target, tmp_path / "out", CasePolicy.dynamic())

    assert not (tmp_path / "out" / "dynamic").exists()
