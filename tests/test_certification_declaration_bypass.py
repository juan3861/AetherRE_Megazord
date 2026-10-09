"""Declarations are not evidence, even when all producer status fields agree."""
import json

from aether_re.profile_certification import REQUIRED_MEASUREMENTS, certify_static_profile
from megazord import main


def test_profile_cannot_certify_nonexistent_evidence():
    evaluation = {
        "oracle_independent": True,
        "evidence_refs": ["nonexistent-evidence.json"],
        **{name: {"status": "measured", "invented": 1,
                  "evidence_refs": ["nonexistent-evidence.json"]}
           for name in REQUIRED_MEASUREMENTS},
    }
    result = certify_static_profile(
        {"schema": "profile-scope.v1", "profile_id": "wasm"},
        {"development_hash": "a", "calibration_hash": "b", "blind_hash": "c"},
        {"workers": [{"name": "fake", "executable_sha256": "0" * 64,
                      "version": "1", "license_spdx": "MIT", "invocation": ["missing"]}]},
        evaluation, {},
    )
    assert result["status"] == "NAO_COMPROVADA"
    assert "profile_evidence_verification_unavailable" in {x["code"] for x in result["errors"]}


def test_release_build_cannot_succeed_from_thirteen_status_strings(tmp_path, monkeypatch):
    phase = tmp_path / "phases.json"
    out = tmp_path / "release.json"
    phase.write_text(json.dumps({"schema": "phase-gate-report.v1", "phases": [
        {"phase_id": f"F{i:02d}", "status": "QUITADA"} for i in range(13)
    ]}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["megazord", "release-build", "--phase-report", str(phase), "--out", str(out)])
    assert main() == 3
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["status"] == "blocked"
    assert report["manifest_built"] is False
    assert "release_manifest_builder_inputs_missing" in {x["code"] for x in report["errors"]}
