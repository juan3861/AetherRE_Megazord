from __future__ import annotations

import json
import os
import sys
import subprocess
from pathlib import Path

import pytest

from aether_re.validation_campaign import CampaignCase, run_validation_campaign
from tools.run_validation_campaign import mandatory_cases


def _case(case_id="ok", *, category="timeout", script=None, expected_exit=0,
          expected_codes=("OK_CODE",), timeout_s=5):
    script = script or "print('OK_CODE')"
    return CampaignCase(case_id, category, (sys.executable, "-c", script),
                        expected_exit, expected_codes, timeout_s)


def test_campaign_records_hashes_codes_and_atomic_report(tmp_path):
    report = run_validation_campaign([_case()], root=tmp_path,
                                     output=tmp_path / "campaign.json")
    assert report["status"] == "passed"
    assert report["summary"] == {
        "total": 1, "passed": 1, "failed": 0, "partial": 0,
        "categories": ["timeout"],
    }
    row = report["cases"][0]
    expected_stdout = f"OK_CODE{os.linesep}".encode()
    assert row["stdout_sha256"] == __import__("hashlib").sha256(expected_stdout).hexdigest()
    assert row["matched_codes"] == ["OK_CODE"]
    assert json.loads((tmp_path / "campaign.json").read_text())["status"] == "passed"


def test_campaign_fails_for_unexpected_exit_or_missing_code(tmp_path):
    cases = [
        _case("wrong-exit", script="print('OK_CODE'); raise SystemExit(4)"),
        _case("missing-code", script="print('something else')"),
    ]
    report = run_validation_campaign(cases, root=tmp_path, output=tmp_path / "r.json")
    assert report["status"] == "failed"
    assert report["summary"]["failed"] == 2


def test_timeout_kills_case_and_uses_machine_code(tmp_path):
    report = run_validation_campaign([
        _case("slow", script="import time; time.sleep(10)", expected_exit=0,
              expected_codes=("timeout",), timeout_s=1)
    ], root=tmp_path, output=tmp_path / "r.json")
    assert report["status"] == "failed"
    assert report["cases"][0]["outcome_code"] == "timeout"


def test_unavailable_physical_case_makes_campaign_partial(tmp_path):
    report = run_validation_campaign([
        _case("physical-enospc", category="disk_full", script="print('CAPABILITY_UNAVAILABLE')",
              expected_codes=("CAPABILITY_UNAVAILABLE",)).__class__(
                  "physical-enospc", "disk_full",
                  (sys.executable, "-c", "print('CAPABILITY_UNAVAILABLE')"),
                  0, ("CAPABILITY_UNAVAILABLE",), 5, capability_optional=True)
    ], root=tmp_path, output=tmp_path / "r.json")
    assert report["status"] == "partial"
    assert report["summary"]["partial"] == 1


def test_capability_marker_without_contract_or_with_wrong_exit_fails(tmp_path):
    cases = [
        _case("undeclared", script="print('CAPABILITY_UNAVAILABLE')",
              expected_codes=("CAPABILITY_UNAVAILABLE",)),
        CampaignCase("wrong-exit", "disk_full",
                     (sys.executable, "-c", "print('CAPABILITY_UNAVAILABLE');raise SystemExit(9)"),
                     0, ("CAPABILITY_UNAVAILABLE",), 5, capability_optional=True),
    ]
    report = run_validation_campaign(cases, root=tmp_path, output=tmp_path / "r.json")
    assert report["status"] == "failed"
    assert report["summary"]["failed"] == 2


def test_oversized_output_is_killed_and_bounded(tmp_path):
    report = run_validation_campaign([
        _case("bomb", category="oversized_output",
              script="import sys; sys.stdout.write('x'*2000000)", expected_codes=("never",))
    ], root=tmp_path, output=tmp_path / "r.json", max_output_bytes=8192)
    row = report["cases"][0]
    assert row["status"] == "failed"
    assert row["outcome_code"] == "output_limit_exceeded"
    assert row["stdout_bytes"] <= 16384


def test_json_artifact_is_schema_bound_and_hashed(tmp_path):
    artifact = tmp_path / "proof.json"
    script = "import json;json.dump({'schema':'proof.v1','status':'complete','cases':[1]},open('proof.json','w'));print('DONE')"
    case = CampaignCase("proof", "tamper", (sys.executable, "-c", script), 0,
                        ("DONE",), 5, evidence_files=("proof.json",),
                        evidence_schema="proof.v1", evidence_status="complete",
                        minimum_evidence_cases=1)
    report = run_validation_campaign([case], root=tmp_path, output=tmp_path / "r.json")
    assert report["status"] == "passed"
    assert report["cases"][0]["evidence_hashes"][0]["sha256"]

    artifact.write_text('{"schema":"wrong","status":"complete","cases":[1]}')
    bad = CampaignCase("bad", "tamper", (sys.executable, "-c", "print('DONE')"), 0,
                       ("DONE",), 5, evidence_files=("proof.json",), evidence_schema="proof.v1")
    assert run_validation_campaign([bad], root=tmp_path, output=tmp_path / "bad.json")["status"] == "failed"


def test_stale_preexisting_artifact_is_removed_and_cannot_satisfy_case(tmp_path):
    (tmp_path / "proof.json").write_text('{"schema":"proof.v1","status":"complete","cases":[1]}')
    case = CampaignCase("stale", "tamper", (sys.executable, "-c", "print('DONE')"),
                        0, ("DONE",), 5, evidence_files=("proof.json",),
                        evidence_schema="proof.v1", evidence_status="complete")
    report = run_validation_campaign([case], root=tmp_path, output=tmp_path / "r.json")
    assert report["status"] == "failed"
    assert "evidence_missing:proof.json" in report["cases"][0]["evidence_errors"]


@pytest.mark.parametrize("cases, max_cases", [
    ([], 500),
    ([_case("dup"), _case("dup")], 500),
    ([_case(category="not-allowed")], 500),
    ([_case(timeout_s=0)], 500),
    ([_case()], 0),
])
def test_invalid_contracts_are_rejected(tmp_path, cases, max_cases):
    with pytest.raises(ValueError):
        run_validation_campaign(cases, root=tmp_path, output=tmp_path / "r.json",
                                max_cases=max_cases)


def test_output_must_remain_under_root(tmp_path):
    with pytest.raises(ValueError, match="output_outside_root"):
        run_validation_campaign([_case()], root=tmp_path,
                                output=tmp_path.parent / "escape.json")


def test_tails_are_bounded_and_secrets_redacted(tmp_path):
    script = "print('token=supersecret ' + 'x' * 20000)"
    report = run_validation_campaign([
        _case(script=script, expected_codes=("token=",))
    ], root=tmp_path, output=tmp_path / "r.json")
    tail = report["cases"][0]["stdout_tail"]
    assert "supersecret" not in tail
    assert len(tail) <= 4096


def test_cli_runs_from_checkout_without_pythonpath(tmp_path):
    root = Path(__file__).resolve().parents[1]
    output = root / "output" / "test-validation-campaign.json"
    completed = subprocess.run(
        [sys.executable, str(root / "tools" / "run_validation_campaign.py"),
         "--root", str(root), "--output", str(output)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert completed.returncode == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "passed"
    assert report["summary"]["failed"] == 0
    assert report["summary"]["partial"] == 0


def test_mandatory_matrix_binds_existing_f02_and_f11_campaigns():
    root = Path(__file__).resolve().parents[1]
    commands = [" ".join(case.command) for case in mandatory_cases(root)]
    scripts_present = all((root / "tools" / name).is_file() for name in (
        "f02_fault_campaign.py", "f11_adversarial_campaign.py", "f11_adversarial_cli_campaign.py"))
    if scripts_present:
        assert any("f02_fault_campaign.py" in command for command in commands)
        assert any("f11_adversarial_campaign.py" in command for command in commands)
        assert any("f11_adversarial_cli_campaign.py" in command for command in commands)
    else:
        assert not any("f02_fault_campaign.py" in command for command in commands)
        assert all(case.capability_optional for case in mandatory_cases(root))
    assert not any("CASE_OK:" in command for command in commands)


def test_mandatory_matrix_is_self_contained_when_optional_scripts_are_absent(tmp_path):
    cases = mandatory_cases(tmp_path)
    commands = [" ".join(case.command) for case in cases]
    assert not any("f02_fault_campaign.py" in command for command in commands)
    assert all(case.capability_optional for case in cases)
    report = run_validation_campaign(cases, root=tmp_path, output=tmp_path / "campaign.json")
    assert report["status"] == "partial"
    assert report["summary"]["failed"] == 0
