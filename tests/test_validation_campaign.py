from __future__ import annotations

import json
import os
import sys
import subprocess
from pathlib import Path

import pytest

from aether_re.validation_campaign import CampaignCase, run_validation_campaign


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
              expected_codes=("CAPABILITY_UNAVAILABLE",))
    ], root=tmp_path, output=tmp_path / "r.json")
    assert report["status"] == "partial"
    assert report["summary"]["partial"] == 1


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
    assert completed.returncode == 3
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "partial"
