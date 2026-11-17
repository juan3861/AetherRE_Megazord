from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


def _api():
    if importlib.util.find_spec("aether_re.hyperv_observation") is None:
        pytest.fail("Hyper-V observation verifier is not implemented")
    return importlib.import_module("aether_re.hyperv_observation")


def _reports():
    provision = {
        "schema_version": "hyperv-provision-report.v1",
        "status": "provisioned_offline_pre_execution",
        "host": "LAB-HOST",
        "execution": {
            "guest_started": False,
            "sample_executed": False,
            "rollback_proven": False,
        },
        "resources": {
            "vm": {
                "id": "88ac73d9-76e7-429f-a8ac-51c08a53fa60",
                "name": "AetherRE-Ubuntu-Noble-test",
                "state": "Off",
                "generation": 1,
            },
            "switch": {
                "id": "b2156506-91ff-4674-9ca1-da42b22b510c",
                "name": "AetherRE-Private-test",
                "type": "Private",
                "internet_enabled": False,
            },
            "vhd": {
                "path": r"E:\AetherRE_DynamicLab\guests\test\ubuntu-diff.vhd",
                "parent_path": r"E:\AetherRE_DynamicLab\parents\ubuntu.vhd",
                "type": "Differencing",
                "virtual_size_bytes": 32_213_303_296,
                "file_size_bytes": 143_360,
                "sha256": "5a809dac89161cc4154cc07a1a11033ac035879a627fc887c54189f646040873",
            },
            "checkpoint": {
                "id": "4a8cd557-8f02-47c6-9bee-b146d67fc9c8",
                "name": "pre-execution-test",
                "state": "created_before_any_guest_execution",
            },
        },
    }
    observation = {
        "schema_version": "hyperv-live-observation.v2",
        "collected_at_utc": "2026-10-12T19:00:00Z",
        "collector": {
            "host": "LAB-HOST",
            "is_admin": True,
            "powershell_version": "5.1",
        },
        "vm": {
            "id": "88ac73d9-76e7-429f-a8ac-51c08a53fa60",
            "name": "AetherRE-Ubuntu-Noble-test",
            "state": "Off",
            "generation": 1,
        },
        "switch": {
            "id": "b2156506-91ff-4674-9ca1-da42b22b510c",
            "name": "AetherRE-Private-test",
            "type": "Private",
        },
        "switch_attachments": [
            {
                "vm_id": "88ac73d9-76e7-429f-a8ac-51c08a53fa60",
                "vm_name": "AetherRE-Ubuntu-Noble-test",
                "adapter_switch_name": "AetherRE-Private-test",
            }
        ],
        "network_adapters": [
            {"switch_name": "AetherRE-Private-test", "mac_address": "00155D123456"}
        ],
        "hard_disk_drives": [
            {
                "path": r"E:\AetherRE_DynamicLab\guests\test\ubuntu-diff.vhd",
                "parent_path": r"E:\AetherRE_DynamicLab\parents\ubuntu.vhd",
                "vhd_type": "Differencing",
                "virtual_size_bytes": 32_213_303_296,
                "file_size_bytes": 143_360,
                "sha256": "5a809dac89161cc4154cc07a1a11033ac035879a627fc887c54189f646040873",
            }
        ],
        "disk": {
            "path": r"E:\AetherRE_DynamicLab\guests\test\ubuntu-diff.vhd",
            "parent_path": r"E:\AetherRE_DynamicLab\parents\ubuntu.vhd",
            "vhd_type": "Differencing",
            "virtual_size_bytes": 32_213_303_296,
            "file_size_bytes": 143_360,
            "sha256": "5a809dac89161cc4154cc07a1a11033ac035879a627fc887c54189f646040873",
        },
        "checkpoint": {
            "id": "4a8cd557-8f02-47c6-9bee-b146d67fc9c8",
            "name": "pre-execution-test",
            "creation_time_utc": "2026-10-12T18:54:37Z",
        },
    }
    return provision, observation


def test_matching_live_observation_verifies_only_current_state_not_history():
    validate = _api().validate_hyperv_observation
    provision, observation = _reports()

    result = validate(
        provision,
        observation,
        now_utc=datetime(2026, 10, 12, 19, 5, tzinfo=timezone.utc),
    )

    assert result["status"] == "verified_current_state"
    assert result["summary"]["gate_eligible"] is False


def test_checkpoint_child_disk_is_linked_to_the_provisioned_vhd_by_parent_path():
    validate = _api().validate_hyperv_observation
    provision, observation = _reports()
    provisioned_vhd = provision["resources"]["vhd"]["path"]
    observation["hard_disk_drives"] = [{
        "path": provisioned_vhd.replace(".vhd", "_01234567-89ab-cdef-0123-456789abcdef.avhd"),
        "parent_path": provisioned_vhd,
        "vhd_type": "Differencing",
        "virtual_size_bytes": provision["resources"]["vhd"]["virtual_size_bytes"],
        "file_size_bytes": 143_360,
        "sha256": "a" * 64,
    }]

    result = validate(
        provision,
        observation,
        now_utc=datetime(2026, 10, 12, 19, 5, tzinfo=timezone.utc),
    )

    assert result["status"] == "verified_current_state"
    assert "attached_disk_path_mismatch" not in {
        issue["code"] for issue in result["issues"]
    }


@pytest.mark.parametrize(
    ("path", "parent_path", "issue_code"),
    [
        (
            r"E:\AetherRE_DynamicLab\guests\test\ubuntu-diff_01234567-89ab-cdef-0123-456789abcdef.avhd",
            r"E:\unexpected\parent.vhd",
            "attached_disk_parent_mismatch",
        ),
        (
            r"E:\outside\ubuntu-diff_01234567-89ab-cdef-0123-456789abcdef.avhd",
            r"E:\AetherRE_DynamicLab\guests\test\ubuntu-diff.vhd",
            "attached_disk_path_mismatch",
        ),
    ],
)
def test_checkpoint_child_must_be_a_sibling_and_have_exact_parent(path, parent_path, issue_code):
    validate = _api().validate_hyperv_observation
    provision, observation = _reports()
    observation["hard_disk_drives"][0].update(path=path, parent_path=parent_path)

    result = validate(
        provision,
        observation,
        now_utc=datetime(2026, 10, 12, 19, 5, tzinfo=timezone.utc),
    )

    assert result["status"] == "refused"
    assert issue_code in {issue["code"] for issue in result["issues"]}


def test_cli_rejects_duplicate_json_keys(tmp_path):
    module = _api()
    _, observation = _reports()
    observation["collected_at_utc"] = datetime.now(timezone.utc).isoformat()
    provision_path = tmp_path / "provision-duplicate.json"
    observation_path = tmp_path / "observation.json"
    result_path = tmp_path / "verification.json"
    provision_path.write_text(
        '{"schema_version":"wrong","schema_version":"hyperv-provision-report.v1"}',
        encoding="utf-8",
    )
    observation_path.write_text(json.dumps(observation), encoding="utf-8")

    code = module.main([
        "--provision-report", str(provision_path),
        "--observation", str(observation_path),
        "--out", str(result_path),
    ])

    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert code == 2
    assert result["status"] == "invalid"
    assert result["issues"][0]["code"] == "input_read_failed"


@pytest.mark.parametrize(
    ("mutate", "issue_code"),
    [
        (lambda p, o: o["vm"].update(state="Running"), "vm_state_not_off"),
        (lambda p, o: o["vm"].update(id="different-vm"), "vm_id_mismatch"),
        (lambda p, o: o["switch"].update(type="External"), "switch_not_private"),
        (lambda p, o: p["resources"]["switch"].update(type="External"), "provision_switch_not_private"),
        (lambda p, o: o["switch_attachments"].append({"vm_id": "other", "vm_name": "Other", "adapter_switch_name": "AetherRE-Private-test"}), "switch_shared_with_other_vm"),
        (lambda p, o: o["switch_attachments"].clear(), "switch_attachment_target_missing"),
        (lambda p, o: o["network_adapters"].append(dict(o["network_adapters"][0])), "network_adapter_count_invalid"),
        (lambda p, o: o["hard_disk_drives"][0].update(path=r"E:\unexpected.vhd"), "attached_disk_path_mismatch"),
        (lambda p, o: o["disk"].update(sha256="0" * 64), "disk_sha256_mismatch"),
        (lambda p, o: o["checkpoint"].update(id="different-checkpoint"), "checkpoint_id_mismatch"),
    ],
)
def test_observation_mismatches_fail_closed(mutate, issue_code):
    validate = _api().validate_hyperv_observation
    provision, observation = _reports()
    mutate(provision, observation)

    result = validate(
        provision,
        observation,
        now_utc=datetime(2026, 10, 12, 19, 5, tzinfo=timezone.utc),
    )

    assert result["status"] == "refused"
    assert issue_code in {issue["code"] for issue in result["issues"]}


def test_unprivileged_or_stale_observation_is_refused():
    validate = _api().validate_hyperv_observation
    provision, observation = _reports()
    observation["collector"]["is_admin"] = False

    unprivileged = validate(
        provision,
        observation,
        now_utc=datetime(2026, 10, 12, 19, 5, tzinfo=timezone.utc),
    )
    assert unprivileged["status"] == "refused"
    assert "collector_not_elevated" in {issue["code"] for issue in unprivileged["issues"]}

    _, stale_observation = _reports()
    stale = validate(
        provision,
        stale_observation,
        now_utc=datetime(2026, 10, 13, 20, 0, tzinfo=timezone.utc),
    )
    assert stale["status"] == "refused"
    assert "observation_stale" in {issue["code"] for issue in stale["issues"]}


def test_malformed_observation_is_invalid_without_exception():
    validate = _api().validate_hyperv_observation

    result = validate({"schema_version": "wrong"}, {"schema_version": "wrong"})

    assert result["status"] == "invalid"
    assert result["issues"]


def test_missing_identity_field_cannot_match_missing_value_on_both_sides():
    validate = _api().validate_hyperv_observation
    provision, observation = _reports()
    provision["resources"]["vm"].pop("id")
    observation["vm"].pop("id")

    result = validate(
        provision,
        observation,
        now_utc=datetime(2026, 10, 12, 19, 5, tzinfo=timezone.utc),
    )

    assert result["status"] == "invalid"
    assert "vm_id_invalid" in {issue["code"] for issue in result["issues"]}


def test_cli_verifies_documents_and_writes_machine_readable_result(tmp_path):
    module = _api()
    provision, observation = _reports()
    observation["collected_at_utc"] = datetime.now(timezone.utc).isoformat()
    provision_path = tmp_path / "provision.json"
    observation_path = tmp_path / "observation.json"
    result_path = tmp_path / "verification.json"
    provision_path.write_text(json.dumps(provision), encoding="utf-8")
    observation_path.write_text(json.dumps(observation), encoding="utf-8")

    code = module.main([
        "--provision-report", str(provision_path),
        "--observation", str(observation_path),
        "--out", str(result_path),
    ])

    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert code == 0
    assert result["status"] == "verified_current_state"
    assert result["summary"]["gate_eligible"] is False
    assert result["summary"]["historical_nonexecution_proven"] is False
    assert result["summary"]["rollback_proven"] is False
    assert result["summary"]["provision_report_sha256"] == hashlib.sha256(provision_path.read_bytes()).hexdigest()
    assert result["summary"]["observation_sha256"] == hashlib.sha256(observation_path.read_bytes()).hexdigest()
    assert all(check["status"] == "pass" for check in result["checks"])


def test_cli_refuses_output_that_would_overwrite_an_input(tmp_path):
    module = _api()
    provision, observation = _reports()
    observation["collected_at_utc"] = datetime.now(timezone.utc).isoformat()
    provision_path = tmp_path / "provision.json"
    observation_path = tmp_path / "observation.json"
    provision_path.write_text(json.dumps(provision), encoding="utf-8")
    observation_path.write_text(json.dumps(observation), encoding="utf-8")
    original = provision_path.read_bytes()

    code = module.main([
        "--provision-report", str(provision_path),
        "--observation", str(observation_path),
        "--out", str(provision_path),
    ])

    assert code == 2
    assert provision_path.read_bytes() == original


def test_megazord_exposes_the_current_state_verifier(tmp_path, monkeypatch):
    import megazord

    provision, observation = _reports()
    observation["collected_at_utc"] = datetime.now(timezone.utc).isoformat()
    provision_path = tmp_path / "provision.json"
    observation_path = tmp_path / "observation.json"
    result_path = tmp_path / "verification.json"
    provision_path.write_text(json.dumps(provision), encoding="utf-8")
    observation_path.write_text(json.dumps(observation), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "megazord", "hyperv-observation-verify",
        "--provision-report", str(provision_path),
        "--observation", str(observation_path),
        "--out", str(result_path),
    ])

    assert megazord.main() == 0
    assert json.loads(result_path.read_text(encoding="utf-8"))["status"] == "verified_current_state"


def test_powershell_collector_is_read_only_for_vm_state():
    path = Path(__file__).parents[1] / "tools" / "hyperv_observe.ps1"
    assert path.is_file(), "read-only Hyper-V observation collector is not implemented"
    source = path.read_text(encoding="utf-8").casefold()
    for forbidden in ("start-vm", "stop-vm", "restore-vm", "checkpoint-vm", "remove-vm", "remove-vhd"):
        assert forbidden not in source
    for required in ("get-vm", "get-vmswitch", "get-vhd", "get-vmsnapshot", "get-vmnetworkadapter", "get-vmharddiskdrive"):
        assert required in source
    for required in ("parent_path", "vhd_type", "virtual_size_bytes", "file_size_bytes", "sha256"):
        assert required in source
    assert "hyperv-live-observation.v2" in source


def test_one_click_launcher_uses_visible_uac_and_keeps_evidence_on_e_drive():
    path = Path(__file__).parents[1] / "tools" / "hyperv_observe_and_verify.bat"
    assert path.is_file(), "clickable read-only Hyper-V verification launcher is not implemented"
    source = path.read_text(encoding="utf-8").casefold()
    assert "start-process" in source and "-verb runas" in source
    assert "-windowstyle normal" in source
    assert "-executionpolicy bypass" not in source
    assert "hyperv_observe.ps1" in source
    assert "hyperv-observation-verify" in source
    assert "e:\\aetherre_evidence" in source


def test_hyperv_observer_scripts_are_not_excluded_from_git():
    root = Path(__file__).parents[1]
    for relative in ("tools/hyperv_observe.ps1", "tools/hyperv_observe_and_verify.bat"):
        result = subprocess.run(
            ["git", "check-ignore", "-q", relative],
            cwd=root,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 1, f"{relative} is ignored and would be lost from a clean checkout"
