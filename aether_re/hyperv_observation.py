"""Fail-closed comparison of Hyper-V's live read-only observation to a provision report.

This verifies a bounded snapshot of current host state. It is not a VM
attestation, does not prove historical non-execution, and never promotes a
release gate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PureWindowsPath
import re
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_CHECKPOINT_GUID_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
_PROVISION_SCHEMA = "hyperv-provision-report.v1"
_OBSERVATION_SCHEMA = "hyperv-live-observation.v2"
_RESULT_SCHEMA = "hyperv-current-state-verification.v1"
_MAX_AGE_SECONDS_DEFAULT = 3600


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _path_key(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().replace("/", "\\").rstrip("\\").casefold()


def validate_hyperv_observation(
    provision: dict[str, Any],
    observation: dict[str, Any],
    *,
    now_utc: datetime | None = None,
    max_age_seconds: int = _MAX_AGE_SECONDS_DEFAULT,
) -> dict[str, Any]:
    """Compare provision claims with a fresh, privileged, read-only observation.

    A ``verified_current_state`` result only means that the observed VM, private
    switch, single NIC, differencing disk and checkpoint match the provision
    report at collection time. It is deliberately not a rollback or execution
    attestation.
    """
    limitations = [
        "observacao local sem assinatura de atestador independente",
        "estado atual Off nao prova historicamente que a VM nunca iniciou",
        "checkpoint existente nao prova rollback exercitado",
        "hashes do disco anexado e do VHD provisionado sao registrados; o parent externo nao e re-hashado aqui",
        "resultado nao e elegivel para promover gate ou release",
    ]
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 1:
        return {
            "schema_version": _RESULT_SCHEMA,
            "status": "invalid",
            "summary": {"gate_eligible": False},
            "checks": [],
            "issues": [{"code": "max_age_seconds_invalid"}],
            "limitations": limitations,
        }
    if not isinstance(provision, dict) or not isinstance(observation, dict):
        return {
            "schema_version": _RESULT_SCHEMA,
            "status": "invalid",
            "summary": {"gate_eligible": False},
            "checks": [],
            "issues": [{"code": "documents_must_be_objects"}],
            "limitations": limitations,
        }

    if provision.get("schema_version") != _PROVISION_SCHEMA:
        issues.append({"code": "provision_schema_invalid"})
    if observation.get("schema_version") != _OBSERVATION_SCHEMA:
        issues.append({"code": "observation_schema_invalid"})
    resources = provision.get("resources")
    execution = provision.get("execution")
    collector = observation.get("collector")
    if not isinstance(resources, dict):
        issues.append({"code": "provision_resources_invalid"})
        resources = {}
    if not isinstance(execution, dict):
        issues.append({"code": "provision_execution_invalid"})
        execution = {}
    if not isinstance(collector, dict):
        issues.append({"code": "collector_invalid"})
        collector = {}

    required_provision = ("vm", "switch", "vhd", "checkpoint")
    required_observation = ("vm", "switch", "switch_attachments", "network_adapters", "hard_disk_drives", "disk", "checkpoint")
    expected: dict[str, dict[str, Any]] = {}
    actual: dict[str, Any] = {}
    for field in required_provision:
        value = resources.get(field)
        if not isinstance(value, dict):
            issues.append({"code": "provision_resource_missing_or_invalid", "field": field})
        else:
            expected[field] = value
    for field in required_observation:
        value = observation.get(field)
        if field in {"switch_attachments", "network_adapters", "hard_disk_drives"}:
            if not isinstance(value, list):
                issues.append({"code": "observation_field_invalid", "field": field})
            else:
                actual[field] = value
        elif not isinstance(value, dict):
            issues.append({"code": "observation_field_invalid", "field": field})
        else:
            actual[field] = value
    if issues:
        return {
            "schema_version": _RESULT_SCHEMA,
            "status": "invalid",
            "summary": {"gate_eligible": False},
            "checks": checks,
            "issues": issues,
            "limitations": limitations,
        }

    string_requirements = (
        ("provision.host", provision, "host", "provision_host_invalid"),
        ("provision.vm.id", expected["vm"], "id", "vm_id_invalid"),
        ("provision.vm.name", expected["vm"], "name", "vm_name_invalid"),
        ("provision.vm.state", expected["vm"], "state", "provision_vm_state_invalid"),
        ("provision.switch.id", expected["switch"], "id", "switch_id_invalid"),
        ("provision.switch.name", expected["switch"], "name", "switch_name_invalid"),
        ("provision.switch.type", expected["switch"], "type", "provision_switch_type_invalid"),
        ("provision.vhd.path", expected["vhd"], "path", "disk_path_invalid"),
        ("provision.vhd.parent_path", expected["vhd"], "parent_path", "disk_parent_invalid"),
        ("provision.vhd.type", expected["vhd"], "type", "disk_type_invalid"),
        ("provision.vhd.sha256", expected["vhd"], "sha256", "disk_sha256_invalid"),
        ("provision.checkpoint.id", expected["checkpoint"], "id", "checkpoint_id_invalid"),
        ("provision.checkpoint.name", expected["checkpoint"], "name", "checkpoint_name_invalid"),
        ("provision.checkpoint.state", expected["checkpoint"], "state", "checkpoint_state_invalid"),
        ("collector.host", collector, "host", "collector_host_invalid"),
        ("observation.vm.id", actual["vm"], "id", "vm_id_invalid"),
        ("observation.vm.name", actual["vm"], "name", "observed_vm_name_invalid"),
        ("observation.vm.state", actual["vm"], "state", "observed_vm_state_invalid"),
        ("observation.switch.id", actual["switch"], "id", "switch_id_invalid"),
        ("observation.switch.name", actual["switch"], "name", "switch_name_invalid"),
        ("observation.switch.type", actual["switch"], "type", "observed_switch_type_invalid"),
        ("observation.disk.path", actual["disk"], "path", "disk_path_invalid"),
        ("observation.disk.parent_path", actual["disk"], "parent_path", "disk_parent_invalid"),
        ("observation.disk.type", actual["disk"], "vhd_type", "disk_type_invalid"),
        ("observation.disk.sha256", actual["disk"], "sha256", "disk_sha256_invalid"),
        ("observation.checkpoint.id", actual["checkpoint"], "id", "checkpoint_id_invalid"),
        ("observation.checkpoint.name", actual["checkpoint"], "name", "checkpoint_name_invalid"),
    )
    for label, mapping, field, code in string_requirements:
        value = mapping.get(field)
        if not isinstance(value, str) or not value.strip():
            issues.append({"code": code, "field": label})
    for label, mapping, field in (
        ("provision.vm.generation", expected["vm"], "generation"),
        ("observation.vm.generation", actual["vm"], "generation"),
        ("provision.vhd.virtual_size_bytes", expected["vhd"], "virtual_size_bytes"),
        ("provision.vhd.file_size_bytes", expected["vhd"], "file_size_bytes"),
        ("observation.disk.virtual_size_bytes", actual["disk"], "virtual_size_bytes"),
        ("observation.disk.file_size_bytes", actual["disk"], "file_size_bytes"),
    ):
        value = mapping.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            issues.append({"code": "numeric_field_invalid", "field": label})
    for label, mapping, field in (
        ("collector.is_admin", collector, "is_admin"),
        ("provision.switch.internet_enabled", expected["switch"], "internet_enabled"),
    ):
        if not isinstance(mapping.get(field), bool):
            issues.append({"code": "boolean_field_invalid", "field": label})
    for index, drive in enumerate(actual["hard_disk_drives"]):
        if not isinstance(drive, dict):
            issues.append({"code": "hard_disk_drive_invalid", "index": index})
            continue
        for field in ("path", "parent_path", "vhd_type", "sha256"):
            value = drive.get(field)
            if not isinstance(value, str) or not value.strip():
                issues.append({"code": "hard_disk_drive_invalid", "index": index, "field": field})
        for field in ("virtual_size_bytes", "file_size_bytes"):
            value = drive.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                issues.append({"code": "hard_disk_drive_invalid", "index": index, "field": field})
        if not isinstance(drive.get("sha256"), str) or not _SHA256_RE.fullmatch(drive["sha256"]):
            issues.append({"code": "hard_disk_drive_invalid", "index": index, "field": "sha256"})
    for label, mapping, field in (
        ("provision.vhd.sha256", expected["vhd"], "sha256"),
        ("observation.disk.sha256", actual["disk"], "sha256"),
    ):
        if not isinstance(mapping.get(field), str) or not _SHA256_RE.fullmatch(mapping[field]):
            issues.append({"code": "disk_sha256_invalid", "field": label})
    if issues:
        return {
            "schema_version": _RESULT_SCHEMA,
            "status": "invalid",
            "summary": {"gate_eligible": False},
            "checks": checks,
            "issues": issues,
            "limitations": limitations,
        }

    observed_at = _parse_utc(observation.get("collected_at_utc"))
    if observed_at is None:
        issues.append({"code": "observation_timestamp_invalid"})
    current_time = now_utc if now_utc is not None else datetime.now(timezone.utc)
    if not isinstance(current_time, datetime) or current_time.tzinfo is None:
        issues.append({"code": "now_utc_invalid"})
        current_time = datetime.now(timezone.utc)
    current_time = current_time.astimezone(timezone.utc)
    if observed_at is not None:
        age = (current_time - observed_at).total_seconds()
        if age < -60:
            issues.append({"code": "observation_timestamp_in_future"})
        elif age > max_age_seconds:
            issues.append({"code": "observation_stale", "age_seconds": int(age), "max_age_seconds": max_age_seconds})

    if collector.get("is_admin") is not True:
        issues.append({"code": "collector_not_elevated"})
    expected_host = provision.get("host")
    observed_host = collector.get("host")
    if expected_host.strip().casefold() != observed_host.strip().casefold():
        issues.append({"code": "collector_host_mismatch", "expected": expected_host, "observed": observed_host})

    def check(name: str, code: str, expected_value: Any, observed_value: Any, *, equal: bool | None = None) -> None:
        passed = equal if equal is not None else expected_value == observed_value
        checks.append({"name": name, "status": "pass" if passed else "fail"})
        if not passed:
            issues.append({"code": code, "expected": expected_value, "observed": observed_value})

    if provision.get("status") != "provisioned_offline_pre_execution":
        issues.append({"code": "provision_status_not_pre_execution"})
    for field in ("guest_started", "sample_executed", "rollback_proven"):
        if not isinstance(execution.get(field), bool):
            issues.append({"code": "provision_execution_field_invalid", "field": field})
        elif execution[field] is not False:
            issues.append({"code": "provision_execution_claim_invalid", "field": field})

    exp_vm, obs_vm = expected["vm"], actual["vm"]
    if not isinstance(exp_vm.get("state"), str) or exp_vm["state"].casefold() != "off":
        issues.append({"code": "provision_vm_state_not_off"})
    for key, code in (("id", "vm_id_mismatch"), ("name", "vm_name_mismatch"), ("generation", "vm_generation_mismatch")):
        check(f"vm.{key}", code, exp_vm.get(key), obs_vm.get(key), equal=_same_scalar(exp_vm.get(key), obs_vm.get(key)))
    check("vm.state", "vm_state_not_off", "Off", obs_vm.get("state"), equal=isinstance(obs_vm.get("state"), str) and obs_vm["state"].casefold() == "off")

    exp_switch, obs_switch = expected["switch"], actual["switch"]
    for key, code in (("id", "switch_id_mismatch"), ("name", "switch_name_mismatch")):
        check(f"switch.{key}", code, exp_switch.get(key), obs_switch.get(key), equal=_same_scalar(exp_switch.get(key), obs_switch.get(key)))
    check("switch.type", "switch_not_private", "Private", obs_switch.get("type"), equal=isinstance(obs_switch.get("type"), str) and obs_switch["type"].casefold() == "private")
    if exp_switch.get("internet_enabled") is not False:
        issues.append({"code": "provision_network_claim_not_isolated"})
    if not isinstance(exp_switch.get("type"), str) or exp_switch["type"].casefold() != "private":
        issues.append({"code": "provision_switch_not_private"})

    switch_attachments = actual["switch_attachments"]
    if any(not isinstance(item, dict) for item in switch_attachments):
        issues.append({"code": "switch_attachment_invalid"})
    else:
        target_id = str(exp_vm.get("id", "")).casefold()
        target_attachments = [item for item in switch_attachments if str(item.get("vm_id", "")).casefold() == target_id]
        if not target_attachments:
            issues.append({"code": "switch_attachment_target_missing"})
        if len(switch_attachments) > 1:
            issues.append({"code": "switch_shared_with_other_vm", "attachment_count": len(switch_attachments)})
        if len(target_attachments) == 1:
            target_attachment = target_attachments[0]
            if not _same_scalar(exp_vm.get("name"), target_attachment.get("vm_name")):
                issues.append({"code": "switch_attachment_vm_name_mismatch"})
            if not _same_scalar(exp_switch.get("name"), target_attachment.get("adapter_switch_name")):
                issues.append({"code": "switch_attachment_switch_mismatch"})

    adapters = actual["network_adapters"]
    check("network_adapters.count", "network_adapter_count_invalid", 1, len(adapters))
    if len(adapters) == 1 and isinstance(adapters[0], dict):
        check("network_adapters[0].switch_name", "network_adapter_switch_mismatch", exp_switch.get("name"), adapters[0].get("switch_name"), equal=_same_scalar(exp_switch.get("name"), adapters[0].get("switch_name")))
    elif len(adapters) == 1:
        issues.append({"code": "network_adapter_invalid"})

    disk_drives = actual["hard_disk_drives"]
    check("hard_disk_drives.count", "hard_disk_drive_count_invalid", 1, len(disk_drives))
    if len(disk_drives) == 1 and isinstance(disk_drives[0], dict):
        drive = disk_drives[0]
        expected_path = _path_key(expected["vhd"].get("path"))
        observed_path = _path_key(drive.get("path"))
        direct_attachment = expected_path is not None and expected_path == observed_path
        checkpoint_child = _is_checkpoint_child_path(drive.get("path"), expected["vhd"].get("path"))
        check(
            "hard_disk_drives[0].path",
            "attached_disk_path_mismatch",
            expected_path,
            observed_path,
            equal=direct_attachment or checkpoint_child,
        )
        expected_attached_parent = (
            expected["vhd"].get("parent_path") if direct_attachment else expected["vhd"].get("path")
        )
        check(
            "hard_disk_drives[0].parent_path",
            "attached_disk_parent_mismatch",
            _path_key(expected_attached_parent),
            _path_key(drive.get("parent_path")),
            equal=_path_key(expected_attached_parent) is not None
            and _path_key(expected_attached_parent) == _path_key(drive.get("parent_path")),
        )
        check(
            "hard_disk_drives[0].vhd_type",
            "attached_disk_type_mismatch",
            str(expected["vhd"].get("type", "")).casefold(),
            str(drive.get("vhd_type", "")).casefold(),
        )
        check(
            "hard_disk_drives[0].virtual_size_bytes",
            "attached_disk_virtual_size_mismatch",
            expected["vhd"].get("virtual_size_bytes"),
            drive.get("virtual_size_bytes"),
            equal=_same_scalar(expected["vhd"].get("virtual_size_bytes"), drive.get("virtual_size_bytes")),
        )
        if direct_attachment:
            check(
                "hard_disk_drives[0].file_size_bytes",
                "attached_disk_file_size_mismatch",
                expected["vhd"].get("file_size_bytes"),
                drive.get("file_size_bytes"),
                equal=_same_scalar(expected["vhd"].get("file_size_bytes"), drive.get("file_size_bytes")),
            )
            check(
                "hard_disk_drives[0].sha256",
                "attached_disk_sha256_mismatch",
                expected["vhd"].get("sha256"),
                drive.get("sha256"),
                equal=_same_scalar(expected["vhd"].get("sha256"), drive.get("sha256")),
            )
        else:
            check(
                "hard_disk_drives[0].file_size_bytes",
                "attached_disk_file_size_invalid",
                True,
                isinstance(drive.get("file_size_bytes"), int)
                and not isinstance(drive.get("file_size_bytes"), bool)
                and drive.get("file_size_bytes", 0) > 0,
            )
            check(
                "hard_disk_drives[0].sha256",
                "attached_disk_sha256_invalid",
                True,
                isinstance(drive.get("sha256"), str)
                and _SHA256_RE.fullmatch(drive.get("sha256", "")) is not None,
            )
    elif len(disk_drives) == 1:
        issues.append({"code": "hard_disk_drive_invalid"})

    exp_disk, obs_disk = expected["vhd"], actual["disk"]
    checks_disk = (
        ("path", "disk_path_mismatch", _path_key(exp_disk.get("path")), _path_key(obs_disk.get("path"))),
        ("parent_path", "disk_parent_mismatch", _path_key(exp_disk.get("parent_path")), _path_key(obs_disk.get("parent_path"))),
        ("type", "disk_type_mismatch", str(exp_disk.get("type", "")).casefold(), str(obs_disk.get("vhd_type", "")).casefold()),
        ("virtual_size_bytes", "disk_virtual_size_mismatch", exp_disk.get("virtual_size_bytes"), obs_disk.get("virtual_size_bytes")),
        ("file_size_bytes", "disk_file_size_mismatch", exp_disk.get("file_size_bytes"), obs_disk.get("file_size_bytes")),
        ("sha256", "disk_sha256_mismatch", exp_disk.get("sha256"), obs_disk.get("sha256")),
    )
    for key, code, expected_value, observed_value in checks_disk:
        check(f"disk.{key}", code, expected_value, observed_value, equal=_same_scalar(expected_value, observed_value))
    if not isinstance(obs_disk.get("sha256"), str) or not _SHA256_RE.fullmatch(obs_disk["sha256"]):
        issues.append({"code": "disk_sha256_invalid"})

    exp_checkpoint, obs_checkpoint = expected["checkpoint"], actual["checkpoint"]
    for key, code in (("id", "checkpoint_id_mismatch"), ("name", "checkpoint_name_mismatch")):
        check(f"checkpoint.{key}", code, exp_checkpoint.get(key), obs_checkpoint.get(key), equal=_same_scalar(exp_checkpoint.get(key), obs_checkpoint.get(key)))
    if exp_checkpoint.get("state") != "created_before_any_guest_execution":
        issues.append({"code": "checkpoint_claim_invalid"})
    checkpoint_at = _parse_utc(obs_checkpoint.get("creation_time_utc"))
    if checkpoint_at is None:
        issues.append({"code": "checkpoint_timestamp_invalid"})
    elif observed_at is not None and checkpoint_at > observed_at:
        issues.append({"code": "checkpoint_created_after_observation"})

    malformed_codes = {
        "max_age_seconds_invalid",
        "documents_must_be_objects",
        "provision_schema_invalid",
        "observation_schema_invalid",
        "provision_resources_invalid",
        "provision_execution_invalid",
        "collector_invalid",
        "provision_resource_missing_or_invalid",
        "observation_field_invalid",
        "observation_timestamp_invalid",
        "now_utc_invalid",
        "collector_host_invalid",
        "network_adapter_invalid",
        "disk_sha256_invalid",
        "checkpoint_timestamp_invalid",
        "provision_host_invalid",
        "vm_id_invalid",
        "vm_name_invalid",
        "provision_vm_state_invalid",
        "switch_id_invalid",
        "switch_name_invalid",
        "provision_switch_type_invalid",
        "disk_path_invalid",
        "disk_parent_invalid",
        "disk_type_invalid",
        "disk_sha256_invalid",
        "checkpoint_id_invalid",
        "checkpoint_name_invalid",
        "checkpoint_state_invalid",
        "observed_vm_name_invalid",
        "observed_vm_state_invalid",
        "observed_switch_type_invalid",
        "numeric_field_invalid",
        "boolean_field_invalid",
        "hard_disk_drive_invalid",
        "network_adapter_invalid",
        "switch_attachment_invalid",
        "provision_execution_field_invalid",
    }
    status = "invalid" if any(issue["code"] in malformed_codes for issue in issues) else "refused" if issues else "verified_current_state"
    return {
        "schema_version": _RESULT_SCHEMA,
        "status": status,
        "summary": {
            "vm_id": obs_vm.get("id"),
            "observed_at_utc": observation.get("collected_at_utc"),
            "checks_passed": sum(1 for item in checks if item["status"] == "pass"),
            "checks_failed": sum(1 for item in checks if item["status"] != "pass"),
            "gate_eligible": False,
            "historical_nonexecution_proven": False,
            "rollback_proven": False,
            "parent_hash_rechecked": False,
        },
        "checks": checks,
        "issues": issues,
        "limitations": limitations,
    }


def _same_scalar(expected: Any, observed: Any) -> bool:
    if isinstance(expected, bool) or isinstance(observed, bool):
        return type(expected) is type(observed) and expected == observed
    if isinstance(expected, int) and isinstance(observed, int):
        return expected == observed
    if isinstance(expected, str) and isinstance(observed, str):
        return expected.strip().casefold() == observed.strip().casefold()
    return expected == observed


def _is_checkpoint_child_path(observed_path: Any, expected_vhd_path: Any) -> bool:
    """Accept only Hyper-V's sibling AVHD(X) child directly parented by the locked VHD."""
    if not isinstance(observed_path, str) or not isinstance(expected_vhd_path, str):
        return False
    observed = PureWindowsPath(observed_path.strip())
    expected = PureWindowsPath(expected_vhd_path.strip())
    if _path_key(str(observed.parent)) != _path_key(str(expected.parent)):
        return False
    if observed.suffix.casefold() not in {".avhd", ".avhdx"}:
        return False
    prefix = expected.stem.casefold() + "_"
    if not observed.stem.casefold().startswith(prefix):
        return False
    suffix = observed.stem[len(prefix) :]
    return _CHECKPOINT_GUID_RE.fullmatch(suffix) is not None


def main(argv: list[str] | None = None) -> int:
    """CLI: compare provision and live observation JSON without executing a VM."""
    import argparse
    import hashlib
    import json
    import os
    import sys
    import tempfile
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Verify current Hyper-V state against a provision report.")
    parser.add_argument("--provision-report", required=True)
    parser.add_argument("--observation", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-age-seconds", type=int, default=_MAX_AGE_SECONDS_DEFAULT)
    args = parser.parse_args(argv)

    input_paths = {
        Path(args.provision_report).resolve(strict=False),
        Path(args.observation).resolve(strict=False),
    }
    if Path(args.out).resolve(strict=False) in input_paths:
        print("verification output must not overwrite either input document", file=sys.stderr)
        return 2

    try:
        documents = []
        input_hashes: list[str] = []

        def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_json_key")
                result[key] = value
            return result

        def reject_non_json_constant(value: str) -> None:
            raise ValueError("non_json_constant")

        for label, path in (("provision", args.provision_report), ("observation", args.observation)):
            input_path = Path(path)
            size_before = input_path.stat().st_size
            if size_before > 16 * 1024 * 1024:
                raise ValueError(f"{label}_document_too_large")
            raw = input_path.read_bytes()
            if len(raw) > 16 * 1024 * 1024 or len(raw) != size_before:
                raise ValueError(f"{label}_document_changed_during_read")
            input_hashes.append(hashlib.sha256(raw).hexdigest())
            documents.append(json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicate_pairs,
                parse_constant=reject_non_json_constant,
            ))
        result = validate_hyperv_observation(documents[0], documents[1], max_age_seconds=args.max_age_seconds)
        result["summary"].update({
            "provision_report_sha256": input_hashes[0],
            "observation_sha256": input_hashes[1],
        })
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        result = {
            "schema_version": _RESULT_SCHEMA,
            "status": "invalid",
            "summary": {"gate_eligible": False},
            "checks": [],
            "issues": [{"code": "input_read_failed", "detail": str(exc)[:500]}],
            "limitations": ["input errors never authorize a release gate"],
        }

    output_path = Path(args.out)
    temp_name: str | None = None
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=output_path.parent, prefix=output_path.name + ".", suffix=".tmp", delete=False) as stream:
            temp_name = stream.name
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, output_path)
    except OSError as exc:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        print(f"verification result write failed: {exc}", file=sys.stderr)
        return 2

    passed = result.get("summary", {}).get("checks_passed", 0)
    failed = result.get("summary", {}).get("checks_failed", 0)
    print(f"Hyper-V observation: status={result['status']} checks={passed}/{passed + failed} out={output_path}")
    return 0 if result["status"] == "verified_current_state" else 3 if result["status"] == "refused" else 2


if __name__ == "__main__":
    raise SystemExit(main())
