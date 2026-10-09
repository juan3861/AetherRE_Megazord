import json

from aether_re.hyperv_preflight import inspect_hyperv_lab


def _runner_ok(argv, timeout_s):
    assert argv[:4] == ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive"]
    assert timeout_s == 15
    return 0, json.dumps({
        "module_available": True,
        "service_status": "Running",
        "host": {"name": "LABHOST", "virtualization_namespace": True},
        "vms": [{
            "id": "vm-id", "name": "AetherRE-Windows", "state": "Off",
            "generation": 2, "checkpoint_type": "Standard",
            "checkpoints": [{"id": "cp-id", "name": "clean"}],
            "adapters": [{"switch_name": "AetherRE-Isolated", "connected": True}],
            "disks": [{"path": "E:\\VMs\\diff.avhdx", "type": "Differencing"}],
        }],
        "switches": [{"name": "AetherRE-Isolated", "type": "Private"}],
    }), ""


def test_hyperv_preflight_requires_real_off_vm_checkpoint_private_switch_and_disposable_disk():
    report = inspect_hyperv_lab("AetherRE-Windows", "clean", runner=_runner_ok)
    assert report["status"] == "ready"
    assert report["qualified"] is False
    assert report["execution"] is False
    assert report["facts"]["vm_id"] == "vm-id"
    assert report["facts"]["checkpoint_id"] == "cp-id"
    assert report["limitations"]


def test_hyperv_preflight_fails_closed_when_vm_is_absent():
    def runner(argv, timeout_s):
        code, stdout, stderr = _runner_ok(argv, timeout_s)
        payload = json.loads(stdout)
        payload["vms"] = []
        return code, json.dumps(payload), stderr

    report = inspect_hyperv_lab("missing", "clean", runner=runner)
    assert report["status"] == "blocked"
    assert "vm_not_found" in report["blocking_reasons"]


def test_hyperv_preflight_reports_an_observable_empty_host_as_missing_vm_not_inventory_failure():
    def runner(_argv, _timeout_s):
        return 0, json.dumps({
            "module_available": True,
            "service_status": "Running",
            "host": {"name": "LABHOST", "virtualization_namespace": True},
            "vms": [], "switches": [],
            "inventory_warnings": ["Get-VM unavailable"],
        }), ""

    report = inspect_hyperv_lab("AetherRE-Windows", "clean", runner=runner)
    assert report["status"] == "blocked"
    assert report["blocking_reasons"] == ["vm_not_found"]


def test_hyperv_preflight_rejects_external_or_default_switch_and_fixed_disk():
    def runner(argv, timeout_s):
        code, stdout, stderr = _runner_ok(argv, timeout_s)
        payload = json.loads(stdout)
        payload["switches"][0]["type"] = "External"
        payload["vms"][0]["disks"][0]["type"] = "Fixed"
        return code, json.dumps(payload), stderr

    report = inspect_hyperv_lab("AetherRE-Windows", "clean", runner=runner)
    assert report["status"] == "blocked"
    assert {"network_not_isolated", "disposable_disk_not_proven"} <= set(report["blocking_reasons"])


def test_hyperv_preflight_rejects_ambiguous_names_and_command_failures():
    def duplicate_runner(argv, timeout_s):
        code, stdout, stderr = _runner_ok(argv, timeout_s)
        payload = json.loads(stdout)
        payload["vms"].append(dict(payload["vms"][0], id="vm-id-2"))
        return code, json.dumps(payload), stderr

    assert "vm_name_ambiguous" in inspect_hyperv_lab("AetherRE-Windows", "clean", runner=duplicate_runner)["blocking_reasons"]
    failed = inspect_hyperv_lab("vm", "cp", runner=lambda _a, _t: (1, "", "access denied"))
    assert failed["status"] == "blocked"
    assert failed["blocking_reasons"] == ["hyperv_inventory_failed"]
    assert "access denied" not in json.dumps(failed).lower()


def test_hyperv_preflight_validates_inputs_without_invoking_powershell():
    invoked = False

    def runner(_argv, _timeout):
        nonlocal invoked
        invoked = True
        raise AssertionError

    report = inspect_hyperv_lab(" ", "clean", runner=runner)
    assert report["blocking_reasons"] == ["vm_name_invalid"]
    assert invoked is False
