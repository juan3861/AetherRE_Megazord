"""Read-only Hyper-V inventory gate for the dynamic lab.

This module deliberately does not start, stop, checkpoint, or restore a VM.
It only establishes whether the physical prerequisites are observable.  A
successful preflight is never a qualification or rollback attestation.
"""
from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from typing import Any


Runner = Callable[[Sequence[str], int], tuple[int, str, str]]


_INVENTORY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$module = [bool](Get-Module -ListAvailable -Name Hyper-V)
$service = Get-Service -Name vmms -ErrorAction Stop
$vms = @()
# Some hosts expose the Hyper-V WMI namespace even when the PowerShell cmdlets
# fail during an empty inventory (observed on a freshly enabled host).  Do not
# turn that into a misleading "inventory failed" result: an empty, observable
# inventory is useful fail-closed evidence that no lab guest is registered.
$vmCmdletError = $null
try { $vmCandidates = @(Get-VM -ErrorAction Stop) } catch { $vmCmdletError = $_.Exception.Message; $vmCandidates = @() }
foreach ($vm in $vmCandidates) {
  $checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ id = [string]$_.Id; name = [string]$_.Name }
  })
  $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ switch_name = [string]$_.SwitchName; connected = [bool]$_.Connected }
  })
  $disks = @(Get-VMHardDiskDrive -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {
    $kind = $null
    try { $kind = [string](Get-VHD -Path $_.Path -ErrorAction Stop).VhdType } catch {}
    [ordered]@{ path = [string]$_.Path; type = $kind }
  })
  $vms += [ordered]@{
    id = [string]$vm.Id; name = [string]$vm.Name; state = [string]$vm.State
    generation = [int]$vm.Generation; checkpoint_type = [string]$vm.CheckpointType
    checkpoints = $checkpoints; adapters = $adapters; disks = $disks
  }
}
$switchCmdletError = $null
try { $switchCandidates = @(Get-VMSwitch -ErrorAction Stop) } catch { $switchCmdletError = $_.Exception.Message; $switchCandidates = @() }
$switches = @($switchCandidates | ForEach-Object {
  [ordered]@{ name = [string]$_.Name; type = [string]$_.SwitchType }
})
[ordered]@{
  module_available = $module; service_status = [string]$service.Status
  host = [ordered]@{ name = $env:COMPUTERNAME; virtualization_namespace = $true }
  vms = $vms; switches = $switches
  inventory_warnings = @($vmCmdletError, $switchCmdletError | Where-Object { $_ })
} | ConvertTo-Json -Depth 8 -Compress
"""


def _default_runner(argv: Sequence[str], timeout_s: int) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            list(argv), capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout_s, check=False, shell=False,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 127, "", ""


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "schema": "hyperv-lab-preflight.v1", "status": "blocked",
        "qualified": False, "execution": False, "facts": {},
        "blocking_reasons": [reason],
        "limitations": [
            "read-only inventory does not execute a guest",
            "read-only inventory does not prove trace capture or rollback",
            "qualification requires signed run evidence bound to a lease and nonce",
        ],
    }


def inspect_hyperv_lab(
    vm_name: str, checkpoint_name: str, *, runner: Runner = _default_runner,
    timeout_s: int = 15,
) -> dict[str, Any]:
    """Inventory an exact Hyper-V VM/checkpoint pair and fail closed."""
    if not isinstance(vm_name, str) or not vm_name.strip():
        return _blocked("vm_name_invalid")
    if not isinstance(checkpoint_name, str) or not checkpoint_name.strip():
        return _blocked("checkpoint_name_invalid")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int) or not 1 <= timeout_s <= 120:
        return _blocked("timeout_invalid")

    argv = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _INVENTORY_SCRIPT]
    try:
        returncode, stdout, _stderr = runner(argv, timeout_s)
    except Exception:
        return _blocked("hyperv_inventory_failed")
    if returncode != 0:
        return _blocked("hyperv_inventory_failed")
    try:
        inventory = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return _blocked("hyperv_inventory_invalid")
    if not isinstance(inventory, dict):
        return _blocked("hyperv_inventory_invalid")

    reasons: list[str] = []
    if inventory.get("module_available") is not True:
        reasons.append("hyperv_module_unavailable")
    if inventory.get("service_status") != "Running":
        reasons.append("hyperv_service_not_running")
    vms = inventory.get("vms")
    if not isinstance(vms, list):
        return _blocked("hyperv_inventory_invalid")
    matches = [vm for vm in vms if isinstance(vm, dict) and vm.get("name") == vm_name.strip()]
    if not matches:
        reasons.append("vm_not_found")
        vm: dict[str, Any] = {}
    elif len(matches) != 1:
        reasons.append("vm_name_ambiguous")
        vm = {}
    else:
        vm = matches[0]

    checkpoints = vm.get("checkpoints", [])
    cp_matches = [cp for cp in checkpoints if isinstance(cp, dict) and cp.get("name") == checkpoint_name.strip()] if isinstance(checkpoints, list) else []
    if vm and len(cp_matches) != 1:
        reasons.append("checkpoint_not_found" if not cp_matches else "checkpoint_name_ambiguous")
    checkpoint = cp_matches[0] if len(cp_matches) == 1 else {}
    if vm and vm.get("state") != "Off":
        reasons.append("vm_must_be_off_for_baseline")

    switches = inventory.get("switches", [])
    switch_types = {s.get("name"): s.get("type") for s in switches if isinstance(s, dict)} if isinstance(switches, list) else {}
    adapters = vm.get("adapters", [])
    isolated = bool(adapters) and all(
        isinstance(adapter, dict) and adapter.get("connected") is True
        and switch_types.get(adapter.get("switch_name")) in {"Private", "Internal"}
        for adapter in adapters
    )
    if vm and not isolated:
        reasons.append("network_not_isolated")
    disks = vm.get("disks", [])
    disposable = bool(disks) and all(
        isinstance(disk, dict) and str(disk.get("type", "")).casefold() == "differencing"
        for disk in disks
    )
    if vm and not disposable:
        reasons.append("disposable_disk_not_proven")

    return {
        "schema": "hyperv-lab-preflight.v1",
        "status": "ready" if not reasons else "blocked",
        "qualified": False,
        "execution": False,
        "facts": {
            "host": (inventory.get("host") or {}).get("name") if isinstance(inventory.get("host"), dict) else None,
            "vm_id": vm.get("id"), "vm_name": vm.get("name"), "vm_state": vm.get("state"),
            "checkpoint_id": checkpoint.get("id"), "checkpoint_name": checkpoint.get("name"),
            "network_isolated": isolated, "disposable_disk": disposable,
        },
        "blocking_reasons": reasons,
        "limitations": [
            "read-only inventory does not execute a guest",
            "read-only inventory does not prove trace capture or rollback",
            "qualification requires signed run evidence bound to a lease and nonce",
        ],
    }


__all__ = ["inspect_hyperv_lab"]
