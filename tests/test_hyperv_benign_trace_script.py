from pathlib import Path


def test_hyperv_benign_runner_is_pinned_bounded_and_always_restores_checkpoint():
    root = Path(__file__).resolve().parents[1]
    script = (root / "tools" / "hyperv_benign_trace_run.ps1").read_text(encoding="utf-8")

    assert "#Requires -RunAsAdministrator" in script
    assert "AetherRE-Ubuntu-Noble-85907e22" in script
    assert "AetherRE-Private-85907e22" in script
    assert "SwitchType -ne 'Private'" in script
    assert "switchParticipants.Count -ne 1" in script
    assert "6.8-0ubuntu2" in script
    assert "LGPL-2.1-or-later" in script
    assert "d588810ae26b06fee6678dc81e5b54f6efcde8e718e4589adb4d11d254b9820b" in script
    assert "825cb8724bb6b3389587e30c03ab3381f56a2422cafe3b1945f37e055c65e942" in script
    assert "trace-import-strace" in script
    assert "Restore-VMCheckpoint" in script
    assert "function Confirm-CheckpointRollback" in script
    assert "Get-Volume -Partition" in script
    assert "Where-Object { $_.Type -eq 'Basic' }" not in script
    assert "cloudinit-bootcmd.txt" in script
    assert "umount /mnt/aetherre-boot" in script
    assert "dsmode: local" in script
    assert "guest_boot_observed" in script
    assert "cloud-localds -f iso" in script
    assert "sha256sum /usr/bin/cloud-localds /usr/bin/genisoimage" in script
    assert "Volume id:\\s*cidata" in script
    assert "Add-VMDvdDrive" in script and "Set-VMDvdDrive" in script
    assert "AETHERSEED" in script and "payload_vhd" in script
    assert "seedVhdPath" not in script
    assert script.count("Confirm-CheckpointRollback -VmName") >= 2
    assert "$report.rollback_proven = [bool]$rollbackAttestation.verified" in script
    assert "$report.status = 'running_local_qualification'" in script
    assert "[DateTime]::Parse($report.vm.started_at_utc).ToUniversalTime()" in script
    assert "Save-RunReport" in script[script.index("$report.guest_started = $true"):]
    assert "Start-Sleep -Seconds 5" in script
    assert "Add-VMNetworkAdapter" not in script
    assert "Connect-VMNetworkAdapter" not in script


def test_hyperv_benign_runner_bat_uses_standard_uac_without_persisting_policy_changes():
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "tools" / "hyperv_benign_trace_run.bat").read_text(encoding="utf-8")

    assert "-Verb RunAs" in launcher
    assert "Set-ExecutionPolicy" not in launcher
    assert "hyperv_benign_trace_run.ps1" in launcher
