from pathlib import Path


def test_nocloud_preparation_uses_new_image_and_preserves_original_vm_evidence():
    root = Path(__file__).resolve().parents[1]
    script = (root / "tools" / "hyperv_prepare_nocloud.ps1").read_text(encoding="utf-8")

    assert "#Requires -RunAsAdministrator" in script
    assert "AetherRE-Ubuntu-Noble-85907e22" in script
    assert "AetherRE-Private-85907e22" in script
    assert "SwitchType -ne 'Private'" in script
    assert "participants.Count -ne 1" in script
    assert "Refusing to overwrite an existing derived image" in script
    assert "Refusing to overwrite an existing provision report" in script
    assert "New-VHD -Path $sourceChildDiskPath -ParentPath $sourceParentPath -Differencing" in script
    assert "historical_materialization_provenance_reused_not_rehashed" in script
    assert "$parentItem.Length -ne [Int64]$provision.source.length_bytes" in script
    assert "$sourceParent.Size -ne [Int64]$provision.resources.vhd.virtual_size_bytes" in script
    assert "wsl.exe --mount $physicalDrivePath --bare" in script
    assert "wsl.exe --unmount $physicalDrivePath" in script
    assert "Mount-VHD -Path $sourceChildDiskPath -Passthru" in script
    assert "Set-VMHardDiskDrive -VMHardDiskDrive $currentRoot -Path $sourceChildDiskPath" in script
    assert "derived_boot_disk_sha256" in script
    assert "derived_boot_vhdx_sha256" not in script
    assert "[string]$derived.VhdFormat -ne 'VHD'" in script
    assert "Convert-VHD -Path $sourceParentPath" not in script
    assert "Get-FileHash -LiteralPath $sourceParentPath" not in script
    assert "datasource_list: [ NoCloud, Azure ]" in script
    assert "datasource_list: [ NoCloud, Azure ]" in script
    assert "Set-VMHardDiskDrive -VMHardDiskDrive $currentRoot -Path $sourceChildDiskPath" in script
    assert "Checkpoint-VM -Name $vmName -SnapshotName $preExecutionName" in script
    assert "provisioned_offline_pre_execution" in script
    assert "Start-VM" not in script
    assert "New-VMSwitch" not in script
    assert "Connect-VMNetworkAdapter" not in script
    assert "Remove-VMHardDiskDrive" not in script
    assert "Remove-VMSnapshot" not in script


def test_nocloud_preparation_launcher_uses_standard_uac_only():
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "tools" / "hyperv_prepare_nocloud.bat").read_text(encoding="utf-8")

    assert "-Verb RunAs" in launcher
    assert "Set-ExecutionPolicy" not in launcher
    assert "hyperv_prepare_nocloud.ps1" in launcher
