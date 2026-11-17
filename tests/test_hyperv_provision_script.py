from pathlib import Path
import json
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
PS1 = (ROOT / "tools" / "hyperv_provision.ps1").read_text(encoding="utf-8")
BAT = (ROOT / "tools" / "hyperv_provision.bat").read_text(encoding="utf-8")


def test_launcher_uses_normal_visible_uac_and_does_not_bypass_execution_policy():
    assert "Start-Process" in BAT
    assert "-Verb RunAs" in BAT
    assert "-WindowStyle Hidden" not in BAT
    assert "ExecutionPolicy Bypass" not in BAT
    assert "-ExecutionPolicy" not in BAT
    assert "hyperv_provision.ps1" in BAT
    assert "[char]34" in BAT


def test_provisioner_checks_host_features_privileges_space_and_source_hash():
    for required in (
        "WindowsBuiltInRole]::Administrator",
        "Get-WindowsOptionalFeature -Online",
        "Get-Service -Name 'vmms'",
        "Win32_ComputerSystem",
        "VirtualizationFirmwareEnabled",
        "AvailableFreeSpace",
        "Get-FileSha256Fast -Path $sourceVhd",
        "Get-VHD -Path $sourceVhd -ComputerName localhost",
    ):
        assert required in PS1
    assert r"E:\AetherRE_DynamicLab\vm-images\ubuntu-noble-20260926\livecd.ubuntu-cpc.azure.vhd" in PS1
    assert r"E:\AetherRE_DynamicLab\ubuntu-noble-20260926\noble-server-cloudimg-amd64-azure.vhd.tar.gz" in PS1
    assert "3543723afd820d7a8a64ea7399376856a95ce15200439c38447170652a60a5f3" in PS1
    assert "Get-FileSha256Fast -Path $sourceArchive" in PS1
    assert "FileOptions]::SequentialScan" in PS1
    assert "$bufferSize = 8MB" in PS1


def test_active_hypervisor_does_not_fail_on_wmi_firmware_flag_masked_by_hypervisor():
    assert "if (-not $report.preflight.hypervisor_present) {" in PS1
    assert "if (-not $report.preflight.firmware_virtualization_enabled)" in PS1
    assert "hypervisor_active_requirements_masked" in PS1


def test_only_unique_private_network_and_native_generation_differencing_vm_are_provisioned():
    assert "$parentVhd.VhdFormat" in PS1
    assert "'VHD' { return '.vhd' }" in PS1
    assert "'VHDX' { return '.vhdx' }" in PS1
    assert "Unsupported source VHD format" in PS1
    assert "refusing to guess child format" in PS1
    assert "$diffVhd = Join-Path $vmRoot (\"ubuntu-noble-diff{0}\" -f $diffExtension)" in PS1
    assert "$diffVhd = Join-Path $vmRoot 'ubuntu-noble-diff.vhdx'" not in PS1
    assert PS1.index("$parentVhd = Get-VHD") < PS1.index("$parentFormat = [string]$parentVhd.VhdFormat")
    assert "Resolve-VMProvisionPlan -RequestedGeneration $VmGeneration -SourceFormat $parentFormat" in PS1
    assert "if ($vmPlan.convert_to_vhdx)" in PS1
    assert "native_vhd_uses_generation1_without_conversion" in PS1
    assert "native_vhdx_uses_generation2_without_conversion" in PS1
    assert PS1.index("Resolve-Gen2CompatibleParent `") < PS1.index("New-VHD -ComputerName localhost")
    for required in (
        "New-VMSwitch -ComputerName localhost",
        "-SwitchType Private",
        "New-VHD -ComputerName localhost -Path $diffVhd -ParentPath $selectedBootParent -Differencing",
        "New-VM -ComputerName localhost -Name $vmName -Generation $vmPlan.generation",
        "Set-VMFirmware -ComputerName localhost",
        "MicrosoftUEFICertificateAuthority",
        "Checkpoint-VM -ComputerName localhost",
        "Get-VM -ComputerName localhost",
        "Get-VMSwitch -ComputerName localhost",
        "Get-VMNetworkAdapter -ComputerName localhost",
    ):
        assert required in PS1
    assert "CreateNew" in PS1
    assert "Test-Path -LiteralPath $vmRoot" in PS1


def test_script_never_starts_guest_or_performs_destructive_cleanup_or_internet_setup():
    forbidden = (
        "Start-VM",
        "Remove-VM",
        "Remove-VMSwitch",
        "New-NetNat",
        "Add-NetNat",
        "-SwitchType External",
        "-SwitchType Internal",
        "Default Switch",
    )
    for token in forbidden:
        assert token.lower() not in PS1.lower()
    assert "guest_started = $false" in PS1
    assert "sample_executed = $false" in PS1
    assert "dynamic_test = 'not_performed'" in PS1
    assert "rollback_proven = $false" in PS1


def test_report_distinguishes_extracted_vhd_hash_from_published_archive_hash():
    assert "vhd_sha256" in PS1
    assert "published_archive_sha256_claim" in PS1
    assert "not an authenticity claim" in PS1
    assert "rollback_proven = $false" in PS1


@pytest.mark.parametrize(
    ("requested", "source_format", "expected_generation", "expected_conversion"),
    (("Auto", "VHD", 1, False), ("Auto", "VHDX", 2, False), ("2", "VHD", 2, True)),
)
def test_vm_plan_chooses_native_generation_without_unneeded_conversion(
    tmp_path, requested, source_format, expected_generation, expected_conversion
):
    result = _run_materialization_harness(
        tmp_path,
        rf"""
$plan = Resolve-VMProvisionPlan -RequestedGeneration '{requested}' -SourceFormat '{source_format}'
[ordered]@{{ generation=[int]$plan.generation; convert_to_vhdx=[bool]$plan.convert_to_vhdx; reason=[string]$plan.reason }} | ConvertTo-Json -Compress
""",
    )
    assert result["generation"] == expected_generation
    assert result["convert_to_vhdx"] is expected_conversion


def test_vm_plan_refuses_generation1_for_vhdx_boot_image(tmp_path):
    result = _run_materialization_harness(
        tmp_path,
        r"""
$message = ''
try { Resolve-VMProvisionPlan -RequestedGeneration '1' -SourceFormat 'VHDX' }
catch { $message = $_.Exception.Message }
[ordered]@{ refused=([string]::IsNullOrWhiteSpace($message) -eq $false); message=$message } | ConvertTo-Json -Compress
""",
    )
    assert result["refused"] is True
    assert "VHD" in result["message"]


def test_large_file_sha256_helper_matches_builtin_hash_for_empty_and_multibuffer_inputs(tmp_path):
    result = _run_materialization_harness(
        tmp_path,
        r"""
$empty = Join-Path $testRoot 'empty.bin'
$large = Join-Path $testRoot 'large.bin'
[IO.File]::WriteAllBytes($empty, [byte[]]@())
$bytes = New-Object byte[] (9MB + 17)
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[IO.File]::WriteAllBytes($large, $bytes)
$emptyFast = Get-FileSha256Fast -Path $empty
$emptyBuiltin = Get-TestSha256 $empty
$largeFast = Get-FileSha256Fast -Path $large
$largeBuiltin = Get-TestSha256 $large
[ordered]@{empty_match=($emptyFast -eq $emptyBuiltin);large_match=($largeFast -eq $largeBuiltin);length=(Get-Item -LiteralPath $large).Length} | ConvertTo-Json -Compress
""",
    )
    assert result["empty_match"] is True
    assert result["large_match"] is True
    assert result["length"] == 9 * 1024 * 1024 + 17


def test_validated_materialized_parent_reuse_does_not_reserve_a_second_full_copy(tmp_path):
    result = _run_materialization_harness(
        tmp_path,
        r"""
$source = Join-Path $testRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
$sourceHash = Get-TestSha256 $source
$sourceLength = [Int64](32GB)
$sourceVhd = [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64](32GB) }
$attributes = [IO.FileAttributes]::SparseFile
$materialized = Join-Path $testRoot 'materialized'
$getVhd = { param($Path) [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64](32GB); ParentPath=$null } }
$first = [ordered]@{}
$selected1 = Resolve-ValidatedParentVhd -OriginalPath $source -OriginalSha256 $sourceHash -OriginalVhd $sourceVhd -OriginalAttributes $attributes -OriginalLengthBytes $sourceLength -MaterializedRoot $materialized -AvailableFreeBytes 100GB -Result $first -GetVhdAction $getVhd -GetHashAction { param($Path) Get-TestSha256 $Path }
$second = [ordered]@{}
$selected2 = Resolve-ValidatedParentVhd -OriginalPath $source -OriginalSha256 $sourceHash -OriginalVhd $sourceVhd -OriginalAttributes $attributes -OriginalLengthBytes $sourceLength -MaterializedRoot $materialized -AvailableFreeBytes 60GB -Result $second -CopyAction { throw 'copy_must_not_repeat' } -GetVhdAction $getVhd -GetHashAction { param($Path) Get-TestSha256 $Path }
[ordered]@{ first_status=$first.status; second_status=$second.status; second_required=[Int64]$second.required_free_bytes; selected_same=($selected1 -eq $selected2) } | ConvertTo-Json -Compress
""",
    )
    assert result["first_status"] == "created_validated_copy"
    assert result["second_status"] == "reused_validated_copy"
    assert result["selected_same"] is True
    assert result["second_required"] < 60 * 1024**3




def _ps_quote(value: Path | str) -> str:
    return str(value).replace("'", "''")


def _run_materialization_harness(tmp_path: Path, body: str) -> dict:
    script = f"""
$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
. '{_ps_quote(ROOT / 'tools' / 'hyperv_provision.ps1')}'
$ErrorActionPreference = 'Stop'
$testRoot = '{_ps_quote(tmp_path)}'
function Get-TestSha256([string]$Path) {{
  $sha = [Security.Cryptography.SHA256]::Create()
  $stream = [IO.File]::OpenRead($Path)
  try {{ return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }}
  finally {{ $stream.Dispose(); $sha.Dispose() }}
}}
{body}
"""
    proc = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize(("vhd_format", "extension"), (("VHD", ".vhd"), ("VHDX", ".vhdx")))
def test_sparse_parent_is_materialized_as_dense_create_only_copy_and_reused(tmp_path, vhd_format, extension):
    result = _run_materialization_harness(tmp_path, rf"""
$source = Join-Path $testRoot 'source{extension}'
$stream = [IO.File]::Open($source, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
try {{
  $stream.SetLength(1MB)
  $stream.Position = 0
  $stream.Write([byte[]](1,2,3), 0, 3)
  $stream.Position = 1MB - 3
  $stream.Write([byte[]](4,5,6), 0, 3)
  $stream.Flush($true)
}} finally {{ $stream.Dispose() }}
& fsutil.exe sparse setflag $source | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw 'could_not_mark_source_sparse' }}
$sourceHash = Get-TestSha256 $source
$sourceLength = (Get-Item -LiteralPath $source -Force).Length
$materialized = Join-Path $testRoot 'materialized'
$original = [pscustomobject]@{{ VhdFormat = '{vhd_format}'; VhdType = 'Fixed'; Size = [Int64]1048576 }}
$getVhd = {{ param($Path) [pscustomobject]@{{ VhdFormat = '{vhd_format}'; VhdType = 'Fixed'; Size = [Int64]1048576; ParentPath = $null }} }}
$getHash = {{ param($Path) Get-TestSha256 $Path }}
$first = [ordered]@{{}}
$selected1 = Resolve-ValidatedParentVhd -OriginalPath $source -OriginalSha256 $sourceHash -OriginalVhd $original -OriginalAttributes ([IO.FileAttributes]::SparseFile) -OriginalLengthBytes $sourceLength -MaterializedRoot $materialized -AvailableFreeBytes 100GB -Result $first -GetVhdAction $getVhd -GetHashAction $getHash
$second = [ordered]@{{}}
$selected2 = Resolve-ValidatedParentVhd -OriginalPath $source -OriginalSha256 $sourceHash -OriginalVhd $original -OriginalAttributes ([IO.FileAttributes]::SparseFile) -OriginalLengthBytes $sourceLength -MaterializedRoot $materialized -AvailableFreeBytes 100GB -Result $second -CopyAction {{ throw 'copy_must_not_repeat' }} -GetVhdAction $getVhd -GetHashAction $getHash
$sourceSparse = ((Get-Item -LiteralPath $source -Force).Attributes -band [IO.FileAttributes]::SparseFile) -ne 0
$destinationSparse = ((Get-Item -LiteralPath $selected1 -Force).Attributes -band [IO.FileAttributes]::SparseFile) -ne 0
[ordered]@{{ first = $first; second = $second; selected1 = $selected1; selected2 = $selected2; source_exists = Test-Path -LiteralPath $source; source_sparse = $sourceSparse; destination_sparse = $destinationSparse; source_hash = $sourceHash }} | ConvertTo-Json -Depth 10 -Compress
""")
    assert result["first"]["status"] == "created_validated_copy"
    assert result["first"]["destination_type"] == "Fixed"
    assert result["first"]["destination_path"].lower().endswith(extension)
    assert result["second"]["status"] == "reused_validated_copy"
    assert result["selected1"] == result["selected2"]
    assert result["source_exists"] is True
    assert result["source_sparse"] is True
    assert result["destination_sparse"] is False
    assert result["first"]["destination_sha256"] == result["source_hash"]


def test_materialization_fails_before_copy_when_space_is_insufficient(tmp_path):
    result = _run_materialization_harness(tmp_path, r"""
$source = Join-Path $testRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1))
$state = [ordered]@{}
try {
  Resolve-ValidatedParentVhd -OriginalPath $source -OriginalSha256 ('a' * 64) -OriginalVhd ([pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]10GB }) -OriginalAttributes ([IO.FileAttributes]::SparseFile) -OriginalLengthBytes 10GB -MaterializedRoot (Join-Path $testRoot 'materialized') -AvailableFreeBytes 1 -Result $state -CopyAction { throw 'copy_must_not_run' }
} catch { $message = $_.Exception.Message }
[ordered]@{ state=$state; message=$message } | ConvertTo-Json -Depth 10 -Compress
""")
    assert result["state"]["status"] == "insufficient_space"
    assert "Insufficient free space" in result["message"]


@pytest.mark.parametrize("partial", (False, True))
def test_copy_failure_is_reported_and_partial_output_is_preserved(tmp_path, partial):
    write_partial = "[IO.File]::WriteAllBytes($Destination, [byte[]](9,9))" if partial else ""
    result = _run_materialization_harness(tmp_path, rf"""
$source = Join-Path $testRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1))
$sourceHash = Get-TestSha256 $source
$state = [ordered]@{{}}
$copy = {{ param($Source, $Destination) {write_partial}; throw 'simulated_copy_failure' }}
try {{
  Resolve-ValidatedParentVhd -OriginalPath $source -OriginalSha256 $sourceHash -OriginalVhd ([pscustomobject]@{{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576 }}) -OriginalAttributes ([IO.FileAttributes]::SparseFile) -OriginalLengthBytes 1 -MaterializedRoot (Join-Path $testRoot 'materialized') -AvailableFreeBytes 100GB -Result $state -CopyAction $copy
}} catch {{ $message = $_.Exception.Message }}
[ordered]@{{ state=$state; message=$message; source_exists=Test-Path -LiteralPath $source }} | ConvertTo-Json -Depth 10 -Compress
""")
    assert result["state"]["status"] == "copy_failed_or_partial"
    assert result["source_exists"] is True
    assert result["message"] == "simulated_copy_failure"
    if partial:
        assert result["state"]["partial_output"]["preserved"] is True
        assert result["state"]["partial_output"]["length_bytes"] == 2
    else:
        assert result["state"].get("partial_output") is None


def test_script_uses_create_only_raw_copy_without_destructive_source_removal():
    assert "[System.IO.File]::Copy($Source, $Destination, $false)" in PS1
    assert "copy_content_hash_mismatch" in PS1
    assert "DeleteSource" not in PS1
    assert "FileMode]::CreateNew" in PS1
    assert "SparseFile" in PS1
    assert "materialized-parents" in PS1
    assert "selected_parent_path" in PS1


def test_launcher_declares_non_destructive_fixed_copy_policy():
    assert "VHD fonte sera preservado" in BAT
    assert "copia Fixed create-only" in BAT


def test_generation2_parent_converts_vhd_to_vhdx_and_reuses_verified_copy(tmp_path):
    result = _run_materialization_harness(tmp_path, _NEW_VHDX_BODY + r"""
$source = Join-Path $testRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
$sourceHash = Get-TestSha256 $source
$sourceVhd = [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576 }
$getVhd = { param($Path)
  if ([IO.Path]::GetExtension($Path) -eq '.vhdx') {
    [pscustomobject]@{ VhdFormat='VHDX'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }
  } else {
    [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }
  }
}
$convert = { param($Source, $Destination) New-TestVhdxFile -Path $Destination }
$first = [ordered]@{}
$selected1 = Resolve-Gen2CompatibleParent -SourcePath $source -SourceVhd $sourceVhd -SourceSha256 $sourceHash -AvailableFreeBytes 100GB -RequiredFreeBytes 80GB -Result $first -ConvertAction $convert -GetVhdAction $getVhd -GetHashAction { param($Path) Get-TestSha256 $Path }
$second = [ordered]@{}
$selected2 = Resolve-Gen2CompatibleParent -SourcePath $source -SourceVhd $sourceVhd -SourceSha256 $sourceHash -AvailableFreeBytes 100GB -RequiredFreeBytes 80GB -Result $second -ConvertAction { throw 'conversion_must_not_repeat' } -GetVhdAction $getVhd -GetHashAction { param($Path) Get-TestSha256 $Path }
[ordered]@{ first=$first; second=$second; selected1=$selected1; selected2=$selected2; source_hash=(Get-TestSha256 $source); source_bytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($source)) } | ConvertTo-Json -Depth 10 -Compress
""")
    assert result["first"]["status"] == "created_validated_vhdx"
    assert result["first"]["destination_format"] == "VHDX"
    assert result["first"]["destination_type"] == "Fixed"
    assert result["first"]["destination_path"].lower().endswith(".vhdx")
    assert result["second"]["status"] == "reused_validated_vhdx"
    assert result["selected1"] == result["selected2"]
    assert result["source_hash"] == result["first"]["source_sha256"]
    assert result["source_bytes"] == "AQIDBA=="


def test_generation2_vhdx_parent_is_reused_without_conversion(tmp_path):
    result = _run_materialization_harness(tmp_path, r"""
$source = Join-Path $testRoot 'source.vhdx'
[IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
$sourceHash = Get-TestSha256 $source
$sourceVhd = [pscustomobject]@{ VhdFormat='VHDX'; VhdType='Fixed'; Size=[Int64]1048576 }
$state = [ordered]@{}
$selected = Resolve-Gen2CompatibleParent -SourcePath $source -SourceVhd $sourceVhd -SourceSha256 $sourceHash -AvailableFreeBytes 100GB -RequiredFreeBytes 80GB -Result $state -ConvertAction { throw 'conversion_must_not_run' } -GetVhdAction { param($Path) [pscustomobject]@{ VhdFormat='VHDX'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null } }
[ordered]@{ state=$state; selected=$selected } | ConvertTo-Json -Depth 10 -Compress
""")
    assert result["state"]["required"] is False
    assert result["state"]["status"] == "already_gen2_compatible"
    assert result["selected"].lower().endswith(".vhdx")


@pytest.mark.parametrize("reparse_target", ("parent", "destination", "manifest"))
def test_generation2_conversion_rejects_existing_reparse_components_before_conversion(tmp_path, reparse_target):
    result = _run_materialization_harness(tmp_path, rf"""
$realRoot = Join-Path $testRoot 'real-root'
$targetDir = Join-Path $testRoot 'junction-target'
[IO.Directory]::CreateDirectory($realRoot) | Out-Null
[IO.Directory]::CreateDirectory($targetDir) | Out-Null
if ('{reparse_target}' -eq 'parent') {{
  $sourceRoot = Join-Path $testRoot 'source-link'
  & cmd.exe /d /c mklink /J $sourceRoot $realRoot | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'could_not_create_parent_junction' }}
}} else {{
  $sourceRoot = $realRoot
}}
$source = Join-Path $sourceRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
$destination = Join-Path $sourceRoot 'source.gen2.vhdx'
$manifest = $destination + '.provenance.json'
if ('{reparse_target}' -eq 'destination') {{
  & cmd.exe /d /c mklink /J $destination $targetDir | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'could_not_create_destination_junction' }}
}}
if ('{reparse_target}' -eq 'manifest') {{
  & cmd.exe /d /c mklink /J $manifest $targetDir | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'could_not_create_manifest_junction' }}
}}
$sourceHash = Get-TestSha256 $source
$state = [ordered]@{{}}
try {{
  Resolve-Gen2CompatibleParent -SourcePath $source -SourceVhd ([pscustomobject]@{{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576 }}) -SourceSha256 $sourceHash -AvailableFreeBytes 100GB -RequiredFreeBytes 80GB -Result $state -ConvertAction {{ throw 'conversion_must_not_run' }} -GetVhdAction {{ param($Path) [pscustomobject]@{{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }} }}
}} catch {{ $message = $_.Exception.Message }}
[ordered]@{{ state=$state; message=$message }} | ConvertTo-Json -Depth 10 -Compress
""")
    assert result["state"]["status"] == f"{reparse_target}_reparse_point"
    assert "reparse" in result["message"].lower()


_NEW_VHDX_BODY = r"""
function New-TestVhdxFile([string]$Path, [switch]$CorruptSignature) {
  $size = 4MB
  $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
  try {
    $stream.SetLength($size)
    if ($CorruptSignature) {
      $bytes = [Text.Encoding]::ASCII.GetBytes('notavhdx')
      $stream.Position = 0
      $stream.Write($bytes, 0, $bytes.Length)
    } else {
      $sig = [Text.Encoding]::ASCII.GetBytes('vhdxfile')
      $stream.Position = 0
      $stream.Write($sig, 0, $sig.Length)
      $head = [Text.Encoding]::ASCII.GetBytes('head')
      $stream.Position = 0x10000
      $stream.Write($head, 0, 4)
      $stream.Position = 0x20000
      $stream.Write($head, 0, 4)
    }
    $stream.Flush($true)
  } finally { $stream.Dispose() }
}
"""


def test_vhdx_signature_check_accepts_real_layout_and_rejects_garbage(tmp_path):
    """A assinatura/cabecalhos sao condicoes necessarias; lixo obvio e rejeitado.

    Nota de honestidade: uma versao anterior tambem exigia que o ultimo 1 MiB nao
    fosse zero. Isso era FALSO POSITIVO - o VHDX real deste host tem esse trecho
    zerado e ainda assim serve de pai para New-VHD -Differencing. A validacao
    autoritativa e Get-VHD, nao esta funcao.
    """
    result = _run_materialization_harness(tmp_path, _NEW_VHDX_BODY + r"""
$good = Join-Path $testRoot 'good.vhdx'
$garbage = Join-Path $testRoot 'garbage.vhdx'
New-TestVhdxFile -Path $good
New-TestVhdxFile -Path $garbage -CorruptSignature
[ordered]@{
  good = [bool](Test-VhdxFileStructurallyValid -Path $good)
  garbage = [bool](Test-VhdxFileStructurallyValid -Path $garbage)
  absent = [bool](Test-VhdxFileStructurallyValid -Path (Join-Path $testRoot 'absent.vhdx'))
} | ConvertTo-Json -Compress
""")
    assert result["good"] is True
    assert result["garbage"] is False, "arquivo sem assinatura vhdxfile nao pode passar"
    assert result["absent"] is False


def test_generation2_reuse_refuses_garbage_existing_vhdx(tmp_path):
    """Um destino sem assinatura VHDX nunca pode ser reusado como pai Gen2."""
    result = _run_materialization_harness(tmp_path, _NEW_VHDX_BODY + r"""
$source = Join-Path $testRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
$destination = Join-Path $testRoot 'source.gen2.vhdx'
New-TestVhdxFile -Path $destination -CorruptSignature
$sourceHash = Get-TestSha256 $source
$destinationHash = Get-TestSha256 $destination
$manifestPath = $destination + '.provenance.json'
$manifest = [ordered]@{
  schema = 'hyperv-gen2-parent-conversion.v1'
  source_path = $source
  source_sha256 = $sourceHash
  destination_path = $destination
  destination_sha256 = $destinationHash
  destination_format = 'VHDX'
  destination_type = 'Fixed'
  virtual_size_bytes = [Int64]1048576
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5))
$state = [ordered]@{}
$message = ''
try {
  $selected = Resolve-Gen2CompatibleParent -SourcePath $source `
    -SourceVhd ([pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }) `
    -SourceSha256 $sourceHash -AvailableFreeBytes 100GB -RequiredFreeBytes 80GB -Result $state `
    -ConvertAction { throw 'conversion_must_not_run' } `
    -GetVhdAction { param($Path) if ([IO.Path]::GetExtension($Path) -eq '.vhdx') { [pscustomobject]@{ VhdFormat='VHDX'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null } } else { [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null } } } `
    -GetItemAction { param($Path) Get-Item -LiteralPath $Path -Force } `
    -GetHashAction { param($Path) Get-TestSha256 $Path }
} catch { $message = $_.Exception.Message }
[ordered]@{
  state = $state
  message = $message
  destination_preserved = (Test-Path -LiteralPath $destination)
} | ConvertTo-Json -Depth 10 -Compress
""")
    assert result["state"]["status"] == "existing_vhdx_corrupt"
    assert result["destination_preserved"] is True, "artefato suspeito deve ser preservado, nao apagado"


def test_generation2_discards_proven_invalid_partial_only_with_explicit_switch(tmp_path):
    """Recuperacao de parcial orfao INVALIDO: explicita, com hash, fail-closed."""
    result = _run_materialization_harness(tmp_path, _NEW_VHDX_BODY + r"""
$source = Join-Path $testRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
$destination = Join-Path $testRoot 'source.gen2.vhdx'
New-TestVhdxFile -Path $destination -CorruptSignature
$sourceHash = Get-TestSha256 $source
$partialHash = Get-TestSha256 $destination
$getVhd = { param($Path) if ([IO.Path]::GetExtension($Path) -eq '.vhdx') { [pscustomobject]@{ VhdFormat='VHDX'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null } } else { [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null } } }
$convert = { param($Source, $Destination) New-TestVhdxFile -Path $Destination }
$strict = [ordered]@{}
$strictMessage = ''
try {
  $strictSelected = Resolve-Gen2CompatibleParent -SourcePath $source `
    -SourceVhd ([pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }) `
    -SourceSha256 $sourceHash -AvailableFreeBytes 100GB -RequiredFreeBytes 80GB -Result $strict `
    -ConvertAction $convert -GetVhdAction $getVhd `
    -GetItemAction { param($Path) Get-Item -LiteralPath $Path -Force } `
    -GetHashAction { param($Path) Get-TestSha256 $Path }
} catch { $strictMessage = $_.Exception.Message }
$strictPreserved = Test-Path -LiteralPath $destination

$recovery = [ordered]@{}
$recoveryMessage = ''
try {
  $recoverySelected = Resolve-Gen2CompatibleParent -SourcePath $source `
    -SourceVhd ([pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }) `
    -SourceSha256 $sourceHash -AvailableFreeBytes 100GB -RequiredFreeBytes 80GB -Result $recovery `
    -AllowDiscardInvalidDestination `
    -ConvertAction $convert -GetVhdAction $getVhd `
    -GetItemAction { param($Path) Get-Item -LiteralPath $Path -Force } `
    -GetHashAction { param($Path) Get-TestSha256 $Path }
} catch { $recoveryMessage = $_.Exception.Message }
[ordered]@{
  strict_status = $strict.status
  strict_message = $strictMessage
  strict_preserved = $strictPreserved
  recovery_status = $recovery.status
  recovery_message = $recoveryMessage
  discarded = $recovery.discarded_invalid_destination
  partial_hash = $partialHash
  manifest_exists = (Test-Path -LiteralPath ($destination + '.provenance.json'))
} | ConvertTo-Json -Depth 10 -Compress
""")
    # Sem o switch: fail-closed e nada removido.
    assert result["strict_status"] == "existing_vhdx_unbound"
    assert result["strict_preserved"] is True
    # Com o switch: remove o parcial PROVADO invalido, registra o hash e converte.
    assert result["recovery_status"] == "created_validated_vhdx"
    assert result["discarded"]["sha256"] == result["partial_hash"]
    assert result["discarded"]["reason"] == "structurally_invalid_vhdx"
    assert result["manifest_exists"] is True


def test_generation2_binds_orphan_destination_only_after_authoritative_validation(tmp_path):
    """Orfao com assinatura VALIDA e aceito por Get-VHD: so vincula com switch.

    Este e o caso real do host: um .gen2.vhdx de 30 GB produzido por uma execucao
    que falhou antes de gravar o manifesto. Ele e estruturalmente valido e o
    Hyper-V o aceita como pai; descarta-lo seria destruir 30 GB sem necessidade.
    A vinculacao e explicita e registra adopted_orphan_destination=true.
    """
    result = _run_materialization_harness(tmp_path, _NEW_VHDX_BODY + r"""
$source = Join-Path $testRoot 'source.vhd'
[IO.File]::WriteAllBytes($source, [byte[]](1,2,3,4))
$destination = Join-Path $testRoot 'source.gen2.vhdx'
New-TestVhdxFile -Path $destination
$sourceHash = Get-TestSha256 $source
$destinationHash = Get-TestSha256 $destination
$getVhd = { param($Path) if ([IO.Path]::GetExtension($Path) -eq '.vhdx') { [pscustomobject]@{ VhdFormat='VHDX'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null } } else { [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null } } }
$common = @{
  SourcePath = $source
  SourceVhd = [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }
  SourceSha256 = $sourceHash
  AvailableFreeBytes = 100GB
  RequiredFreeBytes = 80GB
  ConvertAction = { throw 'conversion_must_not_run' }
  GetVhdAction = $getVhd
  GetItemAction = { param($Path) Get-Item -LiteralPath $Path -Force }
  GetHashAction = { param($Path) Get-TestSha256 $Path }
}
$strict = [ordered]@{}
$strictMessage = ''
try { $strictSelected = Resolve-Gen2CompatibleParent @common -Result $strict } catch { $strictMessage = $_.Exception.Message }
$strictMessage = $strictMessage

$binding = [ordered]@{}
$bindingMessage = ''
try { $bindingSelected = Resolve-Gen2CompatibleParent @common -Result $binding -AllowOrphanDestinationBinding } catch { $bindingMessage = $_.Exception.Message }

$unreadable = [ordered]@{}
$unreadableMessage = ''
$getVhdThrows = {
  param($Path)
  if ([IO.Path]::GetExtension($Path) -eq '.vhdx') { throw 'parser_cannot_read' }
  [pscustomobject]@{ VhdFormat='VHD'; VhdType='Fixed'; Size=[Int64]1048576; ParentPath=$null }
}
$manifestPath = $destination + '.provenance.json'
# Captura o estado LOGO apos a vinculacao, antes de qualquer limpeza do teste.
$bindingManifestExists = Test-Path -LiteralPath $manifestPath
$bindingManifestAdopted = if ($bindingManifestExists) { (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).adopted_orphan_destination } else { $null }
if ($bindingManifestExists) { Remove-Item -LiteralPath $manifestPath -Force }
$commonUnreadable = $common.Clone()
$commonUnreadable.GetVhdAction = $getVhdThrows
try { $unreadableSelected = Resolve-Gen2CompatibleParent @commonUnreadable -Result $unreadable -AllowOrphanDestinationBinding } catch { $unreadableMessage = $_.Exception.Message }

[ordered]@{
  strict_status = $strict.status
  strict_message = $strictMessage
  binding_status = $binding.status
  binding_message = $bindingMessage
  adopted_flag = $binding.adopted_orphan_destination
  destination_hash_before = $destinationHash
  destination_hash_after = (Get-TestSha256 $destination)
  manifest_exists = $bindingManifestExists
  manifest_adopted = $bindingManifestAdopted
  unreadable_status = $unreadable.status
  unreadable_message = $unreadableMessage
} | ConvertTo-Json -Depth 10 -Compress
""")
    # Sem switch: fail-closed, mesmo sendo estruturalmente valido.
    assert result["strict_status"] == "existing_vhdx_unbound"
    assert "AllowOrphanDestinationBinding" in result["strict_message"]
    # Com switch: vincula, grava proveniencia marcada e NAO apaga o artefato.
    assert result["binding_status"] == "adopted_validated_vhdx"
    assert result["adopted_flag"] is True
    assert result["destination_hash_after"] == result["destination_hash_before"]
    assert result["manifest_exists"] is True
    assert result["manifest_adopted"] is True
    # Se o parser autoritativo nao le, ainda falha fechado.
    assert result["unreadable_status"] == "orphan_destination_unreadable"
