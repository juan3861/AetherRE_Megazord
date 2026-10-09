[CmdletBinding()]
param(
    # Recuperacao explicita de um parcial de conversao ORFAO e comprovadamente
    # invalido (sem manifesto de proveniencia e sem assinatura/cabecalho VHDX).
    # Sem este switch o script falha fechado com status existing_vhdx_unbound.
    [switch]$AllowDiscardInvalidDestination,
    # Vinculacao explicita de um destino ORFAO que passa na checagem de
    # assinatura E e aceito pelo parser autoritativo do Hyper-V. Registra
    # adopted_orphan_destination=true na proveniencia. Evita reconverter 30 GB
    # quando a execucao anterior falhou apenas antes de gravar o manifesto.
    [switch]$AllowOrphanDestinationBinding
)

# RE_Megazord authorized lab bootstrap. This script only provisions an OFF VM;
# it never starts the guest, executes a sample, enables internet access, or
# claims a dynamic-analysis or rollback qualification.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$sourceVhd = 'E:\AetherRE_DynamicLab\vm-images\ubuntu-noble-20260926\livecd.ubuntu-cpc.azure.vhd'
$sourceArchive = 'E:\AetherRE_DynamicLab\ubuntu-noble-20260926\noble-server-cloudimg-amd64-azure.vhd.tar.gz'
$labRoot = 'E:\AetherRE_DynamicLab'
$evidenceRoot = Join-Path $labRoot 'provisioning-reports'
$publishedArchiveSha256 = '3543723afd820d7a8a64ea7399376856a95ce15200439c38447170652a60a5f3'
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$reportPath = Join-Path $evidenceRoot ("hyperv-provision-{0}.json" -f $runId)
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$vmName = "AetherRE-Ubuntu-Noble-$suffix"
$switchName = "AetherRE-Private-$suffix"
$checkpointName = "pre-execution-$suffix"
$vmRoot = Join-Path $labRoot (Join-Path 'guests' $suffix)

$report = [ordered]@{
    schema_version = 'hyperv-provision-report.v1'
    run_id = $runId
    started_at_utc = [DateTime]::UtcNow.ToString('o')
    completed_at_utc = $null
    status = 'blocked'
    stage = 'initializing'
    host = $env:COMPUTERNAME
    computer_name_target = 'localhost'
    source = [ordered]@{
        path = $sourceVhd
        exists = $false
        length_bytes = $null
        vhd_sha256 = $null
        archive_path = $sourceArchive
        published_archive_sha256_claim = $publishedArchiveSha256
        observed_archive_sha256 = $null
        published_archive_verification = 'archive_not_present'
        attributes = @()
        sparse = $null
        compressed = $null
        encrypted = $null
        note = 'The published hash is for the compressed archive, not the extracted VHD. If the archive is present, it is checked against the published hash. The extracted VHD SHA-256 is computed locally and is not an authenticity claim by itself.'
    }
    materialized_parent = [ordered]@{
        required = $false
        reason = 'not_evaluated'
        status = 'not_evaluated'
        reused = $false
        original_path = $sourceVhd
        original_sha256 = $null
        original_format = $null
        original_type = $null
        original_attributes = @()
        destination_path = $null
        destination_sha256 = $null
        destination_format = $null
        destination_type = $null
        destination_attributes = @()
        manifest_path = $null
        manifest_sha256 = $null
        available_free_bytes = $null
        required_free_bytes = $null
        selected_parent_path = $null
        partial_output = $null
    }
    generation2_parent_conversion = [ordered]@{
        required = $false
        status = 'not_evaluated'
        source_path = $null
        source_sha256 = $null
        source_format = $null
        source_type = $null
        destination_path = $null
        destination_sha256 = $null
        destination_format = $null
        destination_type = $null
        manifest_path = $null
        manifest_sha256 = $null
        available_free_bytes = $null
        required_free_bytes = $null
        selected_parent_path = $null
        partial_output = $null
    }
    preflight = [ordered]@{
        is_admin = $false
        windows_features = @()
        vmms_status = $null
        hypervisor_present = $false
        firmware_virtualization_enabled = $false
        virtualization_check = $null
        free_bytes = $null
        required_free_bytes = $null
    }
    resources = [ordered]@{
        switch = $null
        vhd = $null
        vm = $null
        checkpoint = $null
    }
    execution = [ordered]@{
        guest_started = $false
        sample_executed = $false
        internet_enabled = $false
        dynamic_test = 'not_performed'
        rollback_proven = $false
    }
    errors = @()
    report_path = $reportPath
}


function Test-UnsafeVhdStorageAttributes {
    param([Parameter(Mandatory = $true)][IO.FileAttributes]$Attributes)
    $unsafe = [IO.FileAttributes]::SparseFile -bor [IO.FileAttributes]::Compressed -bor [IO.FileAttributes]::Encrypted
    return (($Attributes -band $unsafe) -ne 0)
}

function Test-VhdxFileStructurallyValid {
    <#
    Verifica condicoes NECESSARIAS (nao suficientes) de um arquivo VHDX:
    assinatura 'vhdxfile' e cabecalhos 'head' em 0x10000 e 0x20000.

    ATENCAO (corrigido em 2026-10-09): uma versao anterior desta funcao tambem
    exigia que o ultimo 1 MiB nao fosse todo zero. Isso era um FALSO POSITIVO:
    o VHDX real deste host tem esse trecho zerado e mesmo assim e aceito por
    Get-VHD e serve de pai para New-VHD -Differencing (comprovado). A validacao
    AUTORITATIVA e o parser do Hyper-V ($GetVhdAction / Get-VHD), executado
    adiante no fluxo; esta funcao apenas descarta lixo obvio.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        if ($stream.Length -lt 2MB) { return $false }

        $signature = New-Object byte[] 8
        if ($stream.Read($signature, 0, 8) -ne 8) { return $false }
        if ([Text.Encoding]::ASCII.GetString($signature) -ne 'vhdxfile') { return $false }

        foreach ($offset in @(0x10000, 0x20000)) {
            $stream.Position = $offset
            $header = New-Object byte[] 4
            if ($stream.Read($header, 0, 4) -ne 4) { return $false }
            if ([Text.Encoding]::ASCII.GetString($header) -ne 'head') { return $false }
        }
        return $true
    }
    catch { return $false }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Get-VhdExtensionForFormat {
    param([Parameter(Mandatory = $true)][string]$Format)
    switch ($Format.ToUpperInvariant()) {
        'VHD' { return '.vhd' }
        'VHDX' { return '.vhdx' }
        default { throw "Unsupported source VHD format '$Format'; refusing to guess child format." }
    }
}

function Write-CreateOnlyJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 10
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Assert-NoExistingReparseComponent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$IncludeLeaf
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        $Result.status = $Status
        throw "$Description path has no rooted filesystem location."
    }
    $parts = @($fullPath.Substring($root.Length) -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $limit = if ($IncludeLeaf) { $parts.Count } else { [Math]::Max(0, $parts.Count - 1) }
    $cursor = $root
    try {
        $rootItem = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
    }
    catch {
        $Result.status = $Status
        throw "$Description filesystem root could not be inspected fail-closed: $cursor"
    }
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        $Result.status = $Status
        throw "$Description path contains an existing reparse point or junction: $cursor"
    }
    for ($index = 0; $index -lt $limit; $index++) {
        $cursor = Join-Path $cursor $parts[$index]
        try {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            break
        }
        catch {
            $Result.status = $Status
            throw "$Description path component could not be inspected fail-closed: $cursor"
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $Result.status = $Status
            throw "$Description path contains an existing reparse point or junction: $cursor"
        }
    }
}

function Resolve-ValidatedParentVhd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OriginalPath,
        [Parameter(Mandatory = $true)][string]$OriginalSha256,
        [Parameter(Mandatory = $true)]$OriginalVhd,
        [Parameter(Mandatory = $true)][IO.FileAttributes]$OriginalAttributes,
        [Parameter(Mandatory = $true)][Int64]$OriginalLengthBytes,
        [Parameter(Mandatory = $true)][string]$MaterializedRoot,
        [Parameter(Mandatory = $true)][Int64]$AvailableFreeBytes,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Result,
        [scriptblock]$CopyAction = { param($Source, $Destination) [System.IO.File]::Copy($Source, $Destination, $false) },
        [scriptblock]$GetVhdAction = { param($Path) Get-VHD -Path $Path -ComputerName localhost -ErrorAction Stop },
        [scriptblock]$GetItemAction = { param($Path) Get-Item -LiteralPath $Path -Force -ErrorAction Stop },
        [scriptblock]$GetHashAction = { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    )

    $format = [string]$OriginalVhd.VhdFormat
    $extension = Get-VhdExtensionForFormat -Format $format
    $Result.original_path = $OriginalPath
    $Result.original_sha256 = $OriginalSha256
    $Result.original_format = $format
    $Result.original_type = [string]$OriginalVhd.VhdType
    $Result.original_attributes = @([Enum]::GetValues([IO.FileAttributes]) | Where-Object { $_ -ne 0 -and ($OriginalAttributes -band $_) -eq $_ } | ForEach-Object { [string]$_ })

    if (-not (Test-UnsafeVhdStorageAttributes -Attributes $OriginalAttributes)) {
        $Result.required = $false
        $Result.reason = 'original_storage_attributes_compatible'
        $Result.status = 'original_validated'
        $Result.selected_parent_path = $OriginalPath
        return $OriginalPath
    }

    $Result.required = $true
    $Result.reason = 'original_sparse_compressed_or_encrypted'
    if ($OriginalLengthBytes -le 0) {
        $Result.status = 'source_length_invalid'
        throw 'Source VHD length must be a positive integer before materialization.'
    }
    $stableId = $OriginalSha256.Substring(0, 16).ToLowerInvariant()
    $parentRoot = Join-Path $MaterializedRoot $stableId
    $destination = Join-Path $parentRoot ("ubuntu-noble-parent-fixed{0}" -f $extension)
    $manifestPath = $destination + '.provenance.json'
    $downstreamReserve = [Int64]([Math]::Ceiling([double]$OriginalVhd.Size * 1.25) + 10GB)
    # A byte-for-byte copy allocates the original file length, even when the
    # source is sparse. Reserve the exact copy size plus the later VM/diff budget.
    $requiredFree = [Int64]($OriginalLengthBytes + $downstreamReserve + 1GB)
    $Result.destination_path = $destination
    $Result.manifest_path = $manifestPath
    $Result.available_free_bytes = $AvailableFreeBytes
    $Result.required_free_bytes = $requiredFree

    if ($AvailableFreeBytes -lt $requiredFree) {
        $Result.status = 'insufficient_space'
        throw "Insufficient free space to materialize a Fixed parent while preserving downstream reserve. Required at least $requiredFree bytes; available $AvailableFreeBytes."
    }

    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        $Result.status = 'validating_existing_copy'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            $Result.status = 'existing_copy_unbound'
            throw "Existing materialized parent has no provenance manifest; refusing to reuse or overwrite: $destination"
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($manifest.schema -ne 'hyperv-fixed-parent-provenance.v1' -or $manifest.original_sha256 -ne $OriginalSha256 -or $manifest.destination_path -ne $destination) {
            $Result.status = 'existing_copy_manifest_mismatch'
            throw "Existing materialized parent provenance does not match the current source; refusing to reuse or overwrite: $destination"
        }
    }
    else {
        if (Test-Path -LiteralPath $manifestPath) {
            $Result.status = 'orphan_manifest_detected'
            throw "Provenance manifest exists without its materialized parent; refusing to overwrite evidence: $manifestPath"
        }
        if (-not (Test-Path -LiteralPath $parentRoot -PathType Container)) {
            New-Item -ItemType Directory -Path $parentRoot -ErrorAction Stop | Out-Null
        }
        $Result.status = 'copy_started'
        try {
            # File.Copy reads the sparse source and writes its logical bytes to
            # a new create-only destination. This materializes holes as zeros;
            # the source is never modified and an existing destination fails.
            & $CopyAction $OriginalPath $destination
        }
        catch {
            $Result.status = 'copy_failed_or_partial'
            if (Test-Path -LiteralPath $destination -PathType Leaf) {
                $partial = & $GetItemAction $destination
                $Result.partial_output = [ordered]@{
                    path = $destination
                    length_bytes = [Int64]$partial.Length
                    attributes = [string]$partial.Attributes
                    preserved = $true
                }
            }
            throw
        }
    }

    try {
        $copyItem = & $GetItemAction $destination
        $copyVhd = & $GetVhdAction $destination
        $copyHash = [string](& $GetHashAction $destination)
    }
    catch {
        $Result.status = 'copy_validation_failed_or_partial'
        if (Test-Path -LiteralPath $destination -PathType Leaf) {
            $partial = Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            if ($null -ne $partial) {
                $Result.partial_output = [ordered]@{
                    path = $destination
                    length_bytes = [Int64]$partial.Length
                    attributes = [string]$partial.Attributes
                    preserved = $true
                }
            }
        }
        throw
    }
    $copyAttributes = [IO.FileAttributes]$copyItem.Attributes
    $Result.destination_sha256 = $copyHash.ToLowerInvariant()
    $Result.destination_format = [string]$copyVhd.VhdFormat
    $Result.destination_type = [string]$copyVhd.VhdType
    $Result.destination_attributes = @([Enum]::GetValues([IO.FileAttributes]) | Where-Object { $_ -ne 0 -and ($copyAttributes -band $_) -eq $_ } | ForEach-Object { [string]$_ })

    if (Test-UnsafeVhdStorageAttributes -Attributes $copyAttributes) {
        $Result.status = 'copy_storage_attributes_invalid'
        throw "Materialized parent remains sparse, compressed, or encrypted; refusing to use it: $destination"
    }
    if ($copyHash.ToLowerInvariant() -ne $OriginalSha256.ToLowerInvariant()) {
        $Result.status = 'copy_content_hash_mismatch'
        throw "Materialized parent is not a byte-for-byte copy of the source VHD: $destination"
    }
    if ([string]$copyVhd.VhdType -ne 'Fixed' -or [string]$copyVhd.VhdFormat -ne $format) {
        $Result.status = 'copy_vhd_contract_invalid'
        throw "Materialized parent is not a Fixed $format disk; refusing to use it: $destination"
    }

    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($manifest.destination_sha256 -ne $copyHash -or $manifest.original_sha256 -ne $OriginalSha256) {
            $Result.status = 'existing_copy_hash_mismatch'
            throw "Materialized parent hash does not match its provenance manifest: $destination"
        }
        $Result.reused = $true
    }
    else {
        $provenance = [ordered]@{
            schema = 'hyperv-fixed-parent-provenance.v1'
            created_at_utc = [DateTime]::UtcNow.ToString('o')
            original_path = $OriginalPath
            original_sha256 = $OriginalSha256
            original_format = $format
            destination_path = $destination
            destination_sha256 = $copyHash.ToLowerInvariant()
            destination_format = [string]$copyVhd.VhdFormat
            destination_type = [string]$copyVhd.VhdType
            materialization = 'File.Copy create-only; byte-for-byte source preserved; sparse holes are written as ordinary file data'
        }
        Write-CreateOnlyJson -Path $manifestPath -Value $provenance
        $Result.reused = $false
    }
    $Result.manifest_sha256 = [string](& $GetHashAction $manifestPath)
    $Result.status = if ($Result.reused) { 'reused_validated_copy' } else { 'created_validated_copy' }
    $Result.selected_parent_path = $destination
    return $destination
}

function Resolve-Gen2CompatibleParent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)]$SourceVhd,
        [Parameter(Mandatory = $true)][string]$SourceSha256,
        [Parameter(Mandatory = $true)][Int64]$AvailableFreeBytes,
        [Parameter(Mandatory = $true)][Int64]$RequiredFreeBytes,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Result,
        [scriptblock]$ConvertAction = { param($Source, $Destination) Convert-VHD -Path $Source -DestinationPath $Destination -VHDType Fixed -ErrorAction Stop | Out-Null },
        [scriptblock]$GetVhdAction = { param($Path) Get-VHD -Path $Path -ComputerName localhost -ErrorAction Stop },
        [scriptblock]$GetItemAction = { param($Path) Get-Item -LiteralPath $Path -Force -ErrorAction Stop },
        [scriptblock]$GetHashAction = { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() },
        [switch]$AllowDiscardInvalidDestination,
        [switch]$AllowOrphanDestinationBinding
    )

    $format = [string]$SourceVhd.VhdFormat
    $type = [string]$SourceVhd.VhdType
    $Result.required = ($format -eq 'VHD')
    $Result.status = 'validating_source'
    $Result.source_path = $SourcePath
    $Result.source_sha256 = $SourceSha256.ToLowerInvariant()
    $Result.source_format = $format
    $Result.source_type = $type
    $Result.available_free_bytes = $AvailableFreeBytes
    $Result.required_free_bytes = $RequiredFreeBytes

    if ($SourceSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        $Result.status = 'source_hash_invalid'
        throw 'Generation 2 parent source SHA-256 is invalid.'
    }
    if ($type -eq 'Differencing' -or -not [string]::IsNullOrWhiteSpace([string]$SourceVhd.ParentPath)) {
        $Result.status = 'source_parent_chain_unverified'
        throw 'Generation 2 parent conversion refuses a differencing source or unverified parent chain.'
    }

    $sourceItem = & $GetItemAction $SourcePath
    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        $Result.status = 'source_reparse_point'
        throw 'Generation 2 parent source is a reparse point; refusing an indirect input.'
    }
    if (Test-UnsafeVhdStorageAttributes -Attributes ([IO.FileAttributes]$sourceItem.Attributes)) {
        $Result.status = 'source_storage_attributes_invalid'
        throw 'Generation 2 parent source must be materialized, uncompressed, and unencrypted.'
    }
    $sourceFacts = & $GetVhdAction $SourcePath
    if ([string]$sourceFacts.VhdFormat -ne $format -or [string]$sourceFacts.VhdType -ne $type) {
        $Result.status = 'source_vhd_contract_changed'
        throw 'Generation 2 parent source format/type changed after validation.'
    }

    if ($format -eq 'VHDX') {
        if ([string]$sourceFacts.VhdFormat -ne 'VHDX' -or [string]$sourceFacts.VhdType -eq 'Differencing') {
            $Result.status = 'source_vhd_contract_invalid'
            throw 'Generation 2 source is not a supported standalone VHDX parent.'
        }
        $Result.required = $false
        $Result.status = 'already_gen2_compatible'
        $Result.destination_path = $SourcePath
        $Result.destination_sha256 = $SourceSha256.ToLowerInvariant()
        $Result.destination_format = [string]$sourceFacts.VhdFormat
        $Result.destination_type = [string]$sourceFacts.VhdType
        $Result.selected_parent_path = $SourcePath
        return $SourcePath
    }
    if ($format -ne 'VHD') {
        $Result.status = 'source_format_unsupported'
        throw "Generation 2 requires VHDX; unsupported validated parent format '$format'."
    }

    $sourceDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($SourcePath))
    $sourceStem = [IO.Path]::GetFileNameWithoutExtension($SourcePath)
    $destination = Join-Path $sourceDirectory ($sourceStem + '.gen2.vhdx')
    $manifestPath = $destination + '.provenance.json'
    $Result.destination_path = $destination
    $Result.manifest_path = $manifestPath
    Assert-NoExistingReparseComponent -Path $sourceDirectory -Result $Result -Status 'parent_reparse_point' -Description 'Generation 2 destination parent' -IncludeLeaf
    Assert-NoExistingReparseComponent -Path $destination -Result $Result -Status 'destination_reparse_point' -Description 'Generation 2 destination VHDX' -IncludeLeaf
    Assert-NoExistingReparseComponent -Path $manifestPath -Result $Result -Status 'manifest_reparse_point' -Description 'Generation 2 provenance manifest' -IncludeLeaf
    if ($AvailableFreeBytes -lt $RequiredFreeBytes) {
        $Result.status = 'insufficient_space'
        throw "Insufficient free space to convert the VHD to a Generation 2-compatible VHDX. Required at least $RequiredFreeBytes bytes; available $AvailableFreeBytes."
    }

    $reuse = $false
    $adopt = $false
    $destinationExists = Test-Path -LiteralPath $destination -PathType Leaf
    $manifestExists = Test-Path -LiteralPath $manifestPath -PathType Leaf
    if ($destinationExists) {
        $Result.status = 'validating_existing_vhdx'
        $existingStructurallyValid = Test-VhdxFileStructurallyValid -Path $destination
        $Result.existing_vhdx_structurally_valid = $existingStructurallyValid
        if (-not $manifestExists) {
            if ($existingStructurallyValid) {
                if (-not $AllowOrphanDestinationBinding) {
                    $Result.status = 'existing_vhdx_unbound'
                    throw "Existing converted VHDX has no provenance manifest; refusing to reuse or overwrite without -AllowOrphanDestinationBinding: $destination"
                }
                $Result.status = 'binding_orphan_destination'
                try {
                    $orphanFacts = & $GetVhdAction $destination
                }
                catch {
                    $Result.status = 'orphan_destination_unreadable'
                    throw "Existing converted VHDX cannot be read by the Hyper-V parser; refusing to bind it: $destination"
                }
                if ([string]$orphanFacts.VhdFormat -ne 'VHDX' -or
                    [string]$orphanFacts.VhdType -ne 'Fixed' -or
                    [Int64]$orphanFacts.Size -ne [Int64]$SourceVhd.Size) {
                    $Result.status = 'orphan_destination_contract_invalid'
                    throw "Existing converted VHDX does not satisfy the expected Fixed VHDX contract; refusing to bind it: $destination"
                }
                $Result.adopted_orphan_destination = $true
                $Result.adopted_orphan_note = 'destination pre-existed without a provenance manifest; bound after authoritative Hyper-V validation'
                $adopt = $true
            }
            elseif (-not $AllowDiscardInvalidDestination) {
                $Result.status = 'existing_vhdx_unbound'
                throw "Existing converted VHDX has no provenance manifest and fails the VHDX signature/header check; refusing to reuse or overwrite without -AllowDiscardInvalidDestination: $destination"
            }
            else {
                $partial = & $GetItemAction $destination
                $Result.discarded_invalid_destination = [ordered]@{
                    path = $destination
                    length_bytes = [Int64]$partial.Length
                    sha256 = [string](& $GetHashAction $destination)
                    reason = 'structurally_invalid_vhdx'
                    discarded_at_utc = [DateTime]::UtcNow.ToString('o')
                }
                Remove-Item -LiteralPath $destination -Force -ErrorAction Stop
                $Result.status = 'discarded_invalid_partial'
                $destinationExists = $false
            }
        }
        elseif (-not $existingStructurallyValid) {
            $Result.status = 'existing_vhdx_corrupt'
            throw "Existing converted VHDX fails the VHDX signature/header check; refusing to reuse or overwrite: $destination"
        }
        else {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($manifest.schema -ne 'hyperv-gen2-parent-conversion.v1' -or
                $manifest.source_path -ne $SourcePath -or
                $manifest.source_sha256 -ne $SourceSha256.ToLowerInvariant() -or
                $manifest.destination_path -ne $destination) {
                $Result.status = 'existing_vhdx_manifest_mismatch'
                throw "Converted VHDX provenance does not match the validated source; refusing to reuse or overwrite: $destination"
            }
            $reuse = $true
        }
    }
    elseif ($manifestExists) {
        $Result.status = 'orphan_vhdx_manifest'
        throw "Conversion provenance manifest exists without its VHDX; refusing to overwrite evidence: $manifestPath"
    }

    if (-not $reuse -and -not $adopt) {
        $Result.status = 'conversion_started'
        try {
            & $ConvertAction $SourcePath $destination
        }
        catch {
            $Result.status = 'conversion_failed_or_partial'
            if (Test-Path -LiteralPath $destination -PathType Leaf) {
                $partial = & $GetItemAction $destination
                $Result.partial_output = [ordered]@{
                    path = $destination
                    length_bytes = [Int64]$partial.Length
                    attributes = [string]$partial.Attributes
                    preserved = $true
                }
            }
            throw
        }
    }

    try {
        $destinationItem = & $GetItemAction $destination
        $destinationFacts = & $GetVhdAction $destination
        $destinationHash = [string](& $GetHashAction $destination)
        $sourceHashAfterConversion = [string](& $GetHashAction $SourcePath)
    }
    catch {
        $Result.status = 'conversion_validation_failed_or_partial'
        if (Test-Path -LiteralPath $destination -PathType Leaf) {
            $partial = Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            if ($null -ne $partial) {
                $Result.partial_output = [ordered]@{
                    path = $destination
                    length_bytes = [Int64]$partial.Length
                    attributes = [string]$partial.Attributes
                    preserved = $true
                }
            }
        }
        throw
    }

    if (-not (Test-VhdxFileStructurallyValid -Path $destination)) {
        $Result.status = 'destination_structurally_invalid'
        throw 'Converted Generation 2 VHDX fails the VHDX signature/header check; refusing to use it.'
    }

    $destinationAttributes = [IO.FileAttributes]$destinationItem.Attributes
    $Result.destination_sha256 = $destinationHash.ToLowerInvariant()
    $Result.destination_format = [string]$destinationFacts.VhdFormat
    $Result.destination_type = [string]$destinationFacts.VhdType
    if (Test-UnsafeVhdStorageAttributes -Attributes $destinationAttributes) {
        $Result.status = 'destination_storage_attributes_invalid'
        throw 'Converted Generation 2 VHDX is sparse, compressed, or encrypted; refusing to use it.'
    }
    if ([string]$destinationFacts.VhdFormat -ne 'VHDX' -or
        [string]$destinationFacts.VhdType -ne 'Fixed' -or
        [Int64]$destinationFacts.Size -ne [Int64]$SourceVhd.Size) {
        $Result.status = 'destination_vhd_contract_invalid'
        throw 'Converted parent is not a Fixed VHDX with the source virtual size; refusing to use it.'
    }
    if ($sourceHashAfterConversion.ToLowerInvariant() -ne $SourceSha256.ToLowerInvariant()) {
        $Result.status = 'source_changed_during_conversion'
        throw 'Validated source hash changed during VHDX conversion; refusing to use the converted parent.'
    }

    if ($reuse) {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($manifest.destination_sha256 -ne $destinationHash.ToLowerInvariant() -or
            $manifest.destination_format -ne 'VHDX' -or
            $manifest.destination_type -ne 'Fixed' -or
            [Int64]$manifest.virtual_size_bytes -ne [Int64]$SourceVhd.Size) {
            $Result.status = 'existing_vhdx_hash_mismatch'
            throw "Converted VHDX does not match its provenance manifest: $destination"
        }
        $Result.reused = $true
        $Result.status = 'reused_validated_vhdx'
    }
    else {
        $provenance = [ordered]@{
            schema = 'hyperv-gen2-parent-conversion.v1'
            created_at_utc = [DateTime]::UtcNow.ToString('o')
            source_path = $SourcePath
            source_sha256 = $SourceSha256.ToLowerInvariant()
            source_format = 'VHD'
            source_type = $type
            destination_path = $destination
            destination_sha256 = $destinationHash.ToLowerInvariant()
            destination_format = 'VHDX'
            destination_type = 'Fixed'
            virtual_size_bytes = [Int64]$SourceVhd.Size
            conversion = 'Convert-VHD to Fixed VHDX; source preserved and SHA-256 rechecked after conversion'
        }
        if ($adopt) {
            $provenance.adopted_orphan_destination = $true
            $provenance.adopted_orphan_note = $Result.adopted_orphan_note
            $provenance.adopted_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        Write-CreateOnlyJson -Path $manifestPath -Value $provenance
        $Result.reused = $false
        $Result.status = if ($adopt) { 'adopted_validated_vhdx' } else { 'created_validated_vhdx' }
    }
    $Result.manifest_sha256 = [string](& $GetHashAction $manifestPath)
    $Result.selected_parent_path = $destination
    return $destination
}

function Write-ProvisionReport {
    $report.completed_at_utc = [DateTime]::UtcNow.ToString('o')
    if (-not (Test-Path -LiteralPath $evidenceRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
    }
    $json = $report | ConvertTo-Json -Depth 10
    # CreateNew makes the report append-only for this run ID: never overwrite.
    $stream = [System.IO.FileStream]::new(
        $reportPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read
    )
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') {
try {
    $report.stage = 'preflight'
    $report.host_powershell_version = [string]$PSVersionTable.PSVersion
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
        throw 'Run this provisioner with Windows PowerShell 5.1 (powershell.exe), not PowerShell Core.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $report.preflight.is_admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $report.preflight.is_admin) { throw 'Administrator privileges are required; rerun through the normal Windows UAC prompt.' }

    Import-Module Hyper-V -ErrorAction Stop
    $requiredFeatures = @('Microsoft-Hyper-V-All', 'VirtualMachinePlatform', 'HypervisorPlatform')
    foreach ($featureName in $requiredFeatures) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
        $report.preflight.windows_features += [ordered]@{ name = $featureName; state = [string]$feature.State }
        if ([string]$feature.State -ne 'Enabled') { throw "Required Windows feature is not enabled: $featureName ($($feature.State))." }
    }

    $vmms = Get-Service -Name 'vmms' -ErrorAction Stop
    $report.preflight.vmms_status = [string]$vmms.Status
    if ([string]$vmms.Status -ne 'Running') { throw 'Hyper-V Virtual Machine Management service (vmms) is not running.' }

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $report.preflight.hypervisor_present = [bool]$computer.HypervisorPresent
    $report.preflight.firmware_virtualization_enabled = [bool]$processor.VirtualizationFirmwareEnabled
    if (-not $report.preflight.hypervisor_present) {
        if (-not $report.preflight.firmware_virtualization_enabled) {
            throw 'Firmware virtualization is not enabled or not reported by Windows.'
        }
        if (-not $processor.VMMonitorModeExtensions -or -not $processor.SecondLevelAddressTranslationExtensions) {
            throw 'Processor VM-monitor or SLAT capability is not enabled or not reported by Windows.'
        }
        $report.preflight.virtualization_check = 'firmware_requirements_confirmed_but_hypervisor_not_active'
        throw 'Hyper-V hypervisor is not active yet; reboot or finish host provisioning before creating a VM.'
    }
    else {
        # When Windows reports an active hypervisor, systeminfo says the
        # Hyper-V requirement details are not displayed. WMI may consequently
        # report the firmware bit as false even though the hypervisor is
        # running. Do not misclassify that masked probe as a missing feature.
        $report.preflight.virtualization_check = 'hypervisor_active_requirements_masked'
    }

    if (-not (Test-Path -LiteralPath $sourceVhd -PathType Leaf)) { throw "Source VHD not found: $sourceVhd" }
    $sourceItem = Get-Item -LiteralPath $sourceVhd -Force
    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Source VHD is a reparse point; refusing to use an indirect input.' }
    $sourceHash = (Get-FileHash -LiteralPath $sourceVhd -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $report.source.exists = $true
    $report.source.length_bytes = [Int64]$sourceItem.Length
    $report.source.vhd_sha256 = $sourceHash
    $report.source.attributes = @([Enum]::GetValues([IO.FileAttributes]) | Where-Object { $_ -ne 0 -and ($sourceItem.Attributes -band $_) -eq $_ } | ForEach-Object { [string]$_ })
    $report.source.sparse = (($sourceItem.Attributes -band [IO.FileAttributes]::SparseFile) -ne 0)
    $report.source.compressed = (($sourceItem.Attributes -band [IO.FileAttributes]::Compressed) -ne 0)
    $report.source.encrypted = (($sourceItem.Attributes -band [IO.FileAttributes]::Encrypted) -ne 0)
    if (Test-Path -LiteralPath $sourceArchive -PathType Leaf) {
        $archiveHash = (Get-FileHash -LiteralPath $sourceArchive -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $report.source.observed_archive_sha256 = $archiveHash
        if ($archiveHash -ne $publishedArchiveSha256) { throw 'Downloaded source archive hash does not match the published SHA-256.' }
        $report.source.published_archive_verification = 'matched_published_sha256'
    }

    $parentVhd = Get-VHD -Path $sourceVhd -ComputerName localhost -ErrorAction Stop
    if ($parentVhd.VhdType -eq 'Differencing' -or -not [string]::IsNullOrWhiteSpace([string]$parentVhd.ParentPath)) {
        throw 'Source VHD is itself a differencing disk; refusing an unverified parent chain.'
    }
    $parentFormat = [string]$parentVhd.VhdFormat
    $diffExtension = Get-VhdExtensionForFormat -Format $parentFormat
    $driveRoot = [IO.Path]::GetPathRoot($vmRoot)
    $driveInfo = [System.IO.DriveInfo]::new($driveRoot)
    $report.stage = 'materialize_parent_if_required'
    $selectedParentVhd = Resolve-ValidatedParentVhd `
        -OriginalPath $sourceVhd `
        -OriginalSha256 $sourceHash `
        -OriginalVhd $parentVhd `
        -OriginalAttributes $sourceItem.Attributes `
        -OriginalLengthBytes ([Int64]$sourceItem.Length) `
        -MaterializedRoot (Join-Path $labRoot 'materialized-parents') `
        -AvailableFreeBytes ([Int64]$driveInfo.AvailableFreeSpace) `
        -Result $report.materialized_parent
    $selectedParentFacts = Get-VHD -Path $selectedParentVhd -ComputerName localhost -ErrorAction Stop
    if ($report.materialized_parent.required) {
        $selectedParentSha256 = [string]$report.materialized_parent.destination_sha256
    }
    else {
        $selectedParentSha256 = $sourceHash
    }
    $downstreamReserve = [Int64]([Math]::Ceiling([double]$selectedParentFacts.Size * 1.25) + 10GB)
    $gen2RequiredFree = [Int64]([Int64]$selectedParentFacts.Size + $downstreamReserve + 1GB)
    $driveInfo = [System.IO.DriveInfo]::new($driveRoot)
    $report.preflight.free_bytes = [Int64]$driveInfo.AvailableFreeSpace
    $report.preflight.required_free_bytes = $gen2RequiredFree
    $report.stage = 'convert_parent_for_generation2'
    $report.allow_discard_invalid_destination = [bool]$AllowDiscardInvalidDestination
    $report.allow_orphan_destination_binding = [bool]$AllowOrphanDestinationBinding
    $selectedGen2Parent = Resolve-Gen2CompatibleParent `
        -SourcePath $selectedParentVhd `
        -SourceVhd $selectedParentFacts `
        -SourceSha256 $selectedParentSha256 `
        -AvailableFreeBytes ([Int64]$driveInfo.AvailableFreeSpace) `
        -RequiredFreeBytes $gen2RequiredFree `
        -Result $report.generation2_parent_conversion `
        -AllowDiscardInvalidDestination:$AllowDiscardInvalidDestination `
        -AllowOrphanDestinationBinding:$AllowOrphanDestinationBinding
    $selectedParentFacts = Get-VHD -Path $selectedGen2Parent -ComputerName localhost -ErrorAction Stop
    $selectedParentFormat = [string]$selectedParentFacts.VhdFormat
    $diffExtension = Get-VhdExtensionForFormat -Format $selectedParentFormat
    if ($diffExtension -ne '.vhdx') { throw 'Generation 2 requires a validated VHDX parent; refusing to create a VHD child.' }
    $diffVhd = Join-Path $vmRoot ("ubuntu-noble-diff{0}" -f $diffExtension)
    $requiredFree = $downstreamReserve
    $driveInfo = [System.IO.DriveInfo]::new($driveRoot)
    $report.preflight.free_bytes = [Int64]$driveInfo.AvailableFreeSpace
    $report.preflight.required_free_bytes = $requiredFree
    if ($driveInfo.AvailableFreeSpace -lt $requiredFree) {
        throw "Insufficient free space on $driveRoot after Generation 2 parent validation. Required at least $requiredFree bytes; available $($driveInfo.AvailableFreeSpace)."
    }

    # The source hash is an observation. The supplied published hash refers to
    # the source archive and is deliberately not compared to this extracted VHD.
    # Unique names and explicit collision checks prevent replacement of existing
    # switches, guests, checkpoints, or disks.
    $report.stage = 'collision_check'
    if (Test-Path -LiteralPath $vmRoot) { throw "Guest workspace already exists; refusing to reuse: $vmRoot" }
    if (Test-Path -LiteralPath $diffVhd) { throw "Differencing VHD already exists; refusing to overwrite: $diffVhd" }
    $existingVm = Get-VM -ComputerName localhost -ErrorAction Stop | Where-Object { $_.Name -eq $vmName }
    if ($existingVm) { throw "VM name collision: $vmName" }
    $existingSwitch = Get-VMSwitch -ComputerName localhost -ErrorAction Stop | Where-Object { $_.Name -eq $switchName }
    if ($existingSwitch) { throw "Switch name collision: $switchName" }

    $report.stage = 'create_private_switch'
    $switch = New-VMSwitch -ComputerName localhost -Name $switchName -SwitchType Private -ErrorAction Stop
    $switchFacts = Get-VMSwitch -ComputerName localhost -Name $switchName -ErrorAction Stop
    if ($switchFacts.SwitchType -ne 'Private') { throw "Created switch is not Private (actual: $($switchFacts.SwitchType))." }
    $report.resources.switch = [ordered]@{
        name = [string]$switchFacts.Name
        id = [string]$switchFacts.Id
        type = [string]$switchFacts.SwitchType
        internet_enabled = $false
    }

    $report.stage = 'create_differencing_disk'
    New-Item -ItemType Directory -Path $vmRoot -ErrorAction Stop | Out-Null
    if (Test-Path -LiteralPath $diffVhd) { throw "Differencing VHD appeared before creation; refusing to overwrite: $diffVhd" }
    $newDisk = New-VHD -ComputerName localhost -Path $diffVhd -ParentPath $selectedGen2Parent -Differencing -ErrorAction Stop
    $diskFacts = Get-VHD -ComputerName localhost -Path $diffVhd -ErrorAction Stop
    if ($diskFacts.VhdType -ne 'Differencing' -or [string]$diskFacts.VhdFormat -ne 'VHDX' -or [IO.Path]::GetFullPath($diskFacts.ParentPath) -ne [IO.Path]::GetFullPath($selectedGen2Parent)) {
        throw 'Created disk does not have the expected differencing type and source parent.'
    }
    $report.resources.vhd = [ordered]@{
        path = [string]$diskFacts.Path
        parent_path = [string]$diskFacts.ParentPath
        type = [string]$diskFacts.VhdType
        virtual_size_bytes = [Int64]$diskFacts.Size
        file_size_bytes = [Int64]$diskFacts.FileSize
        sha256 = (Get-FileHash -LiteralPath $diffVhd -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }

    $report.stage = 'create_vm_offline'
    $vm = New-VM -ComputerName localhost -Name $vmName -Generation 2 -MemoryStartupBytes 4GB -VHDPath $diffVhd -SwitchName $switchName -Path $vmRoot -ErrorAction Stop
    Set-VM -ComputerName localhost -VMName $vmName -AutomaticStartAction Nothing -AutomaticStopAction TurnOff -AutomaticCheckpointsEnabled $false -ErrorAction Stop
    Set-VMProcessor -ComputerName localhost -VMName $vmName -Count 2 -ErrorAction Stop
    Set-VMMemory -ComputerName localhost -VMName $vmName -DynamicMemoryEnabled $true -MinimumBytes 2GB -StartupBytes 4GB -MaximumBytes 8GB -ErrorAction Stop
    Set-VMFirmware -ComputerName localhost -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority -ErrorAction Stop
    $vmFacts = Get-VM -ComputerName localhost -Name $vmName -ErrorAction Stop
    if ($vmFacts.State -ne 'Off' -or $vmFacts.Generation -ne 2) { throw 'Created VM is not in the expected powered-off Generation 2 state.' }
    $networkAdapters = @(Get-VMNetworkAdapter -ComputerName localhost -VMName $vmName -ErrorAction Stop)
    if ($networkAdapters.Count -ne 1 -or $networkAdapters[0].SwitchName -ne $switchName) {
        throw 'VM network adapter inventory differs from the single isolated Private switch expected.'
    }
    $report.resources.vm = [ordered]@{
        name = [string]$vmFacts.Name
        id = [string]$vmFacts.Id
        state = [string]$vmFacts.State
        generation = [int]$vmFacts.Generation
        memory_startup_bytes = [Int64]$vmFacts.MemoryStartup
        secure_boot_template = 'MicrosoftUEFICertificateAuthority'
        network = 'private-switch-only; no NAT or external adapter'
        network_adapters = @($networkAdapters | ForEach-Object { [ordered]@{ name = [string]$_.Name; switch_name = [string]$_.SwitchName; mac_address = [string]$_.MacAddress } })
    }

    $report.stage = 'create_pre_execution_checkpoint'
    Checkpoint-VM -ComputerName localhost -VMName $vmName -SnapshotName $checkpointName -ErrorAction Stop | Out-Null
    $checkpoint = Get-VMSnapshot -ComputerName localhost -VMName $vmName -Name $checkpointName -ErrorAction Stop
    $report.resources.checkpoint = [ordered]@{
        name = [string]$checkpoint.Name
        id = [string]$checkpoint.Id
        creation_time = [DateTime]$checkpoint.CreationTime
        state = 'created_before_any_guest_execution'
    }

    $report.status = 'provisioned_offline_pre_execution'
    $report.stage = 'complete'
    Write-ProvisionReport
    Write-Host ''
    Write-Host 'Provisionamento concluido: VM desligada e isolada em switch Private.' -ForegroundColor Green
    Write-Host 'Nenhuma amostra foi executada; teste dinamico e rollback NAO foram comprovados.' -ForegroundColor Yellow
    Write-Host "Relatorio: $reportPath"
    exit 0
}
catch {
    $message = $_.Exception.Message
    if ($message -match 'denied|permission|access is denied|permiss') { $message = 'Acesso negado pelo host/ACL ao consultar ou provisionar Hyper-V; nenhuma elevação alternativa foi tentada.' }
    $report.status = 'blocked_or_partial'
    $report.errors += [ordered]@{ stage = [string]$report.stage; message = $message }
    try { Write-ProvisionReport } catch { Write-Error "Falha ao persistir o relatório: $($_.Exception.Message)" }
    Write-Host "Falha: $message" -ForegroundColor Red
    Write-Host "Recursos criados, se houver, foram preservados; nenhuma limpeza destrutiva foi executada. Relatorio: $reportPath" -ForegroundColor Yellow
    exit 2
}
}

