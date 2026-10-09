<#
  AetherRE Megazord - project-state restore (read-only)

  This script restores the *project investigation context* (status, Git state,
  latest run checkpoints and report hashes). It cannot reopen a Codex/Telegram
  conversation; the supplied session id is retained as a trace label only.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$SessionId = "d7949791-7071-4f79-b103-55391122e723",
    [int]$MaxRuns = 12
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $PSCommandPath
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = $scriptRoot }
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
Set-Location -LiteralPath $ProjectRoot

$outputDir = Join-Path $ProjectRoot "output"
if (-not (Test-Path -LiteralPath $outputDir -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$python = $null
$pythonCandidates = @(
    "C:\Users\juanp\AppData\Local\Programs\Python\Python313\python.exe",
    (Get-Command py -ErrorAction SilentlyContinue).Source
)
foreach ($candidate in $pythonCandidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $python = $candidate
        break
    }
}

$statusOutput = @()
$statusExit = $null
if ($python) {
    $pythonArgs = @()
    if ([IO.Path]::GetFileName($python) -ieq "py.exe") { $pythonArgs = @("-3.13") }
    $statusOutput = & $python @pythonArgs .\megazord.py status 2>&1
    $statusExit = $LASTEXITCODE
} else {
    $statusOutput = @("Python 3.13 não encontrado; status não executado")
    $statusExit = 127
}

$gitOutput = @(git -C $ProjectRoot status --short 2>&1)
$gitExit = $LASTEXITCODE
$runs = @()
if (Test-Path -LiteralPath $outputDir -PathType Container) {
    $runCandidates = Get-ChildItem -LiteralPath $outputDir -Directory |
        Where-Object { (Test-Path (Join-Path $_.FullName "report.json")) -or (Test-Path (Join-Path $_.FullName "checkpoint.json")) } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First ([Math]::Max(0, $MaxRuns))
    foreach ($run in $runCandidates) {
        $checkpointPath = Join-Path $run.FullName "checkpoint.json"
        $reportPath = Join-Path $run.FullName "report.json"
        $checkpoint = $null
        $report = $null
        $reportSha256 = $null
        if (Test-Path -LiteralPath $checkpointPath) {
            try { $checkpoint = Get-Content -Raw -LiteralPath $checkpointPath | ConvertFrom-Json } catch { $checkpoint = @{ parse_error = $_.Exception.Message } }
        }
        if (Test-Path -LiteralPath $reportPath) {
            try { $report = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json } catch { $report = @{ parse_error = $_.Exception.Message } }
            try { $reportSha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant() } catch { $reportSha256 = $null }
        }
        $runs += [ordered]@{
            name = $run.Name
            path = $run.FullName
            last_write = $run.LastWriteTime.ToUniversalTime().ToString("o")
            checkpoint_status = if ($checkpoint) { $checkpoint.status } else { $null }
            checkpoint_stage = if ($checkpoint) { $checkpoint.stage } else { $null }
            target_sha256 = if ($report) { $report.target_sha256 } else { $null }
            report_sha256 = $reportSha256
            report_format = if ($report -and $report.target_identity) { $report.target_identity.format } else { $null }
        }
    }
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$restorePath = Join-Path $outputDir ("session_restore_{0}.json" -f $timestamp)
$snapshot = [ordered]@{
    schema = "session-restore.v1"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    session_id = $SessionId
    project_root = $ProjectRoot
    conversation_restored = $false
    note = "Session id is a trace label; this local script restores project state only, not a Codex/Telegram conversation."
    python = $python
    megazord_status_exit = $statusExit
    megazord_status = @($statusOutput | ForEach-Object { $_.ToString() })
    git_status_exit = $gitExit
    git_status = @($gitOutput | ForEach-Object { $_.ToString() })
    latest_runs = $runs
}
$snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $restorePath -Encoding UTF8

Write-Host "AetherRE Megazord - project state restored"
Write-Host ("Project : {0}" -f $ProjectRoot)
Write-Host ("Session : {0} (trace label; conversation_restored=false)" -f $SessionId)
Write-Host ("Status  : exit {0}" -f $statusExit)
Write-Host ("Git     : exit {0}; changed entries={1}" -f $gitExit, @($gitOutput).Count)
Write-Host ("Runs    : {0}" -f @($runs).Count)
Write-Host ("Snapshot: {0}" -f $restorePath)
Write-Host "Use this same directory to continue; no target was executed by the restore script."
