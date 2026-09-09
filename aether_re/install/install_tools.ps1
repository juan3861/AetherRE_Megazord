# AetherRE Megazord — instalador de ferramentas externas (opcional)
# Corre como utilizador normal. Verifica espaço em disco ANTES de baixar.
# Uso: powershell -ExecutionPolicy Bypass -File install_tools.ps1 [-What]

param(
    [ValidateSet("status", "python-deps", "rizin", "frida", "unicorn", "ghidra-hint", "all-light")]
    [string]$Action = "status"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ToolsRoot = Join-Path $ProjectRoot "tools"
New-Item -ItemType Directory -Force -Path $ToolsRoot | Out-Null

function Get-FreeGB([string]$Path) {
    $drive = (Get-Item $Path).PSDrive.Name
    $free = (Get-PSDrive $drive).Free
    return [math]::Round($free / 1GB, 2)
}

function Get-GhidraHome {
    if ($env:GHIDRA_HOME -and (Test-Path (Join-Path $env:GHIDRA_HOME "support" "analyzeHeadless"))) {
        return $env:GHIDRA_HOME
    }
    $candidates = @(
        Get-ChildItem $ToolsRoot -Directory |
            Where-Object { $_.Name -like "ghidra_*_PUBLIC" } |
            Sort-Object Name -Descending
    )
    return $candidates[0].FullName
}

function Show-Status {
    Write-Host "=== AetherRE tools status ==="
    Write-Host "Free on D: $(Get-FreeGB 'D:\') GB"
    Write-Host "Free on C: $(Get-FreeGB 'C:\') GB"
    Write-Host "GHIDRA_HOME=$env:GHIDRA_HOME"
    foreach ($c in @("rizin", "r2", "frida", "java")) {
        $g = Get-Command $c -ErrorAction SilentlyContinue
        if ($g) { Write-Host "[OK] $c -> $($g.Source)" } else { Write-Host "[--] $c" }
    }
    $ghidra = Get-GhidraHome
    Write-Host "Ghidra local: $ghidra"
    if ($ghidra) { Write-Host "analyzeHeadless: $(Test-Path (Join-Path $ghidra "support" "analyzeHeadless"))" }
    Write-Host ""
    Write-Host "NOTA: Ghidra full ~400-600MB. ImHex/Cutter instaladores grandes."
    Write-Host "Com pouco disco, use só: python-deps + unicorn + frida."
}

function Install-PythonDeps {
    Write-Host "Instalando deps Python (pefile, capstone, rich, unicorn, frida-tools)..."
    py -3.13 -m pip install --upgrade pefile capstone rich unicorn frida-tools
}

function Install-Rizin {
    Write-Host "Rizin: preferir winget ou release GitHub."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Rizin.Rizin -e --accept-package-agreements --accept-source-agreements
    } else {
        Write-Host "Abra: https://github.com/rizinorg/rizin/releases"
        Write-Host "Extraia para $ToolsRoot\rizin e adicione ao PATH."
    }
}

function Show-GhidraHint {
    $free = Get-FreeGB "D:\"
    Write-Host "Ghidra precisa ~500MB+ livres. Disco D tem $free GB."
    Write-Host "1) Download: https://github.com/NationalSecurityAgency/ghidra/releases"
    Write-Host "2) Extraia para: $ToolsRoot\<versao> (por exemplo ghidra_12.1.2_PUBLIC)"
    Write-Host "3) O instalador detecta automaticamente a pasta mais recente"
    Write-Host "4) megazord.py status  # deve mostrar ghidra OK"
}

switch ($Action) {
    "status"       { Show-Status }
    "python-deps"  { Install-PythonDeps }
    "rizin"        { Install-Rizin }
    "frida"        { py -3.13 -m pip install frida-tools }
    "unicorn"      { py -3.13 -m pip install unicorn }
    "ghidra-hint"  { Show-GhidraHint }
    "all-light"    {
        Install-PythonDeps
        Write-Host "Pacote leve instalado. Ghidra/ImHex/Cutter: corra -Action ghidra-hint (manual, pesado)."
    }
}
