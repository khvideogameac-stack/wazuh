# Rwased EDR - Windows agent installer.
# Copies the EDR response scripts (.ps1 + .cmd shims) and config onto a Wazuh
# WINDOWS AGENT. Idempotent; no agent restart needed (wazuh-execd loads AR
# scripts on demand). Designed to be dropped into your RMM PowerShell wrapper
# (runs as SYSTEM, bypasses execution policy).
#
#   powershell -ExecutionPolicy Bypass -File Install-EdrAgent.ps1
#   powershell -ExecutionPolicy Bypass -File Install-EdrAgent.ps1 -ManagerIp 10.20.22.10
#
# -SourceDir defaults to the edr\ folder two levels up from this script.
param(
    [string]$AgentHome = "C:\Program Files (x86)\ossec-agent",
    [string]$SourceDir,
    [string]$ManagerIp
)
$ErrorActionPreference = "Stop"

if (-not $SourceDir) { $SourceDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
$binDst = Join-Path $AgentHome "active-response\bin"
$etcDst = Join-Path $AgentHome "etc"

Write-Host "==> Rwased EDR Windows agent install"
Write-Host "    source : $SourceDir"
Write-Host "    target : $AgentHome"

if (-not (Test-Path $binDst)) { throw "Not found: $binDst — is the Wazuh agent installed at -AgentHome?" }

# 1) shared helper + response scripts + .cmd shims
Copy-Item (Join-Path $SourceDir "active-response\bin\edr_common.ps1") $binDst -Force
Get-ChildItem (Join-Path $SourceDir "active-response\bin") -Filter "edr-*.ps1" | ForEach-Object { Copy-Item $_.FullName $binDst -Force }
Get-ChildItem (Join-Path $SourceDir "active-response\bin") -Filter "edr-*.cmd" | ForEach-Object { Copy-Item $_.FullName $binDst -Force }
Write-Host "    ok     : scripts + .cmd shims installed"

# 2) config (do not overwrite an existing one)
$cfgDst = Join-Path $etcDst "edr.conf.json"
if (Test-Path $cfgDst) {
    Write-Host "    keep   : existing $cfgDst"
} else {
    Copy-Item (Join-Path $SourceDir "etc\edr.conf.json") $cfgDst -Force
    Write-Host "    ok     : edr.conf.json installed"
}

# 3) optionally set manager.ip
if ($ManagerIp) {
    $c = Get-Content -Raw $cfgDst | ConvertFrom-Json
    if (-not $c.manager) { $c | Add-Member -NotePropertyName manager -NotePropertyValue (@{}) -Force }
    $c.manager.ip = $ManagerIp
    ($c | ConvertTo-Json -Depth 8) | Set-Content -Path $cfgDst -Encoding utf8
    Write-Host "    ok     : manager.ip set to $ManagerIp"
}

Write-Host ""
Write-Host "Done. EDR scripts installed in DRY-RUN by default."
Write-Host "Reminder: set manager.ip in $cfgDst before enabling host isolation."
Write-Host "Reminder: do NOT add <anti_tampering> to agent.conf; run verify-agent-conf after any agent.conf change."
