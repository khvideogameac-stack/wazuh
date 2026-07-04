# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 response: file quarantine (Windows agents).
#
# MOVES (never deletes) a suspicious file into a locked-down quarantine folder.
# Records SHA256 before the move and appends a manifest entry (original path ->
# quarantine path -> timestamp -> triggering rule/agent) so the file can be
# restored by edr-unquarantine-file.ps1. The quarantine folder ACL is tightened
# so only SYSTEM/Administrators can read it. Honours dry-run.
#
# Target resolved from extra_args (a literal path) or the alert
# (syscheck.path / file.path / data.win.eventdata.targetFilename).

. "$PSScriptRoot\edr_common.ps1"

$AR_NAME = "edr-quarantine-file"
$PROTECTED_PREFIXES = @("C:\Windows", "C:\Program Files\ossec-agent", "C:\Program Files (x86)\ossec-agent")

function Get-QuarantineDir {
    param($Cfg)
    $d = "quarantine"; try { if ($Cfg.quarantine.dir_windows) { $d = $Cfg.quarantine.dir_windows } } catch {}
    if (-not [System.IO.Path]::IsPathRooted($d)) { $d = Join-Path $script:EdrAgentHome $d }
    return $d
}
function Get-ManifestPath {
    param($Cfg)
    $n = "quarantine-manifest.jsonl"; try { if ($Cfg.quarantine.manifest) { $n = $Cfg.quarantine.manifest } } catch {}
    Join-Path (Get-QuarantineDir $Cfg) $n
}

function Resolve-Target {
    param($Message, $Alert)
    foreach ($arg in (Get-EdrExtraArgs $Message)) { return "$arg" }
    return (Get-EdrField $Alert @('syscheck.path','file.path','data.win.eventdata.targetFilename','data.file','data.path'))
}

function Test-ProtectedPath {
    param([string]$Path)
    try { $rp = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path } catch { $rp = $Path }
    if ($rp.ToLower().StartsWith($script:EdrAgentHome.ToLower())) { return @{ p = $true; reason = "path is inside the agent install directory" } }
    foreach ($pref in $PROTECTED_PREFIXES) {
        if ($rp.ToLower().StartsWith($pref.ToLower())) { return @{ p = $true; reason = "path is under protected system location $pref" } }
    }
    return @{ p = $false; reason = "" }
}

$cfg = Get-EdrConfig
$dry = Get-EdrDryRun $cfg
$message = Read-EdrMessage
if ($null -eq $message) {
    Write-EdrAudit $cfg $AR_NAME @{} "quarantine" $dry "error" @{ reason = "invalid stdin JSON" } | Out-Null
    exit $script:OS_INVALID
}
$alert = Get-EdrAlert $message
if ($message.command -eq "delete") {
    Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $dry "noop" @{ reason = "delete/timeout callback — use edr-unquarantine-file.ps1 to restore" } | Out-Null
    exit $script:OS_SUCCESS
}

$target = Resolve-Target $message $alert
if (-not $target) {
    Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $dry "not_found" @{ reason = "no file path in alert/extra_args" } | Out-Null
    exit $script:OS_NOTFOUND
}
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
    Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $dry "not_found" @{ reason = "path is not a file or does not exist"; path = $target } | Out-Null
    exit $script:OS_NOTFOUND
}

$prot = Test-ProtectedPath $target
if ($prot.p) {
    Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $dry "refused" @{ path = $target; reason = $prot.reason } | Out-Null
    exit $script:OS_SUCCESS
}

try {
    $digest = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
    $size = (Get-Item -LiteralPath $target).Length
} catch {
    Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $dry "error" @{ path = $target; reason = "cannot read file: $($_.Exception.Message)" } | Out-Null
    exit $script:OS_INVALID
}

$ts = (Get-Date).ToUniversalTime()
$stamp = $ts.ToString("yyyyMMddTHHmmss")
$qdir = Get-QuarantineDir $cfg
$qname = "{0}_{1}_{2}" -f $stamp, $digest.Substring(0,12), [System.IO.Path]::GetFileName($target)
$qpath = Join-Path $qdir $qname
$detail = @{ original_path = $target; quarantine_path = $qpath; sha256 = $digest; size_bytes = $size; quarantined_at = $ts.ToString("o") }

if ($dry) {
    Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $true "dry_run" $detail | Out-Null
    exit $script:OS_SUCCESS
}

try {
    if (-not (Test-Path $qdir)) { New-Item -ItemType Directory -Force -Path $qdir | Out-Null }
    # Tighten the quarantine folder ACL: disable inheritance, SYSTEM + Administrators full only.
    try {
        icacls $qdir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    } catch {}
    Move-Item -LiteralPath $target -Destination $qpath -Force
    # make the quarantined file read-only
    Set-ItemProperty -LiteralPath $qpath -Name IsReadOnly -Value $true
} catch {
    $detail["error"] = $_.Exception.Message
    Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $false "error" $detail | Out-Null
    exit $script:OS_INVALID
}

$entry = $detail.Clone()
$entry["rule_id"] = (Get-EdrRuleId $alert)
$entry["agent_id"] = (Get-EdrAgentId $alert)
$entry["restored"] = $false
($entry | ConvertTo-Json -Compress) | Add-Content -Path (Get-ManifestPath $cfg) -Encoding utf8
Write-EdrAudit $cfg $AR_NAME $alert "quarantine" $false "quarantined" $detail | Out-Null
exit $script:OS_SUCCESS
