# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 rollback: restore a quarantined file (Windows agents).
#
# Reverses edr-quarantine-file.ps1 using the manifest. Verifies SHA256 still
# matches before restoring (a tampered quarantine file is not put back), moves
# the file to its original path, and marks the manifest entry restored.
#
# Manual use (analyst):
#   powershell -File edr-unquarantine-file.ps1 -Sha256 <hash>
#   powershell -File edr-unquarantine-file.ps1 -QuarantinePath <path>
#   powershell -File edr-unquarantine-file.ps1 -List

param(
    [string]$Sha256,
    [string]$QuarantinePath,
    [switch]$List
)

. "$PSScriptRoot\edr_common.ps1"

$AR_NAME = "edr-unquarantine-file"

function Get-QuarantineDir { param($Cfg)
    $d = "quarantine"; try { if ($Cfg.quarantine.dir_windows) { $d = $Cfg.quarantine.dir_windows } } catch {}
    if (-not [System.IO.Path]::IsPathRooted($d)) { $d = Join-Path $script:EdrAgentHome $d }
    return $d
}
function Get-ManifestPath { param($Cfg)
    $n = "quarantine-manifest.jsonl"; try { if ($Cfg.quarantine.manifest) { $n = $Cfg.quarantine.manifest } } catch {}
    Join-Path (Get-QuarantineDir $Cfg) $n
}
function Read-Manifest { param($Cfg)
    $p = Get-ManifestPath $Cfg
    if (-not (Test-Path $p)) { return @() }
    return @(Get-Content $p | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Write-Manifest { param($Cfg, $Entries)
    $p = Get-ManifestPath $Cfg
    ($Entries | ForEach-Object { $_ | ConvertTo-Json -Compress }) | Set-Content -Path $p -Encoding utf8
}

function Restore-One {
    param($Cfg, [bool]$Dry, $Entry, $Alert)
    $detail = @{ original_path = $Entry.original_path; quarantine_path = $Entry.quarantine_path
                sha256 = $Entry.sha256; restored_at = (Get-Date).ToUniversalTime().ToString("o") }
    if (-not $Entry.quarantine_path -or -not (Test-Path -LiteralPath $Entry.quarantine_path)) {
        $detail["error"] = "quarantined file missing"
        Write-EdrAudit $Cfg $AR_NAME $Alert "unquarantine" $Dry "not_found" $detail | Out-Null
        return $script:OS_NOTFOUND
    }
    if ($Entry.sha256) {
        # clear read-only so we can hash/move
        try { Set-ItemProperty -LiteralPath $Entry.quarantine_path -Name IsReadOnly -Value $false } catch {}
        $actual = (Get-FileHash -LiteralPath $Entry.quarantine_path -Algorithm SHA256).Hash.ToLower()
        $detail["sha256_actual"] = $actual
        if ($actual -ne $Entry.sha256) {
            $detail["error"] = "SHA256 mismatch — quarantined file changed; refusing to restore"
            Write-EdrAudit $Cfg $AR_NAME $Alert "unquarantine" $Dry "refused" $detail | Out-Null
            return $script:OS_INVALID
        }
    }
    if ($Dry) {
        $detail["would_do"] = "move $($Entry.quarantine_path) -> $($Entry.original_path)"
        Write-EdrAudit $Cfg $AR_NAME $Alert "unquarantine" $true "dry_run" $detail | Out-Null
        return $script:OS_SUCCESS
    }
    try {
        $od = Split-Path $Entry.original_path
        if ($od -and -not (Test-Path $od)) { New-Item -ItemType Directory -Force -Path $od | Out-Null }
        Move-Item -LiteralPath $Entry.quarantine_path -Destination $Entry.original_path -Force
    } catch {
        $detail["error"] = $_.Exception.Message
        Write-EdrAudit $Cfg $AR_NAME $Alert "unquarantine" $false "error" $detail | Out-Null
        return $script:OS_INVALID
    }
    $Entry.restored = $true
    Write-EdrAudit $Cfg $AR_NAME $Alert "unquarantine" $false "restored" $detail | Out-Null
    return $script:OS_SUCCESS
}

$cfg = Get-EdrConfig
$dry = Get-EdrDryRun $cfg
$entries = Read-Manifest $cfg

if ($List) {
    ($entries | Where-Object { -not $_.restored }) | ConvertTo-Json -Depth 6
    exit $script:OS_SUCCESS
}

$chosen = $null
if ($Sha256) {
    $chosen = $entries | Where-Object { $_.sha256 -eq $Sha256 -and -not $_.restored } | Select-Object -First 1
} elseif ($QuarantinePath) {
    $chosen = $entries | Where-Object { $_.quarantine_path -eq $QuarantinePath -and -not $_.restored } | Select-Object -First 1
} else {
    # AR mode: match by original path from the alert
    $message = Read-EdrMessage
    $alert = if ($message) { Get-EdrAlert $message } else { @{} }
    if ($message -and $message.command -eq "delete") {
        Write-EdrAudit $cfg $AR_NAME $alert "unquarantine" $dry "noop" @{ reason = "delete callback" } | Out-Null
        exit $script:OS_SUCCESS
    }
    $target = Get-EdrField $alert @('syscheck.path','file.path','data.file')
    if (-not $target) {
        Write-EdrAudit $cfg $AR_NAME $alert "unquarantine" $dry "not_found" @{ reason = "no selector and no file path in alert" } | Out-Null
        exit $script:OS_NOTFOUND
    }
    $chosen = $entries | Where-Object { $_.original_path -eq $target -and -not $_.restored } | Select-Object -First 1
    if (-not $chosen) {
        Write-EdrAudit $cfg $AR_NAME $alert "unquarantine" $dry "not_found" @{ reason = "no active quarantine entry for path"; path = $target } | Out-Null
        exit $script:OS_NOTFOUND
    }
    $rc = Restore-One $cfg $dry $chosen $alert
    if (-not $dry) { Write-Manifest $cfg $entries }
    exit $rc
}

if (-not $chosen) {
    Write-EdrAudit $cfg $AR_NAME @{} "unquarantine" $dry "not_found" @{ reason = "no matching active quarantine entry" } | Out-Null
    exit $script:OS_NOTFOUND
}
$rc = Restore-One $cfg $dry $chosen @{}
if (-not $dry) { Write-Manifest $cfg $entries }
exit $rc
