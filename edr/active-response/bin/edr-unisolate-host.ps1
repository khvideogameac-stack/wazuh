# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 rollback: remove network isolation (Windows agents).
#
# Reverses edr-isolate-host.ps1 by deleting every firewall rule in the
# "Rwased-EDR-Isolation" group. Idempotent. Records the isolation window end
# (and duration when the start is known) in the audit log.
#
# Trigger as an active response (command="add") for an "unisolate" rule, or run
# manually by an analyst:  powershell -File edr-unisolate-host.ps1

. "$PSScriptRoot\edr_common.ps1"

$AR_NAME = "edr-unisolate-host"
$RULE_GROUP = "Rwased-EDR-Isolation"

function Get-StateFile { Join-Path $script:EdrAgentHome "active-response\edr-isolation.state" }

function Test-Isolated {
    netsh advfirewall firewall show rule name="$RULE_GROUP-block-out" 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-Unisolate {
    param($Cfg, [bool]$Dry, $Alert, [string]$Reason)
    $now = Get-Date
    $detail = @{ reason = $Reason; isolation_end = $now.ToUniversalTime().ToString("o") }
    try {
        if (Test-Path (Get-StateFile)) {
            $state = Get-Content -Raw (Get-StateFile) | ConvertFrom-Json
            if ($state.start) {
                $detail["isolation_start"] = $state.start
                try { $detail["isolation_seconds"] = [int]((New-TimeSpan -Start ([datetime]$state.start) -End $now).TotalSeconds) } catch {}
            }
        }
    } catch {}

    if (-not (Test-Isolated)) {
        Write-EdrAudit $Cfg $AR_NAME $Alert "unisolate" $Dry "not_isolated" $detail | Out-Null
        return $script:OS_SUCCESS
    }
    if ($Dry) {
        $detail["would_do"] = "delete firewall rules in group $RULE_GROUP"
        Write-EdrAudit $Cfg $AR_NAME $Alert "unisolate" $true "dry_run" $detail | Out-Null
        return $script:OS_SUCCESS
    }

    # Delete the block + manager-allow, then any per-port allow rules from config.
    netsh advfirewall firewall delete rule name="$RULE_GROUP-block-out" 2>$null | Out-Null
    netsh advfirewall firewall delete rule name="$RULE_GROUP-allow-mgr" 2>$null | Out-Null
    try {
        foreach ($p in @($Cfg.isolation.allow_ports)) {
            netsh advfirewall firewall delete rule name="$RULE_GROUP-allow-port-$p" 2>$null | Out-Null
        }
    } catch {}

    if (Test-Isolated) {
        $detail["error"] = "block rule still present after removal"
        Write-EdrAudit $Cfg $AR_NAME $Alert "unisolate" $false "error" $detail | Out-Null
        return $script:OS_INVALID
    }
    Remove-Item -Path (Get-StateFile) -ErrorAction SilentlyContinue
    Write-EdrAudit $Cfg $AR_NAME $Alert "unisolate" $false "unisolated" $detail | Out-Null
    return $script:OS_SUCCESS
}

$cfg = Get-EdrConfig
$dry = Get-EdrDryRun $cfg
$message = Read-EdrMessage
$alert = if ($message) { Get-EdrAlert $message } else { @{} }
if ($message -and $message.command -eq "delete") {
    Write-EdrAudit $cfg $AR_NAME $alert "unisolate" $dry "noop" @{ reason = "delete callback" } | Out-Null
    exit $script:OS_SUCCESS
}
exit (Invoke-Unisolate $cfg $dry $alert "manual/rule")
