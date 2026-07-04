# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 response: network isolation / host quarantine (Windows agents).
#
# Blocks all outbound traffic EXCEPT to the Wazuh manager (and configured
# allow_ips / allow_ports) using Windows Firewall (netsh advfirewall). All rules
# are grouped under the name "Rwased-EDR-Isolation" so edr-unisolate-host.ps1
# can remove them cleanly. Fully reversible; the isolation window start/end is
# recorded in a state file and the audit log.
#
# command="add" isolates; command="delete" (AR timeout) auto-unisolates so a
# stuck isolation self-heals.

. "$PSScriptRoot\edr_common.ps1"

$AR_NAME = "edr-isolate-host"
$RULE_GROUP = "Rwased-EDR-Isolation"

function Get-StateFile { Join-Path $script:EdrAgentHome "active-response\edr-isolation.state" }

function Test-Isolated {
    $out = netsh advfirewall firewall show rule name="$RULE_GROUP-block-out" 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Get-PlannedActions {
    param($Cfg)
    $managerIp = $null; try { $managerIp = $Cfg.manager.ip } catch {}
    $allowIps = @(); try { $allowIps = @($Cfg.isolation.allow_ips) } catch {}
    if ($managerIp -and ($allowIps -notcontains $managerIp)) { $allowIps += $managerIp }
    $allowPorts = @(); try { $allowPorts = @($Cfg.isolation.allow_ports) } catch {}

    $actions = @()
    # Allow rules (evaluated before the block because Windows Firewall lets
    # explicit allow win over a block at equal specificity for these).
    if ($allowIps.Count -gt 0) {
        $actions += "netsh advfirewall firewall add rule name=`"$RULE_GROUP-allow-mgr`" dir=out action=allow remoteip=$($allowIps -join ',') enable=yes"
    }
    foreach ($p in $allowPorts) {
        $actions += "netsh advfirewall firewall add rule name=`"$RULE_GROUP-allow-port-$p`" dir=out action=allow protocol=TCP remoteport=$p enable=yes"
    }
    # Catch-all block
    $actions += "netsh advfirewall firewall add rule name=`"$RULE_GROUP-block-out`" dir=out action=block remoteip=any enable=yes"
    return @{ actions = $actions; allow_ips = $allowIps; allow_ports = $allowPorts; manager_ip = $managerIp }
}

function Invoke-Isolation {
    param($Plan)
    $executed = @()
    if ($Plan.allow_ips.Count -gt 0) {
        netsh advfirewall firewall add rule name="$RULE_GROUP-allow-mgr" dir=out action=allow remoteip=($Plan.allow_ips -join ',') enable=yes | Out-Null
        $executed += "allow $($Plan.allow_ips -join ',')"
    }
    foreach ($p in $Plan.allow_ports) {
        netsh advfirewall firewall add rule name="$RULE_GROUP-allow-port-$p" dir=out action=allow protocol=TCP remoteport=$p enable=yes | Out-Null
        netsh advfirewall firewall add rule name="$RULE_GROUP-allow-port-$p" dir=out action=allow protocol=UDP remoteport=$p enable=yes | Out-Null
        $executed += "allow port $p"
    }
    netsh advfirewall firewall add rule name="$RULE_GROUP-block-out" dir=out action=block remoteip=any enable=yes | Out-Null
    $executed += "block all outbound"
    return $executed
}

$cfg = Get-EdrConfig
$dry = Get-EdrDryRun $cfg
$message = Read-EdrMessage
if ($null -eq $message) {
    Write-EdrAudit $cfg $AR_NAME @{} "isolate" $dry "error" @{ reason = "invalid stdin JSON" } | Out-Null
    exit $script:OS_INVALID
}
$alert = Get-EdrAlert $message

if ($message.command -eq "delete") {
    & "$PSScriptRoot\edr-unisolate-host.ps1"
    exit $script:OS_SUCCESS
}

$now = (Get-Date).ToUniversalTime().ToString("o")
$managerIp = $null; try { $managerIp = $cfg.manager.ip } catch {}
if (-not $managerIp) {
    Write-EdrAudit $cfg $AR_NAME $alert "isolate" $dry "refused" @{ reason = "manager.ip not configured — refusing to isolate (would cut the agent off entirely)" } | Out-Null
    exit $script:OS_INVALID
}

$plan = Get-PlannedActions $cfg
$detail = @{ manager_ip = $managerIp; allow_ips = $plan.allow_ips; allow_ports = $plan.allow_ports; isolation_start = $now; planned_actions = $plan.actions }

if (Test-Isolated) {
    Write-EdrAudit $cfg $AR_NAME $alert "isolate" $dry "already_isolated" $detail | Out-Null
    exit $script:OS_SUCCESS
}
if ($dry) {
    Write-EdrAudit $cfg $AR_NAME $alert "isolate" $true "dry_run" $detail | Out-Null
    exit $script:OS_SUCCESS
}

try {
    $executed = Invoke-Isolation $plan
    $detail["executed"] = $executed
    @{ isolated = $true; start = $now; rule_id = (Get-EdrRuleId $alert); agent_id = (Get-EdrAgentId $alert); manager_ip = $managerIp } |
        ConvertTo-Json -Compress | Set-Content -Path (Get-StateFile) -Encoding utf8
    Write-EdrAudit $cfg $AR_NAME $alert "isolate" $false "isolated" $detail | Out-Null
    exit $script:OS_SUCCESS
} catch {
    $detail["error"] = $_.Exception.Message
    Write-EdrAudit $cfg $AR_NAME $alert "isolate" $false "error" $detail | Out-Null
    exit $script:OS_INVALID
}
