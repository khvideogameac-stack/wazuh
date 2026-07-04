# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Shared helpers for the Rwased EDR active-response scripts (Windows / PowerShell).
# Dot-sourced by each edr-*.ps1 script: . "$PSScriptRoot\edr_common.ps1"
#
# Nothing here acts on the endpoint; it parses the AR stdin contract, loads
# edr.conf.json, resolves the effective dry-run state, and writes the JSON-lines
# audit log. No dependency on Python — pure PowerShell so it runs on any agent.

Set-StrictMode -Version 2.0

# AR bin dir is <AGENT_HOME>\active-response\bin ; agent home is two levels up.
$script:EdrAgentHome = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Get-EdrConfigPath {
    Join-Path $script:EdrAgentHome "etc\edr.conf.json"
}

function Get-EdrConfig {
    # Missing/invalid config is non-fatal: fall back to a dry-run-by-default object
    # so a broken deploy can never silently act.
    $default = [ordered]@{
        dry_run   = $true
        audit_log = @{ windows = "active-response\active-responses-edr.log" }
        manager   = @{ ip = $null; agent_ports = @(1514, 1515) }
        process_kill = @{ denylist_names = @(); protected_pid_max = 100; allowlist_names = @() }
        isolation = @{ allow_ips = @(); allow_ports = @(1514, 1515) }
        quarantine = @{ dir_windows = "quarantine"; manifest = "quarantine-manifest.jsonl" }
    }
    try {
        $raw = Get-Content -Raw -Path (Get-EdrConfigPath) -ErrorAction Stop
        $cfg = $raw | ConvertFrom-Json
        return $cfg
    } catch {
        return ([pscustomobject]$default)
    }
}

function Get-EdrDryRun {
    param($Cfg)
    # Environment variable wins over the config file.
    $env = [Environment]::GetEnvironmentVariable("EDR_DRY_RUN")
    if ($null -ne $env -and $env -ne "") {
        return @("1", "true", "yes", "on") -contains $env.Trim().ToLower()
    }
    try { return [bool]$Cfg.dry_run } catch { return $true }
}

function Get-EdrAuditPath {
    param($Cfg)
    $rel = "active-response\active-responses-edr.log"
    try { if ($Cfg.audit_log.windows) { $rel = $Cfg.audit_log.windows } } catch {}
    if ([System.IO.Path]::IsPathRooted($rel)) { return $rel }
    return (Join-Path $script:EdrAgentHome $rel)
}

function Read-EdrMessage {
    # Read the single JSON line wazuh-execd writes to stdin.
    try {
        $raw = [Console]::In.ReadLine()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json)
    } catch { return $null }
}

function Get-EdrAlert {
    param($Message)
    if ($null -eq $Message) { return $null }
    try { if ($Message.parameters.alert) { return $Message.parameters.alert } } catch {}
    return $Message
}

function Get-EdrExtraArgs {
    param($Message)
    try { if ($Message.parameters.extra_args) { return @($Message.parameters.extra_args) } } catch {}
    return @()
}

function Get-EdrField {
    # First present value among dotted paths, e.g. Get-EdrField $alert 'process.pid','data.win.eventdata.processId'
    param($Obj, [string[]]$Paths)
    foreach ($p in $Paths) {
        $cur = $Obj; $ok = $true
        foreach ($part in $p.Split(".")) {
            if ($null -ne $cur -and ($cur.PSObject.Properties.Name -contains $part)) {
                $cur = $cur.$part
            } else { $ok = $false; break }
        }
        if ($ok -and $null -ne $cur -and "$cur" -ne "") { return $cur }
    }
    return $null
}

function Get-EdrRuleId  { param($A) $v = Get-EdrField $A @('rule.id','rule_id');       if ($v) { $v } else { 'unknown' } }
function Get-EdrAgentId { param($A) $v = Get-EdrField $A @('agent.id','wazuh.agent.id'); if ($v) { $v } else { 'unknown' } }
function Get-EdrAgentName { param($A) $v = Get-EdrField $A @('agent.name','wazuh.agent.name'); if ($v) { $v } else { $env:COMPUTERNAME } }

function Write-EdrAudit {
    # Append one JSON-lines audit record — the authoritative record of every
    # response decision (success, refusal or dry-run).
    param($Cfg, [string]$ArName, $Alert, [string]$Action, [bool]$DryRun, [string]$Outcome, $Detail)
    $record = [ordered]@{
        timestamp  = (Get-Date).ToUniversalTime().ToString("o")
        script     = $ArName
        rule_id    = (Get-EdrRuleId $Alert)
        agent_id   = (Get-EdrAgentId $Alert)
        agent_name = (Get-EdrAgentName $Alert)
        host       = $env:COMPUTERNAME
        action     = $Action
        dry_run    = $DryRun
        outcome    = $Outcome
    }
    if ($null -ne $Detail) { $record["detail"] = $Detail }
    $line = ($record | ConvertTo-Json -Depth 8 -Compress)
    try {
        $path = Get-EdrAuditPath $Cfg
        $dir = Split-Path $path
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -Path $path -Value $line -Encoding utf8
    } catch {}
    try {
        $std = Join-Path $script:EdrAgentHome "active-response\active-responses.log"
        Add-Content -Path $std -Value ("{0} {1}: {2}" -f (Get-Date), $ArName, $line) -Encoding utf8
    } catch {}
    return $record
}

function Test-EdrProcessProtected {
    # Returns @{ protected = $bool; reason = $string }
    param($Cfg, [string]$Name, $Pid)
    $pk = $Cfg.process_kill
    $lname = ($Name).Trim().ToLower()
    $deny = @(); try { $deny = @($pk.denylist_names | ForEach-Object { $_.ToLower() }) } catch {}
    if ($lname -and ($deny -contains $lname)) {
        return @{ protected = $true; reason = "name '$Name' is on the denylist" }
    }
    $maxPid = 100; try { $maxPid = [int]$pk.protected_pid_max } catch {}
    if ($null -ne $Pid) {
        try { if ([int]$Pid -le $maxPid) { return @{ protected = $true; reason = "pid $Pid is in the protected low-PID range (<= $maxPid)" } } } catch {}
    }
    $allow = @(); try { $allow = @($pk.allowlist_names | ForEach-Object { $_.ToLower() }) } catch {}
    if ($allow.Count -gt 0 -and -not ($allow -contains $lname)) {
        return @{ protected = $true; reason = "allowlist mode is on and '$Name' is not permitted" }
    }
    return @{ protected = $false; reason = "" }
}

# Wazuh AR exit codes
$script:OS_SUCCESS = 0
$script:OS_INVALID = 1
$script:OS_NOTFOUND = 2
