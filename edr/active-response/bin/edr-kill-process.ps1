# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 response: safe process termination (Windows agents).
#
# Contract: invoked by wazuh-execd. Reads one JSON line from stdin
# (command + parameters.alert). Target process resolved (in order) from:
#   1. extra_args (a literal PID or image name), OR
#   2. the alert: process.pid / process.name (WCS) or
#      data.win.eventdata.processId / .image (Sysmon EID 1).
#
# Before any Stop-Process: the full process tree (ancestors + descendants) is
# captured and audited, and denylist / protected-PID / allowlist checks must
# pass. Dry-run (EDR_DRY_RUN or edr.conf.json) logs the intended action only.
# A kill is irreversible, so the audit record captures everything needed to
# know exactly what was terminated and why.

. "$PSScriptRoot\edr_common.ps1"

$AR_NAME = "edr-kill-process"

function Get-ProcMap {
    $map = @{}
    # Win32_Process gives ProcessId, ParentProcessId, Name and CommandLine.
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $map[[int]$p.ProcessId] = [ordered]@{
            pid     = [int]$p.ProcessId
            name    = $p.Name
            ppid    = [int]$p.ParentProcessId
            cmdline = $p.CommandLine
        }
    }
    return $map
}

function Find-PidByName {
    param($Map, [string]$Name)
    $base = [System.IO.Path]::GetFileName($Name).ToLower()
    foreach ($p in $Map.Values) {
        if ($p.name.ToLower() -eq $base) { return [int]$p.pid }
    }
    return $null
}

function Build-Tree {
    param($Map, [int]$Pid)
    $target = $Map[$Pid]
    $ancestors = @(); $seen = @{}
    $cur = if ($target) { $target.ppid } else { $null }
    while ($cur -and -not $seen.ContainsKey($cur) -and $Map.ContainsKey($cur)) {
        $seen[$cur] = $true
        $ancestors += $Map[$cur]
        $cur = $Map[$cur].ppid
    }
    $childrenOf = @{}
    foreach ($p in $Map.Values) {
        if (-not $childrenOf.ContainsKey($p.ppid)) { $childrenOf[$p.ppid] = @() }
        $childrenOf[$p.ppid] += $p
    }
    $descendants = @(); $seenD = @{}
    $queue = @(); if ($childrenOf.ContainsKey($Pid)) { $queue = @($childrenOf[$Pid]) }
    while ($queue.Count -gt 0) {
        $child = $queue[0]; $queue = $queue[1..($queue.Count)]
        if ($seenD.ContainsKey($child.pid)) { continue }
        $seenD[$child.pid] = $true
        $descendants += $child
        if ($childrenOf.ContainsKey($child.pid)) { $queue += $childrenOf[$child.pid] }
    }
    return @{ ancestors = $ancestors; target = $target; descendants = $descendants }
}

function Resolve-Target {
    param($Message, $Alert, $Map)
    foreach ($arg in (Get-EdrExtraArgs $Message)) {
        $s = "$arg"
        if ($s -match '^\d+$') { return @{ pid = [int]$s; name = $null } }
        $pid = Find-PidByName $Map $s
        return @{ pid = $pid; name = $s }
    }
    $pid = Get-EdrField $Alert @('process.pid','data.win.eventdata.processId','data.pid')
    if ($null -ne $pid) { try { return @{ pid = [int]$pid; name = $null } } catch {} }
    $name = Get-EdrField $Alert @('process.name','data.win.eventdata.image','data.process')
    if ($name) { return @{ pid = (Find-PidByName $Map ([string]$name)); name = [string]$name } }
    return @{ pid = $null; name = $null }
}

$cfg = Get-EdrConfig
$dry = Get-EdrDryRun $cfg
$message = Read-EdrMessage
if ($null -eq $message) {
    Write-EdrAudit $cfg $AR_NAME @{} "kill" $dry "error" @{ reason = "invalid stdin JSON" } | Out-Null
    exit $script:OS_INVALID
}
$alert = Get-EdrAlert $message
$command = $message.command

if ($command -eq "delete") {
    Write-EdrAudit $cfg $AR_NAME $alert "kill" $dry "noop" @{ reason = "delete/timeout callback — kill is not reversible" } | Out-Null
    exit $script:OS_SUCCESS
}

$map = Get-ProcMap
$t = Resolve-Target $message $alert $map
$pid = $t.pid
$nameHint = $t.name

if ($null -eq $pid) {
    Write-EdrAudit $cfg $AR_NAME $alert "kill" $dry "not_found" @{ reason = "no live process matched"; name_hint = $nameHint } | Out-Null
    exit $script:OS_NOTFOUND
}

$info = if ($map.ContainsKey($pid)) { $map[$pid] } else { @{ pid = $pid; name = $nameHint; ppid = $null; cmdline = "" } }
$name = if ($info.name) { $info.name } elseif ($nameHint) { $nameHint } else { "" }
$tree = Build-Tree $map $pid

$prot = Test-EdrProcessProtected $cfg $name $pid
if ($prot.protected) {
    Write-EdrAudit $cfg $AR_NAME $alert "kill" $dry "refused" @{ pid = $pid; name = $name; reason = $prot.reason; process_tree = $tree } | Out-Null
    exit $script:OS_SUCCESS
}

if ($dry) {
    Write-EdrAudit $cfg $AR_NAME $alert "kill" $true "dry_run" @{ pid = $pid; name = $name; cmdline = $info.cmdline; would_do = "Stop-Process -Force"; process_tree = $tree } | Out-Null
    exit $script:OS_SUCCESS
}

$outcome = "killed"
$detail = @{ pid = $pid; name = $name; cmdline = $info.cmdline; process_tree = $tree }
try {
    Stop-Process -Id $pid -Force -ErrorAction Stop
    Start-Sleep -Seconds 1
    if (Get-Process -Id $pid -ErrorAction SilentlyContinue) { $outcome = "survived" }
} catch {
    if (-not (Get-Process -Id $pid -ErrorAction SilentlyContinue)) {
        $outcome = "already_gone"
    } else {
        $outcome = "error"; $detail["error"] = $_.Exception.Message
    }
}

Write-EdrAudit $cfg $AR_NAME $alert "kill" $false $outcome $detail | Out-Null
if ($outcome -in @("killed", "already_gone")) { exit $script:OS_SUCCESS } else { exit $script:OS_INVALID }
