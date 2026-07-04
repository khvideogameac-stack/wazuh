# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-2 investigation: live-response executor (Windows agents) — READ ONLY.
#
# Agent-side half of the live-response scaffold. NOT a general remote shell. It
# accepts a single command KEY (via extra_args) from a hard-coded allowlist of
# read-only investigation commands and runs the fixed command bound to that key.
# Anything not in the allowlist is refused. Second, independent enforcement
# layer behind the manager-side analyst tool (tools/edr-live-response.py).

. "$PSScriptRoot\edr_common.ps1"

$AR_NAME = "edr-live-response"

# key -> fixed command (scriptblock). All are read-only; none take analyst input.
$ALLOWED = @{
    "processes"   = { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Format-Table -Auto | Out-String }
    "tasklist"    = { tasklist }
    "netstat"     = { netstat -ano }
    "connections" = { Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -Auto | Out-String }
    "listening"   = { Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -Auto | Out-String }
    "whoami"      = { whoami /all }
    "services"    = { Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name,DisplayName,Status | Format-Table -Auto | Out-String }
    "logged-in"   = { query user 2>$null }
    "routes"      = { Get-NetRoute -ErrorAction SilentlyContinue | Format-Table -Auto | Out-String }
    "arp"         = { arp -a }
    "scheduled-tasks" = { Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName,TaskPath,State | Format-Table -Auto | Out-String }
    "autoruns-run"= { Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-String }
}

$MAX_OUTPUT = 64 * 1024

function Get-ResultPath { Join-Path $script:EdrAgentHome "active-response\edr-live-response-output.log" }

$cfg = Get-EdrConfig
$dry = Get-EdrDryRun $cfg
$message = Read-EdrMessage
if ($null -eq $message) {
    Write-EdrAudit $cfg $AR_NAME @{} "live-response" $dry "error" @{ reason = "invalid stdin JSON" } | Out-Null
    exit $script:OS_INVALID
}
$alert = Get-EdrAlert $message
if ($message.command -eq "delete") { exit $script:OS_SUCCESS }

$args = Get-EdrExtraArgs $message
$key = if ($args.Count -gt 0) { "$($args[0])".Trim().ToLower() } else { $null }

if (-not $key -or -not $ALLOWED.ContainsKey($key)) {
    Write-EdrAudit $cfg $AR_NAME $alert "live-response" $dry "refused" @{ requested = $key; reason = "command not in read-only allowlist"; allowed = ($ALLOWED.Keys | Sort-Object) } | Out-Null
    exit $script:OS_INVALID
}

$detail = @{ key = $key }
if ($dry) {
    $detail["would_run"] = $true
    Write-EdrAudit $cfg $AR_NAME $alert "live-response" $true "dry_run" $detail | Out-Null
    exit $script:OS_SUCCESS
}

try {
    $output = & $ALLOWED[$key] 2>&1 | Out-String
    if ($output.Length -gt $MAX_OUTPUT) { $output = $output.Substring(0, $MAX_OUTPUT) }
} catch {
    $detail["error"] = $_.Exception.Message
    Write-EdrAudit $cfg $AR_NAME $alert "live-response" $false "error" $detail | Out-Null
    exit $script:OS_INVALID
}

try {
    # Header is key=value (no pipes) so the Wazuh decoder can parse it.
    $header = "`nEDR-LR host={0} rule={1} key={2}`n" -f (Get-EdrAgentName $alert), (Get-EdrRuleId $alert), $key
    Add-Content -Path (Get-ResultPath) -Value ($header + $output) -Encoding utf8
} catch {}

$detail["output_bytes"] = $output.Length
$detail["output_file"] = (Get-ResultPath)
Write-EdrAudit $cfg $AR_NAME $alert "live-response" $false "executed" $detail | Out-Null
exit $script:OS_SUCCESS
