#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-2 investigation: live-response executor (Linux agents) — READ ONLY.
#
# This is the agent-side half of the live-response scaffold. It is intentionally
# NOT a general remote shell. It accepts a single command KEY (via extra_args)
# from a hard-coded allowlist of read-only investigation commands, runs the
# fixed command bound to that key, and writes the output plus a full audit
# record. It cannot run arbitrary strings: anything not in ALLOWED is refused.
#
# Because the analyst-facing manager tool (tools/edr-live-response.py) also
# enforces the allowlist and requires interactive confirmation, this is the
# second, independent enforcement layer (defense in depth).

import os
import sys
import subprocess

import edr_common as edr

AR_NAME = "edr-live-response"

# key -> fixed argv. NOTHING here mutates state. No shell=True. No user input
# is interpolated into these commands.
ALLOWED = {
    "processes":   ["ps", "-eo", "pid,ppid,user,comm,args"],
    "netstat":     ["ss", "-tunap"],
    "connections": ["ss", "-tunap"],
    "listening":   ["ss", "-tlnp"],
    "whoami":      ["id"],
    "uptime":      ["uptime"],
    "logged-in":   ["who"],
    "routes":      ["ip", "route"],
    "arp":         ["ip", "neigh"],
    "mounts":      ["mount"],
    "loaded-kmods":["lsmod"],
    "cron":        ["ls", "-la", "/etc/cron.d", "/etc/cron.daily", "/var/spool/cron"],
}

MAX_OUTPUT = 64 * 1024   # cap captured output


def result_path():
    return os.path.join(edr.WAZUH_HOME, "logs", "edr-live-response-output.log")


def main():
    cfg = edr.load_config()
    dry = edr.effective_dry_run(cfg)   # live-response is read-only, but honour dry-run for policy consistency
    message = edr.read_stdin_message()
    if message is None:
        edr.audit(cfg, AR_NAME, {}, "live-response", dry, "error", {"reason": "invalid stdin JSON"})
        sys.exit(edr.OS_INVALID)
    alert = edr.get_alert(message)

    if edr.get_command(message) == "delete":
        sys.exit(edr.OS_SUCCESS)

    args = edr.get_extra_args(message)
    key = args[0].strip().lower() if args else None

    if not key or key not in ALLOWED:
        edr.audit(cfg, AR_NAME, alert, "live-response", dry, "refused",
                  {"requested": key, "reason": "command not in read-only allowlist",
                   "allowed": sorted(ALLOWED.keys())})
        sys.exit(edr.OS_INVALID)

    cmd = ALLOWED[key]
    detail = {"key": key, "command": " ".join(cmd)}

    if dry:
        detail["would_run"] = True
        edr.audit(cfg, AR_NAME, alert, "live-response", True, "dry_run", detail)
        sys.exit(edr.OS_SUCCESS)

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=30)
        output = (proc.stdout or "")[:MAX_OUTPUT]
        detail["exit_code"] = proc.returncode
    except Exception as e:
        edr.audit(cfg, AR_NAME, alert, "live-response", False, "error",
                  dict(detail, error=str(e)))
        sys.exit(edr.OS_INVALID)

    # Write the captured output to a dedicated collectable file (keyed by rule/agent).
    try:
        with open(result_path(), "a") as fh:
            # Header is key=value (no pipes) so the Wazuh decoder can parse it.
            fh.write("\nEDR-LR host=%s rule=%s key=%s cmd=%s\n" % (
                edr.get_agent_name(alert), edr.get_rule_id(alert), key, "_".join(cmd)))
            fh.write(output)
            fh.write("\n")
    except Exception:
        pass

    detail["output_bytes"] = len(output)
    detail["output_file"] = result_path()
    edr.audit(cfg, AR_NAME, alert, "live-response", False, "executed", detail)
    sys.exit(edr.OS_SUCCESS)


if __name__ == "__main__":
    main()
