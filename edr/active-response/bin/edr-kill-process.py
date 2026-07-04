#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 response: safe process termination (Linux agents).
#
# Contract: invoked by wazuh-execd as an active response. Reads one JSON line
# from stdin (command + parameters.alert). The target process is taken, in order
# of preference, from:
#   1. extra_args:  the AR <extra_args> (e.g. a literal PID or name), OR
#   2. the alert:   process.pid / process.name (WCS) or
#                   data.win.eventdata.processId / .image (Sysmon), or
#                   data.pid / data.process fields.
#
# Safety model (all enforced BEFORE any signal is sent):
#   * the full process tree (ancestors + descendants) is captured and audited,
#   * denylist / protected-PID / optional strict-allowlist checks must pass,
#   * dry-run (EDR_DRY_RUN or edr.conf.json) logs the intended action only.
#
# A kill cannot be undone, so the audit record is written with everything an
# analyst needs to reconstruct exactly what was terminated and why.

import os
import re
import sys
import signal

import edr_common as edr

AR_NAME = "edr-kill-process"


def _read_proc(pid):
    """Return a dict describing /proc/<pid> or None if it's gone."""
    try:
        with open("/proc/%d/status" % pid) as fh:
            status = fh.read()
        name = re.search(r"^Name:\s+(.*)$", status, re.M)
        ppid = re.search(r"^PPid:\s+(\d+)$", status, re.M)
        try:
            cmdline = open("/proc/%d/cmdline" % pid).read().replace("\0", " ").strip()
        except Exception:
            cmdline = ""
        return {
            "pid": pid,
            "name": name.group(1) if name else "",
            "ppid": int(ppid.group(1)) if ppid else None,
            "cmdline": cmdline,
        }
    except Exception:
        return None


def _all_procs():
    procs = {}
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            info = _read_proc(int(entry))
            if info:
                procs[info["pid"]] = info
    return procs


def _find_pid_by_name(procs, name):
    base = os.path.basename(name).lower()
    for p in procs.values():
        if p["name"].lower() == base or os.path.basename(p["name"]).lower() == base:
            return p["pid"]
    return None


def build_tree(procs, pid):
    """Return {ancestors:[...], target:{...}, descendants:[...]} for the audit log."""
    target = procs.get(pid)
    ancestors = []
    seen = set()
    cur = target.get("ppid") if target else None
    while cur and cur not in seen and cur in procs:
        seen.add(cur)
        ancestors.append(procs[cur])
        cur = procs[cur].get("ppid")
    # descendants (BFS over the ppid graph)
    children_of = {}
    for p in procs.values():
        children_of.setdefault(p.get("ppid"), []).append(p)
    descendants = []
    queue = list(children_of.get(pid, []))
    seen_d = set()
    while queue:
        child = queue.pop(0)
        if child["pid"] in seen_d:
            continue
        seen_d.add(child["pid"])
        descendants.append(child)
        queue.extend(children_of.get(child["pid"], []))
    return {"ancestors": ancestors, "target": target, "descendants": descendants}


def resolve_target(message, alert, procs):
    """Return (pid, name_hint). PID wins; otherwise resolve a name to a live PID."""
    for arg in edr.get_extra_args(message):
        if arg.isdigit():
            return int(arg), None
        pid = _find_pid_by_name(procs, arg)
        if pid:
            return pid, arg
        # a name was given but no live process matches
        return None, arg
    pid = edr._dig(alert, "process.pid", "data.win.eventdata.processId", "data.pid")
    if pid is not None:
        try:
            return int(pid), None
        except (TypeError, ValueError):
            pass
    name = edr._dig(alert, "process.name", "data.win.eventdata.image",
                    "data.process", "data.command")
    if name:
        return _find_pid_by_name(procs, str(name)), str(name)
    return None, None


def main():
    cfg = edr.load_config()
    dry = edr.effective_dry_run(cfg)
    message = edr.read_stdin_message()
    if message is None:
        edr.audit(cfg, AR_NAME, {}, "kill", dry, "error", {"reason": "invalid stdin JSON"})
        sys.exit(edr.OS_INVALID)

    alert = edr.get_alert(message)
    command = edr.get_command(message)

    # 'delete' is the timeout/rollback callback. A kill is irreversible, so there
    # is nothing to roll back — we only record that the timeout fired.
    if command == "delete":
        edr.audit(cfg, AR_NAME, alert, "kill", dry, "noop",
                  {"reason": "delete/timeout callback — kill is not reversible"})
        sys.exit(edr.OS_SUCCESS)

    procs = _all_procs()
    pid, name_hint = resolve_target(message, alert, procs)

    if pid is None:
        edr.audit(cfg, AR_NAME, alert, "kill", dry, "not_found",
                  {"reason": "no live process matched", "name_hint": name_hint})
        sys.exit(edr.OS_NOTFOUND)

    info = procs.get(pid) or {"pid": pid, "name": name_hint or "", "ppid": None, "cmdline": ""}
    name = info.get("name") or name_hint or ""
    tree = build_tree(procs, pid)

    protected, reason = edr.is_process_protected(cfg, name, pid)
    if protected:
        edr.audit(cfg, AR_NAME, alert, "kill", dry, "refused",
                  {"pid": pid, "name": name, "reason": reason, "process_tree": tree})
        # Refusing a protected process is a successful, safe outcome.
        sys.exit(edr.OS_SUCCESS)

    if dry:
        edr.audit(cfg, AR_NAME, alert, "kill", True, "dry_run",
                  {"pid": pid, "name": name, "cmdline": info.get("cmdline"),
                   "would_signal": "SIGTERM then SIGKILL", "process_tree": tree})
        sys.exit(edr.OS_SUCCESS)

    # Act: graceful SIGTERM, then SIGKILL if it survives.
    outcome = "killed"
    detail = {"pid": pid, "name": name, "cmdline": info.get("cmdline"),
              "process_tree": tree, "signals": []}
    try:
        os.kill(pid, signal.SIGTERM)
        detail["signals"].append("SIGTERM")
    except ProcessLookupError:
        outcome = "already_gone"
    except PermissionError:
        outcome = "error"
        detail["error"] = "permission denied sending SIGTERM"
    if outcome == "killed":
        # give it a moment, then force
        import time
        time.sleep(2)
        if _read_proc(pid) is not None:
            try:
                os.kill(pid, signal.SIGKILL)
                detail["signals"].append("SIGKILL")
            except ProcessLookupError:
                pass
            except PermissionError:
                outcome = "error"
                detail["error"] = "permission denied sending SIGKILL"
        if _read_proc(pid) is not None and outcome == "killed":
            outcome = "survived"

    edr.audit(cfg, AR_NAME, alert, "kill", False, outcome, detail)
    sys.exit(edr.OS_SUCCESS if outcome in ("killed", "already_gone") else edr.OS_INVALID)


if __name__ == "__main__":
    main()
