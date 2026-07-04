#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Shared helpers for the Rwased EDR active-response scripts (Linux).
#
# This module is imported by every Tier-1 Linux response script. It centralises:
#   * reading and validating the Wazuh active-response stdin JSON contract,
#   * loading edr.conf.json and resolving the effective dry-run state,
#   * structured (JSON-lines) audit logging,
#   * the allowlist/denylist decision helpers.
#
# Nothing here acts on the endpoint; it only parses, decides and records.

import json
import os
import sys
import socket
import datetime

# Wazuh active-response exit codes (see active_responses.h / execd).
OS_SUCCESS = 0
OS_INVALID = 1          # bad/parse-unfriendly input
OS_NOTFOUND = 2         # nothing to act on

# Resolve the Wazuh installation directory. AR scripts are invoked from
# <WAZUH_HOME>/active-response/bin, so the home is two levels up.
WAZUH_HOME = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", ".."))


def _config_path():
    return os.path.join(WAZUH_HOME, "etc", "edr.conf.json")


def load_config():
    """Load edr.conf.json. Missing/invalid config is non-fatal: we fall back to
    a dry-run-by-default configuration so a broken deploy can never silently act."""
    safe_default = {
        "dry_run": True,
        "audit_log": {"linux": "logs/active-responses-edr.log"},
        "manager": {"ip": None, "agent_ports": [1514, 1515]},
        "process_kill": {"denylist_names": [], "protected_pid_max": 100, "allowlist_names": []},
        "isolation": {"allow_ips": [], "allow_ports": [1514, 1515]},
        "quarantine": {"dir_linux": os.path.join(WAZUH_HOME, "quarantine"),
                       "manifest": "quarantine-manifest.jsonl"},
    }
    try:
        with open(_config_path(), "r") as fh:
            cfg = json.load(fh)
        # merge onto defaults so absent keys never KeyError downstream
        for k, v in safe_default.items():
            cfg.setdefault(k, v)
            if isinstance(v, dict):
                for kk, vv in v.items():
                    cfg[k].setdefault(kk, vv)
        return cfg
    except Exception:
        safe_default["_config_error"] = True
        return safe_default


def effective_dry_run(cfg):
    """Environment variable wins over the config file. EDR_DRY_RUN=true|1|yes forces
    log-only; EDR_DRY_RUN=false|0|no honours the file; unset => use the file value."""
    env = os.environ.get("EDR_DRY_RUN")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "on")
    return bool(cfg.get("dry_run", True))


def audit_log_path(cfg):
    rel = cfg.get("audit_log", {}).get("linux", "logs/active-responses-edr.log")
    return rel if os.path.isabs(rel) else os.path.join(WAZUH_HOME, rel)


def read_stdin_message():
    """Read the single JSON line Wazuh execd writes to stdin. Returns the parsed
    object or None on failure."""
    try:
        raw = sys.stdin.readline()
        if not raw:
            return None
        return json.loads(raw)
    except Exception:
        return None


def get_command(message):
    """'add' when the alert fires, 'delete' on timeout/rollback."""
    return (message or {}).get("command")


def get_alert(message):
    """The alert payload lives under parameters.alert in the AR contract. Some
    5.x WCS deliveries put the alert fields at the root; handle both."""
    if not isinstance(message, dict):
        return {}
    params = message.get("parameters") or {}
    alert = params.get("alert")
    if isinstance(alert, dict):
        return alert
    # WCS-at-root fallback
    return message


def get_extra_args(message):
    params = (message or {}).get("parameters") or {}
    args = params.get("extra_args") or []
    return [str(a) for a in args] if isinstance(args, list) else []


def _dig(obj, *paths):
    """Return the first present value among dotted paths, e.g. _dig(alert,
    'data.win.eventdata.processId', 'process.pid')."""
    for path in paths:
        cur = obj
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, "", []):
            return cur
    return None


def get_rule_id(alert):
    return _dig(alert, "rule.id", "rule_id") or "unknown"


def get_agent_id(alert):
    return _dig(alert, "agent.id", "wazuh.agent.id") or "unknown"


def get_agent_name(alert):
    return _dig(alert, "agent.name", "wazuh.agent.name") or socket.gethostname()


def audit(cfg, ar_name, alert, action, dry_run, outcome, detail=None):
    """Append one JSON-lines audit record. This is the authoritative, tamper-
    evident record of every response decision — success, refusal or dry-run.

    Fields required by the spec: timestamp, triggering rule ID, agent ID,
    action taken, dry-run flag, outcome."""
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "script": ar_name,
        "rule_id": get_rule_id(alert),
        "agent_id": get_agent_id(alert),
        "agent_name": get_agent_name(alert),
        "host": socket.gethostname(),
        "action": action,
        "dry_run": bool(dry_run),
        "outcome": outcome,
    }
    if detail is not None:
        record["detail"] = detail
    line = json.dumps(record, default=str)
    try:
        path = audit_log_path(cfg)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass
    # Also echo to the standard AR log so it shows up in the normal channel.
    try:
        std = os.path.join(WAZUH_HOME, "logs", "active-responses.log")
        with open(std, "a") as fh:
            fh.write("%s %s: %s\n" % (
                datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y"), ar_name, line))
    except Exception:
        pass
    return record


def is_process_protected(cfg, name, pid=None):
    """Return (protected: bool, reason: str). Enforces the denylist, the protected
    low-PID range, and — if configured — strict allowlist mode."""
    pk = cfg.get("process_kill", {})
    lname = (name or "").strip().lower()
    deny = [d.lower() for d in pk.get("denylist_names", [])]
    if lname and lname in deny:
        return True, "name '%s' is on the denylist" % name
    if pid is not None:
        try:
            if int(pid) <= int(pk.get("protected_pid_max", 100)):
                return True, "pid %s is in the protected low-PID range (<= %s)" % (
                    pid, pk.get("protected_pid_max", 100))
        except (TypeError, ValueError):
            pass
    allow = [a.lower() for a in pk.get("allowlist_names", [])]
    if allow and lname not in allow:
        return True, "allowlist mode is on and '%s' is not permitted" % name
    return False, ""
