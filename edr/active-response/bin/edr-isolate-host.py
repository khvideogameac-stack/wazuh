#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 response: network isolation / host quarantine (Linux agents).
#
# Blocks all outbound traffic EXCEPT to the Wazuh manager (and configured
# allow_ips / allow_ports) so the endpoint stays monitorable but can no longer
# communicate. Fully reversible via edr-unisolate-host.py.
#
# Implementation: a dedicated iptables chain RWASED_EDR_ISOLATION in the OUTPUT
# path. Using our own chain (rather than editing existing rules) makes removal
# clean and idempotent. The isolation window start/end timestamps are recorded
# in a state file and the audit log.
#
# Wazuh calls this with command="add" to isolate and command="delete" on
# timeout — the delete path automatically unisolates, so a stuck isolation
# self-heals when the AR timeout elapses.

import os
import sys
import json
import shutil
import subprocess
import datetime

import edr_common as edr

AR_NAME = "edr-isolate-host"
CHAIN = "RWASED_EDR_ISOLATION"


def state_file():
    return os.path.join(edr.WAZUH_HOME, "logs", "edr-isolation.state")


def _run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _iptables_bin():
    return shutil.which("iptables") or "/sbin/iptables"


def build_rules(cfg):
    """Return the ordered list of iptables argument-lists that implement isolation."""
    ipt = _iptables_bin()
    manager_ip = (cfg.get("manager") or {}).get("ip")
    allow_ips = list((cfg.get("isolation") or {}).get("allow_ips") or [])
    if manager_ip and manager_ip not in allow_ips:
        allow_ips.append(manager_ip)
    allow_ports = (cfg.get("isolation") or {}).get("allow_ports") or []
    manager_ports = (cfg.get("manager") or {}).get("agent_ports") or []

    rules = []
    # 1) keep loopback and already-established/related connections working
    rules.append([ipt, "-A", CHAIN, "-o", "lo", "-j", "ACCEPT"])
    rules.append([ipt, "-A", CHAIN, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    # 2) explicitly permit the manager (and any allow_ips)
    for ip in allow_ips:
        rules.append([ipt, "-A", CHAIN, "-d", ip, "-j", "ACCEPT"])
    # 3) permit specific service ports needed to stay reporting (e.g. DNS 53)
    for port in set(list(allow_ports) + list(manager_ports)):
        rules.append([ipt, "-A", CHAIN, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
        rules.append([ipt, "-A", CHAIN, "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])
    # 4) drop everything else leaving the host
    rules.append([ipt, "-A", CHAIN, "-j", "DROP"])
    return rules


def is_isolated(cfg):
    ipt = _iptables_bin()
    r = _run([ipt, "-n", "-L", "OUTPUT"])
    return CHAIN in (r.stdout or "")


def apply_isolation(cfg):
    ipt = _iptables_bin()
    executed = []
    # fresh chain
    _run([ipt, "-N", CHAIN])
    _run([ipt, "-F", CHAIN])
    for rule in build_rules(cfg):
        res = _run(rule)
        executed.append(" ".join(rule))
        if res.returncode != 0:
            return False, executed, res.stdout
    # hook the chain into OUTPUT once
    check = _run([ipt, "-C", "OUTPUT", "-j", CHAIN])
    if check.returncode != 0:
        res = _run([ipt, "-I", "OUTPUT", "1", "-j", CHAIN])
        executed.append(" ".join([ipt, "-I", "OUTPUT", "1", "-j", CHAIN]))
        if res.returncode != 0:
            return False, executed, res.stdout
    return True, executed, ""


def write_state(record):
    try:
        with open(state_file(), "w") as fh:
            json.dump(record, fh)
    except Exception:
        pass


def main():
    cfg = edr.load_config()
    dry = edr.effective_dry_run(cfg)
    message = edr.read_stdin_message()
    if message is None:
        edr.audit(cfg, AR_NAME, {}, "isolate", dry, "error", {"reason": "invalid stdin JSON"})
        sys.exit(edr.OS_INVALID)
    alert = edr.get_alert(message)
    command = edr.get_command(message)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # The AR timeout callback auto-reverses isolation.
    if command == "delete":
        # defer to the unisolate implementation for a single source of truth
        import importlib.util
        uni = os.path.join(os.path.dirname(os.path.realpath(__file__)), "edr-unisolate-host.py")
        spec = importlib.util.spec_from_file_location("edr_unisolate", uni)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.do_unisolate(cfg, dry, alert, AR_NAME, reason="AR timeout")
        sys.exit(edr.OS_SUCCESS)

    manager_ip = (cfg.get("manager") or {}).get("ip")
    detail = {
        "manager_ip": manager_ip,
        "allow_ips": (cfg.get("isolation") or {}).get("allow_ips"),
        "allow_ports": (cfg.get("isolation") or {}).get("allow_ports"),
        "isolation_start": now,
        "planned_rules": [" ".join(r) for r in build_rules(cfg)],
    }

    if not manager_ip:
        edr.audit(cfg, AR_NAME, alert, "isolate", dry, "refused",
                  {"reason": "manager.ip not configured — refusing to isolate (would cut the agent off entirely)"})
        sys.exit(edr.OS_INVALID)

    if is_isolated(cfg):
        edr.audit(cfg, AR_NAME, alert, "isolate", dry, "already_isolated", detail)
        sys.exit(edr.OS_SUCCESS)

    if dry:
        edr.audit(cfg, AR_NAME, alert, "isolate", True, "dry_run", detail)
        sys.exit(edr.OS_SUCCESS)

    ok, executed, err = apply_isolation(cfg)
    detail["executed_rules"] = executed
    if ok:
        state = {"isolated": True, "start": now, "rule_id": edr.get_rule_id(alert),
                 "agent_id": edr.get_agent_id(alert), "manager_ip": manager_ip}
        write_state(state)
        edr.audit(cfg, AR_NAME, alert, "isolate", False, "isolated", detail)
        sys.exit(edr.OS_SUCCESS)
    else:
        detail["error"] = err
        edr.audit(cfg, AR_NAME, alert, "isolate", False, "error", detail)
        sys.exit(edr.OS_INVALID)


if __name__ == "__main__":
    main()
