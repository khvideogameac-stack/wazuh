#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 rollback: remove network isolation (Linux agents).
#
# Reverses edr-isolate-host.py by unhooking and deleting the
# RWASED_EDR_ISOLATION chain. Idempotent: safe to run when not isolated.
# Records the isolation window end timestamp (and duration, if the start is
# known from the state file) in the audit log.
#
# Can be triggered as an active response (command="add") for an "unisolate"
# rule, or run manually by an analyst:  edr-unisolate-host.py  (reads no stdin).

import os
import sys
import json
import shutil
import subprocess
import datetime

import edr_common as edr

AR_NAME = "edr-unisolate-host"
CHAIN = "RWASED_EDR_ISOLATION"


def state_file():
    return os.path.join(edr.WAZUH_HOME, "logs", "edr-isolation.state")


def _run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _iptables_bin():
    return shutil.which("iptables") or "/sbin/iptables"


def _read_state():
    try:
        with open(state_file()) as fh:
            return json.load(fh)
    except Exception:
        return {}


def do_unisolate(cfg, dry, alert, ar_name=AR_NAME, reason="manual/rule"):
    ipt = _iptables_bin()
    now = datetime.datetime.now(datetime.timezone.utc)
    state = _read_state()
    detail = {"reason": reason, "isolation_end": now.isoformat()}
    if state.get("start"):
        detail["isolation_start"] = state["start"]
        try:
            start = datetime.datetime.fromisoformat(state["start"])
            detail["isolation_seconds"] = int((now - start).total_seconds())
        except Exception:
            pass

    check = _run([ipt, "-n", "-L", "OUTPUT"])
    if CHAIN not in (check.stdout or ""):
        edr.audit(cfg, ar_name, alert, "unisolate", dry, "not_isolated", detail)
        return edr.OS_SUCCESS

    if dry:
        detail["would_do"] = ["iptables -D OUTPUT -j %s" % CHAIN,
                              "iptables -F %s" % CHAIN, "iptables -X %s" % CHAIN]
        edr.audit(cfg, ar_name, alert, "unisolate", True, "dry_run", detail)
        return edr.OS_SUCCESS

    # unhook (may appear more than once), then flush + delete the chain
    for _ in range(5):
        if _run([ipt, "-C", "OUTPUT", "-j", CHAIN]).returncode != 0:
            break
        _run([ipt, "-D", "OUTPUT", "-j", CHAIN])
    _run([ipt, "-F", CHAIN])
    _run([ipt, "-X", CHAIN])

    still = _run([ipt, "-n", "-L", "OUTPUT"])
    if CHAIN in (still.stdout or ""):
        detail["error"] = "chain still present after removal"
        edr.audit(cfg, ar_name, alert, "unisolate", False, "error", detail)
        return edr.OS_INVALID

    try:
        os.remove(state_file())
    except Exception:
        pass
    edr.audit(cfg, ar_name, alert, "unisolate", False, "unisolated", detail)
    return edr.OS_SUCCESS


def main():
    cfg = edr.load_config()
    dry = edr.effective_dry_run(cfg)
    message = edr.read_stdin_message()   # may be None when run manually
    alert = edr.get_alert(message) if message else {}
    if message and edr.get_command(message) == "delete":
        # timeout callback for an unisolate rule — nothing to do
        edr.audit(cfg, AR_NAME, alert, "unisolate", dry, "noop", {"reason": "delete callback"})
        sys.exit(edr.OS_SUCCESS)
    sys.exit(do_unisolate(cfg, dry, alert, reason="manual/rule"))


if __name__ == "__main__":
    main()
