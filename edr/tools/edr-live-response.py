#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-2 investigation: live-response — analyst-facing manager CLI.
#
# This is the ONLY intended way to trigger the edr-live-response agent script.
# It is deliberately manual: there is no rule/AR wiring that fires it
# automatically. The workflow is:
#   1. analyst picks an agent + one allowlisted read-only command key,
#   2. the tool prints exactly what will run and requires typed confirmation,
#   3. it calls the Wazuh API active-response endpoint to run the agent-side
#      edr-live-response script with that key,
#   4. every invocation is appended to an audit log on the manager.
#
# The agent-side script independently re-checks the allowlist, so a compromised
# manager tool still cannot run arbitrary commands on the endpoint.
#
# Read-only by design. No dependency beyond the standard library.
#
# Usage:
#   edr-live-response.py --list-commands
#   edr-live-response.py --agent 004 --command netstat
#   edr-live-response.py --agent 004 --command processes --yes   # skip prompt (for a wrapping ticket system)

import os
import ssl
import sys
import json
import base64
import getpass
import argparse
import datetime
import urllib.request
import urllib.error

# Mirror of the agent-side allowlists (keys only). Kept here so the analyst sees
# valid choices; the agent script holds the authoritative command bindings.
ALLOWED_KEYS = {
    "linux":   ["processes", "netstat", "connections", "listening", "whoami",
                "uptime", "logged-in", "routes", "arp", "mounts", "loaded-kmods", "cron"],
    "windows": ["processes", "tasklist", "netstat", "connections", "listening",
                "whoami", "services", "logged-in", "routes", "arp",
                "scheduled-tasks", "autoruns-run"],
}
ALL_KEYS = sorted(set(ALLOWED_KEYS["linux"] + ALLOWED_KEYS["windows"]))

AUDIT_LOG = os.environ.get("EDR_LR_AUDIT", "/var/ossec/logs/edr-live-response-manager.log")


def audit(record):
    record["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        with open(AUDIT_LOG, "a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except Exception as e:
        print("warning: could not write audit log: %s" % e, file=sys.stderr)
    print("[audit] " + json.dumps(record, default=str))


def api_ctx(verify):
    if verify:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def api_request(base, method, path, token=None, user=None, password=None, body=None, verify=False):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    elif user is not None:
        cred = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        req.add_header("Authorization", "Basic " + cred)
    with urllib.request.urlopen(req, context=api_ctx(verify), timeout=30) as resp:
        return json.load(resp)


def get_token(base, user, password, verify):
    res = api_request(base, "POST", "/security/user/authenticate", user=user, password=password, verify=verify)
    return res.get("data", {}).get("token")


def main():
    ap = argparse.ArgumentParser(description="Trigger a read-only live-response command on a Wazuh agent (manual, audited).")
    ap.add_argument("--agent", help="agent ID (e.g. 004)")
    ap.add_argument("--command", help="allowlisted command key (see --list-commands)")
    ap.add_argument("--os", choices=["linux", "windows"], default="linux",
                    help="agent OS — selects the AR script name (default linux)")
    ap.add_argument("--list-commands", action="store_true")
    ap.add_argument("--yes", action="store_true", help="skip the interactive confirmation (use only from an audited wrapper)")
    ap.add_argument("--api", default=os.environ.get("WAZUH_API", "https://localhost:55000"))
    ap.add_argument("--api-user", default=os.environ.get("WAZUH_API_USER", "wazuh"))
    ap.add_argument("--api-password", default=os.environ.get("WAZUH_API_PASSWORD"))
    ap.add_argument("--verify-ssl", action="store_true")
    ap.add_argument("--analyst", default=os.environ.get("USER") or getpass.getuser())
    args = ap.parse_args()

    if args.list_commands:
        print("Read-only live-response command keys:\n")
        for osname in ("linux", "windows"):
            print("  %s: %s" % (osname, ", ".join(ALLOWED_KEYS[osname])))
        sys.exit(0)

    if not args.agent or not args.command:
        ap.error("--agent and --command are required (or use --list-commands)")

    key = args.command.strip().lower()
    if key not in ALLOWED_KEYS[args.os]:
        print("Refused: '%s' is not an allowed read-only command for %s." % (key, args.os), file=sys.stderr)
        print("Allowed: %s" % ", ".join(ALLOWED_KEYS[args.os]), file=sys.stderr)
        audit({"analyst": args.analyst, "agent": args.agent, "command": key,
               "os": args.os, "outcome": "refused_client", "reason": "not in allowlist"})
        sys.exit(1)

    ar_script = "edr-live-response.ps1" if args.os == "windows" else "edr-live-response.py"

    print("\nLive-response request")
    print("  analyst : %s" % args.analyst)
    print("  agent   : %s" % args.agent)
    print("  os      : %s" % args.os)
    print("  command : %s  (read-only)" % key)
    print("  runs    : active-response/bin/%s with extra_args=[%s]" % (ar_script, key))
    print("  This runs a read-only investigation command on the endpoint and is fully audited.")

    if not args.yes:
        confirm = input("\nType the agent ID to confirm (or anything else to abort): ").strip()
        if confirm != str(args.agent):
            print("Aborted — confirmation did not match.")
            audit({"analyst": args.analyst, "agent": args.agent, "command": key,
                   "os": args.os, "outcome": "aborted", "reason": "confirmation mismatch"})
            sys.exit(1)

    password = args.api_password
    if not password:
        password = getpass.getpass("Wazuh API password for %s: " % args.api_user)

    # Wazuh API active-response contract: command must be prefixed with '!'
    # to name a configured command, plus arguments passed as 'arguments'.
    body = {"command": "!" + ar_script, "arguments": [key]}
    try:
        token = get_token(args.api, args.api_user, password, args.verify_ssl)
        if not token:
            raise RuntimeError("authentication returned no token")
        res = api_request(args.api, "PUT", "/active-response?agents_list=" + str(args.agent),
                          token=token, body=body, verify=args.verify_ssl)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        print("API error %s: %s" % (e.code, detail), file=sys.stderr)
        audit({"analyst": args.analyst, "agent": args.agent, "command": key,
               "os": args.os, "outcome": "api_error", "http_status": e.code, "detail": detail})
        sys.exit(1)
    except Exception as e:
        print("Request failed: %s" % e, file=sys.stderr)
        audit({"analyst": args.analyst, "agent": args.agent, "command": key,
               "os": args.os, "outcome": "error", "detail": str(e)})
        sys.exit(1)

    audit({"analyst": args.analyst, "agent": args.agent, "command": key, "os": args.os,
           "outcome": "dispatched", "api_response": res})
    print("\nDispatched. Command output will appear on the agent in "
          "active-response/edr-live-response-output.log and be collected into the manager logs.")


if __name__ == "__main__":
    main()
