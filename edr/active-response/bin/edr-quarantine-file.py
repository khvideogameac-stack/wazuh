#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 response: file quarantine (Linux agents).
#
# MOVES (never deletes) a suspicious file into a locked-down quarantine
# directory. Before the move it computes and records the SHA256, and appends a
# manifest entry mapping original path -> quarantine path -> timestamp ->
# triggering rule/agent, so the file can be restored later by
# edr-unquarantine-file.py.
#
# Target file resolved (in order) from:
#   1. extra_args (a literal path), OR
#   2. the alert: syscheck.path / file.path / data.file / data.win.eventdata.targetFilename
#
# Refuses to quarantine anything inside the Wazuh install dir or obvious system
# paths, and honours dry-run.

import os
import sys
import json
import stat
import shutil
import hashlib
import datetime

import edr_common as edr

AR_NAME = "edr-quarantine-file"

# Never quarantine files under these roots (would break the OS or the agent).
PROTECTED_PREFIXES = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64",
                      "/usr/lib", "/boot", "/etc/passwd", "/etc/shadow"]


def quarantine_dir(cfg):
    d = (cfg.get("quarantine") or {}).get("dir_linux") or os.path.join(edr.WAZUH_HOME, "quarantine")
    return d


def manifest_path(cfg):
    name = (cfg.get("quarantine") or {}).get("manifest") or "quarantine-manifest.jsonl"
    return os.path.join(quarantine_dir(cfg), name)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_target(message, alert):
    for arg in edr.get_extra_args(message):
        return arg
    return edr._dig(alert, "syscheck.path", "file.path", "data.file",
                    "data.win.eventdata.targetFilename", "data.path")


def is_protected_path(path):
    rp = os.path.realpath(path)
    if rp.startswith(os.path.realpath(edr.WAZUH_HOME)):
        return True, "path is inside the Wazuh install directory"
    for pref in PROTECTED_PREFIXES:
        if rp == pref or rp.startswith(pref.rstrip("/") + "/"):
            return True, "path is under protected system location %s" % pref
    return False, ""


def append_manifest(cfg, entry):
    try:
        os.makedirs(quarantine_dir(cfg), exist_ok=True)
        with open(manifest_path(cfg), "a") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass


def main():
    cfg = edr.load_config()
    dry = edr.effective_dry_run(cfg)
    message = edr.read_stdin_message()
    if message is None:
        edr.audit(cfg, AR_NAME, {}, "quarantine", dry, "error", {"reason": "invalid stdin JSON"})
        sys.exit(edr.OS_INVALID)
    alert = edr.get_alert(message)

    if edr.get_command(message) == "delete":
        edr.audit(cfg, AR_NAME, alert, "quarantine", dry, "noop",
                  {"reason": "delete/timeout callback — use edr-unquarantine-file.py to restore"})
        sys.exit(edr.OS_SUCCESS)

    target = resolve_target(message, alert)
    if not target:
        edr.audit(cfg, AR_NAME, alert, "quarantine", dry, "not_found", {"reason": "no file path in alert/extra_args"})
        sys.exit(edr.OS_NOTFOUND)

    if not os.path.isfile(target):
        edr.audit(cfg, AR_NAME, alert, "quarantine", dry, "not_found",
                  {"reason": "path is not a regular file or does not exist", "path": target})
        sys.exit(edr.OS_NOTFOUND)

    protected, reason = is_protected_path(target)
    if protected:
        edr.audit(cfg, AR_NAME, alert, "quarantine", dry, "refused", {"path": target, "reason": reason})
        sys.exit(edr.OS_SUCCESS)

    try:
        digest = sha256_of(target)
        size = os.path.getsize(target)
    except Exception as e:
        edr.audit(cfg, AR_NAME, alert, "quarantine", dry, "error",
                  {"path": target, "reason": "cannot read file: %s" % e})
        sys.exit(edr.OS_INVALID)

    ts = datetime.datetime.now(datetime.timezone.utc)
    stamp = ts.strftime("%Y%m%dT%H%M%S")
    qname = "%s_%s_%s" % (stamp, digest[:12], os.path.basename(target))
    qpath = os.path.join(quarantine_dir(cfg), qname)

    detail = {"original_path": target, "quarantine_path": qpath, "sha256": digest,
              "size_bytes": size, "quarantined_at": ts.isoformat()}

    if dry:
        edr.audit(cfg, AR_NAME, alert, "quarantine", True, "dry_run", detail)
        sys.exit(edr.OS_SUCCESS)

    try:
        os.makedirs(quarantine_dir(cfg), exist_ok=True)
        # lock down the quarantine dir itself (owner-only)
        os.chmod(quarantine_dir(cfg), stat.S_IRWXU)
        shutil.move(target, qpath)
        os.chmod(qpath, stat.S_IRUSR)   # 0400 — read-only, owner only
    except Exception as e:
        detail["error"] = str(e)
        edr.audit(cfg, AR_NAME, alert, "quarantine", False, "error", detail)
        sys.exit(edr.OS_INVALID)

    entry = dict(detail)
    entry.update({"rule_id": edr.get_rule_id(alert), "agent_id": edr.get_agent_id(alert),
                  "restored": False})
    append_manifest(cfg, entry)
    edr.audit(cfg, AR_NAME, alert, "quarantine", False, "quarantined", detail)
    sys.exit(edr.OS_SUCCESS)


if __name__ == "__main__":
    main()
