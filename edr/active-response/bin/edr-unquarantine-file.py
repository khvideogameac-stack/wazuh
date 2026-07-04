#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-1 rollback: restore a quarantined file (Linux agents).
#
# Reverses edr-quarantine-file.py using the manifest. Verifies the SHA256 still
# matches before restoring (so a tampered quarantine file is not silently put
# back), moves the file to its original path, and marks the manifest entry
# restored.
#
# Manual use (analyst):
#   edr-unquarantine-file.py --sha256 <hash>
#   edr-unquarantine-file.py --quarantine-path <path>
#   edr-unquarantine-file.py --list
# It reads no stdin when run manually.

import os
import sys
import json
import shutil
import hashlib
import argparse
import datetime

import edr_common as edr

AR_NAME = "edr-unquarantine-file"


def quarantine_dir(cfg):
    return (cfg.get("quarantine") or {}).get("dir_linux") or os.path.join(edr.WAZUH_HOME, "quarantine")


def manifest_path(cfg):
    name = (cfg.get("quarantine") or {}).get("manifest") or "quarantine-manifest.jsonl"
    return os.path.join(quarantine_dir(cfg), name)


def read_manifest(cfg):
    entries = []
    try:
        with open(manifest_path(cfg)) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except Exception:
        pass
    return entries


def rewrite_manifest(cfg, entries):
    with open(manifest_path(cfg), "w") as fh:
        for e in entries:
            fh.write(json.dumps(e, default=str) + "\n")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def do_restore(cfg, dry, entry, alert):
    qpath = entry.get("quarantine_path")
    orig = entry.get("original_path")
    detail = {"original_path": orig, "quarantine_path": qpath, "sha256": entry.get("sha256"),
              "restored_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    if not qpath or not os.path.isfile(qpath):
        detail["error"] = "quarantined file missing"
        edr.audit(cfg, AR_NAME, alert, "unquarantine", dry, "not_found", detail)
        return edr.OS_NOTFOUND

    # integrity gate
    if entry.get("sha256"):
        actual = sha256_of(qpath)
        detail["sha256_actual"] = actual
        if actual != entry["sha256"]:
            detail["error"] = "SHA256 mismatch — quarantined file changed; refusing to restore"
            edr.audit(cfg, AR_NAME, alert, "unquarantine", dry, "refused", detail)
            return edr.OS_INVALID

    if dry:
        detail["would_do"] = "move %s -> %s" % (qpath, orig)
        edr.audit(cfg, AR_NAME, alert, "unquarantine", True, "dry_run", detail)
        return edr.OS_SUCCESS

    try:
        os.makedirs(os.path.dirname(orig), exist_ok=True)
        shutil.move(qpath, orig)
    except Exception as e:
        detail["error"] = str(e)
        edr.audit(cfg, AR_NAME, alert, "unquarantine", False, "error", detail)
        return edr.OS_INVALID

    entry["restored"] = True
    entry["restored_at"] = detail["restored_at"]
    edr.audit(cfg, AR_NAME, alert, "unquarantine", False, "restored", detail)
    return edr.OS_SUCCESS


def main():
    cfg = edr.load_config()
    dry = edr.effective_dry_run(cfg)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--sha256")
    parser.add_argument("--quarantine-path")
    parser.add_argument("--list", action="store_true")
    # only parse when invoked manually (a tty / args present)
    args, _ = parser.parse_known_args()

    entries = read_manifest(cfg)

    if args.list:
        active = [e for e in entries if not e.get("restored")]
        print(json.dumps(active, indent=2, default=str))
        sys.exit(edr.OS_SUCCESS)

    selector = None
    if args.sha256:
        selector = lambda e: e.get("sha256") == args.sha256
    elif args.quarantine_path:
        selector = lambda e: e.get("quarantine_path") == args.quarantine_path
    else:
        # AR mode: a rule fired an unquarantine — match by original path in the alert
        message = edr.read_stdin_message()
        alert = edr.get_alert(message) if message else {}
        if message and edr.get_command(message) == "delete":
            edr.audit(cfg, AR_NAME, alert, "unquarantine", dry, "noop", {"reason": "delete callback"})
            sys.exit(edr.OS_SUCCESS)
        target = edr._dig(alert, "syscheck.path", "file.path", "data.file")
        if not target:
            edr.audit(cfg, AR_NAME, alert, "unquarantine", dry, "not_found",
                      {"reason": "no selector (use --sha256/--quarantine-path) and no file path in alert"})
            sys.exit(edr.OS_NOTFOUND)
        selector = lambda e: e.get("original_path") == target
        chosen = next((e for e in entries if selector(e) and not e.get("restored")), None)
        if not chosen:
            edr.audit(cfg, AR_NAME, alert, "unquarantine", dry, "not_found",
                      {"reason": "no active quarantine entry for path", "path": target})
            sys.exit(edr.OS_NOTFOUND)
        rc = do_restore(cfg, dry, chosen, alert)
        if not dry:
            rewrite_manifest(cfg, entries)
        sys.exit(rc)

    chosen = next((e for e in entries if selector(e) and not e.get("restored")), None)
    if not chosen:
        edr.audit(cfg, AR_NAME, {}, "unquarantine", dry, "not_found", {"reason": "no matching active quarantine entry"})
        sys.exit(edr.OS_NOTFOUND)
    rc = do_restore(cfg, dry, chosen, {})
    if not dry:
        rewrite_manifest(cfg, entries)
    sys.exit(rc)


if __name__ == "__main__":
    main()
