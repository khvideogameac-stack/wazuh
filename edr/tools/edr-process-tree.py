#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc. / Rwased EDR layer.
# Tier-2 investigation: process ancestry / tree reconstruction.
#
# Given a Sysmon Event ID 1 (process creation) alert — identified by an agent
# and a process GUID or PID — this walks the ParentProcessGuid chain using
# Sysmon events ALREADY ingested into OpenSearch and prints a readable process
# tree. It is a read-only analyst tool: it runs on the manager (or an analyst
# workstation), queries the indexer, and never touches an endpoint.
#
# This deliberately reconstructs ancestry from stored telemetry rather than
# adding a new agent capability, so it works retrospectively on any host whose
# Sysmon logs are in the index.
#
# Usage:
#   edr-process-tree.py --agent web-01 --guid "{aaaa-...}"
#   edr-process-tree.py --agent web-01 --pid 4711 --since 24h
#   edr-process-tree.py --config /var/ossec/etc/edr-indexer.json --agent web-01 --pid 4711
#
# Indexer connection is read from (in order): --url/--user/--password flags,
# the EDR_INDEXER_* environment variables, or a small JSON config file.
# No third-party libraries required (urllib only).

import os
import sys
import ssl
import json
import base64
import argparse
import urllib.request
import urllib.error

# Sysmon field paths as decoded by Wazuh (classic 4.x JSON alert layout).
F_IMAGE = "data.win.eventdata.image"
F_PID = "data.win.eventdata.processId"
F_GUID = "data.win.eventdata.processGuid"
F_PGUID = "data.win.eventdata.parentProcessGuid"
F_PPID = "data.win.eventdata.parentProcessId"
F_PIMAGE = "data.win.eventdata.parentImage"
F_CMDLINE = "data.win.eventdata.commandLine"
F_USER = "data.win.eventdata.user"
F_UTC = "data.win.eventdata.utcTime"
F_AGENT = "agent.name"


def load_indexer_cfg(args):
    cfg = {"url": "https://localhost:9200", "user": "admin", "password": "admin",
           "index": "wazuh-alerts-*", "verify_ssl": False}
    if args.config and os.path.isfile(args.config):
        try:
            cfg.update(json.load(open(args.config)))
        except Exception as e:
            print("warning: could not read config %s: %s" % (args.config, e), file=sys.stderr)
    for key, env in [("url", "EDR_INDEXER_URL"), ("user", "EDR_INDEXER_USER"),
                     ("password", "EDR_INDEXER_PASSWORD"), ("index", "EDR_INDEXER_INDEX")]:
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    if args.url: cfg["url"] = args.url
    if args.user: cfg["user"] = args.user
    if args.password: cfg["password"] = args.password
    if args.index: cfg["index"] = args.index
    return cfg


def search(cfg, body):
    url = "%s/%s/_search" % (cfg["url"].rstrip("/"), cfg["index"])
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    token = base64.b64encode(("%s:%s" % (cfg["user"], cfg["password"])).encode()).decode()
    req.add_header("Authorization", "Basic " + token)
    ctx = None
    if str(cfg.get("verify_ssl")).lower() in ("false", "0", "no"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        print("indexer error %s: %s" % (e.code, e.read().decode(errors="replace")), file=sys.stderr)
    except Exception as e:
        print("indexer request failed: %s" % e, file=sys.stderr)
    return None


def _get(src, dotted):
    cur = src
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def find_event(cfg, agent, since, guid=None, pid=None):
    """Return the Sysmon EID-1 source doc matching guid (preferred) or pid."""
    must = [
        {"term": {"rule.groups": "sysmon_event1"}},
        {"range": {"@timestamp": {"gte": "now-" + since}}},
    ]
    if agent:
        must.append({"match": {F_AGENT: agent}})
    if guid:
        must.append({"match_phrase": {F_GUID: guid}})
    elif pid is not None:
        must.append({"match_phrase": {F_PID: str(pid)}})
    body = {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}}}
    res = search(cfg, body)
    if not res:
        return None
    hits = _get(res, "hits.hits") or []
    return hits[0]["_source"] if hits else None


def find_by_guid(cfg, agent, since, guid):
    if not guid:
        return None
    must = [
        {"term": {"rule.groups": "sysmon_event1"}},
        {"range": {"@timestamp": {"gte": "now-" + since}}},
        {"match_phrase": {F_GUID: guid}},
    ]
    if agent:
        must.append({"match": {F_AGENT: agent}})
    res = search(cfg, {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}],
                       "query": {"bool": {"must": must}}})
    if not res:
        return None
    hits = _get(res, "hits.hits") or []
    return hits[0]["_source"] if hits else None


def summarize(src):
    return {
        "image": _get(src, F_IMAGE),
        "pid": _get(src, F_PID),
        "guid": _get(src, F_GUID),
        "parent_guid": _get(src, F_PGUID),
        "parent_image": _get(src, F_PIMAGE),
        "parent_pid": _get(src, F_PPID),
        "command_line": _get(src, F_CMDLINE),
        "user": _get(src, F_USER),
        "time": _get(src, F_UTC),
    }


def build_ancestry(cfg, agent, since, start_src, max_depth=20):
    chain = [summarize(start_src)]
    parent_guid = chain[0]["parent_guid"]
    depth = 0
    seen = {chain[0]["guid"]}
    while parent_guid and depth < max_depth and parent_guid not in seen:
        seen.add(parent_guid)
        psrc = find_by_guid(cfg, agent, since, parent_guid)
        if not psrc:
            chain.append({"image": chain[-1]["parent_image"], "guid": parent_guid,
                          "pid": chain[-1]["parent_pid"], "note": "not in index (older than window?)"})
            break
        chain.append(summarize(psrc))
        parent_guid = chain[-1]["parent_guid"]
        depth += 1
    chain.reverse()   # root first
    return chain


def render(chain):
    lines = []
    for i, node in enumerate(chain):
        indent = "  " * i + ("└─ " if i else "")
        img = node.get("image") or "(unknown)"
        pid = node.get("pid")
        line = "%s%s (pid %s)" % (indent, img, pid)
        lines.append(line)
        cl = node.get("command_line")
        if cl:
            lines.append("  " * i + "     cmd: " + cl)
        if node.get("user"):
            lines.append("  " * i + "     user: " + str(node["user"]))
        if node.get("time"):
            lines.append("  " * i + "     time: " + str(node["time"]))
        if node.get("note"):
            lines.append("  " * i + "     [" + node["note"] + "]")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Reconstruct a process tree from ingested Sysmon EID-1 events.")
    ap.add_argument("--agent", help="agent name (host) to scope the search")
    ap.add_argument("--guid", help="Sysmon ProcessGuid of the process of interest")
    ap.add_argument("--pid", type=int, help="process id (used if --guid not given)")
    ap.add_argument("--since", default="24h", help="lookback window, e.g. 6h, 24h, 7d (default 24h)")
    ap.add_argument("--json", action="store_true", help="emit the chain as JSON")
    ap.add_argument("--config", default="/var/ossec/etc/edr-indexer.json")
    ap.add_argument("--url"); ap.add_argument("--user"); ap.add_argument("--password"); ap.add_argument("--index")
    args = ap.parse_args()

    if not args.guid and args.pid is None:
        ap.error("provide --guid or --pid")

    cfg = load_indexer_cfg(args)
    start = find_event(cfg, args.agent, args.since, guid=args.guid, pid=args.pid)
    if not start:
        print("No matching Sysmon process-creation event found "
              "(agent=%s, guid=%s, pid=%s, since=%s)." % (args.agent, args.guid, args.pid, args.since),
              file=sys.stderr)
        sys.exit(2)

    chain = build_ancestry(cfg, args.agent, args.since, start)
    if args.json:
        print(json.dumps(chain, indent=2, default=str))
    else:
        print("Process ancestry (root first):\n")
        print(render(chain))


if __name__ == "__main__":
    main()
