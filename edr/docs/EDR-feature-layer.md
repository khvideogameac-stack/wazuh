# Rwased EDR feature layer — build, enablement & test plan

This document describes the EDR (Endpoint Detection & Response) capabilities
layered on top of Wazuh's existing agent / manager / active-response
architecture. It is additive: it does not replace the agent, and it does not
introduce any offensive tooling. Everything here is **detect, contain,
investigate, log** — with a full audit trail and dry-run-first rollout.

---

## 1. What was built

```
edr/
├── etc/
│   ├── edr.conf.json                         # single config: dry-run switch, allow/denylists, paths
│   ├── rules/local_edr_rules.xml             # Tier 3 detection + response-trigger + visibility rules
│   ├── decoders/local_edr_decoders.xml       # live-response output decoder
│   ├── ossec-edr-active-response.conf.example# Tier 3 <command>/<active-response> wiring
│   └── ossec-edr-localfile.conf.example       # ingest EDR logs back into the pipeline
├── active-response/bin/
│   ├── edr_common.py / edr_common.ps1        # shared: AR stdin parsing, config, audit log, allow/deny
│   ├── edr-kill-process.py / .ps1 / .cmd     # Tier 1: process termination
│   ├── edr-isolate-host.py / .ps1 / .cmd     # Tier 1: network isolation
│   ├── edr-unisolate-host.py / .ps1 / .cmd   # Tier 1 rollback: remove isolation
│   ├── edr-quarantine-file.py / .ps1 / .cmd  # Tier 1: file quarantine
│   ├── edr-unquarantine-file.py / .ps1 / .cmd# Tier 1 rollback: restore file
│   └── edr-live-response.py / .ps1 / .cmd     # Tier 2: agent-side read-only executor (allowlisted)
├── tools/
│   ├── edr-process-tree.py                    # Tier 2: process ancestry from OpenSearch
│   └── edr-live-response.py                    # Tier 2: analyst CLI (confirmation + audit + Wazuh API)
└── docs/
    ├── EDR-feature-layer.md                   # this file
    └── rule-id-allocations.md                 # rule-ID source of truth
```

### Design guarantees (apply to every Tier-1 action)

| Guarantee | How |
|---|---|
| **Dry-run first** | `edr.conf.json` `dry_run: true` by default; `EDR_DRY_RUN` env var overrides. Dry-run logs the exact intended action and exits without touching the endpoint. |
| **Structured audit trail** | Every action appends a JSON-lines record to `active-responses-edr.log`: `timestamp, script, rule_id, agent_id, agent_name, host, action, dry_run, outcome, detail`. |
| **Reversibility** | Isolation → `edr-unisolate-host`; quarantine → `edr-unquarantine-file` (SHA256-verified). Kill is irreversible, so the full process tree is recorded before the signal. |
| **Safety allow/denylists** | Kill enforces a protected-process denylist (lsass, wininit, the agent itself…) + a protected low-PID range + optional strict allowlist. Quarantine refuses system/agent paths. Isolation refuses to run without a configured manager IP. |
| **Self-healing containment** | Isolation is time-boxed via the AR `<timeout>`; the `delete` callback auto-unisolates so a missed review never strands a host offline. |

---

## 2. Deploy the files

On the **manager**:

```bash
# rules, decoders, config
cp edr/etc/rules/local_edr_rules.xml         /var/ossec/etc/rules/
cp edr/etc/decoders/local_edr_decoders.xml   /var/ossec/etc/decoders/
cp edr/etc/edr.conf.json                     /var/ossec/etc/
# analyst tools
cp edr/tools/edr-process-tree.py  edr/tools/edr-live-response.py  /var/ossec/etc/edr-tools/
```

On **each agent** (via your RMM/PowerShell deployment, running as SYSTEM):

```
# Linux agents
cp edr/active-response/bin/edr_common.py            /var/ossec/active-response/bin/
cp edr/active-response/bin/edr-*.py                 /var/ossec/active-response/bin/
cp edr/etc/edr.conf.json                            /var/ossec/etc/
chmod 750 /var/ossec/active-response/bin/edr-*.py

# Windows agents  (C:\Program Files (x86)\ossec-agent\)
copy edr\active-response\bin\edr_common.ps1         active-response\bin\
copy edr\active-response\bin\edr-*.ps1              active-response\bin\
copy edr\active-response\bin\edr-*.cmd              active-response\bin\
copy edr\etc\edr.conf.json                          etc\
```

> Distributing `edr.conf.json` through the shared `agent.conf`
> file-distribution mechanism is fine, but remember: **`<anti_tampering>` is not
> a valid element in this Wazuh version — never add it to agent.conf.** After
> any agent.conf change run `/var/ossec/bin/verify-agent-conf`.

Then merge the two example `.conf` files into `/var/ossec/etc/ossec.conf` and:

```bash
/var/ossec/bin/wazuh-logtest      # confirms the rules load
systemctl restart wazuh-manager
```

---

## 3. Enable each feature (dry-run first — always)

`dry_run` starts `true`. **Leave it true until the lab test plan (§5) passes for
that feature.** With dry-run on, the whole layer is safe to deploy: alerts fire,
the AR scripts run, and the audit log fills with `dry_run` records — but nothing
on the endpoint changes.

Rollout order per feature:

1. Deploy with `dry_run: true`. Trigger the detection in the lab. Confirm the
   audit log shows the correct `dry_run` record (right PID / IP / file, safety
   checks evaluated).
2. Set `dry_run: false` **in the lab** and re-run. Confirm the action happens
   and the rollback works.
3. Only then promote `dry_run: false` to production, one feature at a time.
   Watch rules 101121 (enforced) / 101122 (refused) in the dashboard.

To flip a single agent to enforce without editing the file, set the env var for
the agent service (`EDR_DRY_RUN=false`); to force dry-run regardless of file,
`EDR_DRY_RUN=true`.

### Tuning the safety lists

`edr.conf.json` → `process_kill.denylist_names` (never killed),
`process_kill.allowlist_names` (if non-empty, ONLY these may be killed —
strict mode), `isolation.allow_ips`/`allow_ports` (kept reachable while
isolated), `quarantine.dir_*`. The manager IP **must** be set under
`manager.ip` or isolation refuses to run.

---

## 4. How each feature works

### Tier 1.1 — Process termination (`edr-kill-process`)
Resolves a PID or process name from `<extra_args>` or the alert
(`process.pid`/`process.name`, or Sysmon `processId`/`image`). Captures the full
process tree (ancestors + descendants), checks the denylist / low-PID / strict
allowlist, then SIGTERM→SIGKILL (Linux) or `Stop-Process -Force` (Windows).
Protected targets are **refused** (a safe, logged outcome). Irreversible, so the
tree and command line are in the audit record.

### Tier 1.2 — Network isolation (`edr-isolate-host` / `edr-unisolate-host`)
Linux: a dedicated `RWASED_EDR_ISOLATION` iptables chain in OUTPUT that ACCEPTs
loopback, established connections, the manager IP and configured allow_ips/ports
(incl. DNS), then DROPs everything else. Windows: a `Rwased-EDR-Isolation`
Windows Firewall rule group doing the same. Reversible and idempotent; the
isolation window start/end (and duration) are recorded. Time-boxed by the AR
`<timeout>` so it self-reverses.

### Tier 1.3 — File quarantine (`edr-quarantine-file` / `edr-unquarantine-file`)
Computes SHA256, **moves** (never deletes) the file into a locked-down
quarantine dir (0400 / restricted ACL), and appends a manifest entry
(`original_path → quarantine_path → sha256 → timestamp → rule/agent`). Restore
re-verifies the SHA256 before moving the file back (a tampered quarantine file
is refused). System/agent paths are refused.

### Tier 2.1 — Process ancestry (`edr-process-tree.py`)
Read-only manager tool. Given an agent + Sysmon ProcessGuid or PID, walks the
`ParentProcessGuid` chain across Sysmon EID-1 events already in OpenSearch and
prints a readable tree. Retrospective — needs no new agent capability.

### Tier 2.2 — Live response (`tools/edr-live-response.py` + agent executor)
A narrow, authenticated, **read-only** investigation channel — explicitly not a
remote shell. The analyst CLI takes an agent + one allowlisted command *key*
(`netstat`, `tasklist`, `processes`, …), prints exactly what will run, requires
the analyst to **type the agent ID to confirm**, then dispatches via the Wazuh
API. The agent-side executor independently re-checks the allowlist (defense in
depth) and can only run the fixed command bound to that key — never arbitrary
input. Every dispatch and execution is audited. Deliberately **not** wired to
any rule; no automated triggering.

### Tier 3 — Detection & wiring
See `rules/local_edr_rules.xml` and `rule-id-allocations.md`. LOLBin
(`rundll32`, `mshta`, `certutil`, `regsvr32`, …) egress and Office-spawn
detections, a spawn+egress correlation rule, response-trigger rules that
active-response binds to, and visibility rules that alert on the EDR layer's own
audit log so containment actions flow into Shuffle → TheHive like any finding.

---

## 5. Lab test plan

Validate every script in a throwaway lab VM **before it touches a production
endpoint**. Each feature has concrete cases, not just "test it." Do all of §5
with `dry_run: true` first, then repeat the enforce cases with `dry_run: false`.

### 5.0 Harness
- One Linux agent VM + one Windows agent VM enrolled to a lab manager.
- Sysmon installed on Windows with a config that logs EID 1 and EID 3.
- `tail -f /var/ossec/logs/active-responses-edr.log` on each agent.
- A safe target process: `sleep 3600` (Linux) / `notepad.exe` (Windows).

### 5.1 Process termination
| # | Case | Steps | Pass criteria |
|---|---|---|---|
| K1 | Dry-run by PID | `EDR_DRY_RUN=true`; feed the AR a JSON with `extra_args:["<sleep pid>"]` | audit `outcome:dry_run`, correct pid, `process_tree` populated; process still alive |
| K2 | Enforce by PID | `EDR_DRY_RUN=false`; repeat | `outcome:killed`; process gone |
| K3 | Enforce by name | `extra_args:["sleep"]` / `["notepad.exe"]` | resolves to the live PID and kills it |
| K4 | Denylist protection | target `lsass.exe` (Win) / pid 1 (Linux) | `outcome:refused`, reason cites denylist / low-PID; target untouched |
| K5 | Strict allowlist | set `allowlist_names:["sleep"]`; target a different process | `outcome:refused` |
| K6 | Missing target | `extra_args:["99999999"]` | `outcome:not_found`, exit clean |

### 5.2 Network isolation
| # | Case | Steps | Pass criteria |
|---|---|---|---|
| I1 | Dry-run | `EDR_DRY_RUN=true`; run isolate | `outcome:dry_run`, `planned_rules` keep manager+DNS; no firewall change |
| I2 | Enforce | `dry_run:false`; run isolate | manager still pingable / agent still reporting; a ping to 8.8.8.8 **fails**; audit `outcome:isolated` with `isolation_start` |
| I3 | Reversibility | run `edr-unisolate-host` | outbound restored; audit `outcome:unisolated` with `isolation_seconds` |
| I4 | Auto-heal | isolate via a rule with `<timeout>60`; wait | `delete` callback fires; host auto-unisolated within ~60s |
| I5 | No manager IP | blank `manager.ip`; isolate | `outcome:refused` (never cut the agent off blindly) |
| I6 | Idempotency | isolate twice | second run `already_isolated`; unisolate twice → second `not_isolated` |

### 5.3 File quarantine
| # | Case | Steps | Pass criteria |
|---|---|---|---|
| Q1 | Dry-run | drop `/tmp/evil.bin`; dry-run quarantine | `outcome:dry_run` with correct SHA256; file still in place |
| Q2 | Enforce | `dry_run:false`; repeat | file moved to quarantine dir (0400 / locked ACL); manifest entry written; original gone |
| Q3 | Restore | `edr-unquarantine-file.py --sha256 <hash>` | file back at original path; manifest `restored:true` |
| Q4 | Tamper gate | after Q2, overwrite the quarantined file, then restore | `outcome:refused` (SHA256 mismatch) |
| Q5 | Protected path | quarantine `/bin/ls` / a file under the agent dir | `outcome:refused` |
| Q6 | Missing file | quarantine a non-existent path | `outcome:not_found` |

### 5.4 Process ancestry
| # | Case | Steps | Pass criteria |
|---|---|---|---|
| P1 | Known chain | on Windows: `cmd → powershell → whoami`; then `edr-process-tree.py --agent <host> --pid <whoami pid>` | tree shows cmd→powershell→whoami root-first |
| P2 | GUID lookup | use `--guid <ProcessGuid>` | same tree |
| P3 | Window edge | query with `--since 5m` for an older event | gracefully notes the parent is "not in index" |

### 5.5 Live response
| # | Case | Steps | Pass criteria |
|---|---|---|---|
| L1 | Allowed command | `edr-live-response.py --agent <id> --command netstat` and confirm | dispatched; output appears in `edr-live-response-output.log`; rule 101124 alert |
| L2 | Confirmation gate | run without `--yes`, type the wrong agent ID | aborted; manager audit `outcome:aborted` |
| L3 | Client allowlist | `--command "rm -rf /"` | refused client-side, `outcome:refused_client` |
| L4 | Agent allowlist | craft an AR message with `extra_args:["whoami; cat /etc/shadow"]` directly | agent executor `outcome:refused` (defense in depth) |
| L5 | No auto-trigger | grep rules for any `<active-response>` bound to live-response | none exists |

### 5.6 Detection & correlation (Tier 3)
| # | Case | Steps | Pass criteria |
|---|---|---|---|
| D1 | LOLBin egress | on Windows lab host: `certutil.exe -urlcache -f http://<lab-http>/x.txt x.txt` | rule 101002 fires |
| D2 | Office spawn | macro-less repro: `winword.exe` → spawn `mshta.exe` | rule 101021 fires |
| D3 | Correlation | LOLBin spawn + outbound within 120s | rule 101040 fires at level 13 |
| D4 | Response gate | with dry-run ON, let 101040 → 101100 | kill runs in dry-run; audit `dry_run`; rules 101120/101123 alert |
| D5 | Visibility | inspect the dashboard | EDR audit rules 101120–101124 present; enforced actions show as 101121 |

### 5.7 Rollout sign-off
A feature is production-eligible only when: its dry-run cases pass, its enforce
cases pass in the lab, its rollback works, and the audit records are complete
and correct. Record the sign-off per feature before flipping `dry_run:false` in
production.
