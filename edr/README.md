# Rwased EDR feature layer

An EDR (Endpoint Detection & Response) capability layered on top of Wazuh's
existing agent / manager / active-response architecture. It extends the platform
from **detect and alert** into **detect, contain, investigate, and log** —
without replacing the agent and without any offensive tooling.

Everything is dry-run by default, fully audited, and reversible where the action
allows it.

## Contents

| Path | What |
|---|---|
| `etc/edr.conf.json` | Single config: dry-run switch, process/isolation/quarantine allow & denylists, paths. |
| `active-response/bin/` | Tier-1 response scripts (process kill, host isolation, file quarantine) + rollbacks, and the Tier-2 read-only live-response executor. Python for Linux, PowerShell (+`.cmd` shims) for Windows. |
| `tools/` | Tier-2 analyst tools: process-ancestry reconstruction from OpenSearch, and the live-response dispatch CLI. |
| `etc/rules/`, `etc/decoders/` | Tier-3 detection, response-trigger, and visibility rules (ID block 101000–101199) + the live-response decoder. |
| `etc/ossec-edr-*.conf.example` | Active-response wiring and log-ingestion stanzas to merge into `ossec.conf`. |
| `docs/EDR-feature-layer.md` | Full build description, feature-by-feature enablement (dry-run first), and the lab **test plan**. |
| `docs/rule-id-allocations.md` | Rule-ID source of truth alongside the existing custom ranges. |

## Start here

1. Read `docs/EDR-feature-layer.md` — deployment, enablement order, and the test plan.
2. Keep `docs/rule-id-allocations.md` updated whenever you add a custom rule.
3. Deploy with `dry_run: true`, validate each feature in a lab VM, then enforce one feature at a time.

## Safety posture

- **Dry-run by default** (`EDR_DRY_RUN` overrides the config file).
- **Protected-process denylist** (never kill `lsass.exe`, the agent, PID ≤ 100, …).
- **Isolation keeps the manager reachable** and self-heals via the AR timeout.
- **Quarantine moves, never deletes**, and restores are SHA256-verified.
- **Live response is read-only, allowlisted, and analyst-confirmed** — never auto-triggered.
- **Every action is written to a JSON-lines audit log** and surfaced back as alerts (rules 101120–101124), so containment flows into Shuffle → TheHive like any other finding.

> Note for operators: `<anti_tampering>` is **not** a valid `agent.conf` element
> in this Wazuh version — do not add it. Run `/var/ossec/bin/verify-agent-conf`
> after any `agent.conf` change.

---

## Product positioning (Rwased SIEM/XDR)

Rwased extends its Wazuh-based SIEM/XDR foundation with a native endpoint
detection-and-response layer that closes the loop between detection and action.
Built entirely on Wazuh's proven agent and active-response channels, the layer
adds three response primitives — process termination, network isolation, and
file quarantine — alongside read-only investigation tooling for process-ancestry
reconstruction and analyst-driven live response. Detection content ships with
it: correlation rules for living-off-the-land techniques (LOLBins such as
`rundll32`, `mshta`, and `certutil` reaching out to external infrastructure),
mapped to MITRE ATT&CK and NCA ECC-2:2024 controls so findings are audit-ready
for regulated environments.

The layer is defensive by construction. Every response runs dry-run first,
enforces protected-process and protected-path safeguards, keeps isolated hosts
reachable by the manager, and writes an immutable structured audit record of
what it did — or refused to do — and why. Isolation self-reverses on a timer;
quarantine moves files rather than destroying them and restores them on demand
with cryptographic verification; live response is a narrow allowlisted,
analyst-confirmed channel, never a remote shell. The result is an XDR platform
that can contain a compromised endpoint in seconds while remaining accountable,
reversible, and safe to run in production.
