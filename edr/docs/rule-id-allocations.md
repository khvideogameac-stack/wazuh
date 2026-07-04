# Rwased — custom rule ID allocations (single source of truth)

Keep this table authoritative. Before adding any custom rule, claim its ID here
first so nothing collides across `local_rules.xml`,
`local_windows_rules.xml`, `local_rootcheck_suppressions.xml` and the EDR layer.

Wazuh reserves **100000–120000** for user rules. Standard/base rules live below
100000, so never reuse a base ID.

| Range | Owner / purpose | File | Status |
|---|---|---|---|
| 100200–100299 | (existing custom detections) | `local_rules.xml` | in use |
| 100490–100497 | (existing custom detections) | `local_rules.xml` | in use |
| 100513 | (existing custom detection) | `local_rules.xml` | in use |
| 100640 | (existing custom detection) | `local_rules.xml` | in use |
| 100700–100755 | (existing Windows detections) | `local_windows_rules.xml` | in use |
| *(rootcheck)* | rootcheck suppressions | `local_rootcheck_suppressions.xml` | in use |
| **101000–101199** | **EDR telemetry & response (this layer)** | `local_edr_rules.xml` | **new** |

The EDR block is sub-allocated so future EDR rules stay organized:

| Sub-range | Purpose |
|---|---|
| 101000–101019 | LOLBin **outbound network** detections (Sysmon EID 3) |
| 101020–101039 | Suspicious LOLBin **process creation** (Sysmon EID 1) |
| 101040–101059 | **Correlation** (process-creation + network) |
| 101060–101099 | *(reserved for future EDR detections)* |
| 101100–101119 | **Response-trigger** rules (active-response keys off these) |
| 101120–101149 | **EDR action visibility** (alerts on the EDR audit log) |
| 101150–101199 | *(reserved)* |

## Rules defined by this layer

| ID | Level | Description | Triggers response? |
|---|---|---|---|
| 101000 | 12 | rundll32.exe outbound connection | feeds 101040 |
| 101001 | 12 | mshta.exe outbound connection | feeds 101040 |
| 101002 | 12 | certutil.exe outbound connection | → 101101 (quarantine) |
| 101003 | 12 | regsvr32.exe outbound connection | feeds 101040 |
| 101004 | 12 | other LOLBin outbound (bitsadmin/msiexec/…) | — |
| 101020 | 8 | LOLBin process created | feeds 101040 |
| 101021 | 12 | LOLBin spawned by Office/script host | — |
| 101040 | 13 | **Correlation:** LOLBin spawn + egress within 120s | → 101100 (kill), 101110 (isolate) |
| 101100 | 13 | Response-trigger: terminate process | **edr-kill-process** |
| 101101 | 13 | Response-trigger: quarantine file | **edr-quarantine-file** |
| 101110 | 14 | Response-trigger: isolate host (suspicious port) | **edr-isolate-host** |
| 101120 | 3 | EDR audit: any EDR action logged | — |
| 101121 | 12 | EDR action **enforced** (not dry-run) | — |
| 101122 | 6 | EDR action **refused** by safety policy | — |
| 101123 | 4 | EDR action **dry-run** (no change) | — |
| 101124 | 5 | Live-response read-only command executed | — |

## MITRE ATT&CK / NCA ECC-2:2024 mapping note

MITRE technique IDs are carried in `<mitre><id>` per rule. NCA ECC-2:2024
control references are carried as `<group>` CSV tags (`nca_ecc_<control>`),
matching the existing `local_windows_rules.xml` convention. The controls tagged
here map to:

- **2-3 (Cybersecurity Event Logs & Monitoring Management)** — detection/logging rules
- **2-4 (Cybersecurity Incident & Threat Management)** — response-trigger and enforced-action rules
- **2-10 (Malware / malicious-code protection & event handling)** — LOLBin detections

> Verify the exact ECC-2:2024 **sub-control leaf numbers** against your
> organisation's control-mapping sheet before go-live. The domain choices above
> are defensible for host-based LOLBin detection and response; the leaf numbers
> (e.g. `2-3-3`) should be confirmed against your edition.
