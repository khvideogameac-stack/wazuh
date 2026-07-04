# Wazuh Rule Wizard

A self-contained, zero-dependency web wizard for the two most common ruleset tasks:

- **Suppressing a false positive** — a rule keeps firing on legitimate activity
  (a vulnerability scanner, a service account, a backup job) and you want to
  silence that specific noise without disabling detection.
- **Authoring a new detection rule** — building a custom rule with match
  conditions, severity, MITRE ATT&CK and compliance mappings.

It generates deployment-ready output for both supported rule formats:

| Target | Output |
|---|---|
| **Wazuh 5.x** | Sigma-style YAML rule + a ready-to-run `curl` command for the Content Manager API (`POST /_plugins/_content_manager/rules`), plus the Draft → Test → Custom promotion checklist. |
| **Wazuh 4.x** | A `local_rules.xml` snippet (level-0 `if_sid` child rule for suppressions, or a full custom rule), plus `wazuh-logtest` / restart instructions. |

## Usage

No build step, no server, no network access needed:

```bash
# open directly in any browser
xdg-open tools/rule-wizard/index.html        # Linux
open tools/rule-wizard/index.html            # macOS
```

## Workflow

1. **Basics** — pick *Suppress a false positive* or *Author a new rule*, choose
   the target version (5.x YAML / 4.x XML) in the header, and fill in
   title/description. Suppression mode asks which rule you are tuning
   (`if_sid` for 4.x, the standard rule title/UUID for 5.x).
2. **Sample event** *(optional)* — paste the JSON of the alert/finding/event.
   The wizard flattens it into clickable field chips; clicking a chip adds
   `field = value` straight into the condition tables.
3. **Conditions** — field / operator / value rows.
   - Operators map to Sigma modifiers in 5.x (`|contains`, `|re`, `|cidr`,
     `|exists`, numeric comparisons…) and are compiled to the closest 4.x
     construct (`<srcip>`, `<field type="pcre2">`, `<match>`…) with a
     "review needed" warning whenever the translation is lossy.
   - Comma-separated values inside one row mean OR; separate rows mean AND.
   - Suppression exclusions support multiple **groups**: rows in a group AND
     together, groups OR together (`selection and not 1 of filter_*` in 5.x;
     one suppression rule per group in 4.x).
4. **Classification** — severity (5.x keywords, auto-mapped to 4.x numeric
   levels), status/enabled, MITRE tactics + techniques, compliance control IDs
   (PCI DSS, GDPR, HIPAA, NIST, ISO 27001, TSC, NIS2, FedRAMP, CMMC), tags and
   known false positives.
5. **Review & export** — live-generated rule with validation errors, lossy
   conversion warnings, copy/download buttons, the 5.x API `curl` command and
   step-by-step deployment instructions.

## How suppression works per version

- **5.x** — standard rules are read-only, so the wizard emits a *tuned copy*:
  the original rule's match conditions as the `selection` plus your
  false-positive conditions as `filter_*` selections, combined with
  `selection and not filter…`. Deploy it through Draft → Test → Custom, then
  disable the original standard rule.
- **4.x** — the wizard emits a child rule with `<if_sid>` pointing at the noisy
  rule and `level="0"`: events matching the false-positive conditions hit the
  more specific level-0 rule and stop alerting, while everything else still
  fires the original rule. Custom rule IDs are validated against the
  100000–120000 range.

## References

- [Migrating rules from 4.x (XML) to 5.x (YAML)](../../docs/guide/migration/rules-4x-to-5x.md)
- [Sigma rule specification](https://sigmahq.io/docs/basics/rules.html)
- [Wazuh 4.x rules syntax](https://documentation.wazuh.com/4.9/user-manual/ruleset/ruleset-xml-syntax/rules.html)
