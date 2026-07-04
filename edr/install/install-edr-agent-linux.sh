#!/bin/bash
# Rwased EDR — Linux agent installer.
# Copies the EDR response scripts + config onto a Wazuh LINUX AGENT.
# Idempotent; does not restart the agent (AR scripts are loaded on demand by
# wazuh-execd, so no restart is needed). Run from the repo root.
#
#   sudo ./edr/install/install-edr-agent-linux.sh
#   sudo MANAGER_IP=10.20.22.10 ./edr/install/install-edr-agent-linux.sh   # also sets manager.ip
set -euo pipefail

OSSEC="${OSSEC:-/var/ossec}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "==> Rwased EDR Linux agent install ($OSSEC)"
[ -d "$OSSEC/active-response/bin" ] || { echo "ERROR: $OSSEC/active-response/bin not found — is the Wazuh agent installed?"; exit 1; }

install -m 0750 "$SRC/active-response/bin/edr_common.py" "$OSSEC/active-response/bin/edr_common.py"
for f in "$SRC"/active-response/bin/edr-*.py; do
  install -m 0750 "$f" "$OSSEC/active-response/bin/$(basename "$f")"
done

if [ -f "$OSSEC/etc/edr.conf.json" ]; then
  echo "    keep   : existing $OSSEC/etc/edr.conf.json"
else
  install -m 0640 "$SRC/etc/edr.conf.json" "$OSSEC/etc/edr.conf.json"
fi

if [ -n "${MANAGER_IP:-}" ]; then
  # set manager.ip in the JSON config (python is a hard dep of these scripts anyway)
  python3 - "$OSSEC/etc/edr.conf.json" "$MANAGER_IP" <<'PY'
import json,sys
p,ip=sys.argv[1],sys.argv[2]
c=json.load(open(p)); c.setdefault("manager",{})["ip"]=ip
json.dump(c,open(p,"w"),indent=2)
print("    ok     : manager.ip set to %s"%ip)
PY
fi

if id wazuh >/dev/null 2>&1; then
  chown wazuh:wazuh "$OSSEC/active-response/bin/"edr*.py "$OSSEC/etc/edr.conf.json" 2>/dev/null || true
fi

echo "    ok     : EDR scripts installed (DRY-RUN by default)."
echo "    verify : python3 $OSSEC/active-response/bin/edr-kill-process.py <<<'{\"command\":\"add\",\"parameters\":{\"extra_args\":[\"99999999\"],\"alert\":{}}}'"
echo "             (expect a JSON 'not_found' line in $OSSEC/logs/active-responses-edr.log)"
