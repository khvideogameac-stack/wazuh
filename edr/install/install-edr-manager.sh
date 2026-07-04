#!/bin/bash
# Rwased EDR — manager installer.
# Installs the EDR rules, decoders, config and analyst tools on a Wazuh MANAGER,
# and merges the active-response + localfile blocks into ossec.conf.
#
# Idempotent: safe to re-run (it backs up ossec.conf and skips blocks already
# present). It does NOT flip dry-run and does NOT restart the manager unless you
# pass --restart. Run from the repo root (the dir containing edr/).
#
#   sudo ./edr/install/install-edr-manager.sh                 # install, then tells you to restart
#   sudo ./edr/install/install-edr-manager.sh --restart       # install + restart wazuh-manager
#   sudo OSSEC=/var/ossec ./edr/install/install-edr-manager.sh
set -euo pipefail

OSSEC="${OSSEC:-/var/ossec}"
RESTART=0
[ "${1:-}" = "--restart" ] && RESTART=1

# Locate the edr/ source dir relative to this script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$SCRIPT_DIR/.." && pwd)"          # .../edr
MARKER="Rwased EDR active-response wiring"

echo "==> Rwased EDR manager install"
echo "    source : $SRC"
echo "    target : $OSSEC"

[ -d "$OSSEC" ] || { echo "ERROR: $OSSEC not found — is this a Wazuh manager? Set OSSEC=<path>."; exit 1; }
[ -f "$OSSEC/etc/ossec.conf" ] || { echo "ERROR: $OSSEC/etc/ossec.conf missing."; exit 1; }

# 1) rules, decoders, config, tools
install -m 0640 "$SRC/etc/rules/local_edr_rules.xml"       "$OSSEC/etc/rules/local_edr_rules.xml"
install -m 0640 "$SRC/etc/decoders/local_edr_decoders.xml" "$OSSEC/etc/decoders/local_edr_decoders.xml"
if [ -f "$OSSEC/etc/edr.conf.json" ]; then
  echo "    keep   : existing $OSSEC/etc/edr.conf.json (not overwritten)"
else
  install -m 0640 "$SRC/etc/edr.conf.json" "$OSSEC/etc/edr.conf.json"
  echo "    NOTE   : edit $OSSEC/etc/edr.conf.json and set manager.ip before enabling isolation."
fi
mkdir -p "$OSSEC/etc/edr-tools"
install -m 0750 "$SRC/tools/edr-process-tree.py" "$OSSEC/etc/edr-tools/edr-process-tree.py"
install -m 0750 "$SRC/tools/edr-live-response.py" "$OSSEC/etc/edr-tools/edr-live-response.py"
echo "    ok     : rules, decoders, config, tools installed"

# 2) merge ossec.conf blocks (idempotent via marker)
if grep -qF "$MARKER" "$OSSEC/etc/ossec.conf"; then
  echo "    skip   : ossec.conf already contains the EDR blocks"
else
  cp -a "$OSSEC/etc/ossec.conf" "$OSSEC/etc/ossec.conf.bak.$(date +%Y%m%d%H%M%S)"
  {
    echo ""
    echo "<!-- ===== $MARKER (installed $(date -u +%FT%TZ)) ===== -->"
    cat "$SRC/etc/ossec-edr-active-response.conf.example"
    echo ""
    cat "$SRC/etc/ossec-edr-localfile.conf.example"
  } >> "$OSSEC/etc/ossec.conf"
  echo "    ok     : appended AR + localfile blocks to ossec.conf (backup saved)"
fi

# 3) permissions (Wazuh runs as wazuh:wazuh on 4.x+)
if id wazuh >/dev/null 2>&1; then
  chown wazuh:wazuh "$OSSEC/etc/rules/local_edr_rules.xml" "$OSSEC/etc/decoders/local_edr_decoders.xml" \
    "$OSSEC/etc/edr.conf.json" 2>/dev/null || true
fi

# 4) sanity-check the ruleset loads
if [ -x "$OSSEC/bin/wazuh-logtest" ]; then
  echo "==> Validating ruleset (wazuh-logtest -t) ..."
  if echo "" | "$OSSEC/bin/wazuh-logtest" -t >/tmp/edr-logtest.out 2>&1; then
    echo "    ok     : ruleset parsed"
  else
    echo "    WARN   : wazuh-logtest reported issues — review /tmp/edr-logtest.out before restarting:"
    tail -20 /tmp/edr-logtest.out
  fi
fi

if [ "$RESTART" = "1" ]; then
  echo "==> Restarting wazuh-manager ..."
  systemctl restart wazuh-manager && echo "    ok     : wazuh-manager restarted"
else
  echo ""
  echo "Done. The layer is installed in DRY-RUN (nothing is enforced yet)."
  echo "Next:"
  echo "  1. Set manager.ip in $OSSEC/etc/edr.conf.json"
  echo "  2. Restart:  systemctl restart wazuh-manager"
  echo "  3. Install agents:  edr/install/install-edr-agent-linux.sh  /  Install-EdrAgent.ps1"
  echo "  4. Work through the lab test plan (edr/docs/EDR-feature-layer.md §5) before flipping dry_run:false."
fi
