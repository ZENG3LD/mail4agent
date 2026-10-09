#!/usr/bin/env bash
# Run as root on the EDGE. Usage: install.sh /path/to/m4a-edge
# Idempotent; keeps the previous binary. Does not write secrets: /etc/m4a/edge.env is filled by the owner/local agent.
set -euo pipefail
cd "$(dirname "$0")"
src="${1:?usage: install.sh /path/to/m4a-edge}"; bin=/usr/local/bin/m4a-edge
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
id m4a-edge >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin m4a-edge
install -d -m 0750 /etc/m4a; [ -f /etc/m4a/edge.env ] || { touch /etc/m4a/edge.env; }
chgrp m4a-edge /etc/m4a/edge.env; chmod 0640 /etc/m4a/edge.env
[ -f "$bin" ] && cp -p "$bin" "/var/backups/m4a-edge-bin-$(date -u +%Y%m%dT%H%M%SZ)" 2>/dev/null || true
install -m 0755 "$src" "$bin"
install -m 0644 m4a-edge.service /etc/systemd/system/m4a-edge.service
systemctl daemon-reload; systemctl enable m4a-edge >/dev/null
echo "installed. Fill /etc/m4a/edge.env (M4A_CORE_URL, M4A_EDGE_SECRET), stop the old m4a unit, then: systemctl start m4a-edge"
