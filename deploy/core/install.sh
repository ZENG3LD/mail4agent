#!/usr/bin/env bash
# Run as root on the CORE. Usage: install.sh /path/to/mail4agent-server-bin
# Idempotent. Creates the user and state dir, installs binary + unit, keeps the previous binary. Does NOT
# generate or touch M4A_DB_KEY_HEX / M4A_EDGE_SECRET: for a migration the key comes from the old host
# (see deploy/MIGRATION.md); for a fresh core run `gen-secrets` once (prints nothing, writes 0640).
set -euo pipefail
cd "$(dirname "$0")"
env_file=/etc/m4a/core.env; bin=/usr/local/bin/mail4agent-server-bin
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
if [ "${1:-}" = gen-secrets ]; then
  install -d -m 0750 /etc/m4a; touch "$env_file"; chmod 0640 "$env_file"
  grep -q '^M4A_DB_KEY_HEX=' "$env_file" || printf 'M4A_DB_KEY_HEX=%s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" >> "$env_file"
  grep -q '^M4A_EDGE_SECRET=' "$env_file" || printf 'M4A_EDGE_SECRET=%s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" >> "$env_file"
  echo "secrets present in $env_file (not shown; back up the key off-host)"; exit 0
fi
src="${1:?usage: install.sh /path/to/mail4agent-server-bin | gen-secrets}"
id m4a >/dev/null 2>&1 || useradd --system --home /var/lib/m4a --shell /usr/sbin/nologin m4a
install -d -m 0700 -o m4a -g m4a /var/lib/m4a
[ -f "$bin" ] && cp -p "$bin" "/var/backups/m4a-bin-$(date -u +%Y%m%dT%H%M%SZ)" 2>/dev/null || true
install -m 0755 "$src" "$bin"
install -m 0644 m4a-core.service /etc/systemd/system/m4a-core.service
chgrp m4a "$env_file" 2>/dev/null && chmod 0640 "$env_file" || true
systemctl daemon-reload; systemctl enable m4a-core >/dev/null
echo "installed. Fill $env_file, then: systemctl start m4a-core"
