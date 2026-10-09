#!/usr/bin/env bash
# backup | backup-bin | rollback [timestamp]. Binary + DB (+WAL). The DB is SQLCipher: the copy is
# useless without M4A_DB_KEY_HEX, which must be stored separately (never in this directory/git).
set -euo pipefail
B="${M4A_BACKUP_DIR:-/var/backups/m4a}"; S="${M4A_STATE_DIR:-/var/lib/m4a}"; BIN="${M4A_BIN:-/usr/local/bin/mail4agent-server-bin}"
mkdir -p "$B"; chmod 700 "$B"; ts=$(date -u +%Y%m%dT%H%M%SZ)
case "${1:-}" in
  backup-bin) [ -f "$BIN" ] && cp -p "$BIN" "$B/bin-$ts" && echo "bin-$ts";;
  backup)
    systemctl stop m4a-core; trap 'systemctl start m4a-core' EXIT
    [ -f "$BIN" ] && cp -p "$BIN" "$B/bin-$ts"
    tar -C "$S" -cf "$B/db-$ts.tar" . && echo "db-$ts.tar"
    ls -1t "$B"/db-*.tar 2>/dev/null | tail -n +8 | xargs -r rm -f;;
  rollback)
    t="${2:-}"; [ -n "$t" ] || t=$(ls -1t "$B"/bin-* | head -1 | sed 's/.*bin-//')
    systemctl stop m4a-core
    cp -p "$B/bin-$t" "$BIN"
    [ -f "$B/db-$t.tar" ] && { rm -rf "$S"/*; tar -C "$S" -xf "$B/db-$t.tar"; chown -R "${M4A_USER:-m4a}" "$S"; }
    systemctl start m4a-core; echo "rolled back to $t";;
  *) echo "usage: backup.sh backup|backup-bin|rollback [timestamp]" >&2; exit 2;;
esac
