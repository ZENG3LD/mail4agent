# CORE deploy (private VPS, reachable only over wg-msg)

Prerequisites: Ubuntu 22.04 host, `wg-msg` tunnel up (`wg-msg.md`), firewall per `ufw-notes.md`, binary built per
`../hub/build-jammy.md` (`target/release/mail4agent-server-bin`).

## Steps (as root on the core)
1. Install: `deploy/core/install.sh /path/to/mail4agent-server-bin` (user `m4a`, state dir `/var/lib/m4a` 0700, unit `m4a-core`).
2. Create `/etc/m4a/core.env` (0640 root:m4a) from `core.env.example`. Variables:
   - `M4A_SERVER_NAME`: this instance's identity (the server_name in all its mxids). Never changes after users exist.
   - `M4A_CORE_BIND`: `<core-wg-ip>:8741`, the wg-msg address of the core. Never a wildcard (the server refuses it).
   - `M4A_STATE_DIR`: `/var/lib/m4a`; the DB file is `messenger.db` inside it.
   - `M4A_RETENTION`: `on` (delete delivered ciphertext after all live devices acked) or `off`.
   - `M4A_EVENT_TTL_DAYS`: safety-net TTL for ciphertext/media nobody fetched, default `14`.
   - `M4A_LOCAL_NAMES`: comma list of entry-point hostnames accepted in mxids (`m4a.` / `messenger.` aliases).
   - `M4A_PUBLIC_BASE_URL`: `https://<entry host>`; served at `/.well-known/matrix/client`.
   - `M4A_FEDERATION_DELEGATE`: leave empty (federation is not implemented; empty = 404).
   - `M4A_DB_KEY_HEX`: SQLCipher key, even-length hex.
   - `M4A_EDGE_SECRET`: shared secret with the edge, at least 32 characters.
3. Secrets (fresh core): `deploy/core/install.sh gen-secrets` appends `M4A_DB_KEY_HEX` and `M4A_EDGE_SECRET`
   (each 64 hex chars from `/dev/urandom`) to the env file without printing them. Manual equivalent:
   `head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'`. Back the DB key up off-host: without it the DB is unreadable.
   For a MIGRATION the key comes from the old host, not from `gen-secrets` (see `../MIGRATION.md`).
4. Start: `systemctl start m4a-core`; `journalctl -u m4a-core -n 50`; it must stay up.
5. Smoke from the edge host: `CORE_URL=http://<core-wg-ip>:8741 M4A_EDGE_SECRET=... deploy/core/smoke-core.sh`.
6. Backup: `deploy/core/backup.sh backup` daily, copy off-host; test `rollback` once.
