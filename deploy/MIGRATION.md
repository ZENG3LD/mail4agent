# Migrating the existing DB from the current edge host to the core

Today the `m4a` process and its SQLCipher DB run on the EDGE host. Target: the DB lives only on the CORE and the edge
runs `m4a-edge`. Key rule: the DB key (`M4A_DB_KEY_HEX`) is handled by the owner/local agent only. It never enters git,
chat, logs or command lines; it is moved host to host through a pipe that nobody prints.

## 0. Before the window (no downtime)
1. CORE: tunnel up, firewall rule for `<edge-wg-ip>`, binary installed (`deploy/core/install.sh`), env file WITHOUT starting
   the service yet. Verify `ping <core-wg-ip>` from the edge and that the core port is closed from anywhere else.
2. Build artifacts: core binary (`mail4agent-server-bin`) and `m4a-edge`, both jammy-built (see `deploy/hub/build-jammy.md`).
3. Rehearsal (optional, recommended): online copy of the DB (`sqlite3`/`sqlcipher` `.backup` with the key read from the env file
   inside the same shell, never echoed) to the core staging dir, start the core on a scratch port, check it opens. Delete the
   rehearsal copy afterwards.
4. Announce the window. Expected downtime = stop old process -> final copy -> core up -> edge up = copy time + about 2 minutes.
   Clients reconnect on their own (push v1 sockets drop and re-register).

## 1. Window
1. EDGE: record the old unit name, binary path, DB path (they stay untouched as the rollback). `systemctl stop <old m4a unit>`.
2. EDGE: consistent copy. Stopped process => the DB files are quiescent. Copy the DB file and its `-wal`/`-shm` if present into one
   tar, compute sha256, send over the tunnel to `<core-wg-ip>` (scp/rsync to the core's incoming dir; write to a temp name, then rename).
3. CORE: verify sha256, extract to the state dir, `chown`/mode as the unit expects (0600, owner `m4a`).
4. KEY: owner/local agent copies the key line host to host without showing it, for example:
   `ssh edge 'grep ^M4A_DB_KEY_HEX /path/to/old.env' | ssh core 'umask 077; cat >> /etc/m4a/core.env'`
   (check the file has exactly one key line afterwards, count lines, do not print them). `M4A_EDGE_SECRET` is NEW and generated on
   the core, then the same value is placed in the edge env by the same pipe technique.
5. CORE: start `m4a-core`. Success = the process stays up (it opens the DB with the key and runs boot migrations) and
   `curl -H "x-m4a-edge-secret: <from env>" http://<core-wg-ip>:8741/client/versions` -> 200 from the edge host.
6. EDGE: install `m4a-edge` (listens on the same `127.0.0.1:18741` the old process used, so Caddy needs no change), start it.
   `curl https://<entry host>/_matrix/client/versions` -> 200 and `.../edge/healthz` -> core true (the latter is not exposed by Caddy on purpose; test on loopback).
7. Verify with a real device: an existing client bearer does `sync` 200, a message from the hostbot client reaches a peer, push v1 reconnects.

## 2. Rollback
- Trigger: step 5, 6 or 7 fails and cannot be fixed in the window.
- Action: `systemctl stop m4a-edge`; `systemctl start <old m4a unit>` on the edge (its DB and binary were never modified). Stop the core.
- Data: if clients already wrote through the core, those writes exist only in the core DB. To keep them, copy the core DB back
  (reverse of step 2-3, same key) BEFORE starting the old unit; otherwise accept loss of the writes since the cutover.
- Keep the old binary and old DB on the edge for at least 7 days after a good cutover.

## 3. After
- After the rollback window, remove the old DB from the edge (minimal-state rule: no conversation data on the edge, not even encrypted), verify no DB file is left,
  and make sure the edge env holds only the edge secret and core URL.
- `deploy/core/backup.sh` daily on the core, shipped off-host; restore drill once.
- The old public name set and Caddy stay as they are; only the upstream process changed.
