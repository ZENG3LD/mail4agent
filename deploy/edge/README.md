# EDGE deploy (public host: Caddy + m4a-edge)

Prerequisites: Ubuntu 22.04 host, `wg-msg` up and the core reachable, binary `m4a-edge` built per
`../hub/build-jammy.md` (`target/release/m4a-edge`), Caddy installed, DNS grey-cloud records for the entry names
(`../hub/cf-dns.sh plan|apply`, `CF_API_TOKEN` read from the environment only).

## Steps (as root on the edge)
1. Install: `deploy/edge/install.sh /path/to/m4a-edge` (user `m4a-edge`, unit `m4a-edge`, no writable state).
2. Create `/etc/m4a/edge.env` (0640 root:m4a-edge) from `edge.env.example`. Variables:
   - `M4A_CORE_URL`: `http://<core-wg-ip>:8741`, the core over the tunnel.
   - `M4A_EDGE_SECRET`: the SAME value as in the core env file. Generated on the core (see `../core/README.md`); move it host to
     host without printing it, e.g. `ssh core 'grep ^M4A_EDGE_SECRET /etc/m4a/core.env' | ssh edge 'umask 077; cat >> /etc/m4a/edge.env'`.
3. Caddy: take `Caddyfile.tmpl`, replace the placeholder names with the real entry hostnames and the ACME email, install as
   `/etc/caddy/Caddyfile`, `caddy validate --config /etc/caddy/Caddyfile`, `systemctl reload caddy`. For names that are not publicly
   delegated yet use the DNS-01 line (needs a Caddy build with the Cloudflare DNS module and `CF_API_TOKEN` in Caddy's own env file).
4. Start: stop the old single-host m4a unit if migrating (`../MIGRATION.md`), then `systemctl start m4a-edge`.
   Check: `curl -s http://127.0.0.1:18741/edge/healthz` -> `"core":true`.
5. Smoke: `SMOKE_BASE_URL=https://<entry host> deploy/edge/smoke.sh` (add `SMOKE_INSECURE=1` for staging certs).
