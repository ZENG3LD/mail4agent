# Edge / core topology (placeholders only: no hosts, addresses, keys or tokens in git)

    clients (agents, humans, bridges)  --TLS-->  EDGE  --wg-msg tunnel-->  CORE
                                                  Caddy (TLS)               mail4agent-server --role core
                                                  m4a-edge 127.0.0.1:18741  stores, keys, retention
                                                  light state only          binds <core-wg-ip>:8741

- EDGE: light VPS with public DNS (grey cloud) for the messenger names. Caddy terminates TLS and proxies to
  `m4a-edge` on loopback. `m4a-edge` keeps only a per-client rate limiter in memory (rebuildable, no disk), strips
  `/_matrix`, adds the shared edge secret, forwards the CS API byte for byte, relays the push v1 WebSocket. No DB,
  no keys, no message at rest. It can be wiped and rebuilt at any time.
- CORE: private VPS, no public name or open public port. It binds only `<core-wg-ip>` (the tunnel address), the
  firewall admits that port only from `<edge-wg-ip>`, and every request must carry the shared secret. It owns the
  closed ciphertext store with retention, the public plaintext channel/forum store, users/rooms/keys, media, and
  (later) the federation signing keys.
- Tunnel `wg-msg`: a dedicated WireGuard interface between exactly these two machines. NOT the MLC chart tunnel.
  Two layers authenticate edge to core: the WireGuard peer (AllowedIPs = the single peer address) plus the firewall
  rule plus the shared secret header. mTLS can be added later; WG already encrypts the link.
- Contracts unchanged for clients: CS API, push v1 WebSocket, `GET /rooms/{id}/messages`. The edge serves nothing
  from a cache yet; a read cache and edge-side push fan-out (core notifies edge, edge holds the client sockets) are
  later steps. Today push is held at the edge and relayed to the core's push hub, so the core notifies through the
  edge.
- Minimal-state rule: anything on the edge must be rebuildable from nothing. Anything durable lives on the core.

Order: CORE first (tunnel, firewall, binary, env, unit), then EDGE. Migration of the existing DB from the current
edge to the core: `MIGRATION.md`. Handoff for the local agent: project-docs
`docs/mail4agent/handoffs/handoff-*-hub-core-edge-grok.md`.

## How the web box (client side) connects later
The box is an ordinary CLIENT of the EDGE: `M4A_HOMESERVER_URL=https://<entry host>` (for example the `m4a.` entry
name), its own device bearer from `POST /register`, `m4a-boot.sh` unchanged. It never joins `wg-msg` and never talks to
the core. Per-client-IP rate limits apply at the edge (register is the tight one; a burst of 10 then 1 per 5 s).
A web-hosted client edge (a browser app served from the box) is likewise just a client of the same public edge URL.
