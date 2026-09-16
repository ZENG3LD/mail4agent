# mail4agent

A mailbox for agent sessions: a small service that lets independently running
agents address each other, send messages, read their own inbox, reply in a
thread, and acknowledge.

It is a transport layer, not an agent framework. It knows about participants,
addresses and messages. It knows nothing about tasks, schedulers, workspaces or
whatever system issued a participant its identity.

## Why it exists separately

This code began inside [gate4agent](https://github.com/ZENG3LD/gate4agent) as a
mailbox owned by that system's task kernel, and it worked — agents running under
different providers exchanged threaded mail through it. But living inside the
kernel meant it shared the kernel's fate: a size bound on the task graph once
took every mailbox read down with it, and mail that has nothing to do with tasks
should not be able to die that way.

So the mailbox is its own service, with its own store and its own boundary, and
gate4agent becomes one of its clients rather than its owner.

## Identity

A participant does not say who it is. A caller presents a credential that names
it, the mailbox verifies that credential, and the sender of a message is derived
from the verified identity — never from a field the caller filled in. A session
cannot claim to be another session because it is never asked who it is.

The mailbox verifies credentials; it does not issue them. Any system that runs
agents can be an issuer.

## Addressing

Two kinds of address, and no others:

- **direct** — one participant.
- **room** — a named group. Membership is held by the mailbox and granted
  explicitly; it is not derived from anything.

A message carries a subject, a body, an optional `reply_to` that threads it, an
optional free `correlation` string the mailbox never reads to decide anything,
and up to eight references. A reference is `{ kind, locator, digest }`: the
mailbox stores it and hands it back verbatim, and never resolves one. Only the
application that made a reference knows what it means.

## Doors

The same operations are reachable two ways, dispatching into the same functions:

- HTTP — `POST /mail/send`, `/mail/inbox`, `/mail/ack`, `/mail/get`,
  `/mail/unread`, `/mail/whoami`, plus an operator-only registry under
  `/admin/*`. `GET /health` is the only route without authentication.
- MCP — `POST /mcp`, JSON-RPC 2.0, single or batch, plain JSON, never SSE.
  Tools: `m4a_mail_send`, `m4a_mail_inbox`, `m4a_mail_ack`, `m4a_mail_get`,
  `m4a_mail_whoami`.

`whoami` exists because a participant that has not written yet still needs to
know where it can be answered; a send response carries the sender's own address
for the same reason.

A repeated send carrying the same `idempotency_key` returns the original message
and creates nothing. Without a key, sending the same text twice makes two
messages — which is what you asked for.

## Status

Working, unreleased. Send, threaded reply, room delivery, acknowledgement,
unread counts and the refusals have been exercised against a running instance.
Not yet published, and the wire shapes may still move.

## Crates

- `mail4agent-api` — the wire types. Serialisation and nothing else.
- `mail4agent-core` — the engine and its storage trait, with an in-memory store.
- `mail4agent-store-stk` — SQLite persistence.
- `mail4agent-client` — an HTTP client.
- `mail4agent` — the daemon.

## License

MIT. See [LICENSE](LICENSE).
