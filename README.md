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

**Account and session are two different facts, proved two different ways.** A
bearer token names the *account* — every session of a CLI reads the same
config file, so the token alone cannot tell them apart. Each session is its
own OS process, though, so the daemon asks the kernel instead of the caller:
it attests the connection's peer to a `(pid, process start time)` pair and
derives a stable session id from that pair — a hash, never the raw pid, which
the OS reuses the moment a process exits. First contact registers the
session; every later one refreshes it. There is no fallback: if the
connection cannot be attested, the request is refused by name rather than
treated as coming from the bare account.

What the mailbox knows about a session is kept in three groups, by how sure
it can be: **attested** (pid, start time, executable path — from the kernel,
never rewritable by the process itself), **corroborated** (provider session
id, model, working directory — read out of the process's own command line,
real in the sense that the process held it in memory, never proof of what
launched it), and **declared** (what it is working on, its role, which
session spawned it — said by the session about itself, the only group it can
write, through `POST /mail/status` / `m4a_mail_status`).

## Addressing

Three kinds of address, and no others:

- **direct** — one account.
- **session** — exactly one live session of an account, never the account as
  a whole or a sibling session.
- **room** — a named group. Membership is held by the mailbox and granted
  explicitly; it is not derived from anything, and it is always an account's,
  never one specific session's — every session of a member account inherits
  the room.

A message carries a subject, a body, an optional `reply_to` that threads it, an
optional free `correlation` string the mailbox never reads to decide anything,
and up to eight references. A reference is `{ kind, locator, digest }`: the
mailbox stores it and hands it back verbatim, and never resolves one. Only the
application that made a reference knows what it means.

## Doors

The same operations are reachable two ways, dispatching into the same functions:

- HTTP — `POST /mail/send`, `/mail/inbox`, `/mail/ack`, `/mail/get`,
  `/mail/unread`, `/mail/whoami`, `/mail/status`, `/mail/directory`, plus an
  operator-only registry under `/admin/*`. `GET /health` is the only route
  without authentication.
- MCP — `POST /mcp`, JSON-RPC 2.0, single or batch, plain JSON, never SSE.
  Tools: `m4a_mail_send`, `m4a_mail_inbox`, `m4a_mail_ack`, `m4a_mail_get`,
  `m4a_mail_whoami`, `m4a_mail_status`, `m4a_mail_peers`.

`whoami` exists because a session that has not written yet still needs to know
where it can be answered; a send response carries the sender's own address for
the same reason. `whoami` also returns the session's own card — attested,
corroborated and declared kept apart — so a session can see what the mailbox
knows about it. `status` (`m4a_mail_status` over MCP) is the one way a session
writes its own declared group. `directory` (`m4a_mail_peers` over MCP) exists so
a participant can discover who else is in the mailbox instead of only being able
to write to an id it already learned somewhere else — every registered account
with its live sessions nested under it (each with its card and whether it is
currently live), and every room, with room membership reported relative to the
caller. It never returns a secret digest, only an id and a display label.

An address in the wire types is one of three shapes: a direct account, one of
its sessions (`claude/s-7f3a...`), or a room (`#room-1`). `m4a_mail_send`'s `to`
argument over MCP accepts either the tagged JSON object or that compact string
form directly.

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
