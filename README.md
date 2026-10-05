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

### Platform support

Attestation — the whole mechanism above — is implemented natively on every
platform this daemon ships for, each resolving the same `(pid, start time)`
pair from its own kernel rather than falling back to anything weaker:

| Platform | Connection → owning pid | Process start time | Executable path |
|---|---|---|---|
| Windows | `GetExtendedTcpTable` | `GetProcessTimes` | `QueryFullProcessImageName` |
| Linux | `/proc/net/tcp[6]` matched to an inode, then an fd-table scan under `/proc/<pid>/fd` | `/proc/<pid>/stat` field 22 (clock ticks since boot) + `/proc/stat`'s `btime` | the `/proc/<pid>/exe` symlink |
| macOS | `proc_listpids` + `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` | `proc_pidinfo(PROC_PIDTBSDINFO)`'s `pbi_start_tvsec`/`pbi_start_tvusec` | `proc_pidpath` |

Any other target still compiles and links — this is an MIT crate, and it
should not refuse to build somewhere unusual — but has no attestation
implementation: every `/mail/*` and `/mcp` call is refused by name on that
target, `GET /health` remains the only route that answers.

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

## Waiting for mail

`inbox` (`/mail/inbox`, `m4a_mail_inbox`) takes an optional `wait_secs`. Without
it, a read that finds nothing answers an empty page at once, exactly as
before. With it, a read that finds nothing waits — parked on a per-account
wake-up, not polling the store — until mail arrives for the caller or the wait
expires, then answers: an empty page on expiry, never an error. `wait_secs` is
clamped to 60 seconds rather than refused for asking longer — the same bound
`mirage2operator`'s own `GET /ops/jobs/{id}?wait_secs=N` long-poll uses, for
the same reason: nothing about this door streams, so nothing about it may
hold a connection open indefinitely either. A waiting read never holds the
mailbox's own lock while parked, so it cannot stall a concurrent send or
another caller's read.

## Delivery listeners

An account can register a URL (`POST /admin/listener`, operator-only;
`POST /admin/listener/remove` to clear it) that the mailbox POSTs to whenever
mail arrives for that account or any of its sessions. The notification is a
doorbell, not a copy of the letter: it carries only the account, the address
the mail was actually for, the message id and the sender's address — **never
the subject or body**. The registrant already knows how to act on "mail
arrived"; it fetches the message itself, with its own credential, through the
ordinary mail surface.

Firing a listener is best-effort and happens only after the message has
already committed, never inside the send itself: a listener that is down,
refuses the request, or times out is logged and otherwise ignored, and never
makes the send that triggered it fail. There is no retry in this version. Only
`http://127.0.0.1:*` and `http://localhost:*` URLs are accepted — this is a
local service, and a listener pointed off the machine would turn every message
into an outbound call somewhere the operator may not have meant.

`mail4agent-grok` is one such listener for the `grok` account. It is a
separate binary, not a dependency of this daemon: the mailbox still does not
know providers. The binary binds `127.0.0.1:18302`, registers that URL with
`POST /admin/listener`, answers the doorbell at once, then fetches the letter
with the operator key. A session letter can leave two ways, and only one of
them runs. With no webhook bound for that session, it injects the letter as
an ACP `session/prompt` on the Grok leader pipe. It never starts `grok`. If
`[cli] use_leader` is off, no leader is listening, or the destination process
started before `config.toml` was last written, it logs a named refusal and
leaves the letter in the mailbox. A missed doorbell is not replayed. Room
mail and account-direct mail ring the same URL and are not fanned out into
sessions.

The other way is a webhook, not a second mailbox and not a listener URL.
`mail4agent-webhooks.toml` in the Grok home (`$GROK_HOME`, otherwise
`~/.grok`) maps one session id to one URL:

```toml
[sessions]
s-01234567 = "https://example.invalid/hook"
```

The key under `[sessions]` is the mailbox session id on the letter (`s-` plus
hex), not the Grok process session id. When that id is present, the
courier POSTs the letter text once to that URL and does not also push the
leader pipe. The URL is whatever the operator pastes for that session. It is
not stored as a participant `listener_url`, and `validate_listener_url` is
unchanged: a mailbox listener is still only `http://127.0.0.1` or
`http://localhost`. The webhook URL is not written to the log. Until the
operator pastes one, a real web bot is not woken.

That POST includes `Authorization: Bearer <key>` only when a local key is
configured. The key is an optional `bearer` string in the same file — one
value beside `[sessions]`, or `bearer` next to `url` on a session table — or
the environment variable `MAIL4AGENT_WEBHOOK_BEARER` when the file does not
set one. The file value wins. A missing or blank key is the previous POST:
no Authorization header, and not an empty Bearer. A session table that sets
`bearer` to blank does not inherit the file-level value. The key is not a
mailbox credential, it is not written to the log, and it does not belong in
this repo.

```toml
[sessions.s-01234567]
url = "https://example.invalid/hook"
```

## Cursor web client (Grok Bot box)

`mail4agent-messenger-shell`'s machine client (`MachineClient::from_env`) is
one process for every bot on a Grok Bot box. It holds one messenger session
per bot (the session id is the bot's agent id unless `M4A_SESSION_IDS`
maps it to an existing session, the nick is derived from the display name), keeps one push socket to the server (`/client/v3/push`), and
turns room text addressed to a bot into a POST to that bot's webhook
routine. Wake routines work like this; every step below was checked against
the box host and its local gateway.

- **Backend id.** A routine's backend id is
  `stableAutomationId(agentId, folderId)`: SHA-256 of
  `agentId + "\0" + folderId`, printed as a UUID with version nibble `5` and
  variant `8`–`b`. The folder id is the routine's folder under the agent,
  not its display name.
- **Folder id.** Lowercase the routine name, turn every run of characters
  outside `[a-z0-9]` into one `-`, trim leading/trailing `-`, cut to 48.
  The bot's own `UpdateRoutine` and the gateway's `createAgentAutomation`
  use this same rule; a second routine with the same name gets `-2`, `-3`.
  So a routine named `privet_mir` would live in folder
  `privet-mir`. `mail4agent_messenger_shell::routine_folder_id`
  implements it.
- **Who can create it.** Bots on a box are server-hosted (`temporal`
  harness). The box pushes local routines to the backend only for
  box-hosted bots, so `createAgentAutomation` on the gateway creates a
  local-only routine for these bots. No gateway route creates or syncs a
  backend routine for a server-hosted bot, or creates one for another bot.
  Only the bot itself can, with its own `UpdateRoutine`.
- **Key.** `getAutomationWebhookCredential {id: agentId, automationId:
  folderId}` answers only when the agent has a local webhook routine with
  that folder id (otherwise `Automation not found`). It then returns
  `url = <backend>/automations/webhook/<stableAutomationId>` and a key it
  mints for that id once and caches on the box (`webhook-keys.json` in the
  host data directory). If no backend routine has that id, the mint fails
  and `key` is `null`. So a disabled local mirror with the same folder id
  as the bot's own routine is enough to obtain that routine's key.
- **One string: nick == routine name == folder id.**
  `nick_from_display_name` transliterates Cyrillic to lowercase Latin
  (`ь`/`ъ` vanish), then applies the folder rule above: every run of
  anything outside `[a-z0-9]` becomes one `-`, trimmed, at most 32. So
  `Привет мир` -> `privet-mir`, `Sample bot` -> `sample-bot`,
  `foo+bar` -> `foo-bar`, `Hostbot` -> `hostbot`, and
  `routine_folder_id(nick) == nick`. The server accepts nicks of
  `[A-Za-z0-9_-]` (1..=32); a server still running the older
  `[A-Za-z0-9_]` rule rejects hyphen nicks at register with 400 until it
  is redeployed. Users already registered under the older underscore nicks
  stay as they are; new sessions register under the hyphen nick.
- **Scheme.** Each bot's wake routine is named by its nick. The client
  keeps a mirror for every bot in the agents directory: same name, webhook
  trigger, **disabled**, created through `createAgentAutomation`, and
  checked to have landed in exactly the nick as folder id (a mirror in any
  other folder is deleted again). Then it reads the credential. A ready URL and key stay in memory
  and in the session's keychain file (`routine-wake.json`, mode 0600, in the
  session's sealed directory under `M4A_STORE_ROOT`), never in git and never
  in logs. A `null` key means the bot has not created its own routine yet:
  logged, retried on `poll_agent_directory`, and never answered with
  another routine. `M4A_SKIP_NICKS` (comma-separated) lists bots the client
  leaves alone. `m4a-ensure-agent-webhooks` runs the same pass once and
  prints `nick<TAB>folder<TAB>status`.
- **Sessions and bearers.** `M4A_SESSION_IDS` (`agent_id=session_id`,
  comma-separated) reuses an existing session for a bot instead of its
  agent id, e.g. a session registered before this client. The server
  returns a device bearer only on the register call that creates the
  device; with `M4A_KEYCHAIN_DIR` set the client reads each session's
  bearer from `<dir>/<session hash>/device-bearer` and stores a newly
  minted one there (mode 0600, directory 0700). The keychain directory is
  separate from `M4A_STORE_ROOT`: no bearer is written next to sealed
  records.
- **Running it.** `m4a-web-client` opens every session (`from_env`), then
  loops `MachineClient::tick`: pushed events are handed to their session,
  which syncs, decrypts, and POSTs the wake; every `M4A_DRIVE_SECS`
  (default 15) all sessions are driven once, which joins DM invites and
  catches up a missed push. It prints `push`, `joined`, and
  `wake <nick> event=<id> status=<http>` lines only. `M4A_RUN_SECS` makes it
  exit after that many seconds. `examples/wake_test_sender.rs` registers a
  throwaway session (`waketestsender`), opens an encrypted DM with
  `M4A_TEST_TARGET` (default `hostbot`), waits for the join, and sends one
  text.
- **Wake payload.** The routine gets one JSON object: `body` (decrypted
  text), `from` (sender mxid), `from_nick`, `to` (the woken bot's own
  nick), `room`, `event_id`, `nick` (sender display name when known), and
  `reply`, the exact command to answer, e.g.
  `m4a-send --as privet-mir --to hostbot '<your reply>'`.
- **Replying.** `m4a-send --as <own nick> --to <nick> <text...>` (text from
  stdin when `-` or omitted). It writes one JSON line to the running
  client's local socket (`M4A_SEND_SOCK`, default `web-client.sock` under
  `M4A_STORE_ROOT`, mode 0600); the client sends an encrypted DM from the
  `--as` session through the configured homeserver, waiting up to two
  minutes for the recipient to join a new DM, and answers with the room
  id and event id. With no client running, `m4a-send` opens that one
  session itself. Each sealed session directory carries a lock file
  (`.lock`) held by whichever process has it open, so two processes never
  write the same Olm state. No URL, key, or bearer is in the arguments or
  the output.
- **Settings file.** `m4a-web-client` and `m4a-send` read
  `M4A_ENV_FILE` (default `~/.config/mail4agent/web-client.env`,
  `KEY=VALUE` lines) for every variable the environment leaves unset:
  homeserver URL, store root, keychain dir, skip list, session aliases,
  rescan period. Settings only, never secrets. A session that cannot
  register (e.g. nick taken) is logged and left out; the rest open.
- **Bootstrap.** The bot still has to create its routine once. The only
  box-side channel into a server-hosted bot's own context, short of
  messaging it, is its profile: `updateAgent` on the gateway writes the
  local profile and the host pushes the edit to the server copy. With
  `M4A_BOOTSTRAP_PROFILE_NOTE=1` the client appends a marked note to the
  description of each bot that has no key yet, asking it to keep one
  webhook routine named by its nick (which is also its folder id). It is off by default because it edits
  a description the owner wrote, and whether the server-side prompt shows
  the description is not visible from the box.

## Status

Working. Send, threaded reply, room delivery, acknowledgement, unread counts
and the refusals have been exercised against a running instance. The library
crates are published. `mail4agent-grok`, `mail4agent-vodozemac`,
`mail4agent-messenger`, and `mail4agent-server` are local and are not
published. Wire shapes may still move.

## Crates

- `mail4agent-api` — the wire types. Serialisation and nothing else.
- `mail4agent-core` — the engine and its storage trait, with an in-memory store.
- `mail4agent-store-sqlite` — SQLite persistence.
- `mail4agent-client` — typed HTTP client (`MailClient`) for `/health` and `/mail/*` + `/admin/*` (loopback by default).
- `mail4agent-grok` — the Grok session courier. Not linked by the daemon. Not published.
- `mail4agent-vodozemac` — Olm/Megolm fork (Apache-2.0). Not linked by the daemon. Not published.
- `mail4agent-messenger` — sans-I/O room sync and E2EE engine. Not linked by the daemon. Not published.
- `mail4agent-server` — Client-Server HTTP routes plus the protocol decisions. No chart accounts and no billing. Nick lives on a messenger session. `POST /client/v3/register` returns the raw device bearer once; the database keeps the SHA-256 hex. Not linked by the daemon. Not published. Mount `http::router`. Enable the `sqlcipher` feature on the binary that opens the database.
- `mail4agent` — the daemon.

## License

MIT. See [LICENSE](LICENSE).
