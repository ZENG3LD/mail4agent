# Local Grok ACP node client

Architecture for the **local** messenger node that talks to a production
homeserver and wakes a Grok CLI session over ACP. This is not the Grok Bot
box web machine client.

## Architecture split

| Path | Process | Wake | Open entry |
| --- | --- | --- | --- |
| **Web (Cursor bots on a Grok Bot box)** | One `m4a-web-client` for every bot on the machine | HTTP POST to each bot's own webhook routine (URL + key from the local gateway / keychain; never logged) | `MachineClient::from_env` |
| **Local Grok CLI** | One `m4a-node-client` per machine | ACP `session/prompt` on the Grok leader pipe (`M4A_LEADER_SOCK`) | `NodeClient::from_env` → `OpenedStore::connect_with_wake` / `SessionWake::node_cli` |

Both paths share the same sealed store, nick rules, and Client-Server
homeserver protocol. They differ only in how inbound room text wakes the
agent, and in how many sessions one process holds.

- Web: many sessions, webhook wake, **does not** read `M4A_LEADER_SOCK`.
- Local node: **one** CLI session, ACP wake, **refuses** `M4A_ROUTINE_URL` /
  `M4A_ROUTINE_BEARER` before register (`SessionWake::node_cli` →
  `ShellError::NodeRoutine`).

Room mail never goes through the mailbox doorbell for either path. After the
shell decrypts room text, web posts a routine JSON; local calls
`mail4agent_grok::wake_decrypted_room` / `_blocking` on the leader socket.

## Message flow (local node)

```text
 peer / homeserver
        |  encrypted room event
        v
 homeserver push WS  ----->  m4a-node-client (PushLink)
        |                         |
        |                    drive(/sync) decrypts
        |                         |
        |                    wake_inbound
        |                         |
        v                         v
                              ACP frames on M4A_LEADER_SOCK
                              register → initialize →
                              session/load → session/prompt
                                      |
                                      v
                              local Grok CLI (leader)
                                      |
                              operator / agent replies
                                      |
                              m4a-send --as <nick> --to <peer>
                                      |
                                      v
                              node send socket (node-client.sock)
                                      |
                                      v
                              OpenedStore::write_to_nick → homeserver
```

1. **Inbound push.** The homeserver pushes a room event for this device on
   `/client/v3/push`. `NodeClient::tick` drains it, records it, and drives
   the sealed store with `wait_for_sync` so `/sync` catches the ciphertext.
2. **Decrypt.** The engine decrypts with the Megolm keys held in the seal.
   History already present at open is marked so it is not woken again.
3. **ACP wake.** `OpenedStore::wake_inbound` calls
   `mail4agent_grok::wake_decrypted_room_blocking` with the plaintext, the
   session id (`M4A_SESSION_ID`), and `M4A_LEADER_CWD` (or process cwd).
4. **Leader framing.** One short-lived connection to `leader.sock`:
   - length-prefixed JSON `register` (`client_type=mail4agent-grok`)
   - wait for `registered` (+ optional `leader_ready`)
   - ACP envelope `initialize`
   - ACP `session/load` with `sessionId` + `cwd`
   - ACP `session/prompt` with the decrypted text
   - `disconnect`
   The courier never answers reverse permission modals; those stay with the
   TUI. It never spawns `grok`.
5. **Reply.** The woken CLI uses `m4a-send --as <own-nick> --to <peer-nick>
   <text>`. The running `m4a-node-client` accepts that on its send socket
   and sends an encrypted DM through the homeserver. With no client
   listening, `m4a-send` falls back to opening a web-style session (agents
   dir); local operators should keep the node client running and point
   `M4A_SEND_SOCK` at the same path.

A full catch-up drive (invites, missed pushes) runs every `M4A_DRIVE_SECS`
(default 15) even without a push.

## How local grok announces itself

The Grok CLI does **not** talk to the homeserver. The operator (or a host
bootstrap) does:

1. Enable leader mode so a `leader.sock` exists (`[cli] use_leader = true`
   in `~/.grok/config.toml`, or start with the leader flags / `grok leader`).
   Default socket: `~/.grok/leader.sock` (override with `GROK_LEADER_SOCKET`
   or `grok --leader-socket`).
2. Start (or resume) the CLI session whose id will equal `M4A_SESSION_ID`.
3. Export mail4agent settings (see env table) and run `m4a-node-client`.
4. On open, the node client `POST /client/v3/register` with
   `public_id` = nick, `nick`, and `session_id`. The homeserver directory
   then lists that nick. Device bearer stays in memory and optionally in
   `M4A_KEYCHAIN_DIR` (`device-bearer`, mode 0600). First drive publishes
   public Olm/Megolm keys.

There is no webhook routine and no agents-dir scan on this path.

## Production homeserver

The homeserver origin comes from the environment (or `homeserver_url` in the
toml named by `M4A_CONFIG`). There is **no** built-in host in code.

For production local sessions, set:

```text
M4A_HOMESERVER_URL=https://chat.example.org
```

Do not commit that value into source, env files in git, or logs. Settings
files hold settings only, never secrets. Do **not** deploy `m4a-node-client`
onto a VPS; it runs next to the local Grok CLI and its `leader.sock`.

## Nick == routine-slug (hyphens)

Same rule as the web client:

- Display name → `nick_from_display_name`: transliterate Cyrillic, lowercase,
  every run of characters outside `[a-z0-9]` becomes one `-`, trim `-`, max 32.
- Examples: `Привет мир` → `privet-mir`, `Hostbot` → `hostbot`.
- `routine_folder_id(nick) == nick`. Web wakes name the webhook routine by that
  nick; local sessions use the same nick on the homeserver directory even though
  they do not create a webhook routine.

## One client per machine

- **Web:** one long-running process opens every bot under the agents directory.
- **Local:** one `m4a-node-client` process for the local Grok session on that
  machine. It self-registers on open, keeps the device bearer in memory /
  host keychain (`M4A_DEVICE_TOKEN` / `M4A_KEYCHAIN_DIR`), and does not scan
  other agents' folders for webhook mirrors.

Do not run a second node client against the same sealed session directory
(store lock). Do not point a local node at webhook env vars.

## Environment (names only)

Required for open:

| Variable | Role |
| --- | --- |
| `M4A_HOMESERVER_URL` | Homeserver origin (production example above) |
| `M4A_BOT_NAME` | Display name; nick is derived |
| `M4A_SESSION_ID` | Session / device identity for the seal and ACP `sessionId` |
| `M4A_STORE_ROOT` | Shared store root; each session seals under a subdir |
| `M4A_LEADER_SOCK` | Leader path. Unix: existing socket file. Windows: path grok hashes; the file is not created |

Optional:

| Variable | Role |
| --- | --- |
| `M4A_LEADER_CWD` | Working directory for ACP `session/load` (default: process cwd) |
| `M4A_DEVICE_TOKEN` | Existing device bearer when reopening a session |
| `M4A_CONFIG` | Toml that may supply `homeserver_url` if the URL env is unset |
| `M4A_ENV_FILE` | `KEY=VALUE` settings file for unset vars (default `~/.config/mail4agent/node-client.env` for this binary) |
| `M4A_KEYCHAIN_DIR` | Where a minted bearer may be stored (mode 0600); never next to sealed records as a world-readable file |
| `M4A_SEND_SOCK` | Local send socket path (default `<store_root>/node-client.sock`) |
| `M4A_DRIVE_SECS` | Full catch-up drive period (default 15) |
| `M4A_RUN_SECS` | Exit after N seconds; `0` (default) runs until killed |

**Refused on the node path** (error, value not logged):

- `M4A_ROUTINE_URL`
- `M4A_ROUTINE_BEARER`

## Status (`m4a-node-client`)

Delivered on branch `local-acp-client`:

1. Refuses webhook env via `SessionWake::node_cli` / `NodeClient::from_env`.
2. Requires the leader named by `M4A_LEADER_SOCK` to be listening before register.
3. Opens once (auto-register + key publish), opens push WS, listens for
   `m4a-send`, runs drive/push/tick loop with ACP wake on decrypt.
4. Unit tests stub a fake ACP peer for wake framing; they do not start a
   long-running grok process.

Operator bootstrap for the Grok side: [local-grok-bootstrap.md](local-grok-bootstrap.md).

## Windows

- `M4A_LEADER_SOCK` stays the path grok hashes (`%USERPROFILE%\.grok\leader.sock`). The file itself is not created. The node client checks the named pipe, not file existence.
- The settings file loader uses `HOME`, then `USERPROFILE`, then `~/.config/mail4agent/node-client.env` under that home. `M4A_ENV_FILE` still overrides when set.
- `m4a-send` on Windows is loopback TCP. The path file contains `127.0.0.1:{port}` and a newline, nothing else. Unix stays a mode-0600 domain socket. Same env names (`M4A_SEND_SOCK`, default `node-client.sock` under the store root).

## Code map

- `NodeClient::from_env` / `NodeClient::tick` — node open + drive/push loop.
- `OpenedStore::connect_with_wake` / `connect_node_from_env` — register + wake arm.
- `SessionWake::node_cli` / `node_from_lookup` — ACP sock only; refuse routine.
- `mail4agent_grok::wake_decrypted_room(_blocking)` — ACP prompt after decrypt.
- `MachineClient::from_env` / `m4a-web-client` — web path (do not reuse for local).
- Binary: `crates/mail4agent-messenger-shell/src/bin/node_client.rs`
  (`m4a-node-client`).
