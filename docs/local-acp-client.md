# Local Grok ACP node client

Plan and architecture for the **local** messenger node that talks to a
production homeserver and wakes a Grok CLI session over ACP. This is not the
Grok Bot box web machine client.

## Architecture split

| Path | Process | Wake | Open entry |
| --- | --- | --- | --- |
| **Web (Cursor bots on a Grok Bot box)** | One `m4a-web-client` for every bot on the machine | HTTP POST to each bot's own webhook routine (URL + key from the local gateway / keychain; never logged) | `MachineClient::from_env` |
| **Local Grok CLI** | One `m4a-node-client` per machine | ACP `session/prompt` on the Grok leader pipe (`M4A_LEADER_SOCK`) | `OpenedStore::connect_node_from_env` |

Both paths share the same sealed store, nick rules, and Client-Server homeserver
protocol. They differ only in how inbound room text wakes the agent, and in how
many sessions one process holds.

- Web: many sessions, webhook wake, **does not** read `M4A_LEADER_SOCK`.
- Local node: **one** CLI session, ACP wake, **refuses** `M4A_ROUTINE_URL` /
  `M4A_ROUTINE_BEARER` before register (`SessionWake::node_cli` →
  `ShellError::NodeRoutine`).

Room mail never goes through the mailbox doorbell for either path. After the
shell decrypts room text, web posts a routine JSON; local calls
`mail4agent_grok::wake_decrypted_room` / `_blocking` on the leader socket.

## Production homeserver

The homeserver origin comes from the environment (or `homeserver_url` in the
toml named by `M4A_CONFIG`). There is **no** built-in host in code.

For production local sessions, set:

```text
M4A_HOMESERVER_URL=https://chat.example.org
```

Do not commit that value into source, env files in git, or logs. Settings files
hold settings only, never secrets.

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
  machine. It self-registers on open (`OpenedStore::connect_node_from_env` →
  register + first key publish drive), keeps the device bearer in memory /
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
| `M4A_SESSION_ID` | Session / device identity for the seal |
| `M4A_STORE_ROOT` | Shared store root; each session seals under a subdir |
| `M4A_LEADER_SOCK` | Path to an already-running Grok `leader.sock` |

Optional:

| Variable | Role |
| --- | --- |
| `M4A_LEADER_CWD` | Working directory for ACP `session/load` (default: process cwd) |
| `M4A_DEVICE_TOKEN` | Existing device bearer when reopening a session |
| `M4A_CONFIG` | Toml that may supply `homeserver_url` if the URL env is unset |
| `M4A_ENV_FILE` | `KEY=VALUE` settings file for unset vars (default path documented by the binary; settings only) |
| `M4A_KEYCHAIN_DIR` | Where a minted bearer may be stored (mode 0600); never next to sealed records as a world-readable file |

**Refused on the node path** (error, value not logged):

- `M4A_ROUTINE_URL`
- `M4A_ROUTINE_BEARER`

## Stub status (`m4a-node-client`)

Delivered on branch `local-acp-client`:

1. Refuses webhook env via `SessionWake::node_cli` / `OpenedStore::connect_node_from_env`.
2. Requires `M4A_LEADER_SOCK` to be set (and preferably an existing path).
3. Opens once (auto-register + key publish), prints the nick, exits.
4. Does **not** yet run a push/tick loop, full ACP session lifecycle, or
   long-running drive. That is intentional: no long-running local client until
   the ACP wake path is finished and tested.

## Next steps for local sessions

1. Finish ACP framing already in `mail4agent-grok` (leader pipe register /
   `session/prompt`) against a real local `leader.sock` without starting
   long-running grok from this repo's automation.
2. Add a short drive / push loop to `m4a-node-client` (mirror web `tick`, but
   wake only via leader sock; no webhook mirrors, no agents-dir scan).
3. Optional: local send helper reuse (`m4a-send` or a node-scoped socket) so a
   woken CLI can reply without opening a second store.
4. Document operator bootstrap: create the Grok CLI session with `[cli]
   use_leader`, note `M4A_LEADER_SOCK`, inject homeserver URL + session id from
   the host keychain — still no secrets in git.
5. Keep web docs in the root README in sync when webhook behaviour changes;
   move them under `docs/` when convenient.

## Code map

- `OpenedStore::connect_node_from_env` — node open + register.
- `SessionWake::node_cli` / `node_from_lookup` — ACP sock only; refuse routine.
- `mail4agent_grok::wake_decrypted_room(_blocking)` — ACP prompt after decrypt.
- `MachineClient::from_env` / `m4a-web-client` — web path (do not reuse for local).
- Binary stub: `crates/mail4agent-messenger-shell/src/bin/node_client.rs`
  (`m4a-node-client`).
