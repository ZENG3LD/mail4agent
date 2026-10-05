//! Local Grok ACP node client stub: one session per machine, woken on
//! `M4A_LEADER_SOCK`, never by webhook.
//!
//! Open path: [`mail4agent_messenger_shell::OpenedStore::connect_node_from_env`].
//! That refuses `M4A_ROUTINE_URL` / `M4A_ROUTINE_BEARER` before register.
//! This binary additionally requires `M4A_LEADER_SOCK` to be set.
//!
//! Homeserver URL, bot display name, session id, and store root come from
//! the environment (see `docs/local-acp-client.md`). Nothing here embeds a
//! host, URL, key, or bearer.
//!
//! After a successful open it prints the nick and exits. It does not run a
//! push/tick loop yet (no long-running client in this stub).

use mail4agent_messenger_shell::{
    load_env_file, OpenedStore, SessionWake, ShellError, LEADER_SOCK_ENV,
};
use std::path::Path;

fn main() {
    load_env_file();

    // Fail fast on webhook env with the same error the open path uses, and
    // require an ACP leader socket before any homeserver register.
    if let Err(err) = SessionWake::node_cli() {
        fail(&err);
    }
    let sock = std::env::var(LEADER_SOCK_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    let Some(sock) = sock else {
        eprintln!(
            "node client requires {LEADER_SOCK_ENV} (ACP leader.sock); \
             webhook wake is not used on this path"
        );
        std::process::exit(2);
    };
    if !Path::new(&sock).exists() {
        eprintln!(
            "{LEADER_SOCK_ENV} path is set but does not exist yet; \
             start the Grok leader before opening the node client"
        );
        std::process::exit(2);
    }

    let store = match OpenedStore::connect_node_from_env() {
        Ok(store) => store,
        Err(err) => fail(&err),
    };

    let nick = store.nick().unwrap_or("(unknown)");
    println!("node open ok nick={nick}");
    println!("wake=acp sock_set=1");
    println!("stub: no drive/push loop yet; see docs/local-acp-client.md");
}

fn fail(err: &ShellError) -> ! {
    // ShellError never includes bearers, routine URLs, or keys.
    eprintln!("node open failed: {err}");
    std::process::exit(1);
}
