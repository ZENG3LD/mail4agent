//! The client's commands. They used to be eight binaries; they are subcommands of ONE binary,
//! `m4a-agent <command> ...`, and the old binary names remain as thin wrappers over the same
//! `run` functions for one transition release (service units keep working; update them to
//! `m4a-agent <command>` at leisure).
//!
//! | `m4a-agent`            | old binary                 |
//! | ---------------------- | -------------------------- |
//! | `web-client`           | `m4a-web-client`           |
//! | `grok-listen`          | `m4a-grok-listen`          |
//! | `inbox`                | `m4a-inbox`                |
//! | `send`                 | `m4a-send`                 |
//! | `mail`                 | `m4a`                      |
//! | `ensure-agent-webhooks`| `m4a-ensure-agent-webhooks`|
//! | `enroll`               | —                          |
//! | `wake`                 | — (owner control of wakes) |
//! | `vault`                | — (status, backup, restore)|
//! | `element-open`         | — (open Element, logged in)|
//! | `door-listen`          | — (wake on hatchery node mail)|

pub mod enroll;
pub mod session_arg;
pub mod vault;
pub mod wake;
#[cfg(feature = "element-open")]
pub mod element_open;
pub mod ensure_agent_webhooks;
pub mod grok_listen;
pub mod inbox;
pub mod mail;
pub mod send;
pub mod web_client;
pub mod door_listen;
pub mod launch;
pub mod account;
mod letter;

/// The subcommand names, in the order of the table above.
pub const COMMANDS: &[&str] = &["web-client", "grok-listen", "inbox", "send", "mail", "ensure-agent-webhooks", "enroll", "wake", "vault", "element-open", "door-listen", "launch", "account", "letter"];

/// Runs `command` with its arguments. `Err` names an unknown command (or one this build lacks).
pub fn dispatch(command: &str, args: Vec<String>) -> Result<(), String> {
    match command {
        "web-client" => web_client::run(args),
        "grok-listen" => grok_listen::run(args),
        "node-client" | "claude-channel" => {
            return Err(format!("{command} moved out of m4a: session delivery is g4a's (hatchery node / gate4agent-wake)"))
        }
        "inbox" => inbox::run(args),
        "send" => send::run(args),
        "mail" => mail::run(args),
        "ensure-agent-webhooks" => ensure_agent_webhooks::run(args),
        "enroll" => enroll::run(args),
        "wake" => wake::run(args),
        "vault" => vault::run(args),
        "door-listen" => door_listen::run(args),
        "launch" => launch::run(args),
        "account" => account::run(args),
        "letter" => letter::run(args),
        #[cfg(feature = "element-open")]
        "element-open" => element_open::run(args),
        #[cfg(not(feature = "element-open"))]
        "element-open" => return Err("this build was made without feature element-open".to_string()),
        other => return Err(format!("unknown command {other:?}; commands: {}", COMMANDS.join(", "))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_command_is_named_not_run() {
        let e = dispatch("nope", vec![]).unwrap_err();
        assert!(e.contains("nope") && e.contains("web-client") && e.contains("mail"));
    }

    #[test]
    fn enroll_is_a_command() {
        assert!(COMMANDS.contains(&"enroll"));
    }
}
