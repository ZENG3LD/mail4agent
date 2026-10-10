//! The client's commands. They used to be eight binaries; they are subcommands of ONE binary,
//! `m4a-agent <command> ...`, and the old binary names remain as thin wrappers over the same
//! `run` functions for one transition release (service units keep working; update them to
//! `m4a-agent <command>` at leisure).
//!
//! | `m4a-agent`            | old binary                 |
//! | ---------------------- | -------------------------- |
//! | `web-client`           | `m4a-web-client`           |
//! | `node-client`          | `m4a-node-client`          |
//! | `grok-listen`          | `m4a-grok-listen`          |
//! | `claude-channel`       | `m4a-claude-channel`       |
//! | `inbox`                | `m4a-inbox`                |
//! | `send`                 | `m4a-send`                 |
//! | `mail`                 | `m4a`                      |
//! | `ensure-agent-webhooks`| `m4a-ensure-agent-webhooks`|

#[cfg(feature = "wake-claude")]
pub mod claude_channel;
pub mod ensure_agent_webhooks;
pub mod grok_listen;
pub mod inbox;
pub mod mail;
pub mod node_client;
pub mod send;
pub mod web_client;

/// The subcommand names, in the order of the table above.
pub const COMMANDS: &[&str] = &["web-client", "node-client", "grok-listen", "claude-channel", "inbox", "send", "mail", "ensure-agent-webhooks"];

/// Runs `command` with its arguments. `Err` names an unknown command (or one this build lacks).
pub fn dispatch(command: &str, args: Vec<String>) -> Result<(), String> {
    match command {
        "web-client" => web_client::run(args),
        "node-client" => node_client::run(args),
        "grok-listen" => grok_listen::run(args),
        #[cfg(feature = "wake-claude")]
        "claude-channel" => claude_channel::run(args),
        "inbox" => inbox::run(args),
        "send" => send::run(args),
        "mail" => mail::run(args),
        "ensure-agent-webhooks" => ensure_agent_webhooks::run(args),
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
}
