//! Thin wrapper kept for one transition release: this is `m4a-agent ensure-agent-webhooks`.
//! The code lives in `mail4agent_messenger_shell::cli::ensure_agent_webhooks`.

fn main() {
    mail4agent_messenger_shell::cli::ensure_agent_webhooks::run(std::env::args().skip(1).collect());
}
