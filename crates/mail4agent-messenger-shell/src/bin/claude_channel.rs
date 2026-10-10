//! Thin wrapper kept for one transition release: this is `m4a-agent claude-channel`.
//! The code lives in `mail4agent_messenger_shell::cli::claude_channel`.

fn main() {
    mail4agent_messenger_shell::cli::claude_channel::run(std::env::args().skip(1).collect());
}
