//! Thin wrapper kept for one transition release: this is `m4a-agent grok-listen`.
//! The code lives in `mail4agent_messenger_shell::cli::grok_listen`.

fn main() {
    mail4agent_messenger_shell::cli::grok_listen::run(std::env::args().skip(1).collect());
}
