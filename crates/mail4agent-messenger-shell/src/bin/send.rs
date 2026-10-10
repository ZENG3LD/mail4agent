//! Thin wrapper kept for one transition release: this is `m4a-agent send`.
//! The code lives in `mail4agent_messenger_shell::cli::send`.

fn main() {
    mail4agent_messenger_shell::cli::send::run(std::env::args().skip(1).collect());
}
