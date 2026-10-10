//! Thin wrapper kept for one transition release: this is `m4a-agent mail`.
//! The code lives in `mail4agent_messenger_shell::cli::mail`.

fn main() {
    mail4agent_messenger_shell::cli::mail::run(std::env::args().skip(1).collect());
}
