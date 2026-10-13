//! Thin wrapper kept for one transition release: this is `m4a-agent node-client`.
//! The code lives in `mail4agent_messenger_shell::cli::node_client`.

fn main() {
    mail4agent_messenger_shell::cli::node_client::run(std::env::args().skip(1).collect());
}
