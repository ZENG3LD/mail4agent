//! `m4a-agent <command> [args]`: every command of the client in one binary
//! (see `mail4agent_messenger_shell::cli`).

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        eprintln!("usage: m4a-agent <command> [args]; commands: {}", mail4agent_messenger_shell::cli::COMMANDS.join(", "));
        std::process::exit(64);
    };
    if let Err(e) = mail4agent_messenger_shell::cli::dispatch(&command, args.collect()) {
        eprintln!("m4a-agent: {e}");
        std::process::exit(64);
    }
}
