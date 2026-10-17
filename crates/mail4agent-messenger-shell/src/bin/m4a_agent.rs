//! `m4a-agent [--session-file <path>] <command> [args]`: every command of the client in one
//! binary (see `mail4agent_messenger_shell::cli`).

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    if matches!(args.peek().map(String::as_str), Some("--version" | "-V" | "version")) {
        println!("m4a-agent {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.peek().map(String::as_str) == Some("--session-file") {
        args.next();
        let Some(path) = args.next() else {
            eprintln!("m4a-agent: --session-file needs a path");
            std::process::exit(64);
        };
        if let Err(e) = mail4agent_messenger_shell::session_account::apply_session_file(std::path::Path::new(&path)) {
            eprintln!("m4a-agent: session file: {e}");
            std::process::exit(64);
        }
    }
    let Some(command) = args.next() else {
        eprintln!(
            "usage: m4a-agent [--version] [--session-file <path>] <command> [args]; commands: {}",
            mail4agent_messenger_shell::cli::COMMANDS.join(", ")
        );
        std::process::exit(64);
    };
    if let Err(e) = mail4agent_messenger_shell::cli::dispatch(&command, args.collect()) {
        eprintln!("m4a-agent: {e}");
        std::process::exit(64);
    }
}
