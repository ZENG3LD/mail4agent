//! Create one webhook routine card per live agent on this machine.
//!
//! Reads `/srv/agent-data/agents` (or `M4A_AGENTS_DIR`) and the local
//! gateway file. Prints only the routine names that exist afterwards.
//! Never prints URLs, keys, or tokens.

fn main() {
    match mail4agent_messenger_shell::ensure_agent_webhook_routines_from_env() {
        Ok(names) => {
            for name in names {
                println!("{name}");
            }
        }
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
