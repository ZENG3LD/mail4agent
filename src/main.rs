//! Thin binary over the mailbox library. The node kit links the library,
//! not a copied credential or a second implementation.

fn main() {
    if let Err(err) = mail4agent::main() {
        eprintln!("mail4agent: {err}");
        std::process::exit(1);
    }
}
