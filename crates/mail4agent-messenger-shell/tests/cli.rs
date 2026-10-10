//! One binary, subcommands; the old names are wrappers over the same code.

use std::process::Command;

#[test]
fn the_one_binary_names_its_commands_and_rejects_unknown_ones() {
    let bin = env!("CARGO_BIN_EXE_m4a-agent");
    let none = Command::new(bin).output().unwrap();
    assert_eq!(none.status.code(), Some(64));
    let err = String::from_utf8_lossy(&none.stderr);
    assert!(err.contains("web-client") && err.contains("inbox"), "{err}");
    let bad = Command::new(bin).arg("nope").output().unwrap();
    assert_eq!(bad.status.code(), Some(64));
}

#[test]
fn a_subcommand_and_its_old_wrapper_behave_the_same() {
    // `send` with no recipient prints its usage and exits with its own code, both ways.
    let new = Command::new(env!("CARGO_BIN_EXE_m4a-agent")).args(["send"]).env_remove("M4A_STORE_ROOT").output().unwrap();
    let old = Command::new(env!("CARGO_BIN_EXE_m4a-send")).env_remove("M4A_STORE_ROOT").output().unwrap();
    assert_eq!(new.status.code(), old.status.code());
    assert_eq!(String::from_utf8_lossy(&new.stderr), String::from_utf8_lossy(&old.stderr));
}
