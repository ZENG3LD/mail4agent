//! `m4a-agent vault <status|backup|restore>`: the owner's way to look at, save and move the key
//! vault of `M4A_STORE_ROOT`.
//!
//! * `status`: where the master key lives (`file+keyfile`, `file+keychain`, `file+envkey`) and how
//!   many entries there are. No label values.
//! * `backup --out <file> --passphrase-env <NAME>`: every entry, encrypted under the passphrase held
//!   in the environment variable NAME (never on the command line). Refuses to overwrite.
//! * `restore --from <file> --passphrase-env <NAME>`: writes the entries into the active vault.
//!
//! To move a vault to a master key from the environment (`M4A_VAULT_KEY_ENV` names the variable that
//! holds it): back it up, move the old `vault.enc`, `vault.key` and `vault.home` aside, set the
//! variable, restore. The identity and store keys come back; copy the session store directories
//! along (they are sealed under keys the vault holds).

use super::session_arg::take_flag;
use crate::STORE_ROOT_ENV;

pub fn run(args: Vec<String>) {
    match go(args) {
        Ok(t) => println!("{t}"),
        Err(e) => {
            eprintln!("vault: {e}");
            std::process::exit(if e.starts_with("usage") { 64 } else { 1 });
        }
    }
}

const USAGE: &str = "usage: m4a-agent vault status | backup --out <file> --passphrase-env <NAME> | restore --from <file> --passphrase-env <NAME>";

pub(crate) fn go(mut args: Vec<String>) -> Result<String, String> {
    if args.is_empty() {
        return Err(USAGE.into());
    }
    let sub = args.remove(0);
    let (out, from, pass_env) = (take_flag(&mut args, "--out")?, take_flag(&mut args, "--from")?, take_flag(&mut args, "--passphrase-env")?);
    if !args.is_empty() {
        return Err(USAGE.into());
    }
    let root = std::env::var(STORE_ROOT_ENV).ok().filter(|v| !v.is_empty()).map(std::path::PathBuf::from).ok_or_else(|| format!("{STORE_ROOT_ENV} is not set"))?;
    let vault = crate::store_key::vault(&root).map_err(|e| e.to_string())?;
    match sub.as_str() {
        "status" => {
            let n = vault.labels().map(|l| l.len().to_string()).unwrap_or_else(|_| "?".into());
            Ok(format!("vault: {}\nentries: {n}", vault.kind()))
        }
        #[cfg(feature = "vault-backup")]
        "backup" | "restore" => {
            let var = pass_env.ok_or("--passphrase-env <NAME> is required (the passphrase is never taken from the command line)")?;
            let pass = zeroize::Zeroizing::new(std::env::var(&var).map_err(|_| format!("the variable {var} is not set"))?);
            if sub == "backup" {
                let path = std::path::PathBuf::from(out.ok_or("backup needs --out <file>")?);
                if path.exists() {
                    return Err("the output file exists; give a new path".into());
                }
                let blob = m4a_agent::vault_backup::backup(&*vault, &pass).map_err(|e| e.to_string())?;
                write_private(&path, &blob)?;
                Ok(format!("backup written ({} bytes); it opens only with the passphrase", blob.len()))
            } else {
                let path = from.ok_or("restore needs --from <file>")?;
                let blob = std::fs::read(&path).map_err(|_| "the backup file cannot be read".to_string())?;
                let n = m4a_agent::vault_backup::restore(&*vault, &blob, &pass).map_err(|e| e.to_string())?;
                Ok(format!("restored {n} entries into the {} vault", vault.kind()))
            }
        }
        #[cfg(not(feature = "vault-backup"))]
        "backup" | "restore" => {
            let _ = (out, from, pass_env);
            Err("this build was made without feature vault-backup".into())
        }
        _ => Err(USAGE.into()),
    }
}

#[cfg(feature = "vault-backup")]
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).and_then(|mut f| f.write_all(data)).map_err(|e| format!("cannot write the backup: {e}"))
}

#[cfg(all(test, feature = "vault-backup"))]
mod tests {
    use super::*;

    #[test]
    fn a_vault_moves_from_a_key_file_to_a_key_from_the_environment_through_a_backup() {
        let _g = super::super::session_arg::ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("store");
        std::env::set_var(STORE_ROOT_ENV, &root);
        std::env::remove_var(m4a_agent::vault::VAULT_KEY_ENV);
        let say = |a: &[&str]| go(a.iter().map(|s| s.to_string()).collect());
        crate::store_key::vault(&root).unwrap().put("identity-key/s1", b"seed").unwrap();
        assert!(say(&["status"]).unwrap().contains("file+key"));

        std::env::set_var("M4A_TEST_BACKUP_PASS", "a good long passphrase");
        let bk = d.path().join("v.bak");
        assert!(say(&["backup", "--out", bk.to_str().unwrap()]).is_err(), "a passphrase variable is required");
        assert!(say(&["backup", "--out", bk.to_str().unwrap(), "--passphrase-env", "M4A_TEST_BACKUP_PASS"]).unwrap().contains("written"));
        assert!(say(&["backup", "--out", bk.to_str().unwrap(), "--passphrase-env", "M4A_TEST_BACKUP_PASS"]).is_err(), "no overwrite");

        // A new store root whose vault key comes from the environment; restore into it.
        let root2 = d.path().join("store2");
        std::env::set_var("M4A_TEST_MASTER", "a master secret from the host env");
        std::env::set_var(m4a_agent::vault::VAULT_KEY_ENV, "M4A_TEST_MASTER");
        std::env::set_var(STORE_ROOT_ENV, &root2);
        let out = say(&["restore", "--from", bk.to_str().unwrap(), "--passphrase-env", "M4A_TEST_BACKUP_PASS"]).unwrap();
        assert!(out.contains("restored 1 entries into the file+envkey"), "{out}");
        assert!(!root2.join(".m4a-agent/vault.key").exists(), "no key file beside the vault");
        assert_eq!(&crate::store_key::vault(&root2).unwrap().get("identity-key/s1").unwrap().unwrap()[..], b"seed");
        assert!(say(&["status"]).unwrap().contains("file+envkey"));
        std::env::set_var("M4A_TEST_BACKUP_PASS", "another long passphrase!");
        assert!(say(&["restore", "--from", bk.to_str().unwrap(), "--passphrase-env", "M4A_TEST_BACKUP_PASS"]).is_err());
        std::env::remove_var(m4a_agent::vault::VAULT_KEY_ENV);
    }
}
