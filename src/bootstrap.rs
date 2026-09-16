//! First-boot operator bootstrap. On a fresh mailbox there are no
//! participants at all, so nothing can authenticate and no caller could
//! ever mint the first one through `/admin/participant` (which itself
//! requires an operator bearer) -- a bootstrapping deadlock every
//! registrar-style service hits once. Resolved the way `mirage-operator`
//! resolves the identical problem for its own admin key
//! (`mirage2operator/crates/operator-box/CLAUDE.md`, "Auth"): generate the
//! credential once, write it to a fixed path under the operator's home
//! directory, and never speak it again anywhere else -- including a log
//! line. A log is routinely shipped, aggregated and retained well past the
//! moment it stops being operationally useful; a file at one fixed, narrow
//! path is available to exactly the operator who is meant to read it, and
//! no more available than that. The log line below records that the file
//! was written, deliberately never what it contains.

use std::io::Write;
use std::path::PathBuf;

use mail4agent_api::{MailError, ParticipantId};
use mail4agent_core::ParticipantPermissions;

use crate::service::MailboxService;

/// The id minted for the bootstrap operator. Fixed and well-known so a
/// later start can check for exactly this participant rather than
/// scanning the registry -- which `MailStore` has no call to do anyway
/// (see `mail4agent-core`'s own store contract: participants are looked up
/// by id or by secret digest, never listed).
const BOOTSTRAP_OPERATOR_ID: &str = "operator";

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("mailbox: {0}")]
    Mailbox(MailError),
    #[error("resolve home directory to write the operator key")]
    NoHomeDir,
    #[error("create {0}: {1}")]
    CreateDir(PathBuf, std::io::Error),
    #[error(
        "operator key file {0} already exists but no operator participant is registered -- \
         refusing to overwrite a secret that may still be in use; remove the file by hand \
         only after confirming it is stale"
    )]
    KeyFileAlreadyExists(PathBuf),
    #[error("write {0}: {1}")]
    WriteKeyFile(PathBuf, std::io::Error),
}

/// Ensures a bootstrap operator participant exists, minting one on first
/// start only. Does nothing on every later start once that participant is
/// registered, regardless of whether the key file still exists -- that
/// file is a one-time hand-off to the operator, not a credential store
/// this daemon ever reads back from.
pub async fn ensure_bootstrap_operator(service: &MailboxService) -> Result<(), BootstrapError> {
    let id = ParticipantId::new(BOOTSTRAP_OPERATOR_ID).map_err(BootstrapError::Mailbox)?;
    let already_registered = service
        .participant_exists(id.clone())
        .await
        .map_err(BootstrapError::Mailbox)?;
    if already_registered {
        tracing::info!(participant = BOOTSTRAP_OPERATOR_ID, "bootstrap operator already registered");
        return Ok(());
    }

    let key_path = operator_key_path()?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| BootstrapError::CreateDir(parent.to_path_buf(), err))?;
    }

    // Refuse BEFORE minting, not after. Registering first and discovering the
    // file afterwards would leave an operator in the database whose secret was
    // never written anywhere: the next start finds it already registered, skips
    // bootstrap, and the mailbox has an operator nobody can ever authenticate
    // as. `write_key_file_fresh` still uses `create_new`, which closes the race
    // between this check and that write; this check closes the far likelier
    // case of a stale file left behind by an earlier database.
    if key_path.exists() {
        return Err(BootstrapError::KeyFileAlreadyExists(key_path));
    }

    let permissions = ParticipantPermissions { may_send: true, may_read: true, operator: true };
    let secret = service
        .register_participant(id, Some("bootstrap operator".to_string()), permissions)
        .await
        .map_err(BootstrapError::Mailbox)?;

    write_key_file_fresh(&key_path, &secret)?;
    // Deliberately never logs `secret` itself -- see the module doc comment.
    tracing::info!(path = %key_path.display(), "bootstrap operator registered; secret written to disk");
    Ok(())
}

fn operator_key_path() -> Result<PathBuf, BootstrapError> {
    let base = directories::BaseDirs::new().ok_or(BootstrapError::NoHomeDir)?;
    Ok(base.home_dir().join(".mail4agent").join("operator-key.raw"))
}

/// Writes `secret` to `path`, refusing to touch it if it already exists.
/// `create_new` is the whole point: this file is written exactly once per
/// bootstrap participant, and silently overwriting an existing one could
/// discard a secret an operator has already picked up and is relying on.
fn write_key_file_fresh(path: &PathBuf, secret: &str) -> Result<(), BootstrapError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                BootstrapError::KeyFileAlreadyExists(path.clone())
            } else {
                BootstrapError::WriteKeyFile(path.clone(), err)
            }
        })?;
    file.write_all(secret.as_bytes())
        .map_err(|err| BootstrapError::WriteKeyFile(path.clone(), err))?;
    Ok(())
}
