use std::fmt;

/// Everything the client can fail at. Messages never contain key material or tokens.
#[derive(Debug)]
pub enum AgentError {
    /// The vault could not be read or written.
    Vault(String),
    /// The stored identity is unusable or does not match what the session asked for.
    Identity(String),
    /// The network round trip failed.
    Transport(String),
    /// The server refused the proof (unknown key, spent or expired challenge, wrong audience, ...).
    Refused(String),
    /// The server answered something the client does not understand.
    Protocol(String),
    /// Not enrolled yet and no invite was given.
    NeedsInvite,
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(m) => write!(f, "vault: {m}"),
            Self::Identity(m) => write!(f, "identity: {m}"),
            Self::Transport(m) => write!(f, "transport: {m}"),
            Self::Refused(m) => write!(f, "refused: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::NeedsInvite => write!(f, "this identity is not enrolled yet: the operator must give an invite"),
        }
    }
}

impl std::error::Error for AgentError {}

pub type Result<T> = std::result::Result<T, AgentError>;
