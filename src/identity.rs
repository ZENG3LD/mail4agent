//! Resolves which session is calling, from the connection carrying the
//! request -- never from anything the caller states.
//!
//! The bearer token in a provider's config proves the **account**: every
//! session of that CLI reads the same file, so the token cannot tell them
//! apart. The operating system can, because each session is its own
//! process. So on every `/mail/*` and `/mcp` request this daemon:
//!
//! 1. attests the connection's peer to an OS process
//!    ([`mail4agent_attest::attest`], given the request's own
//!    `ConnectInfo<SocketAddr>` as `peer` and this server's own bound
//!    address as `local`);
//! 2. derives a stable [`SessionId`] from `(pid, started_at_unix_ms)`
//!    ([`derive_session_id`]) -- a hash, never the raw pid, which the OS
//!    reuses the moment a process exits;
//! 3. calls [`mail4agent_core::MailboxEngine::ensure_session`] (through
//!    [`MailboxService::ensure_session`]), which registers the session on
//!    first contact and refreshes it on every later one.
//!
//! **There is no fallback.** If step 1 cannot even start because
//! `ConnectInfo<SocketAddr>` is missing from the request, that is a wiring
//! failure -- every `serve()` call in this daemon must be built with
//! `into_make_service_with_connect_info` -- and the request is refused by
//! name ([`SessionError::MissingConnectInfo`]), never quietly treated as
//! coming from the bare account. If attestation itself fails for an
//! ordinary reason (the connection already closed, the platform has no
//! attestation implementation), the request is refused by name too
//! ([`SessionError::Attest`]). A caller that cannot be identified does not
//! get to send as somebody -- that is the exact hole this mechanism exists
//! to close, so nothing here is allowed to reopen it by falling back.
//!
//! Everything past step 1 is a plain function of an already-attested
//! [`PeerProcess`] ([`ensure_session_from_peer_process`]), kept separate
//! from [`resolve_session`] (which does the actual attestation) precisely
//! so it can be unit tested without a socket -- see this module's tests.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use mail4agent_api::{
    Address, Declared, MailError, ParticipantId, SessionAttested, SessionCard, SessionCorroborated, SessionId,
};
use mail4agent_attest::{AttestError, PeerProcess};
use sha2::{Digest, Sha256};

use crate::service::MailboxService;

/// The request's own `ConnectInfo<SocketAddr>`, if this server was wired to
/// supply one -- `None` otherwise. Stands in for `Option<ConnectInfo<SocketAddr>>`,
/// which cannot be used as a handler parameter directly on this axum
/// version: `ConnectInfo` does not implement `OptionalFromRequestParts`,
/// the trait axum 0.8 requires to make `Option<T>` extraction sugar work,
/// so this extractor does the equivalent by hand -- attempts `ConnectInfo`'s
/// own extraction and turns a failure into `None` rather than a response,
/// so a handler refuses by name (`SessionError::MissingConnectInfo`)
/// instead of the request failing outside its own control.
pub struct PeerAddr(pub Option<SocketAddr>);

impl<S> FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await {
            Ok(ConnectInfo(addr)) => Ok(Self(Some(addr))),
            Err(_) => Ok(Self(None)),
        }
    }
}

/// Length, in lower-hex characters, of a session id derived by
/// [`derive_session_id`]. Within [`mail4agent_api::SESSION_ID_HEX_MIN_CHARS`]..=
/// [`mail4agent_api::SESSION_ID_HEX_MAX_CHARS`]; chosen the same way
/// `mail4agent_core::engine::derive_message_id` truncates its own SHA-256
/// digest rather than carrying the full 64 characters.
const DERIVED_SESSION_ID_HEX_LEN: usize = 32;

/// Why a caller's session could not be named. Every variant is refused by
/// name; see this module's doc comment for why none of them fall back to
/// the bare account.
#[derive(Debug)]
pub enum SessionError {
    /// `ConnectInfo<SocketAddr>` was absent from the request. A wiring
    /// failure, not a caller mistake: this daemon's `serve()` call must
    /// supply it (`servertoolkit`'s `into_make_service_with_connect_info`
    /// fix is what this feature depends on).
    MissingConnectInfo,
    /// Attestation failed for an ordinary reason -- the connection already
    /// closed between accept and this call, the platform has no
    /// attestation implementation, or the resolved process vanished
    /// mid-lookup. See [`mail4agent_attest::AttestError`] for exactly
    /// which.
    Attest(AttestError),
    /// The mailbox itself refused the session registration (a malformed
    /// card, or a session id already on file under a different account).
    Mailbox(MailError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingConnectInfo => write!(
                f,
                "ConnectInfo<SocketAddr> is absent from this request -- the server is not wired to supply it"
            ),
            Self::Attest(err) => write!(f, "could not attest the calling process: {err}"),
            Self::Mailbox(err) => write!(f, "session registration refused: {err}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<AttestError> for SessionError {
    fn from(err: AttestError) -> Self {
        Self::Attest(err)
    }
}

/// Derives a stable [`SessionId`] from `(pid, started_at_unix_ms)`: a
/// SHA-256 hash, so the same process always resolves to the same id and a
/// different process never collides. Never the raw pid -- see
/// `mail4agent_attest::is_alive`'s own doc comment on why a bare pid
/// answers the wrong question the moment the OS reuses it.
pub fn derive_session_id(pid: u32, started_at_unix_ms: u64) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(pid.to_le_bytes());
    hasher.update(started_at_unix_ms.to_le_bytes());
    let digest = hasher.finalize();
    let hex_digest = hex::encode(digest);
    let body = &hex_digest[..DERIVED_SESSION_ID_HEX_LEN];
    SessionId::new(format!("{}{body}", SessionId::PREFIX))
        .expect("a fixed-length lower-hex body within SessionId's own bounds always validates")
}

/// Fields recognised out of a Claude Code command line -- `None` for
/// anything not found, never a guess. See [`parse_claude_command_line`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorroboratedCommandLine {
    pub provider_session_id: Option<String>,
    pub model: Option<String>,
}

/// Parses `--resume=<uuid>` and `--model <name>` out of a Claude Code
/// command line -- this is where a session's real identity is legible
/// (`mailbox-service-extraction-and-signed-session-identity-2026-09-16.md`
/// §5e). Deliberately narrow: recognises exactly those two shapes and
/// nothing else, so a command line from a different CLI, or a future
/// Claude Code flag shape this has not been taught, yields every field
/// `None` rather than a wrong guess -- a corroborated value that turns out
/// wrong is worse than one left absent.
pub fn parse_claude_command_line(command_line: &str) -> CorroboratedCommandLine {
    let tokens: Vec<&str> = command_line.split_whitespace().collect();
    let mut result = CorroboratedCommandLine::default();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        if let Some(value) = token.strip_prefix("--resume=") {
            if !value.is_empty() {
                result.provider_session_id = Some(value.to_string());
            }
        } else if token == "--model" {
            if let Some(value) = tokens.get(index + 1) {
                result.model = Some((*value).to_string());
                index += 1;
            }
        }
        index += 1;
    }
    result
}

/// Builds the [`SessionCard`] this daemon can vouch for from an
/// already-attested [`PeerProcess`]: `attested` copies the kernel-sourced
/// fields verbatim; `corroborated` is [`parse_claude_command_line`]'s
/// reading of the process's own command line when one was readable, plus
/// its `cwd` copied through unparsed; `declared` is always empty here --
/// [`mail4agent_core::MailboxEngine::set_declared`] (reached through
/// `POST /mail/status`) is the only writer of that group, and
/// `MailboxEngine::ensure_session` never touches it either.
pub fn session_card_from_peer_process(peer: &PeerProcess) -> SessionCard {
    let parsed = peer
        .command_line
        .as_ref()
        .map(|declared| parse_claude_command_line(declared.as_ref()))
        .unwrap_or_default();
    SessionCard {
        attested: SessionAttested { pid: peer.pid, started_at_unix_ms: peer.started_at_unix_ms, exe: peer.exe.clone() },
        corroborated: SessionCorroborated {
            provider_session_id: parsed.provider_session_id.map(Declared::new),
            model: parsed.model.map(Declared::new),
            cwd: peer.cwd.as_ref().map(|declared| Declared::new(declared.as_ref().clone())),
        },
        declared: Default::default(),
    }
}

/// The testable half of session resolution: everything after attestation
/// has already produced a [`PeerProcess`]. Registers or refreshes the
/// session ([`MailboxService::ensure_session`]) and returns the caller's
/// own session address. Kept separate from [`resolve_session`] (which
/// performs the attestation itself and needs a real socket) so this half
/// can be unit tested directly -- see this module's tests.
pub async fn ensure_session_from_peer_process(
    service: &MailboxService,
    account: ParticipantId,
    peer_process: &PeerProcess,
    now_unix_ms: u64,
) -> Result<Address, SessionError> {
    let session_id = derive_session_id(peer_process.pid, peer_process.started_at_unix_ms);
    let card = session_card_from_peer_process(peer_process);
    service
        .ensure_session(account.clone(), session_id.clone(), card, now_unix_ms)
        .await
        .map_err(SessionError::Mailbox)?;
    Ok(Address::Session { participant: account, session: session_id })
}

/// Resolves `account`'s calling session from the connection itself:
/// `peer` is the request's own `ConnectInfo<SocketAddr>`, `local` is this
/// server's own bound address ([`crate::state::AppState::bind_addr`]).
/// Never falls back to `account`'s bare address on any failure -- see
/// [`SessionError`] and this module's doc comment.
pub async fn resolve_session(
    service: &MailboxService,
    account: ParticipantId,
    peer: SocketAddr,
    local: SocketAddr,
    now_unix_ms: u64,
) -> Result<Address, SessionError> {
    let peer_process = mail4agent_attest::attest(peer, local)?;
    ensure_session_from_peer_process(service, account, &peer_process, now_unix_ms).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail4agent_core::ParticipantPermissions;
    use mail4agent_store_stk::SqliteMailStore;

    /// A minimal [`PeerProcess`] for tests. `command_line`/`cwd` stay
    /// `None`: `mail4agent_attest::Declared::new` is `pub(crate)` to that
    /// crate on purpose (a caller outside it must never be able to fabricate
    /// a "kernel-adjacent" value), so no test outside that crate can build
    /// one carrying a `Some`. That is exactly why
    /// [`parse_claude_command_line`] has its own tests below, taking a
    /// plain `&str` and needing no [`PeerProcess`] at all -- this helper
    /// only needs to exercise the "nothing to corroborate" path.
    fn peer_process(pid: u32, started_at_unix_ms: u64) -> PeerProcess {
        PeerProcess { pid, started_at_unix_ms, exe: Some("C:\\claude.exe".to_string()), command_line: None, cwd: None }
    }

    async fn test_service() -> MailboxService {
        let engine_store = SqliteMailStore::open_in_memory().expect("in-memory store opens and migrates");
        let reader_store = SqliteMailStore::new(engine_store.db());
        MailboxService::new(engine_store, reader_store)
    }

    async fn register(service: &MailboxService, id: &ParticipantId) {
        let permissions = ParticipantPermissions { may_send: true, may_read: true, operator: false };
        service.register_participant(id.clone(), None, permissions).await.expect("register test participant");
    }

    #[test]
    fn derive_session_id_is_stable_for_the_same_pid_and_start_time() {
        assert_eq!(derive_session_id(4242, 1_000), derive_session_id(4242, 1_000));
    }

    #[test]
    fn derive_session_id_differs_when_start_time_differs_for_the_same_pid() {
        // The exact case a bare pid would get wrong: the OS reused 4242 for
        // an unrelated process.
        assert_ne!(derive_session_id(4242, 1_000), derive_session_id(4242, 2_000));
    }

    #[test]
    fn derive_session_id_differs_across_pids() {
        assert_ne!(derive_session_id(1, 1_000), derive_session_id(2, 1_000));
    }

    #[test]
    fn parse_claude_command_line_recognises_resume_and_model() {
        let parsed = parse_claude_command_line("claude --resume=1234-uuid --model sonnet");
        assert_eq!(parsed.provider_session_id.as_deref(), Some("1234-uuid"));
        assert_eq!(parsed.model.as_deref(), Some("sonnet"));
    }

    #[test]
    fn parse_claude_command_line_tolerates_either_order() {
        let parsed = parse_claude_command_line("claude --model opus --resume=abc");
        assert_eq!(parsed.provider_session_id.as_deref(), Some("abc"));
        assert_eq!(parsed.model.as_deref(), Some("opus"));
    }

    #[test]
    fn parse_claude_command_line_yields_nothing_for_an_unrecognised_line() {
        let parsed = parse_claude_command_line("some-other-cli --flag value");
        assert_eq!(parsed, CorroboratedCommandLine::default());
    }

    #[test]
    fn parse_claude_command_line_ignores_a_dangling_model_flag_with_no_value() {
        let parsed = parse_claude_command_line("claude --model");
        assert_eq!(parsed.model, None);
    }

    #[test]
    fn parse_claude_command_line_ignores_an_empty_resume_value() {
        let parsed = parse_claude_command_line("claude --resume=");
        assert_eq!(parsed.provider_session_id, None);
    }

    #[tokio::test]
    async fn ensure_session_from_peer_process_returns_a_session_address_for_the_account() {
        let service = test_service().await;
        let account = ParticipantId::new("alice").expect("valid participant id");
        register(&service, &account).await;

        let address = ensure_session_from_peer_process(&service, account.clone(), &peer_process(111, 222), 1_000)
            .await
            .expect("resolves a session address");

        match address {
            Address::Session { participant, session } => {
                assert_eq!(participant, account);
                assert_eq!(session, derive_session_id(111, 222));
            }
            other => panic!("expected a session address, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ensure_session_from_peer_process_is_idempotent_for_the_same_process() {
        let service = test_service().await;
        let account = ParticipantId::new("alice").expect("valid participant id");
        register(&service, &account).await;

        let first = ensure_session_from_peer_process(&service, account.clone(), &peer_process(111, 222), 1_000)
            .await
            .expect("first call resolves");
        let second = ensure_session_from_peer_process(&service, account.clone(), &peer_process(111, 222), 2_000)
            .await
            .expect("second call resolves the same session");
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn ensure_session_from_peer_process_gives_different_processes_different_sessions() {
        let service = test_service().await;
        let account = ParticipantId::new("alice").expect("valid participant id");
        register(&service, &account).await;

        let first = ensure_session_from_peer_process(&service, account.clone(), &peer_process(111, 222), 1_000)
            .await
            .expect("first process resolves");
        let second = ensure_session_from_peer_process(&service, account.clone(), &peer_process(333, 444), 1_000)
            .await
            .expect("second, distinct process resolves");
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn ensure_session_from_peer_process_refuses_a_session_already_owned_by_another_account() {
        let service = test_service().await;
        let alice = ParticipantId::new("alice").expect("valid participant id");
        let bob = ParticipantId::new("bob").expect("valid participant id");
        register(&service, &alice).await;
        register(&service, &bob).await;

        ensure_session_from_peer_process(&service, alice, &peer_process(111, 222), 1_000)
            .await
            .expect("alice's session registers");

        let err = ensure_session_from_peer_process(&service, bob, &peer_process(111, 222), 2_000)
            .await
            .expect_err("the same (pid, started_at) presented under a different account must be refused");
        assert!(matches!(err, SessionError::Mailbox(MailError::SessionAccountMismatch { .. })));
    }
}
