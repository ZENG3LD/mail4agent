//! m4a's keystore layer. m4a CONSUMES keys; the crypto is `tesserax-keytree`.
//!
//! - **Standalone**: [`Authority::Own`] — m4a holds its own root, issues session capabilities
//!   and signs letters itself.
//! - **Under an orchestrator**: [`Authority::Delegated`] — m4a holds no root. Session keys live
//!   with the orchestrator's keystore; m4a receives attenuated capabilities and signed letters
//!   and only verifies them against public keys (shared per room rules).
//!
//! A session never signs as another: the signer takes the identity from the capability, and
//! [`verify_letter`] binds the signature to the sender's nick and public key.

use std::collections::BTreeSet;

pub use tesserax_keytree as keytree;

/// m4a grants (namespace `m4a`).
pub mod grants {
    pub const SEND: &str = "m4a.send_as";
    pub const RECV: &str = "m4a.recv_inbox";
    /// Earlier un-namespaced names, accepted as aliases.
    pub const LEGACY: &[(&str, &str)] = &[("send_as", SEND), ("recv_inbox", RECV)];

    pub fn canonical(name: &str) -> &str {
        LEGACY.iter().find(|(l, _)| *l == name).map(|(_, g)| *g).unwrap_or(name)
    }
    /// Op name inside signed letters (the legacy name where one exists, for wire compatibility).
    pub fn wire(name: &str) -> &str {
        let g = canonical(name);
        LEGACY.iter().find(|(_, x)| *x == g).map(|(l, _)| *l).unwrap_or(g)
    }
    pub fn is_m4a(name: &str) -> bool {
        canonical(name).starts_with("m4a.")
    }
}

/// Environment names a session process sees (contract with the node; never renamed).
pub mod env {
    pub const SESSION_HANDLE: &str = "M4A_SESSION_HANDLE";
    pub const SIGNER_SOCK: &str = "M4A_SIGNER_SOCK";
}

/// Who is the root of m4a's keys.
pub enum Authority {
    /// Standalone: m4a's own root.
    Own(keytree::Authority),
    /// Under an orchestrator: no root here; keys and capabilities are delegated.
    Delegated,
}

impl Authority {
    pub fn standalone() -> Self {
        Self::Own(keytree::Authority::generate())
    }
    pub fn is_delegated(&self) -> bool {
        matches!(self, Self::Delegated)
    }

    /// Standalone only: capability for a session nick with m4a grants.
    pub fn issue_session(&self, nick: &str, grants: &BTreeSet<String>) -> Result<keytree::Issued, keytree::Error> {
        let Self::Own(root) = self else { return Err(keytree::Error::Denied) };
        if !grants.iter().all(|g| grants::is_m4a(g)) {
            return Err(keytree::Error::Denied);
        }
        let g: BTreeSet<String> = grants.iter().map(|g| grants::canonical(g).to_owned()).collect();
        root.issue(&[("nick", nick)], nick, &g)
    }

    /// Standalone only: the nick a capability grants `op` to.
    pub fn verify_session(&self, token: &str, op: &str) -> Result<String, keytree::Error> {
        let Self::Own(root) = self else { return Err(keytree::Error::Denied) };
        let v = root.verify(token, grants::canonical(op), "nick", &[])?;
        v.facts.get("nick").cloned().ok_or(keytree::Error::BadToken)
    }
}

/// Signed letter bytes: `domain\0nick\0op\0payload`. `domain` comes from the deployment.
pub fn letter_message(domain: &[u8], nick: &str, op: &str, payload: &[u8]) -> Vec<u8> {
    keytree::domain_message(domain, &[nick.as_bytes(), grants::wire(op).as_bytes(), payload])
}

/// Check a letter signed by a session key (own or delegated mode alike).
pub fn verify_letter(domain: &[u8], public_key: &[u8; 32], nick: &str, op: &str, payload: &[u8], signature: &[u8; 64]) -> bool {
    keytree::verify_signature(public_key, &letter_message(domain, nick, op, payload), signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &[u8] = b"test-domain/v1";

    #[test]
    fn letters_bind_nick_and_op() {
        let h = keytree::Secret::random().signing_handle();
        let sig = h.sign(&letter_message(DOMAIN, "a-1", grants::SEND, b"hi"));
        assert!(verify_letter(DOMAIN, &h.public_key(), "a-1", "send_as", b"hi", &sig));
        assert!(!verify_letter(DOMAIN, &h.public_key(), "a-2", grants::SEND, b"hi", &sig));
        assert!(!verify_letter(b"other", &h.public_key(), "a-1", grants::SEND, b"hi", &sig));
    }

    #[test]
    fn modes() {
        let own = Authority::standalone();
        let g: BTreeSet<String> = [grants::SEND.to_owned()].into();
        let t = own.issue_session("a-1", &g).unwrap();
        assert_eq!(own.verify_session(&t.token, "send_as").unwrap(), "a-1");
        assert!(own.verify_session(&t.token, grants::RECV).is_err());
        assert!(own.issue_session("a-1", &["node.uplink".to_owned()].into()).is_err());
        let del = Authority::Delegated;
        assert!(del.issue_session("a-1", &g).is_err(), "no root when delegated");
    }
}
