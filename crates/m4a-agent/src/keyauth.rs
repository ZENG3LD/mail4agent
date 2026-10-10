//! Login by signature, the client half (the verifier half is `m4a_seam::keyproof` plus the
//! product kit's `ChallengeBook`). Shared by every tier that talks to a product door; transport
//! comes in through [`Wire`].

use m4a_seam::keyproof::Challenge;
use serde_json::{json, Value};

use crate::backend::wire::{field, Wire};
use crate::error::{AgentError, Result};
use crate::identity::{token_label, IdentityStore, SessionIdentity};

pub const CHALLENGE_PATH: &str = "/product/v1/login/key/challenge";
pub const ENROLL_PATH: &str = "/product/v1/enroll";
pub const LOGIN_PATH: &str = "/product/v1/login/key";

pub fn refused_or(status: u16, what: &str) -> AgentError {
    match status {
        401 | 403 => AgentError::Refused(format!("{what}: the server did not accept the proof")),
        s => AgentError::Protocol(format!("{what}: status {s}")),
    }
}

pub fn parse_challenge(v: &Value) -> Result<Challenge> {
    serde_json::from_value(v.clone()).map_err(|_| AgentError::Protocol("malformed challenge".into()))
}

/// Asks the product door for a challenge for this identity's key.
pub fn fetch_challenge(wire: &dyn Wire, id: &SessionIdentity) -> Result<Challenge> {
    let (st, v) = wire.post(CHALLENGE_PATH, &json!({ "key_id": id.key_id }), None)?;
    if st != 200 {
        return Err(refused_or(st, "challenge"));
    }
    parse_challenge(&v)
}

/// Redeems the operator's invite: proves possession of the private key and binds the public key to
/// the account the operator prepared (the nick was assigned when the operator invited). Marks the
/// identity enrolled, remembers the nick and the token; returns `(nick, token)`.
pub fn enroll(wire: &dyn Wire, ids: &IdentityStore, id: &mut SessionIdentity, invite: &str) -> Result<(String, String)> {
    // The audience comes from the product itself; the signature is only good for that product.
    let aud = fetch_challenge(wire, id)?.audience;
    let signature = id.sign_enroll(ids.vault(), &aud, invite)?;
    let label = format!("m4a-agent:{}", id.session_id);
    let mut body = json!({ "invite": invite, "public_key": id.public_key, "signature": signature, "label": label });
    if let Some(nick) = id.requested_nick.as_deref().filter(|n| !n.is_empty()) {
        body["nick"] = json!(nick);
    }
    let (st, v) = wire.post(ENROLL_PATH, &body, None)?;
    if st == 400 || st == 409 || st == 429 {
        // The nick request was refused (rules, taken, cooldown, or the invite reserves another): say so.
        let code = v.get("errcode").and_then(|c| c.as_str()).unwrap_or("");
        return Err(AgentError::Refused(format!("enroll: the server refused the requested nick ({st} {code}); the invite is still good")));
    }
    if st != 200 {
        return Err(refused_or(st, "enroll"));
    }
    let (nick, token) = (field(&v, "nick")?, field(&v, "token")?);
    id.enrolled = true;
    id.nick = Some(nick.clone());
    ids.save(id)?;
    ids.vault().put(&token_label(&id.session_id), token.as_bytes())?;
    Ok((nick, token))
}

/// Logs in by signing a fresh challenge at the product door; returns `(nick, token)`.
pub fn login(wire: &dyn Wire, ids: &IdentityStore, id: &SessionIdentity) -> Result<(String, String)> {
    let c = fetch_challenge(wire, id)?;
    let signature = id.sign_login(ids.vault(), &c)?;
    let (st, v) = wire.post(LOGIN_PATH, &json!({ "key_id": id.key_id, "challenge_id": c.challenge_id, "signature": signature }), None)?;
    if st != 200 {
        return Err(refused_or(st, "login"));
    }
    let (nick, token) = (field(&v, "nick")?, field(&v, "token")?);
    ids.vault().put(&token_label(&id.session_id), token.as_bytes())?;
    Ok((nick, token))
}

/// The token stored for this session, if any.
pub fn stored_token(ids: &IdentityStore, id: &SessionIdentity) -> Result<Option<String>> {
    Ok(ids.vault().get(&token_label(&id.session_id))?.and_then(|b| String::from_utf8(b.to_vec()).ok()))
}
