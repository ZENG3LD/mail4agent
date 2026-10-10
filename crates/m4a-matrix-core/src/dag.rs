//! The event DAG of one room, over any store that can answer [`DagRead`].
//!
//! Two entry points share one acceptance path:
//! * [`local_event`] builds, signs and accepts an event this server creates;
//! * [`accept_wire`] verifies and accepts an event received from a peer.
//!
//! Acceptance follows the spec order: state-independent auth rules, auth rules against the state
//! named by the event's own `auth_events`, auth rules against the room state before the event
//! (resolved from its `prev_events`), and finally against the current state, where a failure only
//! soft-fails the event (stored, never made a forward extremity). Forked branches are merged with
//! state resolution v2.

use std::collections::BTreeSet;

use ruma_common::{room_version_rules::RoomVersionRules, CanonicalJsonObject, EventId, OwnedEventId, OwnedRoomId, UserId};
use ruma_events::{StateEventType, TimelineEventType};
use ruma_signatures::{hash_and_sign_event, reference_hash, verify_event, PublicKeyMap, Verified};
use ruma_state_res::{auth_types_for_event, check_state_dependent_auth_rules, check_state_independent_auth_rules, StateMap};
use serde_json::{json, value::RawValue, Value};

use crate::{resolve::resolve_state_with, Pdu, SignedEvent, Signer};

/// What the DAG needs from storage.
pub trait DagRead {
    /// A stored event (accepted, soft-failed or imported outlier).
    fn pdu(&self, id: &EventId) -> Option<Pdu>;
    /// The room state after the event, for events that have one.
    fn state_after(&self, id: &EventId) -> Option<StateMap<OwnedEventId>>;
    /// The room's forward extremities.
    fn extremities(&self) -> Vec<OwnedEventId>;
}

#[derive(Debug, thiserror::Error)]
pub enum Reject {
    #[error("malformed event: {0}")]
    Malformed(String),
    #[error("event already stored")]
    Duplicate,
    #[error("content hash does not match (content was altered or already redacted)")]
    BadContentHash,
    #[error("signature check failed: {0}")]
    BadSignature(String),
    #[error("unknown prev_event {0}")]
    MissingPrev(String),
    #[error("unknown auth_event {0}")]
    MissingAuth(String),
    #[error("auth rules refuse the event: {0}")]
    Auth(String),
    #[error("state resolution failed: {0}")]
    Resolve(String),
}

/// An event that passed the checks, with everything a store must write for it.
#[derive(Clone, Debug)]
pub struct Accepted {
    pub event_id: OwnedEventId,
    pub pdu: Pdu,
    pub json: CanonicalJsonObject,
    /// Room state after this event (its `state_before` plus itself when it is a state event).
    pub state_after: StateMap<OwnedEventId>,
    /// Failed only the check against the current state: store it, do not extend the room with it.
    pub soft_failed: bool,
    /// Forward extremities after acceptance.
    pub extremities: Vec<OwnedEventId>,
    /// Resolved current room state after acceptance.
    pub current_state: StateMap<OwnedEventId>,
    /// The new extremity set has more than one member: branches are open and state was resolved.
    pub forked: bool,
}

fn skey(kind: &TimelineEventType) -> StateEventType {
    StateEventType::from(kind.to_string())
}

/// Resolved room state over a set of event ids' states.
fn resolve_over(rules: &RoomVersionRules, db: &dyn DagRead, ids: &[OwnedEventId], extra: Option<(&OwnedEventId, &StateMap<OwnedEventId>)>) -> Result<StateMap<OwnedEventId>, Reject> {
    let mut forks: Vec<StateMap<OwnedEventId>> = Vec::new();
    for id in ids {
        match extra {
            Some((eid, st)) if eid == id => forks.push(st.clone()),
            _ => forks.push(db.state_after(id).ok_or_else(|| Reject::MissingPrev(id.to_string()))?),
        }
    }
    match forks.len() {
        0 => Ok(StateMap::new()),
        1 => Ok(forks.remove(0)),
        _ => resolve_state_with(rules, &|id: &EventId| db.pdu(id), &forks).map_err(|e| Reject::Resolve(e.to_string())),
    }
}

/// The room's current state: the forward extremities' states, resolved.
pub fn current_state(rules: &RoomVersionRules, db: &dyn DagRead) -> Result<StateMap<OwnedEventId>, Reject> {
    resolve_over(rules, db, &db.extremities(), None)
}

/// Event id of a signed wire event: `$` plus the reference hash.
pub fn compute_event_id(rules: &RoomVersionRules, json: &CanonicalJsonObject) -> Result<OwnedEventId, Reject> {
    let h = reference_hash(json, rules).map_err(|e| Reject::Malformed(e.to_string()))?;
    OwnedEventId::try_from(format!("${h}")).map_err(|e| Reject::Malformed(e.to_string()))
}

/// Checks the content hash and the origin signature (needs the signing server's public key).
pub fn verify_wire(rules: &RoomVersionRules, json: &CanonicalJsonObject, keys: &PublicKeyMap) -> Result<(), Reject> {
    match verify_event(keys, json, rules) {
        Ok(Verified::All) => Ok(()),
        Ok(Verified::Signatures) => Err(Reject::BadContentHash),
        Err(e) => Err(Reject::BadSignature(e.to_string())),
    }
}

/// The skeleton of an event: redacted form (content erased, ids, edges, hashes and signatures kept).
/// Its reference hash, so its event id, is unchanged.
pub fn skeleton(rules: &RoomVersionRules, json: &CanonicalJsonObject) -> Result<CanonicalJsonObject, Reject> {
    ruma_common::canonical_json::redact(json.clone(), &rules.redaction, None).map_err(|e| Reject::Malformed(e.to_string()))
}

/// Accepts one event (already hashed, signed and id-checked by the caller).
/// `state_before` overrides the state derived from `prev_events`; a joining server uses it to
/// start a replica from a state snapshot whose history it does not hold.
pub fn accept(rules: &RoomVersionRules, db: &dyn DagRead, event_id: OwnedEventId, json: CanonicalJsonObject, state_before: Option<StateMap<OwnedEventId>>) -> Result<Accepted, Reject> {
    if db.pdu(&event_id).is_some() {
        return Err(Reject::Duplicate);
    }
    let pdu = Pdu::from_wire(event_id.clone(), &json).map_err(Reject::Malformed)?;
    let fetch = |id: &EventId| -> Option<Pdu> { if id == pdu.event_id { Some(pdu.clone()) } else { db.pdu(id) } };

    // 1. State-independent rules (shape, auth_events present and of allowed types).
    for a in &pdu.auth_events {
        if db.pdu(a).is_none() {
            return Err(Reject::MissingAuth(a.to_string()));
        }
    }
    check_state_independent_auth_rules(&rules.authorization, &pdu, &fetch).map_err(Reject::Auth)?;

    // 2. Against the state named by the event's own auth_events.
    let mut auth_state: std::collections::HashMap<(StateEventType, String), Pdu> = Default::default();
    for a in &pdu.auth_events {
        if let Some(p) = db.pdu(a) {
            if let Some(sk) = &p.state_key {
                auth_state.insert((skey(&p.kind), sk.clone()), p);
            }
        }
    }
    check_state_dependent_auth_rules(&rules.authorization, &pdu, |t: &StateEventType, k: &str| auth_state.get(&(t.clone(), k.to_owned())).cloned()).map_err(Reject::Auth)?;

    // 3. Against the room state before the event.
    let before = match state_before {
        Some(s) => s,
        None => resolve_over(rules, db, &pdu.prev_events, None)?,
    };
    let by_state = |t: &StateEventType, k: &str| before.get(&(t.clone(), k.to_owned())).and_then(|id| db.pdu(id));
    check_state_dependent_auth_rules(&rules.authorization, &pdu, by_state).map_err(Reject::Auth)?;

    let mut state_after = before;
    if let Some(sk) = &pdu.state_key {
        state_after.insert((skey(&pdu.kind), sk.clone()), event_id.clone());
    }

    // 4. Against the current state: failing here only soft-fails.
    let old_ext = db.extremities();
    let current = resolve_over(rules, db, &old_ext, None)?;
    let by_current = |t: &StateEventType, k: &str| current.get(&(t.clone(), k.to_owned())).and_then(|id| db.pdu(id));
    let soft_failed = !old_ext.is_empty() && check_state_dependent_auth_rules(&rules.authorization, &pdu, by_current).is_err();

    if soft_failed {
        return Ok(Accepted { event_id, pdu, json, state_after, soft_failed: true, extremities: old_ext, current_state: current, forked: false });
    }
    let mut ext: Vec<OwnedEventId> = old_ext.into_iter().filter(|e| !pdu.prev_events.contains(e)).collect();
    ext.push(event_id.clone());
    ext.sort();
    let forked = ext.len() > 1;
    let current_state = resolve_over(rules, db, &ext, Some((&event_id, &state_after)))?;
    Ok(Accepted { event_id, pdu, json, state_after, soft_failed: false, extremities: ext, current_state, forked })
}

/// A peer's event: check the origin signature and content hash, derive the id, accept.
pub fn accept_wire(rules: &RoomVersionRules, db: &dyn DagRead, json: CanonicalJsonObject, keys: &PublicKeyMap, state_before: Option<StateMap<OwnedEventId>>) -> Result<Accepted, Reject> {
    verify_wire(rules, &json, keys)?;
    let id = compute_event_id(rules, &json)?;
    accept(rules, db, id, json, state_before)
}

/// An unsigned event for `sender`, ready to be filled in by the sender's server (make_join style):
/// `prev_events`, `auth_events` and `depth` come from this room's DAG.
pub fn template(rules: &RoomVersionRules, db: &dyn DagRead, room_id: &OwnedRoomId, ts: u64, sender: &str, kind: &str, state_key: Option<&str>, content: Value) -> Result<CanonicalJsonObject, Reject> {
    let sender_id = UserId::parse(sender).map_err(|e| Reject::Malformed(e.to_string()))?;
    let raw = RawValue::from_string(content.to_string()).map_err(|e| Reject::Malformed(e.to_string()))?;
    let tl = TimelineEventType::from(kind.to_owned());
    let ext = db.extremities();
    let cur = resolve_over(rules, db, &ext, None)?;
    let auth: Vec<OwnedEventId> = auth_types_for_event(&tl, &sender_id, state_key, &raw, &rules.authorization)
        .map_err(Reject::Auth)?
        .iter()
        .filter_map(|k| cur.get(k).cloned())
        .collect();
    let depth = ext.iter().filter_map(|e| db.pdu(e)).map(|p| p.depth).max().unwrap_or(0) + 1;
    let mut o = json!({
        "room_id": room_id, "sender": sender, "type": kind, "content": content,
        "origin_server_ts": ts, "prev_events": ext, "auth_events": auth, "depth": depth,
    });
    if let Some(sk) = state_key {
        o["state_key"] = json!(sk);
    }
    serde_json::from_value(o).map_err(|e| Reject::Malformed(e.to_string()))
}

/// Hashes and signs a filled-in template; the event id is the reference hash.
pub fn sign_template(rules: &RoomVersionRules, signer: &Signer, mut obj: CanonicalJsonObject) -> Result<SignedEvent, Reject> {
    hash_and_sign_event(signer.server(), signer, &mut obj, &rules.redaction).map_err(|e| Reject::Malformed(e.to_string()))?;
    let event_id = compute_event_id(rules, &obj)?;
    Ok(SignedEvent { event_id, json: obj })
}

/// An event this server creates: template, sign, accept (same checks as a peer's event).
pub fn local_event(rules: &RoomVersionRules, db: &dyn DagRead, signer: &Signer, room_id: &OwnedRoomId, ts: u64, sender: &str, kind: &str, state_key: Option<&str>, content: Value) -> Result<Accepted, Reject> {
    let t = template(rules, db, room_id, ts, sender, kind, state_key, content)?;
    let s = sign_template(rules, signer, t)?;
    accept(rules, db, s.event_id, s.json, None)
}

/// Ids of the events in `ids` that `db` does not hold.
pub fn missing(db: &dyn DagRead, ids: &[OwnedEventId]) -> BTreeSet<OwnedEventId> {
    ids.iter().filter(|i| db.pdu(i).is_none()).cloned().collect()
}
