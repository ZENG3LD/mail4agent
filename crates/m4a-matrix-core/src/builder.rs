use std::collections::HashMap;

use ruma_common::{CanonicalJsonObject, OwnedEventId, OwnedRoomId, UserId};
use ruma_events::{StateEventType, TimelineEventType};
use ruma_signatures::{hash_and_sign_event, reference_hash};
use ruma_state_res::{auth_types_for_event, check_state_dependent_auth_rules, check_state_independent_auth_rules, StateMap};
use serde_json::{json, value::RawValue, Value};

use crate::{Pdu, Signer, ROOM_VERSION};

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("unsupported room version")]
    Version,
    #[error("bad event field: {0}")]
    Field(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("auth rules refuse the event: {0}")]
    Auth(String),
}

/// A finished event: its computed id and the signed wire JSON (no `event_id` inside).
#[derive(Clone, Debug)]
pub struct SignedEvent {
    pub event_id: OwnedEventId,
    pub json: CanonicalJsonObject,
}

/// Builds the timeline of one NEW room, event by event: fills `prev_events`, `depth` and the
/// `auth_events` the spec selects from the current state, hashes and signs, computes the id, and
/// refuses an event the auth rules would reject.
pub struct RoomBuilder<'a> {
    room_id: OwnedRoomId,
    signer: &'a Signer,
    rules: ruma_common::room_version_rules::RoomVersionRules,
    ts: u64,
    depth: u64,
    last: Option<OwnedEventId>,
    state: StateMap<OwnedEventId>,
    pdus: HashMap<OwnedEventId, Pdu>,
    events: Vec<SignedEvent>,
}

impl<'a> RoomBuilder<'a> {
    pub fn new(room_id: OwnedRoomId, signer: &'a Signer, start_ts_ms: u64) -> Result<Self, BuildError> {
        let rules = ROOM_VERSION.rules().ok_or(BuildError::Version)?;
        Ok(Self { room_id, signer, rules, ts: start_ts_ms, depth: 0, last: None, state: StateMap::new(), pdus: HashMap::new(), events: Vec::new() })
    }

    /// Appends one event. `state_key` makes it a state event.
    pub fn push(&mut self, sender: &str, kind: &str, state_key: Option<&str>, content: Value) -> Result<&SignedEvent, BuildError> {
        let sender_id = UserId::parse(sender).map_err(|e| BuildError::Field(e.to_string()))?;
        let raw = RawValue::from_string(content.to_string()).map_err(|e| BuildError::Field(e.to_string()))?;
        let tl_kind = TimelineEventType::from(kind.to_owned());
        let auth_events: Vec<OwnedEventId> = auth_types_for_event(&tl_kind, &sender_id, state_key, &raw, &self.rules.authorization)
            .map_err(BuildError::Auth)?
            .iter()
            .filter_map(|k| self.state.get(k).cloned())
            .collect();
        self.depth += 1;
        self.ts += 1;
        let mut obj = json!({
            "room_id": self.room_id,
            "sender": sender,
            "type": kind,
            "content": content,
            "origin_server_ts": self.ts,
            "prev_events": self.last.iter().collect::<Vec<_>>(),
            "auth_events": auth_events,
            "depth": self.depth,
        });
        if let Some(sk) = state_key {
            obj["state_key"] = json!(sk);
        }
        let mut obj: CanonicalJsonObject = serde_json::from_value(obj).map_err(|e| BuildError::Field(e.to_string()))?;
        hash_and_sign_event(self.signer.server(), self.signer, &mut obj, &self.rules.redaction).map_err(|e| BuildError::Sign(e.to_string()))?;
        let id = format!("${}", reference_hash(&obj, &self.rules).map_err(|e| BuildError::Sign(e.to_string()))?);
        let event_id = OwnedEventId::try_from(id).map_err(|e| BuildError::Field(e.to_string()))?;
        let pdu = Pdu::from_wire(event_id.clone(), &obj).map_err(BuildError::Field)?;

        // The auth rules, as the spec orders them: independent of state, then against the state
        // the event names (its auth events), then against the room state before it.
        let by_id = |id: &ruma_common::EventId| self.pdus.get(id).cloned();
        check_state_independent_auth_rules(&self.rules.authorization, &pdu, by_id).map_err(BuildError::Auth)?;
        let fetch = |t: &StateEventType, k: &str| self.state.get(&(t.clone(), k.to_owned())).and_then(|id| self.pdus.get(id).cloned());
        check_state_dependent_auth_rules(&self.rules.authorization, &pdu, fetch).map_err(BuildError::Auth)?;

        if let Some(sk) = &pdu.state_key {
            self.state.insert((StateEventType::from(pdu.kind.to_string()), sk.clone()), event_id.clone());
        }
        self.last = Some(event_id.clone());
        self.pdus.insert(event_id.clone(), pdu);
        self.events.push(SignedEvent { event_id, json: obj });
        Ok(self.events.last().expect("just pushed"))
    }

    pub fn events(&self) -> &[SignedEvent] {
        &self.events
    }
    pub fn state(&self) -> &StateMap<OwnedEventId> {
        &self.state
    }
    pub fn pdus(&self) -> &HashMap<OwnedEventId, Pdu> {
        &self.pdus
    }
    pub fn rules(&self) -> &ruma_common::room_version_rules::RoomVersionRules {
        &self.rules
    }
}
