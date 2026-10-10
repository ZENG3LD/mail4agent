use std::collections::HashMap;

use ruma_common::{room_version_rules::{RoomVersionRules, StateResolutionVersion}, EventId, OwnedEventId};
use ruma_state_res::{resolve, utils::event_id_set::EventIdSet, StateMap};

use crate::Pdu;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("room version has no state resolution v2")]
    Version,
    #[error("state resolution failed: {0}")]
    Failed(String),
}

/// The full recursive set of auth events of `ids` (the ids themselves included).
pub fn auth_chain(pdus: &HashMap<OwnedEventId, Pdu>, ids: impl IntoIterator<Item = OwnedEventId>) -> EventIdSet<OwnedEventId> {
    auth_chain_with(&|id: &EventId| pdus.get(id).cloned(), ids)
}

/// [`auth_chain`] over any event source.
pub fn auth_chain_with(fetch: &dyn Fn(&EventId) -> Option<Pdu>, ids: impl IntoIterator<Item = OwnedEventId>) -> EventIdSet<OwnedEventId> {
    let mut seen = EventIdSet::new();
    let mut todo: Vec<OwnedEventId> = ids.into_iter().collect();
    while let Some(id) = todo.pop() {
        if seen.contains(&id) {
            continue;
        }
        if let Some(p) = fetch(&id) {
            todo.extend(p.auth_events.iter().cloned());
        }
        seen.insert(id);
    }
    seen
}

/// Resolves forked room states (state resolution v2) over a set of known events.
pub fn resolve_state(rules: &RoomVersionRules, pdus: &HashMap<OwnedEventId, Pdu>, forks: &[StateMap<OwnedEventId>]) -> Result<StateMap<OwnedEventId>, ResolveError> {
    resolve_state_with(rules, &|id: &EventId| pdus.get(id).cloned(), forks)
}

/// [`resolve_state`] over any event source (a store lookup).
pub fn resolve_state_with(rules: &RoomVersionRules, fetch: &dyn Fn(&EventId) -> Option<Pdu>, forks: &[StateMap<OwnedEventId>]) -> Result<StateMap<OwnedEventId>, ResolveError> {
    let StateResolutionVersion::V2(v2) = &rules.state_res else { return Err(ResolveError::Version) };
    let chains: Vec<EventIdSet<OwnedEventId>> = forks.iter().map(|f| auth_chain_with(fetch, f.values().cloned())).collect();
    resolve(
        &rules.authorization,
        v2,
        forks.iter(),
        chains,
        |id: &EventId| fetch(id),
        |_| None,
    )
    .map_err(|e| ResolveError::Failed(e.to_string()))
}
