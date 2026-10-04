//! [`RelationsBundle`] -- one event's aggregated relations (research doc
//! §1.3: reactions via `m.annotation`, edits via `m.replace`, replies via
//! `m.in_reply_to`, threads via `m.thread`). An event is expected to carry
//! **one** relation (research doc §1.3's cross-cutting constraint) -- this
//! module never tries to reconcile two relation kinds off the same relating
//! event; [`aggregate_relation`] dispatches on whichever `rel_type`
//! [`crate::wire::events::RelatesTo::from_content`] already resolved.
//!
//! # Pure aggregation, no storage
//!
//! Nothing here mutates a [`crate::room::timeline::Timeline`] -- that
//! module owns *which* relating events currently contribute to a target
//! (so a later redaction can retract exactly one contribution and
//! recompute), while this module only knows how to fold one more relating
//! event onto a bundle ([`aggregate_relation`]) or rebuild a bundle from
//! scratch given the full, current list of contributors
//! ([`recompute_bundle`]) -- the same function either way, since a
//! redaction is just "the contributor list changed, fold it again."

use crate::ids::{EventId, UserId};
use crate::wire::events::{RelatesTo, RoomMessageContent};
use std::collections::{BTreeMap, BTreeSet};

/// One accepted edit (`m.replace`) onto a target event: the edit event's own
/// id (kept so a later redaction of that edit can be told apart from every
/// other contributor), its `m.new_content`, and when it was sent (to break
/// ties between two edits with equal timestamps deterministically -- see
/// [`aggregate_relation`]).
#[derive(Clone, Debug, PartialEq)]
pub struct EditRecord {
    /// The edit event's own id.
    pub event_id: EventId,
    /// The edit's `m.new_content`, parsed the same way a top-level
    /// `m.room.message` content is.
    pub content: RoomMessageContent,
    /// The edit event's `origin_server_ts`.
    pub origin_server_ts: i64,
}

/// One event's aggregated relations, as folded from every relating event
/// [`crate::room::timeline::Timeline`] currently knows about for it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RelationsBundle {
    /// Reaction key (typically an emoji) -> the set of users who sent that
    /// reaction (research doc §1.3: server-side aggregated, grouped and
    /// summed -- this crate does the same folding client-side from
    /// individual `m.reaction` events).
    pub reactions: BTreeMap<String, BTreeSet<UserId>>,
    /// The most recent accepted edit, if any -- "most recent" by
    /// `origin_server_ts`, ties broken by the edit event's own id so the
    /// result is deterministic regardless of processing order.
    pub latest_edit: Option<EditRecord>,
    /// This event's own reply pointer (`m.in_reply_to`, standalone or
    /// nested inside an `m.thread` relation) -- not aggregated from other
    /// events, since a reply pointer is the replying event's OWN outgoing
    /// relation, not something a child event contributes onto it.
    pub reply_to: Option<EventId>,
    /// This event's own thread-root pointer (`m.thread`) -- same
    /// not-aggregated-from-children note as `reply_to`.
    pub thread_root: Option<EventId>,
}

/// One relating event, kept exactly as read off the wire (module doc) so
/// [`recompute_bundle`] can rebuild a target's bundle from scratch after one
/// contributor is retracted (a redaction -- `crate::room::timeline`'s job).
#[derive(Clone, Debug, PartialEq)]
pub struct RelatingEvent {
    /// The relating event's own id.
    pub event_id: EventId,
    /// The relating event's sender.
    pub sender: UserId,
    /// The relating event's `origin_server_ts`.
    pub origin_server_ts: i64,
    /// The relation this event carries.
    pub relation: RelatesTo,
    /// `m.new_content`, present only when `relation` is
    /// [`RelatesTo::Replace`].
    pub new_content: Option<serde_json::Value>,
}

/// Folds one relating event onto `bundle`, mutating it in place. `bundle`
/// belongs to the event `relating.relation`'s own `event_id` names as its
/// target; `original_sender` is that target's sender (needed only for the
/// `m.replace` rule below). Returns `false` when the relation was rejected
/// outright and `bundle` was left untouched -- currently only possible for
/// an edit whose sender does not match `original_sender` (research doc
/// §1.3: `m.replace` "must come from the original sender"), an edit with no
/// parseable `m.new_content`, or a relation kind this crate does not fold
/// at all ([`RelatesTo::Unknown`]).
pub fn aggregate_relation(bundle: &mut RelationsBundle, original_sender: &UserId, relating: &RelatingEvent) -> bool {
    match &relating.relation {
        RelatesTo::Annotation { key, .. } => {
            bundle.reactions.entry(key.clone()).or_default().insert(relating.sender.clone());
            true
        }
        RelatesTo::Replace { .. } => {
            if &relating.sender != original_sender {
                return false;
            }
            let Some(new_content) = relating.new_content.clone() else { return false };
            let Ok(content) = serde_json::from_value::<RoomMessageContent>(new_content) else { return false };
            let candidate =
                EditRecord { event_id: relating.event_id.clone(), content, origin_server_ts: relating.origin_server_ts };
            let is_newer = match &bundle.latest_edit {
                None => true,
                Some(current) => {
                    (candidate.origin_server_ts, &candidate.event_id) >= (current.origin_server_ts, &current.event_id)
                }
            };
            if is_newer {
                bundle.latest_edit = Some(candidate);
            }
            true
        }
        RelatesTo::InReplyTo(reply) => {
            bundle.reply_to = Some(reply.event_id.clone());
            true
        }
        RelatesTo::Thread { event_id, in_reply_to, .. } => {
            bundle.thread_root = Some(event_id.clone());
            if let Some(reply) = in_reply_to {
                bundle.reply_to = Some(reply.event_id.clone());
            }
            true
        }
        RelatesTo::Unknown(_) => false,
    }
}

/// Rebuilds a target event's [`RelationsBundle`] from scratch given the
/// full, current list of events that relate to it, folded in `relating_
/// events`'s own order (typically `origin_server_ts` order -- the order two
/// same-timestamp edits appear in this slice is [`aggregate_relation`]'s own
/// tie-break, not this function's). Used both for a target's first
/// aggregation and, identically, after a redaction removes one contributor
/// from the list (`crate::room::timeline::Timeline::apply_redaction`).
pub fn recompute_bundle(original_sender: &UserId, relating_events: &[RelatingEvent]) -> RelationsBundle {
    let mut bundle = RelationsBundle::default();
    for relating in relating_events {
        aggregate_relation(&mut bundle, original_sender, relating);
    }
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::EventId;

    fn user(value: &str) -> UserId {
        UserId::parse(value).expect("valid user id")
    }

    fn target_id() -> EventId {
        EventId::parse("$target:example.org").expect("valid event id")
    }

    fn replace_relation() -> RelatesTo {
        // `RelatesTo::from_content`'s own parsing is exercised in
        // `wire::events`; this module only needs a well-formed
        // `RelatesTo::Replace` value.
        match RelatesTo::from_content(&serde_json::json!({
            "m.relates_to": { "rel_type": "m.replace", "event_id": target_id().as_str() }
        })) {
            Some(relation @ RelatesTo::Replace { .. }) => relation,
            other => panic!("expected Replace, got {other:?}"),
        }
    }

    fn edit_new_content(body: &str) -> serde_json::Value {
        serde_json::json!({ "msgtype": "m.text", "body": body })
    }

    #[test]
    fn aggregate_relation_replace_keeps_latest_only() {
        let original_sender = user("@alice:example.org");
        let first = RelatingEvent {
            event_id: EventId::parse("$edit1:example.org").expect("valid event id"),
            sender: original_sender.clone(),
            origin_server_ts: 100,
            relation: replace_relation(),
            new_content: Some(edit_new_content("first edit")),
        };
        let second = RelatingEvent {
            event_id: EventId::parse("$edit2:example.org").expect("valid event id"),
            sender: original_sender.clone(),
            origin_server_ts: 200,
            relation: replace_relation(),
            new_content: Some(edit_new_content("second edit")),
        };

        let mut bundle = RelationsBundle::default();
        assert!(aggregate_relation(&mut bundle, &original_sender, &first));
        assert!(aggregate_relation(&mut bundle, &original_sender, &second));

        let latest = bundle.latest_edit.clone().expect("an edit was accepted");
        assert_eq!(latest.event_id, second.event_id);
        assert_eq!(
            latest.content,
            RoomMessageContent::Text(crate::wire::events::TextLikeMessageContent {
                body: "second edit".to_string(),
                format: None,
                formatted_body: None,
            })
        );

        // Recomputing from the full history (as a redaction of `first`
        // would trigger) yields the same result -- `first` never wins
        // regardless of fold order, since it is genuinely older.
        let recomputed = recompute_bundle(&original_sender, &[second.clone(), first.clone()]);
        assert_eq!(recomputed.latest_edit, bundle.latest_edit);
    }

    #[test]
    fn edit_from_a_different_sender_is_ignored() {
        let original_sender = user("@alice:example.org");
        let impostor = user("@mallory:example.org");
        let relating = RelatingEvent {
            event_id: EventId::parse("$edit:example.org").expect("valid event id"),
            sender: impostor,
            origin_server_ts: 100,
            relation: replace_relation(),
            new_content: Some(edit_new_content("not really alice")),
        };

        let mut bundle = RelationsBundle::default();
        assert!(!aggregate_relation(&mut bundle, &original_sender, &relating));
        assert_eq!(bundle.latest_edit, None);
    }

    #[test]
    fn annotation_aggregates_reactor_sets_per_key() {
        let target = target_id();
        let alice = user("@alice:example.org");
        let bob = user("@bob:example.org");
        let react = |sender: &UserId, key: &str, n: u64| RelatingEvent {
            event_id: EventId::parse(format!("$r{n}:example.org")).expect("valid event id"),
            sender: sender.clone(),
            origin_server_ts: 100 + n as i64,
            relation: RelatesTo::Annotation { event_id: target.clone(), key: key.to_string() },
            new_content: None,
        };

        let mut bundle = RelationsBundle::default();
        assert!(aggregate_relation(&mut bundle, &alice, &react(&alice, "\u{1F44D}", 1)));
        assert!(aggregate_relation(&mut bundle, &alice, &react(&bob, "\u{1F44D}", 2)));
        assert!(aggregate_relation(&mut bundle, &alice, &react(&bob, "\u{1F389}", 3)));

        assert_eq!(bundle.reactions.get("\u{1F44D}").expect("thumbs-up present").len(), 2);
        assert_eq!(bundle.reactions.get("\u{1F389}").expect("party present").len(), 1);
    }
}
