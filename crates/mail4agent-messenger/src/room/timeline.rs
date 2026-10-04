//! [`Timeline`] -- one room's own message list, assembled from `/sync`
//! timeline windows (research doc §1.3-§1.4) and `/messages` back-pages
//! (research doc §1.5).
//!
//! # What gets its own row, and what doesn't
//!
//! A pure relation event -- an `m.reaction` (`m.annotation`) or an edit
//! (`m.replace`) -- never becomes its own [`TimelineItem`]; it folds onto
//! its target's [`RelationsBundle`] instead (`crate::room::relations`). An
//! `m.room.redaction` event never becomes its own row either; it applies
//! [`Timeline::apply_redaction`] to its `redacts` target. Every other event
//! (including one that also carries a reply/thread pointer -- that pointer
//! is the event's OWN outgoing relation, not something contributed onto a
//! different target) gets a row.
//!
//! # A relation or redaction can arrive before its target
//!
//! A reaction, an edit, or a redaction is structurally NEWER than the
//! event it targets -- but this timeline does not necessarily hold that
//! target yet: forward `/sync` can deliver a reaction to a message the
//! user has not back-paginated to, and a redaction can arrive the same
//! way. Dropping either would be a real data loss bug (back-paginating to
//! the target later would render it bare, silently missing a reaction/
//! edit/redaction this timeline already saw) -- so both are queued
//! instead ([`Timeline::pending_relations`]/[`Timeline::pending_redactions`],
//! module-private), keyed by the target's event id, and applied the moment
//! that target is inserted by either [`Timeline::apply_timeline_batch`] or
//! [`Timeline::prepend_back_page`]. Each queue is bounded at
//! [`PENDING_CAPACITY`] entries, oldest evicted first, so a pathological
//! number of never-resolved relations/redactions (a room with far more
//! reactions than the client will ever back-paginate to) cannot grow this
//! timeline's memory without bound; losing the oldest pending contribution
//! once a room is that active is an acceptable, documented trade-off,
//! matching every other bounded-cache-with-FIFO-eviction shape in this
//! codebase.

use crate::ids::{EventId, RoomId, TxnId, UserId};
use crate::room::relations::{aggregate_relation, recompute_bundle, RelatingEvent, RelationsBundle};
use crate::wire::events::{
    Membership, RawEvent, RedactionContent, RelatesTo, RoomEncryptedContent, RoomMessageContent, TextLikeMessageContent,
};
use std::collections::{BTreeMap, VecDeque};

/// How many not-yet-applicable relation contributions (or redactions) this
/// timeline tracks per queue before evicting the oldest -- see the module
/// doc's "A relation or redaction can arrive before its target" section.
const PENDING_CAPACITY: usize = 5_000;

const EVENT_ROOM_MESSAGE: &str = "m.room.message";
const EVENT_ROOM_ENCRYPTED: &str = "m.room.encrypted";
const EVENT_ROOM_REDACTION: &str = "m.room.redaction";
const EVENT_ROOM_MEMBER: &str = "m.room.member";
const EVENT_ROOM_NAME: &str = "m.room.name";
const EVENT_ROOM_TOPIC: &str = "m.room.topic";
const EVENT_ROOM_POWER_LEVELS: &str = "m.room.power_levels";
const EVENT_ROOM_HISTORY_VISIBILITY: &str = "m.room.history_visibility";
const EVENT_ROOM_CREATE: &str = "m.room.create";

/// Content key marking a message forwarded out of an ENCRYPTED room: a bare
/// `true`, carrying nothing about where it came from.
pub(crate) const KEY_FORWARDED: &str = "forwarded";
/// Content key marking a message forwarded out of an unencrypted (public)
/// room: `{ "room_id": .., "room_name": .. }`.
pub(crate) const KEY_FORWARDED_FROM: &str = "forwarded_from";

/// One item's send lifecycle (plan §3: `LocalEcho|Sending|Sent|Failed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendState {
    /// Appended optimistically, not yet handed to the transport (plan
    /// §4.2 step 6).
    LocalEcho,
    /// Handed to the transport, no server acknowledgement yet.
    Sending,
    /// The server accepted it -- every item [`Timeline::apply_timeline_batch`]
    /// builds from a `/sync` response starts here.
    Sent,
    /// The send failed outright (a network error, a rejected request,
    /// ...).
    Failed {
        /// Why the send failed.
        reason: String,
    },
}

/// A state-event-shaped timeline row's own summary -- only the three state
/// types this crate renders inline (member/name/topic; plan §3's
/// `ItemContent` set). Any other state event type appearing in a
/// `timeline.events` window becomes [`ItemContent::Unknown`] instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateChangeSummary {
    /// An `m.room.member` change.
    Member {
        /// The subject's user id (the event's own `state_key`, kept as a
        /// plain `String` rather than [`UserId`] since a malformed
        /// `state_key` must still render something rather than vanish).
        user_id: String,
        /// The subject's new membership.
        membership: Membership,
        /// The subject's display name, if set and not redacted away (the
        /// v11 allow-list drops this field on redaction -- see
        /// [`Timeline::apply_redaction`]).
        displayname: Option<String>,
    },
    /// An `m.room.name` change: the room's new name.
    Name(String),
    /// An `m.room.topic` change: the room's new topic.
    Topic(String),
}

/// One timeline item's content, at whatever stage of decryption/redaction
/// it has reached (plan §3's `ItemContent` set).
#[derive(Clone, Debug, PartialEq)]
pub enum ItemContent {
    /// `m.room.message`, `msgtype: "m.text"`.
    Text(TextLikeMessageContent),
    /// `m.room.message`, `msgtype: "m.notice"`.
    Notice(TextLikeMessageContent),
    /// `m.room.message`, `msgtype: "m.emote"`.
    Emote(TextLikeMessageContent),
    /// `m.room.encrypted` (Megolm), not yet decrypted -- the crypto layer
    /// (a later piece) resolves this via [`Timeline::set_decrypted`] once
    /// it can.
    Encrypted {
        /// The Megolm session this item was encrypted with.
        session_id: String,
        /// The still-sealed ciphertext, base64-encoded, exactly as it
        /// arrived on the wire -- a UI-facing adapter renders this
        /// verbatim (dimmed) rather than a placeholder, the same
        /// "ciphertext proves the encryption is real" posture the DM pane
        /// already has (owner ruling 2026-09-10).
        ciphertext_b64: String,
    },
    /// Decryption was attempted and structurally cannot succeed (no
    /// session, withheld, ...) -- a real UTD, not a transient state.
    Undecryptable {
        /// Why. A plain `String` in this piece; becomes
        /// `crypto::group_sessions::UtdReason` once that piece (M7/M8)
        /// exists.
        reason: String,
    },
    /// This event was redacted and had nothing worth keeping under the
    /// v11 allow-list (research doc §1.1) -- see
    /// [`Timeline::apply_redaction`] for the one event type this crate
    /// renders that keeps something instead.
    Redacted,
    /// A state event rendered inline in the timeline.
    StateChange(StateChangeSummary),
    /// An event type (or an unparseable `msgtype`/`algorithm`) this crate
    /// does not render inline -- kept forward-compatible rather than
    /// failing (same doctrine as `wire::events`).
    Unknown,
}

/// Where a forwarded item says it came from. Read from the two marker keys
/// a forward carries (`forwarded`,
/// `forwarded_from`) -- the marker is asserted by the
/// forwarding sender and is not authenticated by anything here. A missing or
/// malformed marker is simply `None` on the item, never a decode failure of
/// the event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forwarded {
    /// Forwarded out of an encrypted room: the bare fact only -- never the
    /// original sender, room id or room name.
    Hidden,
    /// Forwarded out of an unencrypted (public) room, which is named.
    Channel {
        /// The source room.
        room_id: RoomId,
        /// The source room's display name at the time of forwarding.
        room_name: String,
    },
}

/// Reads the forward marker off an event's content: a well-formed
/// `forwarded_from` wins, otherwise `forwarded: true` gives
/// [`Forwarded::Hidden`], otherwise `None`. Only `m.room.message` carries
/// the marker -- an `m.room.encrypted` envelope's own cleartext content
/// never does, whatever a sender put there. An event type this crate does
/// not render (including `m.sticker`) is not inspected.
fn parse_forwarded(event_type: &str, content: &serde_json::Value) -> Option<Forwarded> {
    if event_type != EVENT_ROOM_MESSAGE {
        return None;
    }
    let channel = content.get(KEY_FORWARDED_FROM).and_then(|from| {
        let room_id = RoomId::parse(from.get("room_id")?.as_str()?).ok()?;
        let room_name = from.get("room_name")?.as_str()?.to_string();
        Some(Forwarded::Channel { room_id, room_name })
    });
    channel.or_else(|| {
        (content.get(KEY_FORWARDED).and_then(serde_json::Value::as_bool) == Some(true)).then_some(Forwarded::Hidden)
    })
}

/// A decrypted Megolm plaintext, kept next to the still-ciphertext wire
/// content so a forward can read what was actually said.
#[derive(Clone, Debug, PartialEq)]
struct DecryptedEvent {
    event_type: String,
    content: serde_json::Value,
}

/// Why [`Timeline::forward_source`] refused an item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForwardRefusal {
    /// No such item in this timeline (or a local echo the server has not
    /// confirmed yet).
    Missing,
    /// The item was redacted.
    Redacted,
    /// The item is still sealed: undecryptable, or not decrypted yet.
    Sealed,
    /// Not an `m.room.message` (or carries no content object).
    NotForwardable {
        /// The event's own type.
        event_type: String,
    },
}

impl std::fmt::Display for ForwardRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardRefusal::Missing => f.write_str("no such event in that room"),
            ForwardRefusal::Redacted => f.write_str("the event was redacted"),
            ForwardRefusal::Sealed => f.write_str("the event is still sealed (undecryptable or not decrypted yet)"),
            ForwardRefusal::NotForwardable { event_type } => write!(f, "{event_type} events cannot be forwarded"),
        }
    }
}

/// What [`Timeline::forward_source`] found: the event type and the CURRENT
/// (latest-edit, decrypted) content of a forwardable item, still carrying
/// whatever relation/mention keys the original had.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ForwardSource {
    /// `m.room.message`.
    pub(crate) event_type: String,
    /// The content object.
    pub(crate) content: serde_json::Value,
}

/// Records that a `limited: true` `/sync` window (research doc §1.4) left
/// a gap between what this timeline holds and the room's full history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GapMarker {
    /// The pagination token (`GET /rooms/{roomId}/messages?from=<token>&
    /// dir=b`) to fetch further back from this gap's boundary. `None`
    /// only when the server did not supply one (the room's entire history
    /// fit in this one window).
    pub prev_batch: Option<String>,
}

/// One row of a room's timeline, or a not-yet-confirmed local echo of one
/// (plan §3: keyed by `event_id | txn_id`).
#[derive(Clone, Debug, PartialEq)]
pub struct TimelineItem {
    /// This item's confirmed event id, once the server has assigned one.
    /// `None` only for a [`SendState::LocalEcho`]/[`SendState::Sending`]
    /// item that has not been reconciled yet.
    pub event_id: Option<EventId>,
    /// The `txn_id` this item was (or will be) sent with, if it
    /// originated locally -- kept even after reconciliation, as
    /// provenance.
    pub txn_id: Option<TxnId>,
    /// The item's sender.
    pub sender: UserId,
    /// Milliseconds since the Unix epoch. For a local echo, this is
    /// whatever client-side clock reading [`Timeline::push_local_echo`]'s
    /// caller supplied, since the server has not assigned a real
    /// `origin_server_ts` yet.
    pub origin_server_ts: i64,
    /// The wire event type this item was built from.
    pub event_type: String,
    /// The wire event's own `state_key`, if it was a state event.
    pub state_key: Option<String>,
    /// This item's interpreted content.
    pub content: ItemContent,
    /// This item's own reply/thread pointer, plus every reaction/edit
    /// relation other events currently contribute onto it
    /// (`crate::room::relations`).
    pub relations: RelationsBundle,
    /// Where this item sits in its own send lifecycle.
    pub send_state: SendState,
    /// `true` once [`Timeline::apply_redaction`] (or an already-redacted
    /// event straight off the wire) has stripped this item's content.
    pub redacted: bool,
    /// The original wire `content` this item was built from, kept so
    /// [`Timeline::apply_redaction`] can rebuild [`TimelineItem::content`]
    /// from the v11 allow-list without needing the original
    /// [`RawEvent`] again. For a local echo, the plaintext content being
    /// sent.
    raw_content: serde_json::Value,
    /// Where this item says it was forwarded from, if it was -- read from
    /// the (decrypted) content's forward marker ([`Forwarded`]).
    pub forwarded: Option<Forwarded>,
    /// The decrypted plaintext of a Megolm item, once decrypted.
    decrypted: Option<DecryptedEvent>,
}

/// Interprets a plain `(event_type, content)` pair into an [`ItemContent`].
/// `pub(crate)` (rather than a `timeline`-private helper) because
/// [`crate::core::MessengerCore`] (M13a) needs the exact same mapping for a
/// Megolm plaintext's own `{type, content}` once
/// [`crate::crypto::group_sessions::GroupSessionManager::decrypt_event`] has
/// recovered it — reusing this function is what keeps a decrypted message
/// rendering identically to a plaintext one, rather than re-deriving the
/// mapping a second time at the crate's sync-engine layer.
pub(crate) fn interpret_content(event_type: &str, state_key: Option<&str>, content: &serde_json::Value) -> ItemContent {
    if let Some(state_key) = state_key {
        return interpret_state_change(event_type, state_key, content);
    }
    match event_type {
        EVENT_ROOM_MESSAGE => match serde_json::from_value::<RoomMessageContent>(content.clone()) {
            Ok(RoomMessageContent::Text(inner)) => ItemContent::Text(inner),
            Ok(RoomMessageContent::Notice(inner)) => ItemContent::Notice(inner),
            Ok(RoomMessageContent::Emote(inner)) => ItemContent::Emote(inner),
            // Any other msgtype, including one this crate does not model,
            // stays [`ItemContent::Unknown`]. The raw content object is kept
            // on the timeline item.
            _ => ItemContent::Unknown,
        },
        EVENT_ROOM_ENCRYPTED => match serde_json::from_value::<RoomEncryptedContent>(content.clone()) {
            Ok(RoomEncryptedContent::Megolm(inner)) => {
                ItemContent::Encrypted { session_id: inner.session_id, ciphertext_b64: inner.ciphertext }
            }
            _ => ItemContent::Undecryptable {
                reason: "m.room.encrypted event in a room timeline was not the megolm algorithm".to_string(),
            },
        },
        _ => ItemContent::Unknown,
    }
}

fn interpret_state_change(event_type: &str, state_key: &str, content: &serde_json::Value) -> ItemContent {
    match event_type {
        EVENT_ROOM_MEMBER => {
            let membership = content
                .get("membership")
                .and_then(|value| serde_json::from_value::<Membership>(value.clone()).ok())
                .unwrap_or(Membership::Unknown);
            let displayname = content.get("displayname").and_then(serde_json::Value::as_str).map(str::to_string);
            ItemContent::StateChange(StateChangeSummary::Member {
                user_id: state_key.to_string(),
                membership,
                displayname,
            })
        }
        EVENT_ROOM_NAME => {
            let name = content.get("name").and_then(serde_json::Value::as_str).unwrap_or_default().to_string();
            ItemContent::StateChange(StateChangeSummary::Name(name))
        }
        EVENT_ROOM_TOPIC => {
            let topic = content.get("topic").and_then(serde_json::Value::as_str).unwrap_or_default().to_string();
            ItemContent::StateChange(StateChangeSummary::Topic(topic))
        }
        _ => ItemContent::Unknown,
    }
}

/// Rebuilds an item's content per the v11 redaction allow-list (research
/// doc §1.1), from whatever `content` it currently has (the server's own
/// already-stripped content for an event that arrives pre-redacted, or
/// this crate's own full `raw_content` for a live redaction --
/// [`Timeline::apply_redaction`]). Only `m.room.member` keeps anything
/// this crate renders as a distinct [`ItemContent`] variant --
/// `m.room.power_levels`/`m.room.history_visibility`/`m.room.create` do
/// have their own v11 allow-list entries too, but none of the three has a
/// dedicated [`ItemContent`] shape in this piece's scope
/// ([`StateChangeSummary`] only covers member/name/topic) and both resolve
/// to [`ItemContent::Unknown`] before and after redaction either way.
/// Every other type (every message type, and every state type with no
/// allow-list entry of its own) has nothing worth keeping.
fn content_after_redaction(event_type: &str, state_key: Option<&str>, content: &serde_json::Value) -> ItemContent {
    if event_type == EVENT_ROOM_MEMBER {
        let membership = content
            .get("membership")
            .and_then(|value| serde_json::from_value::<Membership>(value.clone()).ok())
            .unwrap_or(Membership::Unknown);
        return ItemContent::StateChange(StateChangeSummary::Member {
            user_id: state_key.unwrap_or_default().to_string(),
            membership,
            // `displayname` is not on the v11 allow-list.
            displayname: None,
        });
    }
    match event_type {
        EVENT_ROOM_POWER_LEVELS | EVENT_ROOM_HISTORY_VISIBILITY | EVENT_ROOM_CREATE => ItemContent::Unknown,
        _ => ItemContent::Redacted,
    }
}

fn build_own_relation_pointers(event: &RawEvent) -> RelationsBundle {
    let mut bundle = RelationsBundle::default();
    match event.relates_to() {
        Some(RelatesTo::InReplyTo(reply)) => bundle.reply_to = Some(reply.event_id),
        Some(RelatesTo::Thread { event_id, in_reply_to, .. }) => {
            bundle.thread_root = Some(event_id);
            if let Some(reply) = in_reply_to {
                bundle.reply_to = Some(reply.event_id);
            }
        }
        _ => {}
    }
    bundle
}

fn build_item(event: &RawEvent) -> TimelineItem {
    let already_redacted = event.unsigned.redacted_because.is_some();
    let content = if already_redacted {
        content_after_redaction(&event.event_type, event.state_key.as_deref(), &event.content)
    } else {
        interpret_content(&event.event_type, event.state_key.as_deref(), &event.content)
    };
    let forwarded = if already_redacted || event.state_key.is_some() {
        None
    } else {
        parse_forwarded(&event.event_type, &event.content)
    };
    TimelineItem {
        event_id: Some(event.event_id.clone()),
        txn_id: event.unsigned.transaction_id.clone().map(TxnId::from),
        sender: event.sender.clone(),
        origin_server_ts: event.origin_server_ts,
        event_type: event.event_type.clone(),
        state_key: event.state_key.clone(),
        content,
        relations: build_own_relation_pointers(event),
        send_state: SendState::Sent,
        redacted: already_redacted,
        raw_content: event.content.clone(),
        forwarded,
        decrypted: None,
    }
}

/// Strips `item` down to what survives a redaction: the v11 allow-list
/// content ([`content_after_redaction`]), and nothing of a forward marker or
/// a decrypted plaintext.
fn redact_item(item: &mut TimelineItem) {
    item.content = content_after_redaction(&item.event_type, item.state_key.as_deref(), &item.raw_content);
    item.redacted = true;
    item.forwarded = None;
    item.decrypted = None;
}

/// A room's timeline: ordered items in server order, assembled from
/// `/sync` windows and `/messages` back-pages (module doc).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Timeline {
    items: Vec<TimelineItem>,
    by_event_id: BTreeMap<EventId, usize>,
    by_txn_id: BTreeMap<TxnId, usize>,
    /// For a relating event that never gets its own row (a reaction or an
    /// accepted edit): which target event id it contributed to -- so a
    /// later redaction of the RELATING event can find and retract exactly
    /// that contribution (module doc's redaction section).
    relation_contributions: BTreeMap<EventId, EventId>,
    /// Every relating event currently folded into a target's bundle,
    /// keyed by the target -- the "what remains" [`recompute_bundle`]
    /// needs after one contributor above is retracted.
    relating_events_by_target: BTreeMap<EventId, Vec<RelatingEvent>>,
    /// Relation contributions waiting on a target this timeline has not
    /// loaded yet, keyed by that target -- module doc's "a relation can
    /// arrive before its target" section. Applied and drained by
    /// [`Timeline::resolve_pending_for`] the moment the target is
    /// inserted.
    pending_relations: BTreeMap<EventId, Vec<RelatingEvent>>,
    /// Insertion order of every push into [`Timeline::pending_relations`]
    /// (one entry per queued [`RelatingEvent`], target id repeated if more
    /// than one is pending for the same target) -- lets
    /// [`Timeline::queue_pending_relation`] evict the globally oldest
    /// pending contribution first once [`PENDING_CAPACITY`] is exceeded.
    /// May contain a stale entry for a target already resolved and
    /// removed from `pending_relations`; eviction simply skips it (a
    /// documented, harmless simplification -- see
    /// [`Timeline::queue_pending_relation`]).
    pending_relation_order: VecDeque<EventId>,
    /// Redactions waiting on a target this timeline has not loaded yet,
    /// keyed by that target, value is the redaction event's own id.
    /// Applied and drained by [`Timeline::resolve_pending_for`] the moment
    /// the target is inserted.
    pending_redactions: BTreeMap<EventId, EventId>,
    /// Insertion order of every [`Timeline::pending_redactions`] entry,
    /// same stale-entry caveat as [`Timeline::pending_relation_order`].
    pending_redaction_order: VecDeque<EventId>,
    gap: Option<GapMarker>,
    older_token: Option<String>,
}

impl Timeline {
    /// An empty timeline: no items, no known gap.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every item currently held, oldest first.
    pub fn items(&self) -> &[TimelineItem] {
        &self.items
    }

    /// The item with this confirmed event id, if this timeline has one.
    pub fn item_by_event_id(&self, event_id: &EventId) -> Option<&TimelineItem> {
        self.by_event_id.get(event_id).map(|&idx| &self.items[idx])
    }

    /// Every relating event currently folded onto `target`'s own
    /// [`RelationsBundle`] -- its full contributor list, in the order they
    /// were folded. [`RelationsBundle::reactions`] only ever exposes the
    /// AGGREGATE (which users reacted with which key), never the individual
    /// relating events' own ids; this is how a caller (e.g. a provider
    /// implementing `MessengerIntent::Unreact`) finds exactly which
    /// `m.reaction` event(s) to redact for one sender's own reaction.
    /// Empty if `target` has no contributor at all, or is not loaded.
    pub fn relating_events_for(&self, target: &EventId) -> &[RelatingEvent] {
        self.relating_events_by_target.get(target).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The gap left by the most recent `limited: true` `/sync` window, if
    /// one is still outstanding. This piece never clears it automatically
    /// -- deciding a gap is closed (enough back-pages have filled it) is a
    /// later piece's policy call (`sync_engine.rs`, M13).
    pub fn gap(&self) -> Option<&GapMarker> {
        self.gap.as_ref()
    }

    /// The pagination token to keep fetching further back with, after the
    /// most recent [`Timeline::prepend_back_page`] call.
    pub fn older_token(&self) -> Option<&str> {
        self.older_token.as_deref()
    }

    /// Applies one `/sync` timeline window (research doc §1.4's
    /// `timeline.events`/`timeline.limited`/`timeline.prev_batch`) to this
    /// timeline. `events` must already be in the wire's own order (oldest
    /// first).
    ///
    /// - A pure relation event never gets its own row -- see the module
    ///   doc -- and instead folds onto its already-loaded target's bundle.
    /// - `m.room.redaction` never gets its own row either; it applies
    ///   [`Timeline::apply_redaction`] to its `redacts` target.
    /// - Every other event gets a [`TimelineItem`]. A duplicate
    ///   `event_id` (already present from an earlier batch) updates that
    ///   item in place rather than appending a second row.
    /// - A `txn_id` present in `unsigned.transaction_id` reconciles a
    ///   matching not-yet-confirmed local echo in place (same position,
    ///   `event_id` now known, `send_state` becomes [`SendState::Sent`])
    ///   instead of appending a duplicate.
    /// - `limited: true` records [`Timeline::gap`] (research doc §1.4).
    pub fn apply_timeline_batch(&mut self, events: &[RawEvent], limited: bool, prev_batch: Option<String>) {
        if limited {
            self.gap = Some(GapMarker { prev_batch });
        }
        for event in events {
            self.apply_one_event(event);
        }
    }

    fn apply_one_event(&mut self, event: &RawEvent) {
        if event.event_type == EVENT_ROOM_REDACTION {
            if let Ok(redaction) = serde_json::from_value::<RedactionContent>(event.content.clone()) {
                self.apply_or_queue_redaction(&event.event_id, &redaction.redacts);
            }
            return;
        }

        // A still-ciphertext `m.room.encrypted` event's OUTER envelope
        // already copies its `m.relates_to` pointer in cleartext (server
        // indexing convention, `wire::events::MegolmEncryptedContent`'s own
        // doc) -- but an edit's actual `m.new_content` lives only inside
        // the ciphertext, so this event cannot be classified as a relation
        // yet. It gets an ordinary (temporary) placeholder row here, same
        // as any other not-yet-decrypted event; `MessengerCore`'s own
        // decrypt pass calls [`Timeline::apply_decrypted_relation`] instead
        // of [`Timeline::set_decrypted`] once the plaintext reveals the
        // truth, retracting this placeholder (this method's own doc).
        if event.state_key.is_none() && event.event_type != EVENT_ROOM_ENCRYPTED {
            if let Some(relation) = event.relates_to() {
                if matches!(relation, RelatesTo::Annotation { .. } | RelatesTo::Replace { .. }) {
                    self.apply_relation_contribution(event, relation);
                    return;
                }
            }
        }

        let item = build_item(event);

        if let Some(txn_id) = item.txn_id.clone() {
            if let Some(&idx) = self.by_txn_id.get(&txn_id) {
                self.reconcile_local_echo(idx, item);
                return;
            }
        }

        if let Some(event_id) = item.event_id.clone() {
            if let Some(&idx) = self.by_event_id.get(&event_id) {
                self.items[idx] = item;
                return;
            }
        }

        self.insert_new_item(item);
    }

    fn apply_relation_contribution(&mut self, event: &RawEvent, relation: RelatesTo) {
        let new_content =
            if matches!(relation, RelatesTo::Replace { .. }) { event.content.get("m.new_content").cloned() } else { None };
        let relating = RelatingEvent {
            event_id: event.event_id.clone(),
            sender: event.sender.clone(),
            origin_server_ts: event.origin_server_ts,
            relation,
            new_content,
        };
        self.fold_or_queue_relation(relating);
    }

    /// Folds `relating` onto its own target's bundle if the target is
    /// already loaded, or queues it for later if not (module doc's "a
    /// relation can arrive before its target" section) -- the shared tail
    /// end of [`Timeline::apply_relation_contribution`] (a live plaintext
    /// relation event) and [`Timeline::apply_decrypted_relation`] (a
    /// Megolm-encrypted one, resolved post-decrypt).
    fn fold_or_queue_relation(&mut self, relating: RelatingEvent) {
        let target = match &relating.relation {
            RelatesTo::Annotation { event_id, .. } | RelatesTo::Replace { event_id } => event_id.clone(),
            _ => return,
        };
        let Some(&idx) = self.by_event_id.get(&target) else {
            self.queue_pending_relation(target, relating);
            return;
        };
        let original_sender = self.items[idx].sender.clone();
        if aggregate_relation(&mut self.items[idx].relations, &original_sender, &relating) {
            self.relation_contributions.insert(relating.event_id.clone(), target.clone());
            self.relating_events_by_target.entry(target).or_default().push(relating);
        }
    }

    /// Queues a relation contribution whose target is not loaded yet,
    /// bounded at [`PENDING_CAPACITY`] total pending contributions (across
    /// every target), oldest evicted first -- module doc.
    fn queue_pending_relation(&mut self, target: EventId, relating: RelatingEvent) {
        self.pending_relations.entry(target.clone()).or_default().push(relating);
        self.pending_relation_order.push_back(target);
        while self.pending_relation_order.len() > PENDING_CAPACITY {
            let Some(oldest_target) = self.pending_relation_order.pop_front() else { break };
            let mut now_empty = false;
            if let Some(pending) = self.pending_relations.get_mut(&oldest_target) {
                if !pending.is_empty() {
                    pending.remove(0);
                }
                now_empty = pending.is_empty();
            }
            if now_empty {
                self.pending_relations.remove(&oldest_target);
            }
        }
    }

    /// Queues a redaction whose target is not loaded yet and is not a
    /// currently-tracked relation contribution either, bounded at
    /// [`PENDING_CAPACITY`] entries, oldest evicted first -- module doc. A
    /// second redaction of a target that already has one pending is
    /// ignored (the first one wins; redacting an already-redacted target
    /// is a no-op regardless).
    fn queue_pending_redaction(&mut self, target: EventId, redaction_event_id: EventId) {
        if self.pending_redactions.contains_key(&target) {
            return;
        }
        self.pending_redactions.insert(target.clone(), redaction_event_id);
        self.pending_redaction_order.push_back(target);
        while self.pending_redaction_order.len() > PENDING_CAPACITY {
            let Some(oldest) = self.pending_redaction_order.pop_front() else { break };
            self.pending_redactions.remove(&oldest);
        }
    }

    /// Applies (and drains) whatever this timeline was waiting to apply to
    /// `event_id` -- a pending redaction, then any pending relation
    /// contributions -- now that it has been inserted at `idx`. Called by
    /// [`Timeline::insert_new_item`], [`Timeline::reconcile_local_echo`],
    /// and [`Timeline::prepend_back_page`] for every item they add.
    fn resolve_pending_for(&mut self, event_id: &EventId, idx: usize) {
        if self.pending_redactions.remove(event_id).is_some() {
            redact_item(&mut self.items[idx]);
        }

        if let Some(pending) = self.pending_relations.remove(event_id) {
            let original_sender = self.items[idx].sender.clone();
            for relating in pending {
                if aggregate_relation(&mut self.items[idx].relations, &original_sender, &relating) {
                    self.relation_contributions.insert(relating.event_id.clone(), event_id.clone());
                    self.relating_events_by_target.entry(event_id.clone()).or_default().push(relating);
                }
            }
        }
    }

    /// Applies a redaction to `target`, called for a caller that already
    /// knows `target` and has no distinct redaction event id worth
    /// tracking separately (e.g. re-processing `unsigned.redacted_because`
    /// off an event this timeline already holds un-redacted, though
    /// [`build_item`] already handles that case at insertion time; or a
    /// test). A live `m.room.redaction` event goes through
    /// [`Timeline::apply_or_queue_redaction`] instead, which additionally
    /// queues the redaction if `target` is not loaded yet -- this method
    /// uses `target` itself as that queue's key when it has to fall back
    /// to queuing, since it has no other id to offer.
    pub fn apply_redaction(&mut self, target: &EventId) {
        self.apply_or_queue_redaction(target, target);
    }

    /// The full redaction resolution `apply_redaction` and a live
    /// `m.room.redaction` event (via [`Timeline::apply_one_event`]/
    /// [`Timeline::prepend_back_page`]) both drive:
    ///
    /// - If `target` is a normal timeline item: its content is rebuilt
    ///   from [`content_after_redaction`]'s v11 allow-list, and
    ///   [`TimelineItem::redacted`] is set.
    /// - If `target` is a relation contribution (a reaction or an
    ///   accepted edit) this timeline is still tracking: that one
    ///   contribution is dropped from its own target's history and the
    ///   bundle is [`recompute_bundle`]d from what remains.
    /// - Otherwise (an event this timeline has not loaded at all) the
    ///   redaction is queued under `redaction_event_id` (module doc's "a
    ///   relation or redaction can arrive before its target") and applied
    ///   automatically once `target` is inserted
    ///   ([`Timeline::resolve_pending_for`]).
    fn apply_or_queue_redaction(&mut self, redaction_event_id: &EventId, target: &EventId) {
        if let Some(&idx) = self.by_event_id.get(target) {
            redact_item(&mut self.items[idx]);
            return;
        }

        if let Some(bundle_target) = self.relation_contributions.remove(target) {
            if let Some(contributions) = self.relating_events_by_target.get_mut(&bundle_target) {
                contributions.retain(|relating| &relating.event_id != target);
            }
            if let Some(&target_idx) = self.by_event_id.get(&bundle_target) {
                let original_sender = self.items[target_idx].sender.clone();
                let remaining = self.relating_events_by_target.get(&bundle_target).cloned().unwrap_or_default();
                self.items[target_idx].relations = recompute_bundle(&original_sender, &remaining);
            }
            return;
        }

        self.queue_pending_redaction(target.clone(), redaction_event_id.clone());
    }

    fn insert_new_item(&mut self, item: TimelineItem) {
        let idx = self.items.len();
        let event_id = item.event_id.clone();
        if let Some(event_id) = &event_id {
            self.by_event_id.insert(event_id.clone(), idx);
        }
        if let Some(txn_id) = &item.txn_id {
            self.by_txn_id.insert(txn_id.clone(), idx);
        }
        self.items.push(item);
        if let Some(event_id) = event_id {
            self.resolve_pending_for(&event_id, idx);
        }
    }

    fn reconcile_local_echo(&mut self, idx: usize, confirmed: TimelineItem) {
        let event_id = confirmed.event_id.clone();
        if let Some(event_id) = &event_id {
            self.by_event_id.insert(event_id.clone(), idx);
        }
        self.items[idx] = confirmed;
        if let Some(event_id) = event_id {
            self.resolve_pending_for(&event_id, idx);
        }
    }

    /// Appends a locally-originated item before it has even been handed to
    /// the transport (plan §4.2 step 6: "gets a `LocalEcho` entry ...
    /// immediately, so the adapter can render it before any network round
    /// trip completes"). `txn_id` must be the same id the eventual `PUT
    /// /rooms/{roomId}/send/...` call uses, so a later
    /// [`Timeline::apply_timeline_batch`] call reconciles this row via
    /// `unsigned.transaction_id` instead of appending a duplicate.
    ///
    /// `event_type` and `wire_content` are the PLAINTEXT event being sent
    /// (even in an encrypted room: the echo lives only in this device's own
    /// memory) -- kept so the row can be forwarded, and its forward marker
    /// shown, before the server has echoed it back. `content` is how the row
    /// renders in the meantime.
    pub fn push_local_echo(
        &mut self,
        txn_id: TxnId,
        sender: UserId,
        origin_server_ts: i64,
        event_type: &str,
        content: ItemContent,
        wire_content: serde_json::Value,
    ) {
        let item = TimelineItem {
            event_id: None,
            txn_id: Some(txn_id),
            sender,
            origin_server_ts,
            event_type: event_type.to_string(),
            state_key: None,
            content,
            relations: RelationsBundle::default(),
            send_state: SendState::LocalEcho,
            redacted: false,
            forwarded: parse_forwarded(event_type, &wire_content),
            raw_content: wire_content,
            decrypted: None,
        };
        self.insert_new_item(item);
    }

    /// Updates a not-yet-confirmed local echo's send state in place (e.g.
    /// `LocalEcho` -> `Sending` once handed to the transport, or ->
    /// `Failed` if the send errors out). A no-op if `txn_id` names no
    /// current item (already reconciled into a confirmed item, or never
    /// existed).
    pub fn mark_send_state(&mut self, txn_id: &TxnId, send_state: SendState) {
        if let Some(&idx) = self.by_txn_id.get(txn_id) {
            self.items[idx].send_state = send_state;
        }
    }

    /// Prepends an older page of history (`GET /rooms/{roomId}/messages`,
    /// research doc §1.5), `events` already in this timeline's own order
    /// (oldest first) -- a caller reading a `dir=b` response, which comes
    /// back newest-first, must reverse it before calling this method.
    /// `end_token` is that response's own `end` field: the token to keep
    /// paginating further back from, recorded as [`Timeline::older_token`].
    /// An event already known (by `event_id`) is skipped. A pure relation
    /// or redaction event within this page is resolved the same way a live
    /// one is ([`Timeline::apply_relation_contribution`]/
    /// [`Timeline::apply_or_queue_redaction`]) -- if its target is not
    /// among this page's own new items either, it is queued and applied
    /// once that target does load (module doc). Every newly inserted item
    /// also picks up whatever this timeline was already waiting to apply
    /// to it, from an earlier-seen relation/redaction (the exact scenario
    /// this queue exists for: back-paginating to a target after already
    /// having seen a reaction/edit/redaction of it via forward sync).
    pub fn prepend_back_page(&mut self, events: &[RawEvent], end_token: Option<String>) {
        let mut new_items = Vec::with_capacity(events.len());
        for event in events {
            if self.by_event_id.contains_key(&event.event_id) {
                continue;
            }
            if event.event_type == EVENT_ROOM_REDACTION {
                if let Ok(redaction) = serde_json::from_value::<RedactionContent>(event.content.clone()) {
                    self.apply_or_queue_redaction(&event.event_id, &redaction.redacts);
                }
                continue;
            }
            if event.state_key.is_none() {
                if let Some(relation) = event.relates_to() {
                    if matches!(relation, RelatesTo::Annotation { .. } | RelatesTo::Replace { .. }) {
                        self.apply_relation_contribution(event, relation);
                        continue;
                    }
                }
            }
            new_items.push(build_item(event));
        }
        let inserted_count = new_items.len();
        self.items.splice(0..0, new_items);
        self.older_token = end_token;
        self.reindex();
        for idx in 0..inserted_count {
            if let Some(event_id) = self.items[idx].event_id.clone() {
                self.resolve_pending_for(&event_id, idx);
            }
        }
    }

    fn reindex(&mut self) {
        self.by_event_id.clear();
        self.by_txn_id.clear();
        for (idx, item) in self.items.iter().enumerate() {
            if let Some(event_id) = &item.event_id {
                self.by_event_id.insert(event_id.clone(), idx);
            }
            if let Some(txn_id) = &item.txn_id {
                self.by_txn_id.insert(txn_id.clone(), idx);
            }
        }
    }

    /// Replaces `event_id`'s content once the crypto layer (a later
    /// piece, M7+) has decrypted it -- the hook [`ItemContent::Encrypted`]/
    /// [`ItemContent::Undecryptable`] items wait for. A no-op if this
    /// timeline holds no item for `event_id`.
    pub fn set_decrypted(&mut self, event_id: &EventId, content: ItemContent) {
        if let Some(&idx) = self.by_event_id.get(event_id) {
            self.items[idx].content = content;
        }
    }

    /// Like [`Timeline::set_decrypted`], for a successfully decrypted Megolm
    /// plaintext `{event_type, content}`: the item renders as
    /// [`interpret_content`] says, reads its forward marker off the
    /// plaintext, and keeps the plaintext so it can be forwarded. A no-op if
    /// this timeline holds no item for `event_id`.
    pub(crate) fn set_decrypted_event(&mut self, event_id: &EventId, event_type: &str, content: &serde_json::Value) {
        let Some(&idx) = self.by_event_id.get(event_id) else { return };
        let item = &mut self.items[idx];
        item.content = interpret_content(event_type, None, content);
        item.forwarded = parse_forwarded(event_type, content);
        item.decrypted = Some(DecryptedEvent { event_type: event_type.to_string(), content: content.clone() });
    }

    /// The content of `event_id` a forward would re-send: its event type
    /// and its CURRENT content -- the decrypted plaintext for an encrypted
    /// item, with the latest accepted edit's `m.new_content` in place of the
    /// original for an edited one. Everything the original content carried
    /// (relations, mentions) is still in it; stripping and marking are the
    /// caller's policy.
    ///
    /// Refuses ([`ForwardRefusal`]) an item this timeline does not hold, a
    /// redacted one, one still sealed (undecryptable or not decrypted yet),
    /// and anything that is not an `m.room.message`.
    pub(crate) fn forward_source(&self, event_id: &EventId) -> Result<ForwardSource, ForwardRefusal> {
        let item = self.item_by_event_id(event_id).ok_or(ForwardRefusal::Missing)?;
        if item.redacted || item.content == ItemContent::Redacted {
            return Err(ForwardRefusal::Redacted);
        }
        match &item.content {
            ItemContent::Encrypted { .. } | ItemContent::Undecryptable { .. } => return Err(ForwardRefusal::Sealed),
            _ => {}
        }
        let (event_type, original) = match &item.decrypted {
            Some(decrypted) => (decrypted.event_type.as_str(), &decrypted.content),
            None => (item.event_type.as_str(), &item.raw_content),
        };
        let not_forwardable = || ForwardRefusal::NotForwardable { event_type: event_type.to_string() };
        if item.state_key.is_some() || event_type != EVENT_ROOM_MESSAGE {
            return Err(not_forwardable());
        }
        let mut content = match &item.relations.latest_edit {
            Some(edit) => serde_json::to_value(&edit.content).map_err(|_| not_forwardable())?,
            None => original.clone(),
        };
        // An item that IS an edit event (a local echo of one) carries its
        // replacement under `m.new_content`.
        if let Some(replacement) = content.get("m.new_content").filter(|value| value.is_object()).cloned() {
            content = replacement;
        }
        if !content.is_object() {
            return Err(not_forwardable());
        }
        Ok(ForwardSource { event_type: event_type.to_string(), content })
    }

    /// Resolves a Megolm-encrypted event that, once decrypted, turns out to
    /// carry an `m.annotation`/`m.replace` relation rather than being an
    /// ordinary message — the counterpart to [`Timeline::set_decrypted`] for
    /// that case, and the reason [`Timeline::apply_one_event`] always gives
    /// a still-ciphertext event an ordinary placeholder row first (this
    /// type's own module doc; that method's own doc explains why the
    /// classification cannot happen before decryption). Retracts that
    /// placeholder row entirely (a relation never gets its own row) and
    /// folds it onto its real target exactly as a live plaintext relation
    /// event would have ([`Timeline::apply_relation_contribution`]).
    /// Returns `false`, doing nothing, if `event_id` names no current item
    /// (already resolved some other way) or if `relation` is not actually
    /// an annotation/replace (that plaintext case belongs to
    /// [`Timeline::set_decrypted`] instead).
    pub(crate) fn apply_decrypted_relation(
        &mut self,
        event_id: &EventId,
        sender: UserId,
        origin_server_ts: i64,
        relation: RelatesTo,
        new_content: Option<serde_json::Value>,
    ) -> bool {
        if !matches!(relation, RelatesTo::Annotation { .. } | RelatesTo::Replace { .. }) {
            return false;
        }
        let Some(&idx) = self.by_event_id.get(event_id) else { return false };
        self.items.remove(idx);
        self.reindex();
        let relating = RelatingEvent { event_id: event_id.clone(), sender, origin_server_ts, relation, new_content };
        self.fold_or_queue_relation(relating);
        true
    }

    /// Attaches the server-confirmed event id to a not-yet-reconciled local
    /// echo and marks it [`SendState::Sent`] -- the send pipeline's own
    /// immediate reaction to a successful `PUT .../send/...` response
    /// (`crate::core`'s module doc: "200 -> store `event_id` on the echo"),
    /// without waiting for the next `/sync` to reconcile it via
    /// `unsigned.transaction_id` ([`Timeline::apply_timeline_batch`] still
    /// does that too, redundantly and harmlessly, the moment the confirmed
    /// event itself arrives -- same `idx`, same final content). A no-op if
    /// `txn_id` names no current item.
    pub fn set_echo_event_id(&mut self, txn_id: &TxnId, event_id: EventId) {
        let Some(&idx) = self.by_txn_id.get(txn_id) else { return };
        self.items[idx].event_id = Some(event_id.clone());
        self.items[idx].send_state = SendState::Sent;
        self.by_event_id.insert(event_id, idx);
    }
}

/// `true` when `item`'s already-decrypted text mentions `user_id` or
/// `displayname` at a word boundary, case-insensitively (plan manager
/// decision #5: "highlight in encrypted rooms is computed client-side
/// after decryption"). Only [`ItemContent::Text`]/[`ItemContent::Notice`]/
/// [`ItemContent::Emote`] items can match -- anything else (still
/// encrypted, undecryptable, redacted, a state change, ...) never
/// highlights.
pub fn highlight(user_id: &UserId, displayname: Option<&str>, item: &TimelineItem) -> bool {
    let body = match &item.content {
        ItemContent::Text(inner) | ItemContent::Notice(inner) | ItemContent::Emote(inner) => inner.body.as_str(),
        _ => return false,
    };
    mentions_word(body, user_id.as_str()) || displayname.is_some_and(|name| !name.trim().is_empty() && mentions_word(body, name))
}

/// Word-boundary, case-insensitive substring search -- `needle` must not
/// be immediately preceded or followed by another alphanumeric character
/// in `haystack`, so `"alice"` does not match inside `"notalice123"`.
fn mentions_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let haystack_lower = haystack.to_lowercase();
    let needle_lower = needle.to_lowercase();
    let mut search_from = 0;
    while let Some(found_at) = haystack_lower[search_from..].find(&needle_lower) {
        let start = search_from + found_at;
        let end = start + needle_lower.len();
        let before_is_boundary = haystack_lower[..start].chars().next_back().is_none_or(|c| !c.is_alphanumeric());
        let after_is_boundary = haystack_lower[end..].chars().next().is_none_or(|c| !c.is_alphanumeric());
        if before_is_boundary && after_is_boundary {
            return true;
        }
        search_from = start + needle_lower.len().max(1);
    }
    false
}

/// The latest timeline item eligible for a chat-list preview line: not
/// still encrypted, not undecryptable, not redacted, and not a state
/// change (plan manager decision #5: "last-message preview = latest
/// decryptable timeline item"). `None` for an empty timeline, or one with
/// no eligible item at all (e.g. every message is still awaiting
/// decryption).
pub fn last_preview(timeline: &Timeline) -> Option<&TimelineItem> {
    timeline.items.iter().rev().find(|item| {
        !item.redacted
            && !matches!(
                item.content,
                ItemContent::Encrypted { .. } | ItemContent::Undecryptable { .. } | ItemContent::StateChange(_)
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_event(event_id: &str, event_type: &str, sender: &str, ts: i64, content: serde_json::Value) -> RawEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": event_id,
            "type": event_type,
            "sender": sender,
            "origin_server_ts": ts,
            "content": content,
        }))
        .expect("valid raw event")
    }

    fn raw_event_with_txn(
        event_id: &str,
        event_type: &str,
        sender: &str,
        ts: i64,
        content: serde_json::Value,
        txn_id: &str,
    ) -> RawEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": event_id,
            "type": event_type,
            "sender": sender,
            "origin_server_ts": ts,
            "content": content,
            "unsigned": { "transaction_id": txn_id },
        }))
        .expect("valid raw event")
    }

    fn text_content(body: &str) -> serde_json::Value {
        serde_json::json!({ "msgtype": "m.text", "body": body })
    }

    fn text_item(body: &str) -> TimelineItem {
        TimelineItem {
            event_id: Some(EventId::parse("$x:example.org").expect("valid event id")),
            txn_id: None,
            sender: UserId::parse("@someone:example.org").expect("valid user id"),
            origin_server_ts: 1,
            event_type: EVENT_ROOM_MESSAGE.to_string(),
            state_key: None,
            content: ItemContent::Text(TextLikeMessageContent { body: body.to_string(), format: None, formatted_body: None }),
            relations: RelationsBundle::default(),
            send_state: SendState::Sent,
            redacted: false,
            raw_content: serde_json::Value::Null,
            forwarded: None,
            decrypted: None,
        }
    }

    #[test]
    fn apply_timeline_batch_reconciles_local_echo_by_txn_id() {
        let mut timeline = Timeline::new();
        let alice = UserId::parse("@alice:example.org").expect("valid user id");
        let txn_id = TxnId::new(0);
        timeline.push_local_echo(
            txn_id.clone(),
            alice,
            100,
            EVENT_ROOM_MESSAGE,
            ItemContent::Text(TextLikeMessageContent { body: "hi".to_string(), format: None, formatted_body: None }),
            text_content("hi"),
        );
        assert_eq!(timeline.items().len(), 1);
        assert_eq!(timeline.items()[0].send_state, SendState::LocalEcho);
        assert!(timeline.items()[0].event_id.is_none());

        let confirmed =
            raw_event_with_txn("$confirmed:example.org", "m.room.message", "@alice:example.org", 105, text_content("hi"), txn_id.as_str());
        timeline.apply_timeline_batch(&[confirmed], false, None);

        assert_eq!(timeline.items().len(), 1, "the echo is replaced in place, not duplicated");
        let item = &timeline.items()[0];
        assert_eq!(item.event_id, Some(EventId::parse("$confirmed:example.org").expect("valid event id")));
        assert_eq!(item.send_state, SendState::Sent);
        assert_eq!(item.txn_id, Some(txn_id));
    }

    #[test]
    fn apply_redaction_keeps_v11_allow_listed_fields() {
        let mut timeline = Timeline::new();
        let member_event: RawEvent = serde_json::from_value(serde_json::json!({
            "event_id": "$member:example.org",
            "type": "m.room.member",
            "sender": "@alice:example.org",
            "origin_server_ts": 1,
            "state_key": "@bob:example.org",
            "content": { "membership": "join", "displayname": "Bob" }
        }))
        .expect("valid member event");
        let message_event = raw_event("$msg:example.org", "m.room.message", "@bob:example.org", 2, text_content("hello"));
        timeline.apply_timeline_batch(&[member_event, message_event], false, None);

        let member_id = EventId::parse("$member:example.org").expect("valid event id");
        timeline.apply_redaction(&member_id);
        let member_item = timeline.item_by_event_id(&member_id).expect("present");
        assert!(member_item.redacted);
        match &member_item.content {
            ItemContent::StateChange(StateChangeSummary::Member { membership, displayname, .. }) => {
                assert_eq!(*membership, Membership::Join, "membership survives the v11 allow-list");
                assert_eq!(*displayname, None, "displayname is not on the v11 allow-list");
            }
            other => panic!("expected a Member state change, got {other:?}"),
        }

        let msg_id = EventId::parse("$msg:example.org").expect("valid event id");
        timeline.apply_redaction(&msg_id);
        let msg_item = timeline.item_by_event_id(&msg_id).expect("present");
        assert!(msg_item.redacted);
        assert_eq!(msg_item.content, ItemContent::Redacted, "m.room.message has nothing on the v11 allow-list");
    }

    #[test]
    fn redacting_a_reaction_removes_it_from_the_bundle() {
        let mut timeline = Timeline::new();
        let target = raw_event("$target:example.org", "m.room.message", "@alice:example.org", 1, text_content("hi"));
        let reaction = raw_event(
            "$reaction:example.org",
            "m.reaction",
            "@bob:example.org",
            2,
            serde_json::json!({
                "m.relates_to": { "rel_type": "m.annotation", "event_id": "$target:example.org", "key": "\u{1F44D}" }
            }),
        );
        timeline.apply_timeline_batch(&[target, reaction], false, None);

        let target_id = EventId::parse("$target:example.org").expect("valid event id");
        let bundle_before = timeline.item_by_event_id(&target_id).expect("present").relations.clone();
        assert_eq!(bundle_before.reactions.get("\u{1F44D}").expect("reaction present").len(), 1);
        assert_eq!(timeline.items().len(), 1, "the reaction event never gets its own row");

        timeline.apply_redaction(&EventId::parse("$reaction:example.org").expect("valid event id"));
        let bundle_after = &timeline.item_by_event_id(&target_id).expect("present").relations;
        assert!(
            !bundle_after.reactions.contains_key("\u{1F44D}"),
            "the retracted reaction is gone entirely, not just emptied"
        );
    }

    #[test]
    fn limited_batch_records_a_gap() {
        let mut timeline = Timeline::new();
        assert!(timeline.gap().is_none());

        let event = raw_event("$1:example.org", "m.room.message", "@alice:example.org", 1, text_content("hi"));
        timeline.apply_timeline_batch(&[event], true, Some("t123".to_string()));

        let gap = timeline.gap().expect("limited batch records a gap");
        assert_eq!(gap.prev_batch.as_deref(), Some("t123"));
        assert_eq!(timeline.items().len(), 1, "the window's own events are still applied");
    }

    #[test]
    fn last_preview_skips_redacted_and_state() {
        let mut timeline = Timeline::new();
        let text = raw_event("$text:example.org", "m.room.message", "@alice:example.org", 1, text_content("first"));
        let name_change: RawEvent = serde_json::from_value(serde_json::json!({
            "event_id": "$name:example.org", "type": "m.room.name", "sender": "@alice:example.org",
            "origin_server_ts": 2, "state_key": "", "content": { "name": "New name" }
        }))
        .expect("valid name event");
        let redacted: RawEvent = serde_json::from_value(serde_json::json!({
            "event_id": "$redacted:example.org", "type": "m.room.message", "sender": "@alice:example.org",
            "origin_server_ts": 3, "content": {},
            "unsigned": { "redacted_because": {
                "event_id": "$r:example.org", "type": "m.room.redaction", "sender": "@mod:example.org",
                "origin_server_ts": 4, "content": { "redacts": "$redacted:example.org" }
            }}
        }))
        .expect("valid redacted event");

        timeline.apply_timeline_batch(&[text, name_change, redacted], false, None);

        let preview = last_preview(&timeline).expect("an eligible item exists");
        assert_eq!(preview.event_id, Some(EventId::parse("$text:example.org").expect("valid event id")));
    }

    #[test]
    fn highlight_matches_mention_not_substring() {
        let alice = UserId::parse("@alice:example.org").expect("valid user id");

        let mentioned = text_item("hey @alice:example.org, are you around?");
        assert!(highlight(&alice, Some("Alice"), &mentioned));

        let by_displayname = text_item("Alice, can you review this?");
        assert!(highlight(&alice, Some("Alice"), &by_displayname));

        let substring_only = text_item("notalice123 says hi to nobody");
        assert!(!highlight(&alice, Some("Alice"), &substring_only));
    }

    #[test]
    fn reaction_seen_before_its_target_applies_when_target_back_paginates() {
        let mut timeline = Timeline::new();
        let reaction = raw_event(
            "$reaction:example.org",
            "m.reaction",
            "@bob:example.org",
            10,
            serde_json::json!({
                "m.relates_to": { "rel_type": "m.annotation", "event_id": "$target:example.org", "key": "\u{1F44D}" }
            }),
        );
        // The reaction arrives via forward sync before the user has ever
        // back-paginated to its (older) target.
        timeline.apply_timeline_batch(&[reaction], false, None);
        assert!(timeline.items().is_empty(), "the reaction never gets its own row, pending or not");

        let target = raw_event("$target:example.org", "m.room.message", "@alice:example.org", 1, text_content("hi"));
        timeline.prepend_back_page(&[target], Some("t1".to_string()));

        let target_id = EventId::parse("$target:example.org").expect("valid event id");
        let item = timeline.item_by_event_id(&target_id).expect("target now loaded");
        assert_eq!(
            item.relations.reactions.get("\u{1F44D}").map(std::collections::BTreeSet::len),
            Some(1),
            "the pending reaction applied once its target loaded"
        );
    }

    #[test]
    fn edit_seen_before_its_target_applies_later() {
        let mut timeline = Timeline::new();
        let edit = raw_event(
            "$edit:example.org",
            "m.room.message",
            "@alice:example.org",
            10,
            serde_json::json!({
                "msgtype": "m.text",
                "body": "* edited",
                "m.new_content": { "msgtype": "m.text", "body": "edited" },
                "m.relates_to": { "rel_type": "m.replace", "event_id": "$target:example.org" }
            }),
        );
        timeline.apply_timeline_batch(&[edit], false, None);
        assert!(timeline.items().is_empty(), "an accepted edit never gets its own row, pending or not");

        let target = raw_event("$target:example.org", "m.room.message", "@alice:example.org", 1, text_content("original"));
        timeline.prepend_back_page(&[target], None);

        let target_id = EventId::parse("$target:example.org").expect("valid event id");
        let item = timeline.item_by_event_id(&target_id).expect("target now loaded");
        let latest = item.relations.latest_edit.as_ref().expect("the pending edit applied once its target loaded");
        assert_eq!(
            latest.content,
            RoomMessageContent::Text(TextLikeMessageContent {
                body: "edited".to_string(),
                format: None,
                formatted_body: None
            })
        );
    }

    #[test]
    fn redaction_seen_before_its_target_applies_later() {
        let mut timeline = Timeline::new();
        let redaction = raw_event(
            "$redaction:example.org",
            "m.room.redaction",
            "@mod:example.org",
            10,
            serde_json::json!({ "redacts": "$target:example.org" }),
        );
        timeline.apply_timeline_batch(&[redaction], false, None);
        assert!(timeline.items().is_empty(), "a redaction never gets its own row, pending or not");

        let target = raw_event("$target:example.org", "m.room.message", "@alice:example.org", 1, text_content("hi"));
        timeline.prepend_back_page(&[target], None);

        let target_id = EventId::parse("$target:example.org").expect("valid event id");
        let item = timeline.item_by_event_id(&target_id).expect("target now loaded");
        assert!(item.redacted, "the pending redaction applied once its target loaded");
        assert_eq!(item.content, ItemContent::Redacted);
    }

    fn encrypted_placeholder(event_id: &str, sender: &str, extra: serde_json::Value) -> RawEvent {
        let mut content = serde_json::json!({
            "algorithm": "m.megolm.v1.aes-sha2",
            "ciphertext": "AAAA",
            "session_id": "session-1",
        });
        if let (Some(target), Some(extra)) = (content.as_object_mut(), extra.as_object()) {
            target.extend(extra.clone());
        }
        raw_event(event_id, "m.room.encrypted", sender, 1, content)
    }

    fn event_id(value: &str) -> EventId {
        EventId::parse(value).expect("valid event id")
    }

    fn forwarded_of(timeline: &Timeline, id: &str) -> Option<Forwarded> {
        timeline.item_by_event_id(&event_id(id)).expect("present").forwarded.clone()
    }

    #[test]
    fn unrecognized_event_and_msgtype_stay_unknown() {
        let mut timeline = Timeline::new();
        let sticker = raw_event(
            "$sticker:example.org",
            "m.sticker",
            "@alice:example.org",
            1,
            serde_json::json!({ "body": "Bull", "url": "mxc://example.org/sticker" }),
        );
        timeline.apply_timeline_batch(&[sticker], false, None);
        let item = timeline.item_by_event_id(&event_id("$sticker:example.org")).expect("present");
        assert_eq!(item.content, ItemContent::Unknown);
        assert_eq!(item.raw_content.get("url").and_then(serde_json::Value::as_str), Some("mxc://example.org/sticker"));

        let image = serde_json::json!({ "msgtype": "m.image", "body": "x.png", "url": "mxc://example.org/a" });
        assert_eq!(interpret_content(EVENT_ROOM_MESSAGE, None, &image), ItemContent::Unknown);
        let other = serde_json::json!({ "msgtype": "com.example.card", "body": "card", "symbol": "BTCUSDT" });
        assert_eq!(interpret_content(EVENT_ROOM_MESSAGE, None, &other), ItemContent::Unknown);
    }

    #[test]
    fn forwarded_markers_parse_to_hidden_and_channel() {
        let mut timeline = Timeline::new();
        let hidden = raw_event(
            "$hidden:example.org",
            "m.room.message",
            "@alice:example.org",
            1,
            serde_json::json!({ "msgtype": "m.text", "body": "fwd", "forwarded": true }),
        );
        let channel = raw_event(
            "$channel:example.org",
            "m.room.message",
            "@alice:example.org",
            2,
            serde_json::json!({
                "msgtype": "m.text",
                "body": "fwd",
                "forwarded_from": { "room_id": "!chan:example.org", "room_name": "Announcements" },
            }),
        );
        let sticker = raw_event(
            "$sticker:example.org",
            "m.sticker",
            "@alice:example.org",
            3,
            serde_json::json!({
                "body": "Bull",
                "url": "mxc://example.org/bull",
                "info": { "pack": "trader", "id": "bull" },
                "forwarded": true,
            }),
        );
        let plain = raw_event("$plain:example.org", "m.room.message", "@alice:example.org", 4, text_content("plain"));
        let denied = raw_event(
            "$denied:example.org",
            "m.room.message",
            "@alice:example.org",
            5,
            serde_json::json!({ "msgtype": "m.text", "body": "x", "forwarded": false }),
        );
        timeline.apply_timeline_batch(&[hidden, channel, sticker, plain, denied], false, None);

        assert_eq!(forwarded_of(&timeline, "$hidden:example.org"), Some(Forwarded::Hidden));
        assert_eq!(
            forwarded_of(&timeline, "$channel:example.org"),
            Some(Forwarded::Channel {
                room_id: RoomId::parse("!chan:example.org").expect("valid room id"),
                room_name: "Announcements".to_string(),
            })
        );
        assert_eq!(forwarded_of(&timeline, "$sticker:example.org"), None, "an unrecognized event type is not a forward");
        assert_eq!(forwarded_of(&timeline, "$plain:example.org"), None);
        assert_eq!(forwarded_of(&timeline, "$denied:example.org"), None, "only `true` marks a forward");

        // The marker of an encrypted event lives in the plaintext only: a
        // marker in the cleartext envelope is ignored, the one inside the
        // decrypted content counts.
        let sealed = encrypted_placeholder(
            "$sealed:example.org",
            "@bob:example.org",
            serde_json::json!({ "forwarded": true }),
        );
        timeline.apply_timeline_batch(&[sealed], false, None);
        assert_eq!(forwarded_of(&timeline, "$sealed:example.org"), None);
        timeline.set_decrypted_event(
            &event_id("$sealed:example.org"),
            "m.room.message",
            &serde_json::json!({ "msgtype": "m.text", "body": "fwd", "forwarded": true }),
        );
        assert_eq!(forwarded_of(&timeline, "$sealed:example.org"), Some(Forwarded::Hidden));

        // A local echo shows its own marker before the server echoes it.
        timeline.push_local_echo(
            TxnId::new(7),
            UserId::parse("@alice:example.org").expect("valid user id"),
            10,
            EVENT_ROOM_MESSAGE,
            ItemContent::Unknown,
            serde_json::json!({ "msgtype": "m.text", "body": "fwd", "forwarded": true }),
        );
        let echo = timeline.items().last().expect("echo pushed");
        assert_eq!(echo.forwarded, Some(Forwarded::Hidden));

        // Redaction strips the marker with the content.
        timeline.apply_redaction(&event_id("$hidden:example.org"));
        assert_eq!(forwarded_of(&timeline, "$hidden:example.org"), None);
        timeline.apply_redaction(&event_id("$sealed:example.org"));
        assert_eq!(forwarded_of(&timeline, "$sealed:example.org"), None);
    }

    #[test]
    fn malformed_forwarded_from_is_ignored() {
        let bad_markers = [
            serde_json::json!("a string"),
            serde_json::json!(42),
            serde_json::json!({}),
            serde_json::json!({ "room_id": "!chan:example.org" }),
            serde_json::json!({ "room_name": "Announcements" }),
            serde_json::json!({ "room_id": 5, "room_name": "Announcements" }),
            serde_json::json!({ "room_id": "not a room id", "room_name": "Announcements" }),
            serde_json::json!({ "room_id": "!chan:example.org", "room_name": null }),
        ];
        let mut timeline = Timeline::new();
        for (n, marker) in bad_markers.iter().enumerate() {
            let id = format!("$bad{n}:example.org");
            let event = raw_event(
                &id,
                "m.room.message",
                "@alice:example.org",
                n as i64,
                serde_json::json!({ "msgtype": "m.text", "body": "still readable", "forwarded_from": marker }),
            );
            timeline.apply_timeline_batch(&[event], false, None);
            let item = timeline.item_by_event_id(&event_id(&id)).expect("the event still decodes");
            assert_eq!(item.forwarded, None, "malformed marker {marker} is ignored");
            assert!(matches!(item.content, ItemContent::Text(_)), "the message itself is untouched by a bad marker");
        }

        // A bad `forwarded_from` does not mask a well-formed `forwarded: true`
        // next to it: the safe reading (no origin shown) still applies.
        let both = raw_event(
            "$both:example.org",
            "m.room.message",
            "@alice:example.org",
            99,
            serde_json::json!({
                "msgtype": "m.text",
                "body": "x",
                "forwarded": true,
                "forwarded_from": "garbage",
            }),
        );
        timeline.apply_timeline_batch(&[both], false, None);
        assert_eq!(timeline.item_by_event_id(&event_id("$both:example.org")).expect("present").forwarded, Some(Forwarded::Hidden));
    }

    #[test]
    fn pending_relations_are_bounded() {
        let mut timeline = Timeline::new();

        // Queue PENDING_CAPACITY + 1 reactions, each targeting its own
        // never-loaded event id, oldest first.
        for n in 0..=PENDING_CAPACITY {
            let target = format!("$target{n}:example.org");
            let reaction = raw_event(
                &format!("$reaction{n}:example.org"),
                "m.reaction",
                "@alice:example.org",
                n as i64,
                serde_json::json!({
                    "m.relates_to": { "rel_type": "m.annotation", "event_id": target, "key": "\u{1F44D}" }
                }),
            );
            timeline.apply_timeline_batch(std::slice::from_ref(&reaction), false, None);
        }

        assert_eq!(timeline.pending_relation_order.len(), PENDING_CAPACITY, "bounded at capacity");

        // The very first (oldest) target's pending contribution was
        // evicted -- loading it now shows no reaction at all.
        let oldest_target =
            raw_event("$target0:example.org", "m.room.message", "@alice:example.org", 0, text_content("oldest"));
        timeline.prepend_back_page(&[oldest_target], None);
        let oldest_id = EventId::parse("$target0:example.org").expect("valid event id");
        assert!(
            timeline.item_by_event_id(&oldest_id).expect("present").relations.reactions.is_empty(),
            "the oldest pending contribution was evicted, never applied"
        );

        // The most recently queued target's contribution survived the
        // bound and still applies.
        let newest_target_id_str = format!("$target{PENDING_CAPACITY}:example.org");
        let newest_target = raw_event(&newest_target_id_str, "m.room.message", "@alice:example.org", 0, text_content("newest"));
        timeline.prepend_back_page(&[newest_target], None);
        let newest_id = EventId::parse(&newest_target_id_str).expect("valid event id");
        assert_eq!(
            timeline
                .item_by_event_id(&newest_id)
                .expect("present")
                .relations
                .reactions
                .get("\u{1F44D}")
                .map(std::collections::BTreeSet::len),
            Some(1),
            "the most recently queued pending contribution survived the bound"
        );
    }
}
