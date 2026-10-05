//! [`OutgoingQueue`] — the outgoing HTTP request queue: per-lane ordering,
//! idempotent retries with capped exponential backoff, and
//! [`crate::store::StateStore`]-backed crash safety (plan §5, M12).
//!
//! # Contract
//!
//! This module owns none of the flush-epoch machinery itself (that's
//! [`crate::persist::FlushEpoch`], M1/this piece's own extension of it) and
//! performs no I/O: [`OutgoingQueue::releasable`] hands back plain
//! [`crate::wire::OutgoingRequest`] values for a shell to execute;
//! [`OutgoingQueue::on_response`]/[`OutgoingQueue::on_transport_error`] take
//! the shell's result back in. `now_ms` is always an explicit input — this
//! module never calls a clock itself (same rule as [`crate::ids`]'s
//! monotonic-sequence inputs).
//!
//! # Lanes
//!
//! Every pending request belongs to exactly one [`Lane`], which decides how
//! many of that lane's requests may be in flight at once:
//!
//! | Lane | In flight at once | Why |
//! |---|---|---|
//! | [`Lane::Sync`] | 1 (global) | Only one `/sync` long-poll makes sense at a time. |
//! | [`Lane::ToDevice`] | 1 (global) | Per-device Olm ratchets are consumed in a strict sequence; two to-device sends racing (including a retry racing the next fresh send) would desynchronize a peer's ratchet. |
//! | [`Lane::Room`]`(room_id)` | 1 per room | Preserves the room's own send order (and, for encrypted rooms, its Megolm ratchet order) without serializing unrelated rooms against each other. |
//! | [`Lane::AccountData`] | 1 (global), strict FIFO | Every account-data write replaces the WHOLE value under its `(room, type)` key, so two racing PUTs (or a retry overtaken by a later PUT) would silently lose an update: a later request in this lane never overtakes an earlier one, not even while the earlier one is backing off before a retry. |
//! | [`Lane::Other`] | up to [`OTHER_LANE_CONCURRENCY`] | Everything with no ordering requirement of its own (profile lookups, user-directory search, `/keys/query`, ...) — bounded so this queue cannot flood a homeserver with unlimited concurrent calls. |
//!
//! [`OutgoingQueue::releasable`] always returns requests in the order they
//! were enqueued (see "Restart" below for how that order survives a
//! reload), skipping any whose lane is currently occupied, whose flush
//! epoch is not yet satisfied ([`crate::persist::FlushEpoch::is_released`]),
//! or whose retry backoff has not yet elapsed.
//!
//! # Retry policy
//!
//! [`OutgoingQueue::on_response`] classifies a shell-supplied
//! [`crate::wire::HttpResponseDescriptor`]:
//!
//! - **2xx** → [`ResponseOutcome::Done`] — the pending record is deleted.
//! - **429** → [`ResponseOutcome::Retry`], using the response body's own
//!   `retry_after_ms` (Matrix's `M_LIMIT_EXCEEDED` shape) if present,
//!   falling back to this queue's own capped exponential backoff otherwise.
//! - **5xx**, or [`OutgoingQueue::on_transport_error`] (no response at
//!   all) → [`ResponseOutcome::Retry`] with this queue's own capped
//!   exponential backoff: `min(60_000, 1000 * 2^attempt)` milliseconds,
//!   jittered to `[50%, 100%]` of that value by an injected
//!   [`Jitter`] source (never a global RNG — this crate keeps no hidden
//!   shared mutable state, same rule as [`crate::ids`]'s `TxnId`/
//!   `RequestId`). `attempt` counts this request's own retry attempts and
//!   is capped at `6` internally (`1000 * 2^6 = 64_000` already exceeds the
//!   60s ceiling), so backoff saturates rather than growing unbounded.
//! - Anything else (4xx other than 429, and any other unexpected status) →
//!   [`ResponseOutcome::Failed`] — the pending record is deleted; the
//!   caller (a later piece, `sync_engine`/`MessengerCore`) maps this to
//!   e.g. `SendState::Failed`.
//!
//! A retry always resends the **identical** [`crate::wire::OutgoingRequest`]
//! this queue already has pending — same `txnId` baked into the path, same
//! body — never re-encrypted, never re-minted. [`OutgoingQueue`] does not
//! (and cannot, from this layer) tell a caller to re-encrypt; it simply
//! never discards or mutates a pending request's own bytes between
//! [`OutgoingQueue::releasable`] calls.
//!
//! # Restart
//!
//! [`OutgoingQueue::load`] rebuilds a queue from
//! [`crate::store::StateStore::pending_requests`], with **none** marked in
//! flight (a crash mid-flight means the shell doesn't know whether the
//! previous attempt reached the server) and **no** retry backoff carried
//! over (backoff state is deliberately ephemeral — see [`OutgoingQueue`]'s
//! own fields). Resending after a restart is safe because every mutating
//! Matrix endpoint this crate calls is either server-side idempotent on its
//! own `txnId` (room sends, redactions, to-device sends) or safely
//! re-uploadable as identical bytes (`/keys/upload`, per M5's design) —
//! **except** `/keys/claim`, whose resend may consume a *different*
//! one-time key than the original attempt did; this is an accepted,
//! documented cost (a claimed-but-unused OTK is simply wasted, not a
//! correctness bug) rather than a reason to special-case restart recovery.
//! `/sync` itself is never persisted as a pending request in the first
//! place — a fresh `/sync` (using the durable `sync_token`, a separate
//! [`crate::store::StateStore`] record) is always reissued instead of
//! resumed.
//!
//! [`OutgoingQueue::load`] recovers **enqueue order** from
//! [`crate::store::StateStore::pending_requests`] by sorting on
//! [`crate::ids::RequestId`]'s own `Ord` rather than persisting a
//! redundant sequence field: `RequestId` is documented (`ids` module doc)
//! to be minted from one caller-owned, strictly increasing counter per
//! process, and its fixed-width-hex encoding keeps that counter's order
//! exactly lexicographic (`ids` module's own
//! `txn_id_and_request_id_are_monotonic_and_distinct_namespaces` test).
//! This holds as long as every `RequestId` a `MessengerCore` mints for its
//! whole lifetime comes from that one counter, never reused or reset — a
//! precondition `MessengerCore` (a later piece, M13) is responsible for.
//!
//! # Flush epoch integration
//!
//! [`OutgoingQueue::enqueue`] is the one place this queue touches
//! [`crate::persist::FlushEpoch`]: it calls
//! [`crate::persist::FlushEpoch::seal_for_request`] **before** persisting
//! the new pending record, so the returned [`crate::persist::RequiredSeq`]
//! only ever covers mutations that predate this request (never the
//! request's own about-to-be-created pending record — that record's
//! durability is a separate, ordinary flush the next
//! [`crate::persist::FlushEpoch::seal_for_request`]/
//! [`crate::persist::FlushGate::take_batch`] call will pick up). See
//! `persist`'s module doc for the full per-request epoch rule and a worked
//! timeline.
//!
//! One consequence worth calling out: [`crate::store::Store`]'s
//! [`FlushEpoch`] does not distinguish "a real state mutation" from
//! "another request's own not-yet-batched pending-request record" — both
//! are just dirty [`crate::persist::RecordKey`] entries to
//! [`FlushEpoch::seal_for_request`]. So enqueuing two requests back to back
//! with no flush/ack in between makes the *second* one's `required_seq`
//! cover the *first* one's own bookkeeping write (sealed as a side effect
//! of the second's own `enqueue` call). This is benign, not a bug: it
//! self-resolves the moment a shell performs its normal flush/ack tick
//! (which every driving loop — a later piece, `sync_engine` — does
//! regardless), and it never affects [`RequiredSeq::NONE`] requests (a
//! request enqueued with nothing pending at all, e.g. the very first
//! request of a session).

use crate::ids::{RequestId, RoomId};
use crate::persist::{FlushBatch, FlushEpoch, RequiredSeq};
use crate::store::{StateStore, StoreError};
use crate::wire::{HttpResponseDescriptor, OutgoingRequest, OutgoingRequestKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How many [`Lane::Other`] requests may be in flight at once.
const OTHER_LANE_CONCURRENCY: usize = 4;

/// Retry backoff floor: the smallest possible backoff (before jitter can
/// shrink it toward half of this), used at the first retry attempt.
const BACKOFF_BASE_MS: u64 = 1_000;

/// Retry backoff ceiling: no computed backoff, regardless of attempt count
/// or jitter, ever exceeds this.
const BACKOFF_CAP_MS: u64 = 60_000;

/// Which ordering class a pending request belongs to — see the module
/// doc's "Lanes" table for the exact in-flight limit and rationale of each
/// variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lane {
    /// `GET /sync` — at most one in flight.
    Sync,
    /// `PUT /sendToDevice/...` — strictly ordered, at most one in flight
    /// globally (preserves per-device Olm ratchet order across retries).
    ToDevice,
    /// A room-scoped call — ordered per room, at most one in flight per
    /// room id.
    Room(RoomId),
    /// Every account-data write (`PUT .../account_data/...`, global and
    /// room-scoped) -- strictly FIFO, at most one in flight. A record
    /// persisted before this lane existed carries [`Lane::Other`] instead;
    /// [`OutgoingQueue::load`] moves those into this lane.
    AccountData,
    /// Everything else — unordered, bounded concurrency
    /// ([`OTHER_LANE_CONCURRENCY`]).
    Other,
}

/// One request this queue is tracking: its wire shape, which [`Lane`] it
/// belongs to, and the [`RequiredSeq`] it must wait on before it may ever
/// be released. Persisted via [`crate::store::StateStore::save_pending_request`]
/// so it survives a crash — see the module doc's "Restart" section for
/// exactly what survives and what doesn't.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// The request itself — resent byte-for-byte on every retry.
    pub request: OutgoingRequest,
    /// Which lane governs this request's ordering/concurrency.
    pub lane: Lane,
    /// The flush epoch this request must wait on before release — see the
    /// module doc's "Flush epoch integration" section.
    pub required_seq: RequiredSeq,
}

/// What happened to a request after a shell fed its result back in via
/// [`OutgoingQueue::on_response`] or [`OutgoingQueue::on_transport_error`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// A 2xx response. The pending record has already been deleted.
    Done(HttpResponseDescriptor),
    /// The request should be retried (unchanged) after `after_ms`
    /// milliseconds. The pending record is still tracked; this queue
    /// itself will not offer it again via [`OutgoingQueue::releasable`]
    /// until `after_ms` has elapsed (per the `now_ms` the caller supplies
    /// to that call).
    Retry {
        /// How long to wait before this request may be retried.
        after_ms: u64,
    },
    /// A non-retryable error response. The pending record has already
    /// been deleted; the caller maps `errcode`/`error` to its own
    /// user-facing failure state.
    Failed {
        /// The Matrix `errcode` (e.g. `"M_FORBIDDEN"`), or `"M_UNKNOWN"`
        /// if the body did not carry one.
        errcode: String,
        /// The Matrix `error` human-readable string, empty if absent.
        error: String,
    },
}

/// A source of jitter for retry backoff, injected explicitly rather than
/// reaching for a global RNG — this crate keeps no hidden shared mutable
/// state (same rule as [`crate::ids`]'s `TxnId`/`RequestId`). Implementors
/// return a value in `[0.0, 1.0]`; a shell wires in a real RNG, tests wire
/// in a deterministic fake.
pub trait Jitter {
    /// The next jitter sample, in `[0.0, 1.0]`. Values outside that range
    /// are clamped by the caller.
    fn next_unit(&mut self) -> f64;
}

/// Computes `min(60_000, 1000 * 2^attempt)` milliseconds, then jitters the
/// result to `[50%, 100%]` of that value using `jitter_unit` (clamped to
/// `[0.0, 1.0]`), then re-caps (jitter can only shrink the value here, but
/// the re-cap keeps this function correct even if that ever changes).
/// `attempt` is capped at `6` internally: `1000 * 2^6 = 64_000` already
/// exceeds [`BACKOFF_CAP_MS`], so every attempt from `6` onward computes
/// the same, fully-capped value — this is "capped exponential", not
/// "exponential forever".
fn capped_exponential_backoff_ms(attempt: u32, jitter_unit: f64) -> u64 {
    let shift = attempt.min(6);
    let base = BACKOFF_BASE_MS.saturating_mul(1u64 << shift).min(BACKOFF_CAP_MS);
    let unit = jitter_unit.clamp(0.0, 1.0);
    let jittered = (base as f64 * (0.5 + 0.5 * unit)).round() as u64;
    jittered.min(BACKOFF_CAP_MS)
}

/// Reads a `retry_after_ms` field out of a Matrix-shaped error body (the
/// `M_LIMIT_EXCEEDED` response's own extension field), if present.
fn retry_after_ms_from_body(response: &HttpResponseDescriptor) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(&response.body).ok()?;
    value.get("retry_after_ms")?.as_u64()
}

/// The outgoing HTTP request queue — see the module doc.
#[derive(Debug, Default)]
pub struct OutgoingQueue {
    /// Enqueue order, across every lane. Entries for completed requests
    /// are removed as soon as they complete (see `complete`); a stale
    /// entry (one whose id is no longer in `pending`) is otherwise
    /// impossible.
    order: Vec<RequestId>,
    /// Every currently-pending request, keyed by its own id.
    pending: BTreeMap<RequestId, PendingRequest>,
    /// Every id currently released (handed out by `releasable` and not
    /// yet completed or retried) — prevents re-releasing the same request
    /// concurrently.
    in_flight: BTreeSet<RequestId>,
    sync_in_flight: bool,
    to_device_in_flight: bool,
    room_in_flight: BTreeSet<RoomId>,
    other_in_flight: BTreeSet<RequestId>,
    /// How many times each pending request has been retried so far — feeds
    /// [`capped_exponential_backoff_ms`]. Deliberately NOT persisted: see
    /// the module doc's "Restart" section.
    attempts: BTreeMap<RequestId, u32>,
    /// The earliest `now_ms` at which a retried request may be released
    /// again. Deliberately NOT persisted, for the same reason as
    /// `attempts`.
    retry_not_before_ms: BTreeMap<RequestId, i64>,
}

impl OutgoingQueue {
    /// Builds an empty queue — the brand-new-device case. A shell with an
    /// existing store calls [`OutgoingQueue::load`] instead.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds a queue from `store`'s durably-persisted pending requests.
    /// See the module doc's "Restart" section for exactly what survives
    /// (enqueue order, lanes, flush epochs) and what doesn't (in-flight
    /// status, retry backoff).
    pub fn load<S: StateStore>(store: &S) -> Result<Self, StoreError> {
        let mut records = store.pending_requests()?;
        records.sort_by(|a, b| a.request.id.cmp(&b.request.id));
        let mut queue = Self::new();
        for mut record in records {
            // Account-data writes persisted before `Lane::AccountData`
            // existed were enqueued on `Lane::Other`; they must keep their
            // relative order after an upgrade too.
            if record.lane == Lane::Other
                && matches!(record.request.kind, OutgoingRequestKind::AccountData | OutgoingRequestKind::RoomAccountData)
            {
                record.lane = Lane::AccountData;
            }
            let id = record.request.id.clone();
            queue.order.push(id.clone());
            queue.pending.insert(id, record);
        }
        Ok(queue)
    }

    /// Drops every pending request of `kind` (from the queue and from
    /// `store`). For a kind whose request carries no side effect a restart
    /// could lose -- `/sync` -- so a core can mint a fresh one from current
    /// state instead of replaying a stale one.
    pub fn discard_kind<S: StateStore>(&mut self, store: &mut S, kind: OutgoingRequestKind) -> Result<(), StoreError> {
        let ids: Vec<RequestId> = self.pending.iter().filter(|(_, record)| record.request.kind == kind).map(|(id, _)| id.clone()).collect();
        for id in ids {
            self.complete(store, &id)?;
        }
        Ok(())
    }

    /// Enqueues `request` on `lane`, persisting it via
    /// [`crate::store::StateStore::save_pending_request`] so it survives a
    /// crash before ever being acknowledged. Idempotent on `request.id`:
    /// enqueuing the same id twice (a duplicate dispatch) is a safe no-op
    /// the second time — `Ok(None)` either because nothing was pending to
    /// seal at the time, or because the id was already tracked; both cases
    /// leave this queue and `store` unchanged from the first call's
    /// result, so callers never need to distinguish them.
    ///
    /// Returns whatever [`FlushBatch`] `store`'s flush epoch forced open
    /// (see [`FlushEpoch::seal_for_request`]) for the caller to hand a
    /// shell — `None` if nothing was pending to seal.
    pub fn enqueue<S: StateStore + FlushEpoch>(
        &mut self,
        store: &mut S,
        request: OutgoingRequest,
        lane: Lane,
    ) -> Result<Option<FlushBatch>, StoreError> {
        if self.pending.contains_key(&request.id) {
            return Ok(None);
        }
        let (required_seq, batch) = store.seal_for_request();
        let id = request.id.clone();
        let record = PendingRequest { request, lane, required_seq };
        store.save_pending_request(record.clone())?;
        self.pending.insert(id.clone(), record);
        self.order.push(id);
        Ok(batch)
    }

    /// Every request currently safe to send, in enqueue order: releasable
    /// means not already in flight, its lane currently has room (see the
    /// module doc's "Lanes" table), its flush epoch is satisfied
    /// ([`FlushEpoch::is_released`]), and — for a request that has been
    /// retried before — its backoff has elapsed as of `now_ms`. Every
    /// returned request is marked in flight; a caller that fails to
    /// execute one must eventually call [`OutgoingQueue::on_transport_error`]
    /// (or [`OutgoingQueue::on_response`]) to release its lane again.
    pub fn releasable<S: FlushEpoch>(&mut self, store: &S, now_ms: i64) -> Vec<OutgoingRequest> {
        let mut out = Vec::new();
        let ids = self.order.clone();
        let mut account_data_blocked = false;
        for id in ids {
            let Some(pending) = self.pending.get(&id) else { continue };
            if pending.lane == Lane::AccountData {
                // Strict FIFO: only the head of this lane is ever a
                // candidate, whatever state it is in (in flight, backing
                // off, waiting on its flush) -- everything behind it waits.
                if account_data_blocked {
                    continue;
                }
                account_data_blocked = true;
            }
            if self.in_flight.contains(&id) {
                continue;
            }
            if let Some(&not_before) = self.retry_not_before_ms.get(&id) {
                if now_ms < not_before {
                    continue;
                }
            }
            if !store.is_released(pending.required_seq) {
                continue;
            }
            if !self.lane_available(&pending.lane) {
                continue;
            }
            let request = pending.request.clone();
            let lane = pending.lane.clone();
            self.mark_in_flight(&id, &lane);
            out.push(request);
        }
        out
    }

    /// Feeds one HTTP response back in for `request_id`. Returns `Ok(None)`
    /// if `request_id` is not (or no longer) pending — a duplicate or
    /// stale response is safely ignored. See the module doc's "Retry
    /// policy" section for the exact status-code classification.
    pub fn on_response<S: StateStore>(
        &mut self,
        store: &mut S,
        request_id: &RequestId,
        response: HttpResponseDescriptor,
        now_ms: i64,
        jitter: &mut dyn Jitter,
    ) -> Result<Option<ResponseOutcome>, StoreError> {
        let Some(pending) = self.pending.get(request_id).cloned() else { return Ok(None) };

        if (200..300).contains(&response.status) {
            self.complete(store, request_id)?;
            return Ok(Some(ResponseOutcome::Done(response)));
        }

        if response.status == 429 {
            self.clear_in_flight(request_id, &pending.lane);
            let after_ms =
                retry_after_ms_from_body(&response).unwrap_or_else(|| self.next_backoff_ms(request_id, jitter));
            self.retry_not_before_ms.insert(request_id.clone(), now_ms.saturating_add(after_ms as i64));
            return Ok(Some(ResponseOutcome::Retry { after_ms }));
        }

        if (500..600).contains(&response.status) {
            self.clear_in_flight(request_id, &pending.lane);
            let after_ms = self.next_backoff_ms(request_id, jitter);
            self.retry_not_before_ms.insert(request_id.clone(), now_ms.saturating_add(after_ms as i64));
            return Ok(Some(ResponseOutcome::Retry { after_ms }));
        }

        let (errcode, error) =
            response.matrix_error().unwrap_or_else(|| ("M_UNKNOWN".to_string(), String::new()));
        self.complete(store, request_id)?;
        Ok(Some(ResponseOutcome::Failed { errcode, error }))
    }

    /// Feeds a transport-level failure back in (no response at all — a
    /// timeout, a connection reset, ...). Always a
    /// [`ResponseOutcome::Retry`] with this queue's own capped exponential
    /// backoff. Returns `None` if `request_id` is not (or no longer)
    /// pending.
    pub fn on_transport_error(
        &mut self,
        request_id: &RequestId,
        now_ms: i64,
        jitter: &mut dyn Jitter,
    ) -> Option<ResponseOutcome> {
        let pending = self.pending.get(request_id)?.clone();
        self.clear_in_flight(request_id, &pending.lane);
        let after_ms = self.next_backoff_ms(request_id, jitter);
        self.retry_not_before_ms.insert(request_id.clone(), now_ms.saturating_add(after_ms as i64));
        Some(ResponseOutcome::Retry { after_ms })
    }

    fn next_backoff_ms(&mut self, request_id: &RequestId, jitter: &mut dyn Jitter) -> u64 {
        let attempt = self.attempts.entry(request_id.clone()).or_insert(0);
        let ms = capped_exponential_backoff_ms(*attempt, jitter.next_unit());
        *attempt = attempt.saturating_add(1);
        ms
    }

    fn lane_available(&self, lane: &Lane) -> bool {
        match lane {
            Lane::Sync => !self.sync_in_flight,
            Lane::ToDevice => !self.to_device_in_flight,
            Lane::Room(room_id) => !self.room_in_flight.contains(room_id),
            // Head-of-line ordering is enforced in `releasable` itself.
            Lane::AccountData => true,
            Lane::Other => self.other_in_flight.len() < OTHER_LANE_CONCURRENCY,
        }
    }

    fn mark_in_flight(&mut self, id: &RequestId, lane: &Lane) {
        match lane {
            Lane::Sync => self.sync_in_flight = true,
            Lane::ToDevice => self.to_device_in_flight = true,
            Lane::Room(room_id) => {
                self.room_in_flight.insert(room_id.clone());
            }
            Lane::AccountData => {}
            Lane::Other => {
                self.other_in_flight.insert(id.clone());
            }
        }
        self.in_flight.insert(id.clone());
    }

    fn clear_in_flight(&mut self, id: &RequestId, lane: &Lane) {
        match lane {
            Lane::Sync => self.sync_in_flight = false,
            Lane::ToDevice => self.to_device_in_flight = false,
            Lane::Room(room_id) => {
                self.room_in_flight.remove(room_id);
            }
            Lane::AccountData => {}
            Lane::Other => {
                self.other_in_flight.remove(id);
            }
        }
        self.in_flight.remove(id);
    }

    fn complete<S: StateStore>(&mut self, store: &mut S, id: &RequestId) -> Result<(), StoreError> {
        if let Some(pending) = self.pending.remove(id) {
            self.clear_in_flight(id, &pending.lane);
            self.attempts.remove(id);
            self.retry_not_before_ms.remove(id);
            self.order.retain(|existing| existing != id);
            store.delete_pending_request(id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{DeviceId, RequestId, RoomId, TxnId};
    use crate::store::{CryptoStore, InsecurePlainCodecForTests, Store};
    use crate::wire::OutgoingRequest;

    struct FixedJitter(f64);

    impl Jitter for FixedJitter {
        fn next_unit(&mut self) -> f64 {
            self.0
        }
    }

    fn device_id() -> DeviceId {
        DeviceId::parse("DEV1").expect("valid device id")
    }

    fn room_id() -> RoomId {
        RoomId::parse("!room:example.org").expect("valid room id")
    }

    #[test]
    fn pending_request_survives_a_fresh_core_construction_before_ack() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();

        let request = OutgoingRequest::sync(RequestId::next(0), None, None);
        queue.enqueue(&mut store, request.clone(), Lane::Sync).expect("enqueue succeeds");

        // The shell reads back whatever bytes it durably wrote -- WITHOUT
        // ever acking the old, about-to-be-discarded store's FlushGate.
        let batch = store.take_flush_batch().expect("save_pending_request dirtied a record");
        let reloaded =
            Store::load(batch.records, InsecurePlainCodecForTests, device_id()).expect("load succeeds");

        let mut restored = OutgoingQueue::load(&reloaded).expect("queue reloads");
        assert_eq!(restored.releasable(&reloaded, 0), vec![request]);
    }

    #[test]
    fn discard_kind_drops_the_restored_sync_but_keeps_other_requests() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let sync = OutgoingRequest::sync(RequestId::next(0), Some("s1"), Some(30_000));
        let join = OutgoingRequest::join_room(RequestId::next(1), room_id().as_str());
        queue.enqueue(&mut store, sync, Lane::Sync).expect("enqueue sync");
        queue.enqueue(&mut store, join.clone(), Lane::Other).expect("enqueue join");
        let batch = store.take_flush_batch().expect("pending requests dirtied records");
        let mut reloaded = Store::load(batch.records, InsecurePlainCodecForTests, device_id()).expect("load succeeds");

        let mut restored = OutgoingQueue::load(&reloaded).expect("queue reloads");
        restored.discard_kind(&mut reloaded, OutgoingRequestKind::Sync).expect("discard succeeds");

        assert_eq!(restored.releasable(&reloaded, 0), vec![join], "only the non-sync request is left");
        let stored: Vec<OutgoingRequestKind> = reloaded.pending_requests().expect("no error").iter().map(|record| record.request.kind).collect();
        assert_eq!(stored, vec![OutgoingRequestKind::JoinRoom], "the sync record is gone from the store too");
    }

    #[test]
    fn duplicate_dispatch_does_not_double_enqueue() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let request = OutgoingRequest::sync(RequestId::next(0), None, None);

        queue.enqueue(&mut store, request.clone(), Lane::Sync).expect("first enqueue");
        queue.enqueue(&mut store, request.clone(), Lane::Sync).expect("duplicate enqueue is a no-op");

        assert_eq!(store.pending_requests().expect("no error").len(), 1, "only one record persisted");
        assert_eq!(queue.releasable(&store, 0).len(), 1, "only one request queued for release");
    }

    #[test]
    fn sync_is_not_blocked_by_mutations_made_after_it_was_enqueued() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();

        let sync_req = OutgoingRequest::sync(RequestId::next(0), None, None);
        queue.enqueue(&mut store, sync_req.clone(), Lane::Sync).expect("enqueue sync");
        if let Some(batch) = store.take_flush_batch() {
            store.ack_flush(batch.id);
        }

        // A later, unrelated mutation happens AFTER the sync was already
        // enqueued -- and is never even flushed, let alone acked.
        store.save_account(b"later-mutation".to_vec()).expect("save succeeds");

        assert_eq!(
            queue.releasable(&store, 0),
            vec![sync_req],
            "the sync never depended on a mutation made after it was enqueued"
        );
    }

    #[test]
    fn send_is_blocked_until_the_flush_containing_its_ratchet_advance_is_acked() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let room = room_id();

        // A Megolm ratchet advance happens just before the send is minted.
        store.save_outbound_group_session(&room, b"ratchet-v1".to_vec()).expect("save succeeds");

        let send_req = OutgoingRequest::room_send(
            RequestId::next(1),
            &room,
            "m.room.encrypted",
            &TxnId::new(0),
            serde_json::json!({ "ciphertext": "..." }),
        );
        let batch = queue
            .enqueue(&mut store, send_req.clone(), Lane::Room(room.clone()))
            .expect("enqueue succeeds")
            .expect("the pending ratchet advance was sealed into a batch");

        assert!(queue.releasable(&store, 0).is_empty(), "blocked: the sealed batch is not yet acked");

        store.ack_flush(batch.id);
        assert_eq!(queue.releasable(&store, 0), vec![send_req]);
    }

    #[test]
    fn to_device_lane_is_strictly_ordered_across_retries() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();

        let first = OutgoingRequest::send_to_device(
            RequestId::next(0),
            "m.room.encrypted",
            &TxnId::new(0),
            serde_json::json!({}),
        );
        let second = OutgoingRequest::send_to_device(
            RequestId::next(1),
            "m.room.encrypted",
            &TxnId::new(1),
            serde_json::json!({}),
        );
        queue.enqueue(&mut store, first.clone(), Lane::ToDevice).expect("enqueue first");
        queue.enqueue(&mut store, second.clone(), Lane::ToDevice).expect("enqueue second");

        assert_eq!(queue.releasable(&store, 0), vec![first.clone()], "only the oldest is released");
        assert!(queue.releasable(&store, 0).is_empty(), "the lane is occupied while the first is in flight");

        let mut jitter = FixedJitter(0.0);
        let outcome = queue.on_transport_error(&first.id, 0, &mut jitter).expect("pending");
        let ResponseOutcome::Retry { after_ms } = outcome else { panic!("expected a retry") };

        assert!(queue.releasable(&store, 0).is_empty(), "back off before retrying");
        assert_eq!(
            queue.releasable(&store, after_ms as i64),
            vec![first],
            "the SAME request is retried before the second ever runs"
        );
    }

    #[test]
    fn room_lane_preserves_send_order() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let room = room_id();

        let first = OutgoingRequest::room_send(
            RequestId::next(0),
            &room,
            "m.room.message",
            &TxnId::new(0),
            serde_json::json!({ "body": "a" }),
        );
        let second = OutgoingRequest::room_send(
            RequestId::next(1),
            &room,
            "m.room.message",
            &TxnId::new(1),
            serde_json::json!({ "body": "b" }),
        );
        queue.enqueue(&mut store, first.clone(), Lane::Room(room.clone())).expect("enqueue first");
        // Enqueuing `second` right behind `first`, with nothing acked yet
        // in between, forces `first`'s own not-yet-batched pending-request
        // record into a batch that becomes `second`'s own required epoch
        // (see the module doc's "Flush epoch integration" section) -- ack
        // it, exactly as a shell's normal flush tick would.
        let batch = queue.enqueue(&mut store, second.clone(), Lane::Room(room.clone())).expect("enqueue second");
        if let Some(batch) = batch {
            store.ack_flush(batch.id);
        }

        assert_eq!(queue.releasable(&store, 0), vec![first.clone()], "only the oldest send is released");

        let resp = HttpResponseDescriptor { status: 200, body: b"{}".to_vec() };
        let outcome = queue
            .on_response(&mut store, &first.id, resp, 0, &mut FixedJitter(0.0))
            .expect("no store error")
            .expect("pending");
        assert!(matches!(outcome, ResponseOutcome::Done(_)));

        assert_eq!(queue.releasable(&store, 0), vec![second], "second is released only after the first completes");
    }

    #[test]
    fn retry_resends_identical_bytes() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();

        let request = OutgoingRequest::room_send(
            RequestId::next(0),
            &room_id(),
            "m.room.encrypted",
            &TxnId::new(0),
            serde_json::json!({ "ciphertext": "same-bytes" }),
        );
        queue.enqueue(&mut store, request.clone(), Lane::Room(room_id())).expect("enqueue");

        assert_eq!(queue.releasable(&store, 0), vec![request.clone()]);

        let resp = HttpResponseDescriptor { status: 503, body: b"{}".to_vec() };
        let outcome = queue
            .on_response(&mut store, &request.id, resp, 0, &mut FixedJitter(0.0))
            .expect("no error")
            .expect("pending");
        let ResponseOutcome::Retry { after_ms } = outcome else { panic!("expected a retry") };

        assert_eq!(
            queue.releasable(&store, after_ms as i64),
            vec![request],
            "the retry carries the exact same body/txn id -- never re-minted"
        );
    }

    #[test]
    fn rate_limited_response_uses_retry_after_ms() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let request = OutgoingRequest::sync(RequestId::next(0), None, None);
        queue.enqueue(&mut store, request.clone(), Lane::Sync).expect("enqueue");
        queue.releasable(&store, 0);

        let resp = HttpResponseDescriptor {
            status: 429,
            body: br#"{"errcode":"M_LIMIT_EXCEEDED","retry_after_ms":7500}"#.to_vec(),
        };
        let outcome = queue
            .on_response(&mut store, &request.id, resp, 0, &mut FixedJitter(0.5))
            .expect("no error")
            .expect("pending");
        assert_eq!(outcome, ResponseOutcome::Retry { after_ms: 7500 });
    }

    #[test]
    fn four_hundred_class_error_fails_and_deletes_pending() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let request = OutgoingRequest::sync(RequestId::next(0), None, None);
        queue.enqueue(&mut store, request.clone(), Lane::Sync).expect("enqueue");
        queue.releasable(&store, 0);

        let resp = HttpResponseDescriptor {
            status: 403,
            body: br#"{"errcode":"M_FORBIDDEN","error":"nope"}"#.to_vec(),
        };
        let outcome = queue
            .on_response(&mut store, &request.id, resp, 0, &mut FixedJitter(0.0))
            .expect("no error")
            .expect("pending");
        assert_eq!(outcome, ResponseOutcome::Failed { errcode: "M_FORBIDDEN".to_string(), error: "nope".to_string() });
        assert!(store.pending_requests().expect("no error").is_empty(), "the pending record was deleted");
        assert!(queue.releasable(&store, 0).is_empty(), "nothing left to release");
    }

    #[test]
    fn backoff_is_capped() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let request = OutgoingRequest::sync(RequestId::next(0), None, None);
        queue.enqueue(&mut store, request.clone(), Lane::Sync).expect("enqueue");

        let mut jitter = FixedJitter(1.0); // maximum jitter -- exercises the upper edge
        let mut now = 0i64;
        let mut last_after_ms = 0u64;
        for _ in 0..10 {
            queue.releasable(&store, now);
            let resp = HttpResponseDescriptor { status: 503, body: b"{}".to_vec() };
            let outcome = queue
                .on_response(&mut store, &request.id, resp, now, &mut jitter)
                .expect("no error")
                .expect("pending");
            let ResponseOutcome::Retry { after_ms } = outcome else { panic!("expected a retry") };
            assert!(after_ms <= BACKOFF_CAP_MS, "backoff never exceeds the cap: got {after_ms}");
            last_after_ms = after_ms;
            now += after_ms as i64;
        }
        assert_eq!(last_after_ms, BACKOFF_CAP_MS, "after enough retries, backoff saturates at the cap");
    }

    fn account_data_request(seed: u64) -> OutgoingRequest {
        let user = crate::ids::UserId::parse("@alice:example.org").expect("valid user id");
        OutgoingRequest::account_data(RequestId::next(seed), &user, "org.example.t", serde_json::json!({ "n": seed }))
    }

    #[test]
    fn account_data_lane_holds_followers_behind_a_head_that_is_backing_off() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let requests: Vec<OutgoingRequest> = (0..3).map(account_data_request).collect();
        for request in &requests {
            if let Some(batch) = queue.enqueue(&mut store, request.clone(), Lane::AccountData).expect("enqueue") {
                store.ack_flush(batch.id);
            }
        }

        assert_eq!(queue.releasable(&store, 0), vec![requests[0].clone()], "only the head is released");
        assert!(queue.releasable(&store, 0).is_empty(), "nothing behind an in-flight head");

        let mut jitter = FixedJitter(0.0);
        let unavailable = HttpResponseDescriptor { status: 503, body: b"{}".to_vec() };
        let outcome = queue.on_response(&mut store, &requests[0].id, unavailable, 0, &mut jitter).expect("no error");
        assert!(matches!(outcome, Some(ResponseOutcome::Retry { .. })));
        assert!(
            queue.releasable(&store, 0).is_empty(),
            "followers never overtake a head that is only backing off before its retry"
        );

        assert_eq!(queue.releasable(&store, 10_000), vec![requests[0].clone()], "the head retries once its backoff elapsed");
        let ok = HttpResponseDescriptor { status: 200, body: b"{}".to_vec() };
        queue.on_response(&mut store, &requests[0].id, ok, 10_000, &mut jitter).expect("no error");
        assert_eq!(queue.releasable(&store, 10_000), vec![requests[1].clone()], "FIFO order continues");
    }

    #[test]
    fn account_data_requests_persisted_on_the_other_lane_load_into_the_account_data_lane() {
        let mut store = Store::new(device_id(), InsecurePlainCodecForTests);
        let mut queue = OutgoingQueue::new();
        let mut records = Vec::new();
        for seed in 0..2 {
            if let Some(batch) = queue.enqueue(&mut store, account_data_request(seed), Lane::Other).expect("enqueue") {
                records.extend(batch.records);
            }
        }
        records.extend(store.take_flush_batch().expect("the last record is still dirty").records);

        let reloaded = Store::load(records, InsecurePlainCodecForTests, device_id()).expect("load succeeds");
        let mut restored = OutgoingQueue::load(&reloaded).expect("queue reloads");
        assert_eq!(
            restored.releasable(&reloaded, 0),
            vec![account_data_request(0)],
            "a pre-AccountData-lane record keeps its relative order after an upgrade"
        );
    }
}
