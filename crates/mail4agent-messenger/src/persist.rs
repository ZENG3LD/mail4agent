//! The flush-before-send barrier's data structures.
//!
//! No store logic lives here — `store/` (the actual `CryptoStore`/
//! `StateStore` traits and their sealed-record codec) is a later piece.
//! This module only holds the flush-before-send primitives:
//! a way for the core to (a) mark in-memory state dirty as it mutates, (b)
//! hand a batch of that dirty state to a shell to write durably, and (c)
//! know, before releasing any outgoing network request, whether every
//! mutation that request could depend on has already been written and
//! acknowledged.
//!
//! # Per-request flush epoch — read this before calling [`FlushEpoch::seal_for_request`]
//!
//! An earlier version of this gate enforced one GLOBAL barrier: no request
//! could be released while ANY batch, anywhere, was unacknowledged. That
//! over-blocks a long-poll `/sync` or a typing indicator behind a
//! completely unrelated room's Megolm ratchet advance. [`FlushEpoch`]
//! (implemented by [`FlushGate`] itself, and by `store::Store` on top of
//! its own gate) replaces the global barrier with a **per-request** epoch:
//! each request records the [`RequiredSeq`] of the batch that could
//! contain every mutation made before it was enqueued, and is releasable
//! once every batch up to and including that one is acked — batches
//! produced AFTER a request recorded its `RequiredSeq` never block it.
//!
//! [`FlushEpoch::seal_for_request`] is how a caller (`outgoing_queue`, M12)
//! obtains that `RequiredSeq`: it forces whatever is currently pending
//! into a fresh batch (so that mutation's own bytes start their trip to
//! durable storage right away, rather than waiting for the next unrelated
//! flush tick), or, if nothing is pending, simply returns the sequence id
//! of the last batch already produced ([`RequiredSeq::NONE`] if none ever
//! was) — see the worked example below.
//!
//! ## Worked example
//!
//! 1. `t0`: nothing has happened yet. The next batch produced will be `0`.
//! 2. `t1`: a Megolm ratchet advances (`mark_dirty` on the outbound group
//!    session record). Nothing is batched yet.
//! 3. `t2`: the core is about to mint the `m.room.encrypted` send that
//!    used that ratchet advance. It calls `seal_for_request()` — pending
//!    is non-empty, so this call forces [`FlushGate::take_batch`],
//!    producing batch `0` (unacked) and returning `RequiredSeq(Some(0))`.
//! 4. `t3`: a *different*, unrelated request — a bare `GET /sync` with
//!    `since` already known, nothing dirty — is minted. `seal_for_request()`
//!    finds nothing pending, and the last batch produced is `0`, so it
//!    also returns `RequiredSeq(Some(0))` (it conservatively still waits
//!    on batch `0`, the most recent batch that could contain a prior
//!    mutation — there is no cheaper, still-correct answer without
//!    per-record dependency tracking, which this gate deliberately does
//!    not do; see the crate doc's sans-I/O scope).
//! 5. `t4`: ANOTHER Megolm ratchet advance happens (e.g. a *different*
//!    room's outbound session rotates). This dirties a new record but
//!    does **not** retroactively extend batch `0` — it opens its own,
//!    independent cycle.
//! 6. `t5`: a third request (a typing indicator) is minted. Its
//!    `seal_for_request()` call now finds `t4`'s mutation pending and
//!    forces it into batch `1`, returning `RequiredSeq(Some(1))`.
//! 7. `t6`: the shell acks batch `0`. Both the `t2` send AND the `t3` sync
//!    are now released (`is_released` is `true` for `RequiredSeq(Some(0))`)
//!    — **even though batch `1` is still unacked** — because neither of
//!    them ever depended on batch `1`'s contents. The `t5` typing PUT stays
//!    blocked until batch `1` is also acked.
//!
//! This is the precise sense in which "a `/sync` enqueued with nothing
//! dirty before it is never held back by later mutations": step 4's sync
//! depends only on what predates it (batch `0`), and step 5/6's later
//! mutation opens a cycle of its own that only requests minted *after* it
//! (step 6's typing PUT) can ever be made to wait on.
//!
//! # Batching mechanics (unchanged from the global-barrier design)
//!
//! - [`FlushGate::take_batch`] atomically drains **every** record marked
//!   dirty/deleted since the previous [`FlushGate::take_batch`] call (or
//!   [`FlushEpoch::seal_for_request`] call — both drain the same pending
//!   set) into one [`FlushBatch`], and marks that batch's `id` unacked.
//! - [`FlushGate::ack`] on a batch id that was never produced by
//!   [`take_batch`](FlushGate::take_batch) (already acked, or never
//!   issued) is a no-op — it never panics and never affects any other
//!   batch's state.

use std::collections::{BTreeMap, BTreeSet};

/// A storage key for one sealed record, namespaced under
/// `messenger/{device_id}/...` (see the plan's `store/sealed.rs` layout —
/// not yet implemented in this crate; this type only carries the key
/// string, agnostic of that later layout).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey(String);

impl RecordKey {
    /// Builds a record key from its full storage path.
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// The record's storage path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RecordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One sealed (already encrypted) record ready for a shell to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRecord {
    /// The record's storage key.
    pub key: RecordKey,
    /// The sealed (already-encrypted) bytes to write at `key`.
    pub bytes: Vec<u8>,
}

/// One flush unit: every record write and key deletion a shell must
/// perform, together, before calling [`FlushGate::ack`] with `id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlushBatch {
    /// This batch's sequence id, assigned in the order
    /// [`FlushGate::take_batch`] produced it. [`FlushGate::ack`] and
    /// [`RequiredSeq`] are both keyed by this id.
    pub id: u64,
    /// Sealed records to write.
    pub records: Vec<SealedRecord>,
    /// Keys to delete (tombstones) — riding in the same batch as any
    /// writes dirtied or deleted in the same [`FlushGate::take_batch`]
    /// call, so a shell performs both kinds of change in one durable step.
    pub deletes: Vec<RecordKey>,
}

/// A key is either pending a write or pending a deletion; the latest call
/// for a given key before the next [`FlushGate::take_batch`] wins.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingOp {
    Write(Vec<u8>),
    Delete,
}

/// The flush-epoch a request depends on: the sequence id of the most
/// recent [`FlushBatch`] that could contain a mutation made before the
/// request was enqueued. `None` ([`RequiredSeq::NONE`]) means no batch has
/// ever been produced and nothing was pending at enqueue time — the
/// request depends on nothing and is releasable immediately. Produced by
/// [`FlushEpoch::seal_for_request`], consumed by [`FlushEpoch::is_released`]
/// — see the module doc's worked example for how the two calls interact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RequiredSeq(Option<u64>);

impl RequiredSeq {
    /// No dependency at all — always released. The value a request that
    /// predates every mutation this process has ever made carries.
    pub const NONE: RequiredSeq = RequiredSeq(None);
}

/// The capability [`crate::outgoing_queue::OutgoingQueue`] needs from
/// whatever owns a working set's [`FlushGate`] — implemented by
/// [`FlushGate`] itself and by `crate::store::Store` (which delegates to
/// its own, private gate). Kept as a trait, rather than requiring callers
/// to hold a bare [`FlushGate`] directly, because the real owner of the
/// gate is the working-set store (`store::Store`), not a caller that only
/// ever wants the epoch-sealing behavior.
pub trait FlushEpoch {
    /// Seals whatever is currently pending (dirtied but not yet batched)
    /// into a fresh [`FlushBatch`], returning the [`RequiredSeq`] a
    /// request minted right now must wait on, plus that batch if one was
    /// produced (`None` if nothing was pending). See the module doc's
    /// worked example for the exact rule this implements.
    fn seal_for_request(&mut self) -> (RequiredSeq, Option<FlushBatch>);

    /// `true` iff every batch at or before `required`'s sequence id has
    /// been acknowledged — i.e. it is safe to release a request that
    /// recorded `required` as its [`RequiredSeq`].
    fn is_released(&self, required: RequiredSeq) -> bool;
}

/// The flush-before-send barrier's state machine. See the module doc for
/// the per-request epoch rule [`FlushEpoch::seal_for_request`]/
/// [`FlushEpoch::is_released`] implement.
#[derive(Debug, Default)]
pub struct FlushGate {
    next_batch_id: u64,
    pending: BTreeMap<RecordKey, PendingOp>,
    unacked_batches: BTreeSet<u64>,
}

impl FlushGate {
    /// Builds an empty gate: nothing dirty, nothing outstanding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `key` dirty with new sealed bytes to write on the next
    /// [`take_batch`](Self::take_batch) call. Overwrites any earlier
    /// pending write or deletion for the same `key` that has not yet been
    /// batched — only the latest state before a flush is written.
    pub fn mark_dirty(&mut self, key: RecordKey, bytes: Vec<u8>) {
        self.pending.insert(key, PendingOp::Write(bytes));
    }

    /// Marks `key` for deletion on the next
    /// [`take_batch`](Self::take_batch) call. Overwrites any earlier
    /// pending write or deletion for the same `key` that has not yet been
    /// batched.
    pub fn mark_deleted(&mut self, key: RecordKey) {
        self.pending.insert(key, PendingOp::Delete);
    }

    /// Drains everything currently pending into one new [`FlushBatch`],
    /// or returns `None` if nothing is pending. The returned batch's `id`
    /// is unacknowledged until [`ack`](Self::ack) is called with it.
    pub fn take_batch(&mut self) -> Option<FlushBatch> {
        if self.pending.is_empty() {
            return None;
        }
        let id = self.next_batch_id;
        self.next_batch_id += 1;
        let mut records = Vec::new();
        let mut deletes = Vec::new();
        for (key, op) in std::mem::take(&mut self.pending) {
            match op {
                PendingOp::Write(bytes) => records.push(SealedRecord { key, bytes }),
                PendingOp::Delete => deletes.push(key),
            }
        }
        self.unacked_batches.insert(id);
        Some(FlushBatch { id, records, deletes })
    }

    /// Acknowledges that batch `id` has been durably written. A no-op if
    /// `id` was never produced by [`take_batch`](Self::take_batch), or was
    /// already acknowledged.
    pub fn ack(&mut self, id: u64) {
        self.unacked_batches.remove(&id);
    }
}

impl FlushEpoch for FlushGate {
    fn seal_for_request(&mut self) -> (RequiredSeq, Option<FlushBatch>) {
        if self.pending.is_empty() {
            return (RequiredSeq(self.next_batch_id.checked_sub(1)), None);
        }
        let batch = self
            .take_batch()
            .expect("pending is non-empty (checked above), so take_batch always returns Some here");
        (RequiredSeq(Some(batch.id)), Some(batch))
    }

    fn is_released(&self, required: RequiredSeq) -> bool {
        match required.0 {
            None => true,
            Some(seq) => self.unacked_batches.range(..=seq).next().is_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_for_request_blocks_release_until_the_sealed_batch_is_acked() {
        let mut gate = FlushGate::new();
        gate.mark_dirty(RecordKey::new("messenger/dev/account"), b"v1".to_vec());

        let (required, batch) = gate.seal_for_request();
        let batch = batch.expect("the pending write was sealed into a batch");
        assert!(!gate.is_released(required), "sealed but not yet acked");

        gate.ack(batch.id);
        assert!(gate.is_released(required), "sealed and acked: safe to release");
    }

    #[test]
    fn a_request_minted_with_nothing_pending_depends_on_the_last_batch_already_taken() {
        let mut gate = FlushGate::new();
        gate.mark_dirty(RecordKey::new("messenger/dev/a"), b"1".to_vec());
        let (first_required, first_batch) = gate.seal_for_request();
        let first_batch = first_batch.expect("first mutation was sealed");

        // Nothing new dirtied -- this request still conservatively depends
        // on the most recent batch, since it could contain a mutation that
        // predates this request.
        let (second_required, second_batch) = gate.seal_for_request();
        assert!(second_batch.is_none(), "nothing was pending, so no new batch was forced");
        assert_eq!(second_required, first_required, "both wait on the same, already-produced batch");

        gate.ack(first_batch.id);
        assert!(gate.is_released(first_required));
        assert!(gate.is_released(second_required));
    }

    #[test]
    fn a_request_minted_before_any_mutation_has_no_dependency() {
        let gate = FlushGate::new();
        assert!(gate.is_released(RequiredSeq::NONE));
    }

    #[test]
    fn requests_produced_after_a_flush_are_not_blocked_by_later_dirty_records() {
        let mut gate = FlushGate::new();
        gate.mark_dirty(RecordKey::new("messenger/dev/a"), b"1".to_vec());
        let (required1, batch1) = gate.seal_for_request();
        let batch1 = batch1.expect("first batch");
        gate.ack(batch1.id);
        assert!(gate.is_released(required1), "fully flushed and acked: safe to release");

        // A later, independent mutation (e.g. the NEXT Olm ratchet advance)
        // opens its own flush cycle. A request minted *before* this
        // mutation happened (required1) stays released; the mutation does
        // not retroactively extend batch1's bookkeeping.
        gate.mark_dirty(RecordKey::new("messenger/dev/b"), b"2".to_vec());
        assert!(gate.is_released(required1), "still released: batch1 already acked");

        let (required2, batch2) = gate.seal_for_request();
        let batch2 = batch2.expect("second batch");
        assert_ne!(batch1.id, batch2.id, "each flush cycle gets a fresh id");
        assert!(!gate.is_released(required2), "a request minted just now waits on the fresh batch");

        gate.ack(batch2.id);
        assert!(gate.is_released(required2), "second cycle flushed independently of the first");
    }

    #[test]
    fn ack_of_unknown_batch_is_ignored() {
        let mut gate = FlushGate::new();
        gate.ack(999); // never issued -- must not panic
        assert!(gate.is_released(RequiredSeq::NONE));

        gate.mark_dirty(RecordKey::new("messenger/dev/a"), b"1".to_vec());
        let (required, batch) = gate.seal_for_request();
        let batch = batch.expect("pending");
        gate.ack(batch.id + 1); // wrong id -- ignored, real batch stays unacked
        assert!(!gate.is_released(required));

        gate.ack(batch.id);
        assert!(gate.is_released(required));
    }

    #[test]
    fn deletes_ride_in_the_batch() {
        let mut gate = FlushGate::new();
        gate.mark_dirty(RecordKey::new("messenger/dev/keep"), b"kept".to_vec());
        gate.mark_deleted(RecordKey::new("messenger/dev/gone"));

        let batch = gate.take_batch().expect("pending");
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].key.as_str(), "messenger/dev/keep");
        assert_eq!(batch.records[0].bytes, b"kept".to_vec());
        assert_eq!(batch.deletes.len(), 1);
        assert_eq!(batch.deletes[0].as_str(), "messenger/dev/gone");
    }

    #[test]
    fn take_batch_returns_none_when_nothing_is_pending() {
        let mut gate = FlushGate::new();
        assert!(gate.take_batch().is_none());
    }

    #[test]
    fn a_later_write_to_the_same_key_overwrites_an_earlier_pending_delete() {
        let mut gate = FlushGate::new();
        let key = RecordKey::new("messenger/dev/x");
        gate.mark_deleted(key.clone());
        gate.mark_dirty(key.clone(), b"new".to_vec());

        let batch = gate.take_batch().expect("pending");
        assert!(batch.deletes.is_empty());
        assert_eq!(batch.records.len(), 1);
        assert_eq!(batch.records[0].bytes, b"new".to_vec());
    }
}
