//! The native shell's on-disk record log codec — pure encode/decode, no
//! filesystem access of its own (this crate's own "no I/O" contract, crate
//! doc). A shell's writer thread is the caller: it appends [`encode_batch`]'s
//! output to `records.log` and `sync_data`s the file; boot calls [`replay`]
//! to rebuild the current record set and learn exactly how many bytes of
//! the file were valid frames, so a torn tail left by a crash mid-`write`/
//! mid-`sync_data` can be truncated away rather than re-attempted forever.
//! [`encode_snapshot`] is the same frame format collapsed to a single
//! frame, for the shell's own periodic compaction into `snapshot.bin`. The
//! web shell never touches this module — an IndexedDB transaction already
//! gives it atomicity for free.
//!
//! # Frame format
//!
//! `[u32 LE payload_len][32-byte SHA-256 of payload][payload]`. The hash
//! is what lets [`replay`] tell a genuinely corrupt/truncated frame apart
//! from a well-formed one: a length-prefixed write that stops partway
//! through (the OS crashed mid-`write`) leaves a payload whose declared
//! length does not match what is actually on disk, OR — worse, if the
//! partial write happened to land on a frame boundary from an ENTIRELY
//! different, later write that was itself interrupted — a payload of the
//! right length but wrong bytes. The hash catches both: it is computed over
//! the exact payload bytes this module wrote, so any byte-level corruption
//! (a torn write, a bit-flip) fails the comparison and stops replay right
//! there, never silently accepting partially-written or freshly-allocated
//! (implementation-defined, often zero-filled) filesystem bytes as if they
//! were a real record.
//!
//! ## Payload shape
//!
//! `[u64 LE batch_id][u32 LE record_count][record...][u32 LE delete_count][delete...]`,
//! where one `record` is `[u32 LE key_len][key bytes][u32 LE value_len][value bytes]`
//! and one `delete` is `[u32 LE key_len][key bytes]`. `batch_id` rides along
//! for symmetry with [`crate::persist::FlushBatch::id`] but [`replay`] does
//! not itself validate ordering against it — the shell's writer thread
//! already guarantees batches are appended in the order
//! [`crate::core::MessengerCore::take_flush_batch`] produced them (this
//! crate's own flush-before-send barrier doc), so a gap or repeat here
//! would mean that invariant broke upstream, not something this pure codec
//! can usefully detect on its own.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::persist::{FlushBatch, RecordKey};

/// [`Sha256`]'s own digest length.
const HASH_LEN: usize = 32;

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Builds one frame's payload from an already-flattened record/delete list
/// — shared by [`encode_batch`] (one [`FlushBatch`]'s own writes/deletes)
/// and [`encode_snapshot`] (every currently-live key, no deletes).
fn encode_payload(batch_id: u64, records: &[(&str, &[u8])], deletes: &[&str]) -> Vec<u8> {
    let mut payload = Vec::new();
    write_u64(&mut payload, batch_id);
    write_u32(&mut payload, records.len() as u32);
    for (key, bytes) in records {
        write_bytes(&mut payload, key.as_bytes());
        write_bytes(&mut payload, bytes);
    }
    write_u32(&mut payload, deletes.len() as u32);
    for key in deletes {
        write_bytes(&mut payload, key.as_bytes());
    }
    payload
}

fn frame_from_payload(payload: Vec<u8>) -> Vec<u8> {
    let hash = Sha256::digest(&payload);
    let mut frame = Vec::with_capacity(4 + HASH_LEN + payload.len());
    write_u32(&mut frame, payload.len() as u32);
    frame.extend_from_slice(&hash);
    frame.extend_from_slice(&payload);
    frame
}

/// Encodes one [`FlushBatch`] as a single length-prefixed, hash-checked
/// frame, ready to append to `records.log` (module doc).
pub fn encode_batch(batch: &FlushBatch) -> Vec<u8> {
    let records: Vec<(&str, &[u8])> =
        batch.records.iter().map(|record| (record.key.as_str(), record.bytes.as_slice())).collect();
    let deletes: Vec<&str> = batch.deletes.iter().map(RecordKey::as_str).collect();
    frame_from_payload(encode_payload(batch.id, &records, &deletes))
}

/// Encodes a full record snapshot (e.g. [`replay`]'s own output after
/// boot) as a single frame — the compaction format a shell writes to
/// `snapshot.bin` (module doc). Carries no deletes: a snapshot IS the
/// already-resolved current state, nothing left to delete out of it.
pub fn encode_snapshot(records: &BTreeMap<RecordKey, Vec<u8>>) -> Vec<u8> {
    let entries: Vec<(&str, &[u8])> = records.iter().map(|(key, bytes)| (key.as_str(), bytes.as_slice())).collect();
    frame_from_payload(encode_payload(0, &entries, &[]))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<(u32, usize)> {
    let end = at.checked_add(4)?;
    let slice = bytes.get(at..end)?;
    Some((u32::from_le_bytes(slice.try_into().ok()?), end))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let end = at.checked_add(8)?;
    let slice = bytes.get(at..end)?;
    Some((u64::from_le_bytes(slice.try_into().ok()?), end))
}

fn read_bytes(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let (len, at) = read_u32(bytes, at)?;
    let end = at.checked_add(len as usize)?;
    let slice = bytes.get(at..end)?;
    Some((slice, end))
}

/// The append-only file a shell writes [`encode_batch`] frames to, reduced
/// to the three operations [`append_frame`]'s no-torn-frame rule needs.
/// This crate performs no I/O itself (crate doc): a shell implements this
/// over its own `records.log` handle, and tests implement it over memory
/// with injected faults.
pub trait LogSink {
    /// The log's current length in bytes.
    fn byte_len(&mut self) -> std::io::Result<u64>;
    /// Appends `bytes` at the end of the log and makes them durable
    /// (write plus `sync_data` or the platform equivalent). May fail after
    /// writing only part of `bytes`.
    fn append_synced(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Cuts the log back to `len` bytes.
    fn truncate(&mut self, len: u64) -> std::io::Result<()>;
}

/// Appends one frame so that a failed write can never leave a torn frame
/// in front of later frames. [`replay`] stops at the first torn frame, so
/// any frame written after one is silently lost on the next boot — and
/// those later batches were already acked, i.e. the ciphertext that
/// depended on their ratchet state has left the process, so losing them
/// would reuse a ratchet key after the restart.
///
/// The rule: record the length first; on a write/sync failure, cut the log
/// back to that length and retry the same frame once; if the retry also
/// fails, cut back again (best effort) and return the error. The caller
/// must then treat storage as failed: ack nothing more and write nothing
/// more, so no frame ever lands behind a possibly-torn one.
pub fn append_frame<S: LogSink>(sink: &mut S, frame: &[u8]) -> std::io::Result<()> {
    let prev_len = sink.byte_len()?;
    if sink.append_synced(frame).is_ok() {
        return Ok(());
    }
    sink.truncate(prev_len)?;
    match sink.append_synced(frame) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = sink.truncate(prev_len);
            Err(error)
        }
    }
}

/// One payload's own decoded writes and deletes, in the order they appear.
type DecodedFrame = (Vec<(String, Vec<u8>)>, Vec<String>);

/// Decodes one already hash-verified payload into its writes/deletes.
/// `None` means the payload's own declared lengths ran past its actual end,
/// or left trailing bytes unaccounted for — [`replay`] treats that exactly
/// like a hash mismatch (stop before this frame): the hash already proved
/// these are genuinely the bytes this module wrote, so a shape mismatch
/// here would mean this module's own encoder and decoder disagree, not a
/// disk-level corruption — still not something to panic on in a boot path.
fn decode_payload(payload: &[u8]) -> Option<DecodedFrame> {
    let (_batch_id, mut at) = read_u64(payload, 0)?;
    let (record_count, next) = read_u32(payload, at)?;
    at = next;
    let mut records = Vec::with_capacity(record_count as usize);
    for _ in 0..record_count {
        let (key, next) = read_bytes(payload, at)?;
        let key = String::from_utf8(key.to_vec()).ok()?;
        let (value, next) = read_bytes(payload, next)?;
        at = next;
        records.push((key, value.to_vec()));
    }
    let (delete_count, next) = read_u32(payload, at)?;
    at = next;
    let mut deletes = Vec::with_capacity(delete_count as usize);
    for _ in 0..delete_count {
        let (key, next) = read_bytes(payload, at)?;
        let key = String::from_utf8(key.to_vec()).ok()?;
        at = next;
        deletes.push(key);
    }
    if at != payload.len() {
        return None;
    }
    Some((records, deletes))
}

/// Replays every well-formed frame in `bytes` in order, applying each
/// frame's writes then its deletes to a running map — the merged record set
/// `records.log` (optionally preceded by one `snapshot.bin` frame, which a
/// shell replays first by concatenating it ahead of the log's own bytes)
/// represents. Stops at the first frame that is too short to carry its own
/// length prefix, whose payload is truncated relative to that prefix, or
/// whose SHA-256 does not match the stored one — exactly what a crash
/// mid-`write`/mid-`sync_data` leaves behind (module doc). `valid_len` is
/// how many of `bytes` were consumed by fully valid frames; the shell
/// truncates `records.log` to this length so the torn tail is discarded
/// rather than re-attempted on the next boot.
pub fn replay(bytes: &[u8]) -> (BTreeMap<RecordKey, Vec<u8>>, usize) {
    let mut map = BTreeMap::new();
    let mut pos = 0usize;
    while let Some((payload_len, header_end)) = read_u32(bytes, pos) {
        let Some(hash_end) = header_end.checked_add(HASH_LEN) else { break };
        let Some(payload_end) = hash_end.checked_add(payload_len as usize) else { break };
        let Some(stored_hash) = bytes.get(header_end..hash_end) else { break };
        let Some(payload) = bytes.get(hash_end..payload_end) else { break };
        if Sha256::digest(payload).as_slice() != stored_hash {
            break;
        }
        let Some((records, deletes)) = decode_payload(payload) else { break };
        for (key, value) in records {
            map.insert(RecordKey::new(key), value);
        }
        for key in deletes {
            map.remove(&RecordKey::new(key));
        }
        pos = payload_end;
    }
    (map, pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::SealedRecord;

    fn batch(id: u64, records: &[(&str, &[u8])], deletes: &[&str]) -> FlushBatch {
        FlushBatch {
            id,
            records: records.iter().map(|(key, bytes)| SealedRecord { key: RecordKey::new(*key), bytes: bytes.to_vec() }).collect(),
            deletes: deletes.iter().map(|key| RecordKey::new(*key)).collect(),
        }
    }

    #[test]
    fn log_replay_applies_frames_in_order_and_deletes() {
        let mut log = Vec::new();
        log.extend(encode_batch(&batch(0, &[("a", b"1"), ("b", b"2")], &[])));
        log.extend(encode_batch(&batch(1, &[("b", b"2-updated")], &["a"])));

        let (records, valid_len) = replay(&log);
        assert_eq!(valid_len, log.len(), "every frame here is well-formed");
        assert_eq!(records.len(), 1, "'a' was deleted by the second frame");
        assert_eq!(records.get(&RecordKey::new("b")), Some(&b"2-updated".to_vec()));
        assert_eq!(records.get(&RecordKey::new("a")), None);
    }

    #[test]
    fn log_replay_stops_at_torn_tail() {
        let mut log = encode_batch(&batch(0, &[("a", b"1")], &[]));
        let full_len = log.len();
        // Simulate a crash mid-append: a second frame whose header claims
        // more payload than actually made it to disk.
        log.extend(encode_batch(&batch(1, &[("b", b"this frame's tail is about to be cut off")], &[])));
        log.truncate(full_len + 10);

        let (records, valid_len) = replay(&log);
        assert_eq!(valid_len, full_len, "only the first, complete frame counts");
        assert_eq!(records.len(), 1);
        assert_eq!(records.get(&RecordKey::new("a")), Some(&b"1".to_vec()));
        assert!(!records.contains_key(&RecordKey::new("b")), "the torn second frame never applied");
    }

    #[test]
    fn log_replay_stops_at_a_corrupted_frame() {
        let mut log = encode_batch(&batch(0, &[("a", b"1")], &[]));
        let full_len = log.len();
        // Flip a byte inside the second frame's payload -- length is
        // intact, but the hash no longer matches.
        let mut second = encode_batch(&batch(1, &[("b", b"2")], &[]));
        let corrupt_at = second.len() - 1;
        second[corrupt_at] ^= 0xFF;
        log.extend(second);

        let (records, valid_len) = replay(&log);
        assert_eq!(valid_len, full_len, "the corrupted frame's hash mismatch stops replay before it");
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn log_replay_of_empty_bytes_is_empty() {
        let (records, valid_len) = replay(&[]);
        assert!(records.is_empty());
        assert_eq!(valid_len, 0);
    }

    /// In-memory sink whose next `append_synced` calls can be made to fail
    /// after writing only part of the frame (a torn write).
    struct FaultySink {
        bytes: Vec<u8>,
        /// One entry per upcoming `append_synced`: `Some(n)` = write `n`
        /// bytes then fail, `None` = succeed.
        script: std::collections::VecDeque<Option<usize>>,
        fail_truncate: bool,
    }

    impl FaultySink {
        fn new(bytes: Vec<u8>, script: &[Option<usize>]) -> Self {
            Self { bytes, script: script.iter().copied().collect(), fail_truncate: false }
        }
    }

    impl LogSink for FaultySink {
        fn byte_len(&mut self) -> std::io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }

        fn append_synced(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            match self.script.pop_front().flatten() {
                None => {
                    self.bytes.extend_from_slice(bytes);
                    Ok(())
                }
                Some(partial) => {
                    self.bytes.extend_from_slice(&bytes[..partial.min(bytes.len())]);
                    Err(std::io::Error::other("injected write failure"))
                }
            }
        }

        fn truncate(&mut self, len: u64) -> std::io::Result<()> {
            if self.fail_truncate {
                return Err(std::io::Error::other("injected truncate failure"));
            }
            self.bytes.truncate(len as usize);
            Ok(())
        }
    }

    #[test]
    fn append_frame_cuts_a_torn_frame_and_retries_once() {
        let first = encode_batch(&batch(0, &[("a", b"1")], &[]));
        let second = encode_batch(&batch(1, &[("b", b"2")], &[]));
        // The first attempt at `second` writes 10 bytes and fails.
        let mut sink = FaultySink::new(first.clone(), &[Some(10), None]);

        append_frame(&mut sink, &second).expect("the retry succeeds");

        let mut expected = first;
        expected.extend_from_slice(&second);
        assert_eq!(sink.bytes, expected, "no partial frame left in front of the retried one");
        let (records, valid_len) = replay(&sink.bytes);
        assert_eq!(valid_len, sink.bytes.len());
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn append_frame_gives_up_after_a_second_failure_and_leaves_no_torn_frame() {
        let first = encode_batch(&batch(0, &[("a", b"1")], &[]));
        let second = encode_batch(&batch(1, &[("b", b"2")], &[]));
        let mut sink = FaultySink::new(first.clone(), &[Some(10), Some(20)]);

        assert!(append_frame(&mut sink, &second).is_err());

        assert_eq!(sink.bytes, first, "both partial writes were cut back");
        let (_, valid_len) = replay(&sink.bytes);
        assert_eq!(valid_len, sink.bytes.len());
    }

    #[test]
    fn append_frame_reports_failure_when_the_cut_itself_fails() {
        let first = encode_batch(&batch(0, &[("a", b"1")], &[]));
        let second = encode_batch(&batch(1, &[("b", b"2")], &[]));
        let mut sink = FaultySink::new(first, &[Some(10), None]);
        sink.fail_truncate = true;

        assert!(append_frame(&mut sink, &second).is_err(), "a torn frame that cannot be cut must never look like success");
    }

    #[test]
    fn append_frame_appends_a_clean_write_untouched() {
        let first = encode_batch(&batch(0, &[("a", b"1")], &[]));
        let mut sink = FaultySink::new(Vec::new(), &[None]);
        append_frame(&mut sink, &first).expect("clean write");
        assert_eq!(sink.bytes, first);
    }

    #[test]
    fn log_snapshot_round_trips() {
        let mut source = BTreeMap::new();
        source.insert(RecordKey::new("messenger/DEV1/account"), b"account-bytes".to_vec());
        source.insert(RecordKey::new("messenger/DEV1/sync_token"), b"s123".to_vec());

        let snapshot = encode_snapshot(&source);
        let (replayed, valid_len) = replay(&snapshot);
        assert_eq!(valid_len, snapshot.len());
        assert_eq!(replayed, source);
    }
}
