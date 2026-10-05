//! Device keys, to-device, cross-signing, and backup decisions.
//! Signature checks that the protocol requires stay here. Transport does not.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::Connection;

use crate::error::MatrixError;
use crate::keys::CrossSigningUsage;
use crate::store::{Membership, TxnDedupEntry};

/// Per-request cap on `PUT /sendToDevice`'s flattened target-device count
/// (plan P9 brief: "≤ 1 000 target devices").
pub const SEND_TO_DEVICE_MAX_TARGETS: usize = 1000;

/// Per-target content-size cap (plan P9 brief: "≤ 64 KiB per content").
pub const SEND_TO_DEVICE_MAX_CONTENT_BYTES: usize = 64 * 1024;

/// The one key-backup algorithm this server accepts (plan P9 brief, MSC3270
/// naming) — `m.megolm_backup.v1.curve25519-aes-sha2` (the PkEncryption
/// backup) is refused outright, never even reaching storage.
pub const BACKUP_ALGORITHM: &str = "m.megolm_backup.v1.aes-hmac-sha2";


// ============================================================================
// Shared gate: share-a-room visibility
// ============================================================================

/// Every user id the caller may see key material for through this module's
/// share-a-room gate: `user_id` itself, plus every user who is JOINED or
/// INVITED in a room the caller is JOINED to (plan P9 brief: `/keys/query`/
/// `/keys/claim`/`PUT /sendToDevice` "restrict to users who share a room
/// with the caller, or the caller"; the invited half is P16 S-e — see this
/// module's own doc). The caller must be joined: a room where the caller is
/// only invited, has left, or is banned contributes nothing. A target
/// outside this set is dropped/emptied by the caller, never distinguished
/// from "no such account".
pub fn peers_sharing_a_room_with(conn: &Connection, user_id: i64) -> rusqlite::Result<HashSet<i64>> {
    let mut ids = HashSet::new();
    ids.insert(user_id);
    for room_id in crate::store::rooms_for_user(conn, user_id, Some(Membership::Join))? {
        for member in crate::store::room_members(conn, &room_id, None)? {
            if matches!(member.membership, Membership::Join | Membership::Invite) {
                ids.insert(member.user_id);
            }
        }
    }
    Ok(ids)
}


// ============================================================================
// Device-list delta — the one `device_lists` computation `/sync` and
// `/keys/changes` share
// ============================================================================

/// The `device_lists` object of a sync window: mxids, sorted and de-duplicated.
pub struct DeviceListDelta {
    /// Visible users whose device list changed in the window, plus users who
    /// NEWLY share an encrypted room with the caller (Matrix: "or who now
    /// share an encrypted room with the client since the previous sync") —
    /// the client has never queried their keys.
    pub changed: Vec<String>,
    /// Users who no longer share any room with the caller: they left/were
    /// banned from a shared room, or the caller itself left the room. A
    /// user still sharing another room is never listed.
    pub left: Vec<String>,
}


/// Users who entered (`entered`) or stopped sharing (`departed`, before the
/// still-shares-another-room exclusion the caller applies) an ENCRYPTED room
/// with `caller_user_id` in `(from_exclusive, to_inclusive]`. Encrypted rooms
/// only: the client tracks device lists for those alone, and a public
/// unencrypted channel would otherwise list every one of its members whenever
/// the caller joins it.
///
/// - A joined caller who was already joined at `from_exclusive`: every member
///   whose membership went from not-in-room (`leave`/`ban`/none) to
///   `join`/`invite` inside the window entered. (`invite` -> `join` is not
///   a new share: an invitee was already visible to the joined caller.)
/// - A joined caller who was NOT joined at `from_exclusive` (just joined, or
///   accepted an invite): every current `join`/`invite` member entered.
/// - A caller who left/was banned after being joined at `from_exclusive`:
///   every current `join`/`invite` member departed.
pub fn shared_room_transitions(conn: &Connection, caller_user_id: i64, from_exclusive: i64, to_inclusive: i64) -> rusqlite::Result<(Vec<i64>, Vec<i64>)> {
    let mut entered = Vec::new();
    let mut departed = Vec::new();
    let Some(caller_mxid) = crate::store::mxid_of(conn, caller_user_id)? else {
        return Ok((entered, departed));
    };
    let in_room = |membership: Membership| matches!(membership, Membership::Join | Membership::Invite);

    // Only a room with a member event inside the window can have changed
    // who shares it with the caller (the caller's own join/leave is such an
    // event too), so per-room work is limited to those — one query up front
    // instead of a handful per room on every sync wake.
    let caller_rooms = crate::store::rooms_for_user(conn, caller_user_id, None)?;
    for room_id in crate::store::rooms_with_member_events_in_window(conn, &caller_rooms, from_exclusive, to_inclusive)? {
        let Some(room) = crate::store::get_room(conn, &room_id)? else { continue };
        if !room.is_encrypted {
            continue;
        }
        let Some(own) = crate::store::room_member(conn, &room_id, caller_user_id)? else { continue };
        let was_joined = crate::store::membership_at(conn, &room_id, &caller_mxid, from_exclusive)? == Some(Membership::Join);

        match own.membership {
            Membership::Join if was_joined => {
                for mxid in crate::store::member_state_keys_in_window(conn, &room_id, from_exclusive, to_inclusive)? {
                    let Some(user_id) = crate::store::user_id_of(conn, &mxid)? else { continue };
                    if user_id == caller_user_id {
                        continue;
                    }
                    let now_in = crate::store::room_member(conn, &room_id, user_id)?.is_some_and(|m| in_room(m.membership));
                    let before_in = crate::store::membership_at(conn, &room_id, &mxid, from_exclusive)?.is_some_and(in_room);
                    if now_in && !before_in {
                        entered.push(user_id);
                    }
                }
            }
            Membership::Join => {
                for member in crate::store::room_members(conn, &room_id, None)? {
                    if member.user_id != caller_user_id && in_room(member.membership) {
                        entered.push(member.user_id);
                    }
                }
            }
            Membership::Leave | Membership::Ban if was_joined => {
                for member in crate::store::room_members(conn, &room_id, None)? {
                    if member.user_id != caller_user_id && in_room(member.membership) {
                        departed.push(member.user_id);
                    }
                }
            }
            Membership::Leave | Membership::Ban | Membership::Invite => {}
        }
    }
    Ok((entered, departed))
}


/// The mxids of `user_ids`, sorted and de-duplicated (a user with no mxid row
/// cannot be named to a client and is dropped).
pub fn sorted_mxids(conn: &Connection, user_ids: &HashSet<i64>) -> rusqlite::Result<Vec<String>> {
    let mut mxids = Vec::with_capacity(user_ids.len());
    for &user_id in user_ids {
        if let Some(mxid) = crate::store::mxid_of(conn, user_id)? {
            mxids.push(mxid);
        }
    }
    mxids.sort();
    mxids.dedup();
    Ok(mxids)
}


/// The `device_lists` delta of `(from_exclusive, to_inclusive]` as seen by
/// `caller_user_id` — see [`DeviceListDelta`]. `/sync` (incremental) and
/// `GET /keys/changes` both build their answer from this one function so the
/// two can never disagree.
pub fn device_list_delta(conn: &Connection, caller_user_id: i64, from_exclusive: i64, to_inclusive: i64) -> rusqlite::Result<DeviceListDelta> {
    let visible = peers_sharing_a_room_with(conn, caller_user_id)?;
    let (entered, departed) = shared_room_transitions(conn, caller_user_id, from_exclusive, to_inclusive)?;

    let mut changed_ids: HashSet<i64> = HashSet::new();
    for user_id in crate::keys::device_list_changes_between(conn, from_exclusive, to_inclusive)? {
        if visible.contains(&user_id) {
            changed_ids.insert(user_id);
        }
    }
    changed_ids.extend(entered.into_iter().filter(|user_id| visible.contains(user_id)));

    let caller_rooms = crate::store::rooms_for_user(conn, caller_user_id, None)?;
    let mut left_ids: HashSet<i64> = HashSet::new();
    for user_id in crate::store::user_ids_with_leave_transition_in_rooms(conn, &caller_rooms, from_exclusive, to_inclusive)? {
        if !visible.contains(&user_id) {
            left_ids.insert(user_id);
        }
    }
    left_ids.extend(departed.into_iter().filter(|user_id| !visible.contains(user_id)));

    Ok(DeviceListDelta { changed: sorted_mxids(conn, &changed_ids)?, left: sorted_mxids(conn, &left_ids)? })
}


// ============================================================================
// POST /_matrix/client/v3/keys/upload
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct KeysUploadRequest {
    #[serde(default)]
    pub device_keys: Option<serde_json::Value>,
    #[serde(default)]
    pub one_time_keys: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub fallback_keys: Option<BTreeMap<String, serde_json::Value>>,
}


/// `device_keys.user_id`/`device_id` must name the authenticated caller
/// (plan §2 manager decision 5 / P9 brief) — else `M_INVALID_PARAM`.
pub fn check_device_keys_ownership(device_keys: &serde_json::Value, caller_mxid: &str, caller_device_id: &str) -> Result<(), MatrixError> {
    let user_id = device_keys.get("user_id").and_then(|v| v.as_str());
    let device_id = device_keys.get("device_id").and_then(|v| v.as_str());
    if user_id != Some(caller_mxid) || device_id != Some(caller_device_id) {
        return Err(MatrixError::invalid_param("device_keys.user_id/device_id must name the authenticated caller"));
    }
    Ok(())
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKeysUploadAction {
    Insert,
    Noop,
}


/// A device never changes identity keys once set (plan P9 brief: "a CHANGE
/// to an already-stored device key set for the same device id is refused —
/// a device never changes identity keys; the client must log in again").
/// Compares only the `keys` object (the actual curve25519/ed25519 identity),
/// not `algorithms`/`signatures`, which may legitimately be resent — an
/// identical `keys` resubmission is a silent no-op (many clients re-upload
/// their unchanged device keys on every restart).
pub fn decide_device_keys_upload(existing_keys_json: Option<&str>, new_keys_value: &serde_json::Value) -> Result<DeviceKeysUploadAction, MatrixError> {
    let Some(existing_keys_json) = existing_keys_json else {
        return Ok(DeviceKeysUploadAction::Insert);
    };
    let existing_keys: serde_json::Value = serde_json::from_str(existing_keys_json)?;
    if &existing_keys == new_keys_value {
        Ok(DeviceKeysUploadAction::Noop)
    } else {
        Err(MatrixError::invalid_param(
            "a device's identity keys cannot change once set — log in again to mint a new device",
        ))
    }
}


/// `algorithm:key_id` — every one-time/fallback key's own wire id (plan P9
/// brief: "OTK ids algorithm:key_id format validated").
pub fn split_algorithm_key_id(full_id: &str) -> Result<(&str, &str), MatrixError> {
    let (algorithm, key_id) = full_id
        .split_once(':')
        .ok_or_else(|| MatrixError::invalid_param(format!("malformed one-time key id: {full_id}")))?;
    if algorithm.is_empty() || key_id.is_empty() {
        return Err(MatrixError::invalid_param(format!("malformed one-time key id: {full_id}")));
    }
    Ok((algorithm, key_id))
}


pub struct KeysUploadOutcome {
    pub otk_counts: HashMap<String, i64>,
    pub device_keys_changed: bool,
}


/// DB-only core for `POST /keys/upload` (plan P9 brief): ownership + no-
/// identity-change checks on `device_keys` (a first upload or an identical
/// resubmission only — a change is refused), OTK-id validation, then pure
/// storage of everything provided. Returns the fresh
/// `one_time_key_counts` plus whether `device_keys` actually changed (the
/// caller only wakes peers when it did).
pub fn apply_keys_upload(
    conn: &mut Connection,
    caller_user_id: i64,
    caller_mxid: &str,
    caller_device_id: &str,
    request: &KeysUploadRequest,
    now: &str,
) -> Result<KeysUploadOutcome, MatrixError> {
    let mut device_keys_changed = false;

    if let Some(device_keys) = &request.device_keys {
        check_device_keys_ownership(device_keys, caller_mxid, caller_device_id)?;
        let new_keys_value = device_keys.get("keys").cloned().unwrap_or(serde_json::Value::Null);
        let existing = crate::keys::device_keys_for(conn, &[caller_user_id])?
            .into_iter()
            .find(|d| d.device_id == caller_device_id);
        let action = decide_device_keys_upload(existing.as_ref().map(|d| d.keys.as_str()), &new_keys_value)?;
        if action == DeviceKeysUploadAction::Insert {
            let algorithms_json = device_keys.get("algorithms").cloned().unwrap_or(serde_json::json!([])).to_string();
            let keys_json = new_keys_value.to_string();
            let signatures_json = device_keys.get("signatures").cloned().unwrap_or(serde_json::json!({})).to_string();
            crate::keys::upsert_device_keys(conn, caller_user_id, caller_device_id, &algorithms_json, &keys_json, &signatures_json, now)?;
            device_keys_changed = true;
        }
    }

    if let Some(one_time_keys) = &request.one_time_keys {
        let mut batch = Vec::with_capacity(one_time_keys.len());
        for (full_id, value) in one_time_keys {
            let (algorithm, _) = split_algorithm_key_id(full_id)?;
            batch.push((full_id.clone(), algorithm.to_string(), value.to_string()));
        }
        crate::keys::add_one_time_keys(conn, caller_user_id, caller_device_id, &batch)?;
    }

    if let Some(fallback_keys) = &request.fallback_keys {
        for (full_id, value) in fallback_keys {
            let (algorithm, _) = split_algorithm_key_id(full_id)?;
            crate::keys::upsert_fallback_key(conn, caller_user_id, caller_device_id, algorithm, full_id, &value.to_string(), now)?;
        }
    }

    let otk_counts = crate::keys::count_one_time_keys(conn, caller_user_id, caller_device_id)?;
    Ok(KeysUploadOutcome { otk_counts, device_keys_changed })
}


/// What `keys_upload`'s blocking half hands back: the caller's one-time-key
/// counts, and the peers to wake when its device keys changed.



// ============================================================================
// POST /_matrix/client/v3/keys/query
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct KeysQueryRequest {
    #[serde(default)]
    pub device_keys: BTreeMap<String, Vec<String>>,
}


/// DB-only core for `POST /keys/query` (plan P9 brief): batch `device_keys`
/// for every requested user this caller may see (self, or a shared-room
/// peer — [`peers_sharing_a_room_with`]), plus `master_keys`/
/// `self_signing_keys` for the same allowed set, and `user_signing_keys`
/// ONLY for the caller (spec: a user-signing key is never shared with anyone
/// else). A requested user this caller may NOT see, or an mxid naming no
/// known account, gets an empty `device_keys` entry (`{}`) rather than being
/// omitted — the caller learns nothing about whether the account even
/// exists.
pub fn build_keys_query_response(
    conn: &Connection,
    caller_user_id: i64,
    caller_mxid: &str,
    requested: &BTreeMap<String, Vec<String>>,
) -> Result<serde_json::Value, MatrixError> {
    let visible = peers_sharing_a_room_with(conn, caller_user_id)?;

    let mut device_keys_out = serde_json::Map::new();
    let mut master_keys_out = serde_json::Map::new();
    let mut self_signing_keys_out = serde_json::Map::new();

    for (mxid, requested_device_ids) in requested {
        let allowed_user_id = crate::store::user_id_of(conn, mxid)?.filter(|uid| visible.contains(uid));
        let Some(target_user_id) = allowed_user_id else {
            device_keys_out.insert(mxid.clone(), serde_json::json!({}));
            continue;
        };

        let mut devices_out = serde_json::Map::new();
        for device_keys in crate::keys::device_keys_for(conn, &[target_user_id])? {
            if !requested_device_ids.is_empty() && !requested_device_ids.contains(&device_keys.device_id) {
                continue;
            }
            let algorithms: serde_json::Value = serde_json::from_str(&device_keys.algorithms)?;
            let keys: serde_json::Value = serde_json::from_str(&device_keys.keys)?;
            let signatures: serde_json::Value = serde_json::from_str(&device_keys.signatures)?;
            devices_out.insert(
                device_keys.device_id.clone(),
                serde_json::json!({
                    "user_id": mxid,
                    "device_id": device_keys.device_id,
                    "algorithms": algorithms,
                    "keys": keys,
                    "signatures": signatures,
                }),
            );
        }
        device_keys_out.insert(mxid.clone(), serde_json::Value::Object(devices_out));

        for cross_signing_key in crate::keys::cross_signing_keys_for(conn, &[target_user_id])? {
            let value: serde_json::Value = serde_json::from_str(&cross_signing_key.key_json)?;
            match cross_signing_key.usage {
                CrossSigningUsage::Master => {
                    master_keys_out.insert(mxid.clone(), value);
                }
                CrossSigningUsage::SelfSigning => {
                    self_signing_keys_out.insert(mxid.clone(), value);
                }
                CrossSigningUsage::UserSigning => {} // never exposed for anyone but the caller themself, below
            }
        }
    }

    let mut user_signing_keys_out = serde_json::Map::new();
    if let Some(row) = crate::keys::cross_signing_key_for(conn, caller_user_id, CrossSigningUsage::UserSigning)? {
        user_signing_keys_out.insert(caller_mxid.to_string(), serde_json::from_str(&row.key_json)?);
    }

    Ok(serde_json::json!({
        "device_keys": device_keys_out,
        "master_keys": master_keys_out,
        "self_signing_keys": self_signing_keys_out,
        "user_signing_keys": user_signing_keys_out,
        "failures": {},
    }))
}


// ============================================================================
// POST /_matrix/client/v3/keys/claim
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct KeysClaimRequest {
    #[serde(default)]
    pub one_time_keys: BTreeMap<String, BTreeMap<String, String>>,
}


/// Total number of `(mxid, device)` pairs a `/keys/claim` request asks for —
/// the cost charged against
/// [`crate::typing::ClaimRateLimiter`] (plan P9 brief: "≤ 100
/// device claims / minute per caller").
pub fn count_claim_targets(requested: &BTreeMap<String, BTreeMap<String, String>>) -> usize {
    requested.values().map(BTreeMap::len).sum()
}


/// DB-only core for `POST /keys/claim` (plan P9 brief): per requested
/// `(mxid, device, algorithm)`, claims one OTK (or a reusable fallback) —
/// restricted to the SAME share-a-room set as `/keys/query` — silently
/// omitting any device that yields nothing (no such device, no keys left) or
/// any user this caller may not see.
pub fn build_keys_claim_response(conn: &mut Connection, caller_user_id: i64, requested: &BTreeMap<String, BTreeMap<String, String>>) -> Result<serde_json::Value, MatrixError> {
    let visible = peers_sharing_a_room_with(conn, caller_user_id)?;
    let mut out = serde_json::Map::new();

    for (mxid, per_device) in requested {
        let Some(target_user_id) = crate::store::user_id_of(conn, mxid)?.filter(|uid| visible.contains(uid)) else {
            continue;
        };
        let mut devices_out = serde_json::Map::new();
        for (device_id, algorithm) in per_device {
            let Some((key_id, key_json)) = crate::keys::claim_one_time_key(conn, target_user_id, device_id, algorithm)? else {
                continue;
            };
            let value: serde_json::Value = serde_json::from_str(&key_json)?;
            devices_out.insert(device_id.clone(), serde_json::json!({ key_id: value }));
        }
        if !devices_out.is_empty() {
            out.insert(mxid.clone(), serde_json::Value::Object(devices_out));
        }
    }

    Ok(serde_json::json!({ "one_time_keys": out, "failures": {} }))
}


// ============================================================================
// GET /_matrix/client/v3/keys/changes
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct KeysChangesQuery {
    pub from: Option<String>,
    pub to: Option<String>,
}


/// DB-only core for `GET /keys/changes` (plan §3.7 / P9 brief): the same
/// `device_lists` delta `/sync` reports for `(from, to]`
/// ([`device_list_delta`]) — device-list changes and newly shared encrypted
/// rooms among users the caller can see (`changed`), and users who no longer
/// share any room with the caller (`left`).
pub fn build_keys_changes_response(conn: &Connection, caller_user_id: i64, from_exclusive: i64, to_inclusive: i64) -> Result<serde_json::Value, MatrixError> {
    let delta = device_list_delta(conn, caller_user_id, from_exclusive, to_inclusive)?;
    Ok(serde_json::json!({ "changed": delta.changed, "left": delta.left }))
}


// ============================================================================
// POST /_matrix/client/v3/keys/device_signing/upload
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct DeviceSigningUploadRequest {
    #[serde(default)]
    pub master_key: Option<serde_json::Value>,
    #[serde(default)]
    pub self_signing_key: Option<serde_json::Value>,
    #[serde(default)]
    pub user_signing_key: Option<serde_json::Value>,
}


/// Extract the single `ed25519:<key_id>` entry from a cross-signing key
/// object's `keys` map (Matrix's cross-signing keys always carry exactly
/// one) — `(key_id, decoded 32-byte verifying key)`.
pub fn master_verifying_key(master_key_object: &serde_json::Value) -> Result<(String, VerifyingKey), MatrixError> {
    let keys = master_key_object
        .get("keys")
        .and_then(|v| v.as_object())
        .ok_or_else(|| MatrixError::invalid_param("master_key.keys missing"))?;
    let (full_key_id, value) = keys
        .iter()
        .find(|(k, _)| k.starts_with("ed25519:"))
        .ok_or_else(|| MatrixError::invalid_param("master_key has no ed25519 key"))?;
    let key_id = full_key_id.trim_start_matches("ed25519:").to_string();
    let b64 = value.as_str().ok_or_else(|| MatrixError::invalid_param("master_key.keys value must be a string"))?;
    let bytes = STANDARD_NO_PAD.decode(b64).map_err(|_| MatrixError::invalid_param("master_key public key is not valid base64"))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| MatrixError::invalid_param("master_key public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&array).map_err(|_| MatrixError::invalid_param("master_key is not a valid ed25519 key"))?;
    Ok((key_id, verifying_key))
}


/// Matrix canonical JSON (RFC 8259 subset: sorted keys, no insignificant
/// whitespace) of `value` with `signatures`/`unsigned` stripped — the exact
/// bytes a client signs when producing a cross-signing signature.
/// `serde_json::Value::Object` is backed by a `BTreeMap` everywhere in this
/// workspace (no `preserve_order` feature enabled anywhere in the dependency
/// graph — `Cargo.toml`), so keys are already sorted at every nesting level,
/// and its compact `to_string` emits no insignificant whitespace and leaves
/// non-ASCII UTF-8 unescaped — together already exactly canonical JSON's
/// shape, with no extra re-serialization step needed beyond stripping the
/// two keys.
pub fn canonical_json_without_signatures(value: &serde_json::Value) -> String {
    let mut stripped = value.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }
    stripped.to_string()
}


/// Verify that `target_key_object` (a `self_signing_key`/`user_signing_key`
/// upload) carries a valid ed25519 signature by `master_key_object`'s own
/// key, filed under `signatures[caller_mxid]["ed25519:<master_key_id>"]` —
/// Matrix's own cross-signing trust chain (plan P9 brief: "verify with
/// ed25519 over canonical JSON").
pub fn verify_signed_by_master(target_key_object: &serde_json::Value, caller_mxid: &str, master_key_object: &serde_json::Value) -> Result<(), MatrixError> {
    let (master_key_id, verifying_key) = master_verifying_key(master_key_object)?;
    let signature_b64 = target_key_object
        .get("signatures")
        .and_then(|s| s.get(caller_mxid))
        .and_then(|by_user| by_user.get(format!("ed25519:{master_key_id}").as_str()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MatrixError::invalid_param("missing signature by the master key"))?;
    let sig_bytes = STANDARD_NO_PAD.decode(signature_b64).map_err(|_| MatrixError::invalid_param("signature is not valid base64"))?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| MatrixError::invalid_param("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);
    let message = canonical_json_without_signatures(target_key_object);
    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| MatrixError::invalid_param("signature does not verify against the master key"))
}


/// `user_id`/`usage` shape validation shared by all three cross-signing key
/// kinds (plan P9 brief).
pub fn validate_cross_signing_key_object(value: &serde_json::Value, caller_mxid: &str, expected_usage: &str) -> Result<(), MatrixError> {
    let obj = value.as_object().ok_or_else(|| MatrixError::invalid_param("cross-signing key must be an object"))?;
    if obj.get("user_id").and_then(|v| v.as_str()) != Some(caller_mxid) {
        return Err(MatrixError::invalid_param("cross-signing key user_id must be the caller"));
    }
    let usage = obj.get("usage").and_then(|v| v.as_array()).ok_or_else(|| MatrixError::invalid_param("cross-signing key missing usage"))?;
    if usage.len() != 1 || usage[0].as_str() != Some(expected_usage) {
        return Err(MatrixError::invalid_param(format!("cross-signing key usage must be exactly [\"{expected_usage}\"]")));
    }
    if obj.get("keys").and_then(|v| v.as_object()).is_none_or(|k| k.is_empty()) {
        return Err(MatrixError::invalid_param("cross-signing key missing keys"));
    }
    Ok(())
}


/// DB-only core for `POST /keys/device_signing/upload` (plan P9 brief):
/// validates each provided key object's shape/ownership, verifies
/// self_signing/user_signing against the master key (freshly uploaded in
/// this SAME call, or the caller's existing one), and stores whatever was
/// provided. No UIA (single factor, matches every other route in this
/// tree). Replacing an existing master key is allowed (user reset). Returns
/// whether anything was actually written — the caller only wakes peers when
/// it did.
pub fn apply_device_signing_upload(conn: &mut Connection, caller_user_id: i64, caller_mxid: &str, request: &DeviceSigningUploadRequest, now: &str) -> Result<bool, MatrixError> {
    if let Some(master) = &request.master_key {
        validate_cross_signing_key_object(master, caller_mxid, "master")?;
    }
    let master_for_verification: Option<serde_json::Value> = match &request.master_key {
        Some(master) => Some(master.clone()),
        None => crate::keys::cross_signing_key_for(conn, caller_user_id, CrossSigningUsage::Master)?
            .map(|row| serde_json::from_str(&row.key_json))
            .transpose()?,
    };

    if let Some(self_signing) = &request.self_signing_key {
        validate_cross_signing_key_object(self_signing, caller_mxid, "self_signing")?;
        let master = master_for_verification
            .as_ref()
            .ok_or_else(|| MatrixError::invalid_param("no master key on file to verify self_signing_key against"))?;
        verify_signed_by_master(self_signing, caller_mxid, master)?;
    }
    if let Some(user_signing) = &request.user_signing_key {
        validate_cross_signing_key_object(user_signing, caller_mxid, "user_signing")?;
        let master = master_for_verification
            .as_ref()
            .ok_or_else(|| MatrixError::invalid_param("no master key on file to verify user_signing_key against"))?;
        verify_signed_by_master(user_signing, caller_mxid, master)?;
    }

    let mut wrote = false;
    if let Some(master) = &request.master_key {
        crate::keys::upsert_cross_signing_key(conn, caller_user_id, CrossSigningUsage::Master, &master.to_string(), now)?;
        wrote = true;
    }
    if let Some(self_signing) = &request.self_signing_key {
        crate::keys::upsert_cross_signing_key(conn, caller_user_id, CrossSigningUsage::SelfSigning, &self_signing.to_string(), now)?;
        wrote = true;
    }
    if let Some(user_signing) = &request.user_signing_key {
        crate::keys::upsert_cross_signing_key(conn, caller_user_id, CrossSigningUsage::UserSigning, &user_signing.to_string(), now)?;
        wrote = true;
    }
    Ok(wrote)
}


// ============================================================================
// POST /_matrix/client/v3/keys/signatures/upload
// ============================================================================

/// Whether `user_id`'s master cross-signing key names `local_id` as one of
/// its own `ed25519:<local_id>` entries — the user-signing case's
/// authorization check (plan P9 brief: "target must be ... another user's
/// master key").
pub fn master_key_names_local_id(conn: &Connection, user_id: i64, local_id: &str) -> Result<bool, MatrixError> {
    let Some(row) = crate::keys::cross_signing_key_for(conn, user_id, CrossSigningUsage::Master)? else {
        return Ok(false);
    };
    let value: serde_json::Value = serde_json::from_str(&row.key_json)?;
    let Some(keys) = value.get("keys").and_then(|k| k.as_object()) else {
        return Ok(false);
    };
    Ok(keys.keys().any(|k| k.trim_start_matches("ed25519:") == local_id))
}


/// Whether any of `user_id`'s own cross-signing keys names `local_id` — part
/// of the self-signing case's authorization check (plan P9 brief: "target
/// must be the caller's own device/keys").
fn cross_signing_key_names_local_id(conn: &Connection, user_id: i64, local_id: &str) -> Result<bool, MatrixError> {
    for usage in [CrossSigningUsage::Master, CrossSigningUsage::SelfSigning, CrossSigningUsage::UserSigning] {
        let Some(row) = crate::keys::cross_signing_key_for(conn, user_id, usage)? else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_str(&row.key_json)?;
        if let Some(keys) = value.get("keys").and_then(|k| k.as_object()) {
            if keys.keys().any(|k| k.trim_start_matches("ed25519:") == local_id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}


/// Whether `caller_mxid` may file a signature against `(target_user_id,
/// target_key_id)` (plan P9 brief: "the signer must be the caller; target
/// must be the caller's own device/keys or (for user-signing) another
/// user's master key"). This endpoint never verifies the signature bytes
/// themselves — only this authorization shape — matching
/// `crate::keys::cross_signing_signatures`'s own "opaque, never
/// verified" contract (the one deliberate exception in this module is
/// `/keys/device_signing/upload`'s master-key check, scoped to that
/// endpoint alone — see this module's own doc).
pub fn signature_target_is_authorized(conn: &Connection, caller_mxid: &str, target_mxid: &str, target_user_id: i64, target_key_id: &str) -> Result<bool, MatrixError> {
    if target_mxid == caller_mxid {
        Ok(crate::keys::get_device(conn, target_user_id, target_key_id)?.is_some() || cross_signing_key_names_local_id(conn, target_user_id, target_key_id)?)
    } else {
        master_key_names_local_id(conn, target_user_id, target_key_id)
    }
}


/// DB-only core for `POST /keys/signatures/upload`: per submitted
/// `(target_user, target_key_id)` pair, checks
/// [`signature_target_is_authorized`] and stores the whole submitted value
/// opaquely on success ([`crate::keys::add_signatures`]), or files a
/// per-entry `M_INVALID_PARAM` failure. Returns the `failures` map (empty on
/// full success).
pub fn apply_signatures_upload(conn: &mut Connection, caller_user_id: i64, caller_mxid: &str, body: &serde_json::Map<String, serde_json::Value>, now: &str) -> Result<serde_json::Value, MatrixError> {
    let mut failures = serde_json::Map::new();
    for (target_mxid, per_key) in body {
        let Some(per_key_obj) = per_key.as_object() else { continue };
        let mut user_failures = serde_json::Map::new();
        let target_user_id = crate::store::user_id_of(conn, target_mxid)?;

        for (target_key_id, signed_value) in per_key_obj {
            let authorized = match target_user_id {
                Some(target_user_id) => signature_target_is_authorized(conn, caller_mxid, target_mxid, target_user_id, target_key_id)?,
                None => false,
            };
            if !authorized {
                user_failures.insert(
                    target_key_id.clone(),
                    serde_json::json!({ "errcode": "M_INVALID_PARAM", "error": "signature target not permitted" }),
                );
                continue;
            }
            let target_user_id = target_user_id.ok_or_else(MatrixError::internal)?;
            crate::keys::add_signatures(conn, &[(caller_user_id, target_user_id, target_key_id.clone(), signed_value.to_string(), now.to_string())])?;
        }
        if !user_failures.is_empty() {
            failures.insert(target_mxid.clone(), serde_json::Value::Object(user_failures));
        }
    }
    Ok(serde_json::Value::Object(failures))
}


// ============================================================================
// PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
// ============================================================================

#[derive(serde::Deserialize)]
pub struct SendToDeviceRequest {
    pub messages: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}


/// Resolve `messages` into a flat per-device list, expanding `"*"` to every
/// current device of that recipient (an explicit device entry for the same
/// recipient always overrides the wildcard's content for that one device,
/// never both delivered) and dropping — silently, per this module's own
/// documented policy ("no enumeration via to-device") — any recipient who
/// does not share a joined room with the sender and is not the sender
/// themself. Enforces the per-content-size cap up front; the per-request
/// device-count cap is enforced once, after expansion (a caller mistake,
/// refused outright — unlike the stranger case, a cap violation is
/// unambiguous and refusing it leaks nothing a working client didn't already
/// know about its own request).
pub fn expand_send_to_device_targets(conn: &Connection, sender_user_id: i64, messages: &BTreeMap<String, BTreeMap<String, serde_json::Value>>) -> Result<Vec<(i64, String, String)>, MatrixError> {
    let visible = peers_sharing_a_room_with(conn, sender_user_id)?;
    let mut targets = Vec::new();

    for (mxid, per_device) in messages {
        let Some(recipient_user_id) = crate::store::user_id_of(conn, mxid)?.filter(|uid| visible.contains(uid)) else {
            continue;
        };

        let mut per_recipient: HashMap<String, String> = HashMap::new();
        if let Some(wildcard_content) = per_device.get("*") {
            let content_str = wildcard_content.to_string();
            if content_str.len() > SEND_TO_DEVICE_MAX_CONTENT_BYTES {
                return Err(MatrixError::bad_json("to-device content too large"));
            }
            for device in crate::keys::list_devices(conn, recipient_user_id)? {
                per_recipient.insert(device.device_id, content_str.clone());
            }
        }
        for (device_selector, content) in per_device {
            if device_selector == "*" {
                continue;
            }
            let content_str = content.to_string();
            if content_str.len() > SEND_TO_DEVICE_MAX_CONTENT_BYTES {
                return Err(MatrixError::bad_json("to-device content too large"));
            }
            per_recipient.insert(device_selector.clone(), content_str);
        }

        for (device_id, content_str) in per_recipient {
            targets.push((recipient_user_id, device_id, content_str));
        }
    }

    if targets.len() > SEND_TO_DEVICE_MAX_TARGETS {
        return Err(MatrixError::invalid_param("too many target devices in one call"));
    }
    Ok(targets)
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendToDeviceOutcome {
    New(HashSet<i64>),
    AlreadySent,
}


/// DB-only core for `PUT /sendToDevice/{eventType}/{txnId}`: txn-deduped per
/// `(sender_user_id, sender_device_id, txn_id)` — a repeat is a no-op — then
/// [`expand_send_to_device_targets`] and one atomic dedup-checked enqueue
/// ([`crate::keys::enqueue_to_device_deduped`]).
pub fn apply_send_to_device(
    conn: &mut Connection,
    sender_user_id: i64,
    sender_device_id: &str,
    event_type: &str,
    txn_id: &str,
    messages: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    now: &str,
) -> Result<SendToDeviceOutcome, MatrixError> {
    if let TxnDedupEntry::Seen(_) = crate::store::txn_dedup_lookup(conn, sender_user_id, sender_device_id, txn_id)? {
        return Ok(SendToDeviceOutcome::AlreadySent);
    }
    let targets = expand_send_to_device_targets(conn, sender_user_id, messages)?;
    let wake_ids: HashSet<i64> = targets.iter().map(|(uid, ..)| *uid).collect();
    let rows: Vec<(i64, String, String, String)> = targets.into_iter().map(|(uid, dev, content)| (uid, dev, event_type.to_string(), content)).collect();

    match crate::keys::enqueue_to_device_deduped(conn, sender_user_id, sender_device_id, txn_id, &rows, now)? {
        crate::keys::ToDeviceDedupOutcome::New => Ok(SendToDeviceOutcome::New(wake_ids)),
        crate::keys::ToDeviceDedupOutcome::AlreadySent => Ok(SendToDeviceOutcome::AlreadySent),
    }
}


// ============================================================================
// Devices: GET/DELETE_devices, GET/PUT/DELETE devices/{id}, POST delete_devices
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct PutDeviceRequest {
    #[serde(default)]
    pub display_name: Option<String>,
}


#[derive(serde::Deserialize)]
pub struct DeleteDevicesRequest {
    pub devices: Vec<String>,
}


pub fn device_to_json(device: &crate::keys::Device) -> serde_json::Value {
    let last_seen_ts = chrono::DateTime::parse_from_rfc3339(&device.last_seen_at).ok().map(|dt| dt.timestamp_millis());
    serde_json::json!({
        "device_id": device.device_id,
        "display_name": device.display_name,
        "last_seen_ts": last_seen_ts,
    })
}


// ============================================================================
// Key backup: room_keys/version[/{version}]
// ============================================================================

#[derive(serde::Deserialize)]
pub struct BackupVersionCreateRequest {
    pub algorithm: String,
    pub auth_data: serde_json::Value,
}


#[derive(serde::Deserialize)]
pub struct BackupVersionUpdateRequest {
    #[serde(default)]
    pub algorithm: Option<String>,
    pub auth_data: serde_json::Value,
}


/// Refuse anything but this server's one symmetric key-backup algorithm
/// (plan P9 brief, MSC3270 naming) — `m.megolm_backup.v1.curve25519-aes-sha2`
/// (the PkEncryption backup) is refused outright.
pub fn validate_backup_algorithm(algorithm: &str) -> Result<(), MatrixError> {
    if algorithm == BACKUP_ALGORITHM {
        Ok(())
    } else {
        Err(MatrixError::invalid_param(format!("unsupported key-backup algorithm: {algorithm}")))
    }
}


pub fn backup_version_to_response(row: &crate::keys::KeyBackupVersion, count: i64) -> Result<serde_json::Value, MatrixError> {
    Ok(serde_json::json!({
        "version": row.version.to_string(),
        "algorithm": row.algorithm,
        "auth_data": serde_json::from_str::<serde_json::Value>(&row.auth_data)?,
        "etag": row.etag.to_string(),
        "count": count,
    }))
}


// ============================================================================
// Key backup: room_keys/keys[/{roomId}[/{sessionId}]]
// ============================================================================

#[derive(serde::Deserialize, Default)]
pub struct VersionQuery {
    pub version: Option<String>,
}


pub fn parse_required_version(raw: Option<&str>) -> Result<i64, MatrixError> {
    let raw = raw.ok_or_else(|| MatrixError::invalid_param("version is required"))?;
    raw.parse::<i64>().map_err(|_| MatrixError::invalid_param("version must be an integer"))
}


/// `?version=` must name the caller's CURRENT (non-deleted) backup version —
/// plan P9 brief: "wrong/stale version → 403 M_WRONG_ROOM_KEYS_VERSION with
/// current_version". Applies uniformly to GET/PUT/DELETE
/// `room_keys/keys[...]`.
pub fn require_current_backup_version(conn: &Connection, user_id: i64, requested_version: i64) -> Result<(), MatrixError> {
    let current = crate::keys::current_backup_version(conn, user_id)?;
    match current {
        Some(row) if row.version == requested_version => Ok(()),
        Some(row) => Err(MatrixError::wrong_room_keys_version(Some(row.version))),
        None => Err(MatrixError::wrong_room_keys_version(None)),
    }
}


/// Normalize the three `PUT room_keys/keys[...]` body shapes into a flat
/// `(room_id, session_id, session_data_json)` list — `session_data_json` is
/// the WHOLE submitted `KeyBackupData` object (opaque to this server, see
/// `crate::keys::key_backup_sessions.session_data`'s own doc), not
/// just its inner `session_data` field.
pub fn normalize_put_backup_body(room_id: Option<&str>, session_id: Option<&str>, body: &serde_json::Value) -> Result<Vec<(String, String, String)>, MatrixError> {
    match (room_id, session_id) {
        (Some(room_id), Some(session_id)) => Ok(vec![(room_id.to_string(), session_id.to_string(), body.to_string())]),
        (Some(room_id), None) => {
            let sessions = body
                .get("sessions")
                .and_then(|v| v.as_object())
                .ok_or_else(|| MatrixError::invalid_param("body must have a sessions object"))?;
            Ok(sessions.iter().map(|(sid, data)| (room_id.to_string(), sid.clone(), data.to_string())).collect())
        }
        (None, _) => {
            let rooms = body
                .get("rooms")
                .and_then(|v| v.as_object())
                .ok_or_else(|| MatrixError::invalid_param("body must have a rooms object"))?;
            let mut out = Vec::new();
            for (rid, room_value) in rooms {
                let sessions = room_value
                    .get("sessions")
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| MatrixError::invalid_param("each room must have a sessions object"))?;
                for (sid, data) in sessions {
                    out.push((rid.clone(), sid.clone(), data.to_string()));
                }
            }
            Ok(out)
        }
    }
}


/// Shape a batch of stored [`crate::keys::KeyBackupSession`] rows into
/// the GET response's three tiers.
pub fn backup_sessions_to_response(room_id: Option<&str>, session_id: Option<&str>, sessions: Vec<crate::keys::KeyBackupSession>) -> Result<serde_json::Value, MatrixError> {
    match (room_id, session_id) {
        (Some(_), Some(_)) => {
            let one = sessions.into_iter().next().ok_or_else(|| MatrixError::not_found("no such backup session"))?;
            Ok(serde_json::from_str(&one.session_data)?)
        }
        (Some(_), None) => {
            let mut sessions_out = serde_json::Map::new();
            for s in sessions {
                sessions_out.insert(s.session_id.clone(), serde_json::from_str(&s.session_data)?);
            }
            Ok(serde_json::json!({ "sessions": sessions_out }))
        }
        (None, _) => {
            let mut rooms_out = serde_json::Map::new();
            for s in sessions {
                let room_entry = rooms_out.entry(s.room_id.clone()).or_insert_with(|| serde_json::json!({ "sessions": {} }));
                room_entry["sessions"][s.session_id.as_str()] = serde_json::from_str(&s.session_data)?;
            }
            Ok(serde_json::json!({ "rooms": rooms_out }))
        }
    }
}
