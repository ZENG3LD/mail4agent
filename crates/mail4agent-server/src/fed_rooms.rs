//! Federation F1/F2 room layer (storage side, no network).
//!
//! Profile (documented in the project plan as `m4a-fed-1`):
//! * every server that has members in a room keeps a full replica of it and
//!   pushes its own users' events to every other participating server
//!   (full mesh), so there is no home-server sequencer and no event DAG;
//! * a PDU carries an explicit `event_id`, a content hash and the origin's
//!   signature over the *redacted* form, so the stored PDU stays verifiable
//!   after the ciphertext is dropped (skeleton);
//! * remote users are rows in `matrix_users` with negative ids and their real
//!   mxids, so membership, sync, receipts and key visibility work unchanged;
//! * authorization is a minimal membership/power-level check against the
//!   local replica; there is no state resolution (concurrent conflicting
//!   state changes are last-write-wins per server).

use std::collections::{BTreeSet, HashSet};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::error::MatrixError;
use crate::federation::{active_signing_key, canonical_json, parse_server_name, sign_json, FedError};
use crate::store::{self, JoinRule, MatrixEvent, Membership, PowerAction};

/// Tables owned by this layer.
pub fn create_fed_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS fed_pdus (
            event_id TEXT PRIMARY KEY,
            room_id  TEXT NOT NULL,
            pdu      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fed_skeleton (
            event_id TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS fed_outbox (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            destination TEXT NOT NULL,
            kind        TEXT NOT NULL,
            room_id     TEXT NOT NULL DEFAULT '',
            event_id    TEXT NOT NULL DEFAULT '',
            payload     TEXT NOT NULL,
            created_ms  INTEGER NOT NULL,
            attempts    INTEGER NOT NULL DEFAULT 0,
            next_try_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_fed_outbox_dest ON fed_outbox(destination, id);
        CREATE TABLE IF NOT EXISTS fed_export_cursor (
            id        INTEGER PRIMARY KEY CHECK (id = 1),
            stream_id INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO fed_export_cursor (id, stream_id) VALUES (1, 0);
        "#,
    )
}

fn db_err(e: rusqlite::Error) -> FedError {
    FedError::Db(e.to_string())
}

// ------------------------------------------------------------ remote users

/// Domain part of an mxid (`@u:d` gives `d`, ports included).
pub fn domain_of(mxid: &str) -> Option<&str> {
    mxid.strip_prefix('@')?.split_once(':').map(|(_, d)| d)
}

/// An mxid addressed to another server.
pub fn is_remote_mxid(mxid: &str) -> bool {
    domain_of(mxid).is_some_and(|d| parse_server_name(d).is_some() && !store::is_local_server_name(d))
}

/// Proxy row for a remote user (negative id, real mxid). Idempotent.
pub fn ensure_remote_user(conn: &Connection, mxid: &str, now: &str) -> Result<i64, FedError> {
    if !is_remote_mxid(mxid) {
        return Err(FedError::Malformed(format!("not a remote mxid: {mxid}")));
    }
    if let Some(id) = store::user_id_of(conn, mxid).map_err(db_err)? {
        return Ok(id);
    }
    let next: i64 = conn
        .query_row("SELECT COALESCE(MIN(user_id), 0) FROM matrix_users WHERE user_id < 0", [], |r| r.get::<_, i64>(0))
        .map_err(db_err)?
        - 1;
    conn.execute("INSERT INTO matrix_users (user_id, mxid, created_at) VALUES (?1, ?2, ?3)", params![next, mxid, now]).map_err(db_err)?;
    Ok(next)
}

/// Domains of remote users that have any membership row in the room.
pub fn remote_domains(conn: &Connection, room_id: &str) -> rusqlite::Result<BTreeSet<String>> {
    let mut stmt = conn.prepare(
        "SELECT u.mxid FROM room_members m JOIN matrix_users u ON u.user_id = m.user_id WHERE m.room_id = ?1 AND m.user_id < 0",
    )?;
    let rows = stmt.query_map(params![room_id], |r| r.get::<_, String>(0))?;
    let mut out = BTreeSet::new();
    for r in rows {
        if let Some(d) = domain_of(&r?) {
            out.insert(d.to_string());
        }
    }
    Ok(out)
}

/// Whether the room has remote members (federated closed rooms get skeleton redaction).
pub fn room_is_federated(conn: &Connection, room_id: &str) -> rusqlite::Result<bool> {
    Ok(!remote_domains(conn, room_id)?.is_empty())
}

// ---------------------------------------------------------------- PDU form

fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

/// The signed/hash-stable subset of a PDU (Matrix redaction rules, room v11 shape).
pub fn redact_pdu(pdu: &Value) -> Value {
    const KEEP: [&str; 11] = ["event_id", "type", "room_id", "sender", "state_key", "hashes", "signatures", "depth", "origin", "origin_server_ts", "redacts"];
    let mut out = Map::new();
    for k in KEEP {
        if let Some(v) = pdu.get(k) {
            out.insert(k.to_string(), v.clone());
        }
    }
    let keys: &[&str] = match pdu.get("type").and_then(Value::as_str).unwrap_or("") {
        "m.room.member" => &["membership", "join_authorised_via_users_server"],
        "m.room.join_rules" => &["join_rule", "allow"],
        "m.room.power_levels" => &["ban", "events", "events_default", "invite", "kick", "redact", "state_default", "users", "users_default"],
        "m.room.history_visibility" => &["history_visibility"],
        "m.room.create" => &["creator", "room_version", "type", "m.federate"],
        _ => &[],
    };
    let mut content = Map::new();
    if let Some(c) = pdu.get("content").and_then(Value::as_object) {
        for k in keys {
            if let Some(v) = c.get(*k) {
                content.insert((*k).to_string(), v.clone());
            }
        }
    }
    out.insert("content".into(), Value::Object(content));
    Value::Object(out)
}

fn content_hash(pdu: &Value) -> String {
    let mut bare = pdu.as_object().cloned().unwrap_or_default();
    for k in ["hashes", "signatures", "unsigned"] {
        bare.remove(k);
    }
    b64(&Sha256::digest(canonical_json(&Value::Object(bare))))
}

/// Add `hashes` and the origin's signature (over the redacted form).
pub fn finalize_pdu(conn: &Connection, mut pdu: Map<String, Value>, origin: &str, now_ms: i64) -> Result<Value, FedError> {
    for k in ["hashes", "signatures", "unsigned"] {
        pdu.remove(k);
    }
    let h = content_hash(&Value::Object(pdu.clone()));
    pdu.insert("hashes".into(), json!({ "sha256": h }));
    let (key_id, key) = active_signing_key(conn, now_ms)?;
    let mut red = redact_pdu(&Value::Object(pdu.clone())).as_object().cloned().unwrap_or_default();
    sign_json(&mut red, origin, &key_id, &key);
    if let Some(sigs) = red.remove("signatures") {
        pdu.insert("signatures".into(), sigs);
    }
    Ok(Value::Object(pdu))
}

/// `(signing server, key id)` named by a PDU: the sender's server, first key listed.
pub fn pdu_signer(pdu: &Value) -> Option<(String, String)> {
    let server = domain_of(pdu.get("sender")?.as_str()?)?.to_string();
    let key = pdu.get("signatures")?.get(&server)?.as_object()?.keys().next()?.clone();
    Some((server, key))
}

/// Check a PDU against the signer's public key. `Ok(true)`: signature and
/// content hash good; `Ok(false)`: signature good but content does not match
/// the hash (caller must drop the content, i.e. keep only the redacted form).
pub fn verify_pdu_with_key(pdu: &Value, signer: &str, key_id: &str, public_key_b64: &str) -> Result<bool, FedError> {
    crate::federation::verify_json(&redact_pdu(pdu), signer, key_id, public_key_b64)?;
    let want = pdu.get("hashes").and_then(|h| h.get("sha256")).and_then(Value::as_str).ok_or_else(|| FedError::Malformed("hashes".into()))?;
    Ok(want == content_hash(pdu))
}

/// Signed PDU for a locally created event; stored so it is served unchanged later.
pub fn pdu_for_event(conn: &Connection, ev: &MatrixEvent, local: &str, now_ms: i64) -> Result<Value, FedError> {
    if let Some(s) = conn.query_row("SELECT pdu FROM fed_pdus WHERE event_id = ?1", params![ev.event_id], |r| r.get::<_, String>(0)).optional().map_err(db_err)? {
        return serde_json::from_str(&s).map_err(|_| FedError::Malformed("stored pdu".into()));
    }
    let sender = store::mxid_of(conn, ev.sender_user_id).map_err(db_err)?.ok_or_else(|| FedError::Malformed("sender".into()))?;
    if is_remote_mxid(&sender) {
        return Err(FedError::Malformed("event of a remote sender has no stored pdu".into()));
    }
    let content: Value = serde_json::from_str(&ev.content).map_err(|_| FedError::Malformed("content".into()))?;
    let mut o = Map::new();
    o.insert("event_id".into(), json!(ev.event_id));
    o.insert("room_id".into(), json!(ev.room_id));
    o.insert("sender".into(), json!(sender));
    o.insert("type".into(), json!(ev.event_type));
    if let Some(sk) = &ev.state_key {
        o.insert("state_key".into(), json!(sk));
    }
    o.insert("content".into(), content);
    o.insert("origin_server_ts".into(), json!(ev.origin_server_ts));
    o.insert("origin".into(), json!(local));
    o.insert("depth".into(), json!(ev.stream_id));
    if let Some(r) = &ev.redacts {
        o.insert("redacts".into(), json!(r));
    }
    let pdu = finalize_pdu(conn, o, local, now_ms)?;
    conn.execute("INSERT OR IGNORE INTO fed_pdus (event_id, room_id, pdu) VALUES (?1, ?2, ?3)", params![ev.event_id, ev.room_id, pdu.to_string()]).map_err(db_err)?;
    Ok(pdu)
}

// ------------------------------------------------------------- room info

/// Room metadata a remote replica needs (the part that is not event content).
pub fn room_info(conn: &Connection, room_id: &str) -> Result<Value, FedError> {
    let room = store::get_room(conn, room_id).map_err(db_err)?.ok_or_else(|| FedError::Malformed("unknown room".into()))?;
    let creator = store::mxid_of(conn, room.creator_user_id).map_err(db_err)?.unwrap_or_default();
    Ok(json!({
        "kind": room.kind.as_str(),
        "is_encrypted": room.is_encrypted,
        "join_rule": room.join_rule.as_str(),
        "history_visibility": room.history_visibility.as_str(),
        "room_version": room.room_version,
        "creator": creator,
    }))
}

/// Create the local replica row for a remote room. No-op if present.
pub fn create_replica_room(conn: &Connection, room_id: &str, info: &Value, now: &str) -> Result<(), MatrixError> {
    if store::get_room(conn, room_id)?.is_some() {
        return Ok(());
    }
    let kind = info.get("kind").and_then(Value::as_str).and_then(store::RoomKind::from_wire_name).ok_or_else(|| MatrixError::bad_json("room kind"))?;
    let join_rule = info.get("join_rule").and_then(Value::as_str).and_then(JoinRule::from_wire_name).unwrap_or(JoinRule::Invite);
    let hv = info.get("history_visibility").and_then(Value::as_str).and_then(store::HistoryVisibility::from_wire_name).unwrap_or(store::HistoryVisibility::Shared);
    let creator = info.get("creator").and_then(Value::as_str).unwrap_or_default();
    let creator_id = if is_remote_mxid(creator) { ensure_remote_user(conn, creator, now).map_err(|_| MatrixError::bad_json("creator"))? } else { store::user_id_of(conn, creator)?.unwrap_or(-1) };
    let encrypted = info.get("is_encrypted").and_then(Value::as_bool).unwrap_or(false);
    store::create_room(conn, room_id, kind, creator_id, now, encrypted, join_rule, hv, None, None)?;
    Ok(())
}

// ---------------------------------------------------------------- ingest

/// How strictly an incoming PDU is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Live delivery: membership and power checks against the local replica.
    Live,
    /// State/history inside a signed join or invite response: signature only.
    Trusted,
}

/// Result of one ingest.
#[derive(Debug, Clone, Default)]
pub struct Ingested {
    /// Event id.
    pub event_id: String,
    /// Already stored, nothing done.
    pub duplicate: bool,
    /// Local users to wake.
    pub wake: HashSet<i64>,
}

fn auth_live(conn: &Connection, room: &store::Room, sender_uid: i64, sender: &str, pdu: &Value, content: &Value) -> Result<(), MatrixError> {
    let ty = pdu.get("type").and_then(Value::as_str).unwrap_or("");
    let current = store::room_member(conn, &room.id, sender_uid)?.map(|m| m.membership);
    let pl = crate::rooms::power_levels_of(conn, &room.id)?;
    if ty == "m.room.member" {
        let sk = pdu.get("state_key").and_then(Value::as_str).ok_or_else(|| MatrixError::bad_json("state_key"))?;
        let target_uid = store::user_id_of(conn, sk)?;
        let target_cur = match target_uid {
            Some(u) => store::room_member(conn, &room.id, u)?.map(|m| m.membership),
            None => None,
        };
        return match content.get("membership").and_then(Value::as_str).unwrap_or("") {
            "join" => {
                if sk != sender {
                    return Err(MatrixError::forbidden("join for another user"));
                }
                match current {
                    Some(Membership::Ban) => Err(MatrixError::forbidden("banned")),
                    Some(Membership::Join) | Some(Membership::Invite) => Ok(()),
                    _ if room.join_rule == JoinRule::Public => Ok(()),
                    _ => Err(MatrixError::forbidden("no invitation")),
                }
            }
            "invite" => {
                crate::rooms::require_member(current)?;
                crate::rooms::require_power(&pl, sender, PowerAction::Invite)?;
                match target_cur {
                    Some(Membership::Join) | Some(Membership::Ban) => Err(MatrixError::forbidden("target cannot be invited")),
                    _ => Ok(()),
                }
            }
            "leave" if sk == sender => match current {
                Some(Membership::Join) | Some(Membership::Invite) => Ok(()),
                _ => Err(MatrixError::forbidden("not a member")),
            },
            "leave" => {
                crate::rooms::require_member(current)?;
                crate::rooms::require_power(&pl, sender, PowerAction::Kick)
            }
            "ban" => {
                crate::rooms::require_member(current)?;
                crate::rooms::require_power(&pl, sender, PowerAction::Ban)
            }
            _ => Err(MatrixError::forbidden("unsupported membership")),
        };
    }
    crate::rooms::require_member(current)?;
    let is_state = pdu.get("state_key").is_some();
    if store::user_level(&pl, sender) < store::event_level(&pl, ty, is_state) {
        return Err(MatrixError::forbidden("insufficient power level"));
    }
    Ok(())
}

/// Store one verified PDU into the local replica.
pub fn ingest_pdu(conn: &mut Connection, pdu: &Value, content_ok: bool, mode: Mode, now: &str) -> Result<Ingested, MatrixError> {
    let get = |k: &str| pdu.get(k).and_then(Value::as_str).map(str::to_string);
    let event_id = get("event_id").ok_or_else(|| MatrixError::bad_json("event_id"))?;
    let room_id = get("room_id").ok_or_else(|| MatrixError::bad_json("room_id"))?;
    let sender = get("sender").ok_or_else(|| MatrixError::bad_json("sender"))?;
    let ty = get("type").ok_or_else(|| MatrixError::bad_json("type"))?;
    let ts = pdu.get("origin_server_ts").and_then(Value::as_i64).ok_or_else(|| MatrixError::bad_json("origin_server_ts"))?;
    if store::get_event(conn, &event_id)?.is_some() {
        return Ok(Ingested { event_id, duplicate: true, wake: HashSet::new() });
    }
    if !is_remote_mxid(&sender) {
        return Err(MatrixError::forbidden("sender is not a remote user"));
    }
    let room = store::get_room(conn, &room_id)?.ok_or_else(|| MatrixError::not_found("unknown room"))?;
    let sender_uid = ensure_remote_user(conn, &sender, now).map_err(|_| MatrixError::bad_json("sender"))?;
    let content = if content_ok { pdu.get("content").cloned().unwrap_or_else(|| json!({})) } else { redact_pdu(pdu)["content"].clone() };
    let state_key = get("state_key");
    if ty == "m.room.member" {
        let sk = state_key.as_deref().ok_or_else(|| MatrixError::bad_json("state_key"))?;
        if is_remote_mxid(sk) {
            ensure_remote_user(conn, sk, now).map_err(|_| MatrixError::bad_json("state_key"))?;
        } else if store::user_id_of(conn, sk)?.is_none() {
            return Err(MatrixError::not_found("unknown local user"));
        }
    }
    if mode == Mode::Live {
        auth_live(conn, &room, sender_uid, &sender, pdu, &content)?;
    }
    let text = content.to_string();
    match &state_key {
        Some(sk) => {
            store::apply_state_event(conn, &store::StateEventWrite { event_id: &event_id, room_id: &room_id, sender_user_id: sender_uid, event_type: &ty, state_key: sk, content: &text, origin_server_ts: ts, now })?;
        }
        None if crate::public_channels::is_public_room(conn, &room_id)? => {
            crate::public_channels::insert_event_deduped(conn, "fed", &event_id, &event_id, &room_id, sender_uid, &ty, &text, ts).map_err(|_| MatrixError::internal())?;
        }
        None => {
            store::insert_timeline_event(conn, &event_id, &room_id, sender_uid, &ty, &text, ts)?;
        }
    }
    let stored = if content_ok { pdu.clone() } else { redact_pdu(pdu) };
    conn.execute("INSERT OR REPLACE INTO fed_pdus (event_id, room_id, pdu) VALUES (?1, ?2, ?3)", params![event_id, room_id, stored.to_string()])?;
    let wake = crate::rooms::member_and_invited_ids(conn, &room_id)?;
    Ok(Ingested { event_id, duplicate: false, wake })
}

/// Store a PDU that a local user created (their own join in a remote room), keeping its id.
pub fn store_own_pdu(conn: &mut Connection, pdu: &Value, user_id: i64, mxid: &str, now: &str) -> Result<(), MatrixError> {
    let get = |k: &str| pdu.get(k).and_then(Value::as_str).map(str::to_string);
    let event_id = get("event_id").ok_or_else(|| MatrixError::bad_json("event_id"))?;
    let room_id = get("room_id").ok_or_else(|| MatrixError::bad_json("room_id"))?;
    let ts = pdu.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
    if pdu.get("sender").and_then(Value::as_str) != Some(mxid) || pdu.get("state_key").and_then(Value::as_str) != Some(mxid) {
        return Err(MatrixError::bad_json("own pdu mismatch"));
    }
    let content = pdu.get("content").cloned().unwrap_or_else(|| json!({}));
    store::apply_state_event(conn, &store::StateEventWrite { event_id: &event_id, room_id: &room_id, sender_user_id: user_id, event_type: "m.room.member", state_key: mxid, content: &content.to_string(), origin_server_ts: ts, now })?;
    conn.execute("INSERT OR REPLACE INTO fed_pdus (event_id, room_id, pdu) VALUES (?1, ?2, ?3)", params![event_id, room_id, pdu.to_string()])?;
    Ok(())
}

// ---------------------------------------------------------------- outbox

/// Queue an item for a destination.
pub fn enqueue(conn: &Connection, destination: &str, kind: &str, room_id: &str, event_id: &str, payload: &Value, now_ms: i64) -> Result<(), FedError> {
    conn.execute(
        "INSERT INTO fed_outbox (destination, kind, room_id, event_id, payload, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![destination, kind, room_id, event_id, payload.to_string(), now_ms],
    )
    .map_err(db_err)?;
    Ok(())
}

/// Queue `pdu` as a normal transaction item for every remote server of the room except `exclude`.
pub fn relay_pdu(conn: &Connection, room_id: &str, pdu: &Value, exclude: &[&str], now_ms: i64) -> Result<(), FedError> {
    let event_id = pdu.get("event_id").and_then(Value::as_str).unwrap_or_default();
    for d in remote_domains(conn, room_id).map_err(db_err)? {
        if !exclude.contains(&d.as_str()) {
            enqueue(conn, &d, "send", room_id, event_id, pdu, now_ms)?;
        }
    }
    Ok(())
}

/// State PDUs of the room that this server can vouch for (its own senders').
pub fn local_state_pdus(conn: &Connection, room_id: &str, local: &str, now_ms: i64) -> Result<Vec<Value>, FedError> {
    let mut out = Vec::new();
    for ev in store::current_state_all(conn, room_id).map_err(db_err)? {
        if let Ok(p) = pdu_for_event(conn, &ev, local, now_ms) {
            out.push(p);
        }
    }
    Ok(out)
}

/// Turn new local-sender events in federated rooms into outbox items. Returns how many events were exported.
pub fn export_local_events(conn: &Connection, local: &str, now_ms: i64) -> Result<usize, FedError> {
    let cursor: i64 = conn.query_row("SELECT stream_id FROM fed_export_cursor WHERE id = 1", [], |r| r.get(0)).map_err(db_err)?;
    let ids: Vec<(i64, String)> = {
        let mut stmt = conn
            .prepare("SELECT stream_id, event_id FROM (SELECT stream_id, event_id, sender_user_id FROM events UNION ALL SELECT stream_id, event_id, sender_user_id FROM pub_events) WHERE stream_id > ?1 AND sender_user_id > 0 ORDER BY stream_id LIMIT 500")
            .map_err(db_err)?;
        let rows = stmt.query_map(params![cursor], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))).map_err(db_err)?;
        rows.collect::<Result<_, _>>().map_err(db_err)?
    };
    let mut exported = 0;
    let mut max_seen = cursor;
    for (stream, event_id) in ids {
        max_seen = max_seen.max(stream);
        let Some(ev) = store::get_event(conn, &event_id).map_err(db_err)? else { continue };
        let domains = remote_domains(conn, &ev.room_id).map_err(db_err)?;
        if domains.is_empty() {
            continue;
        }
        let pdu = pdu_for_event(conn, &ev, local, now_ms)?;
        let invitee_domain = if ev.event_type == "m.room.member" && serde_json::from_str::<Value>(&ev.content).ok().and_then(|c| c.get("membership").and_then(Value::as_str).map(str::to_string)).as_deref() == Some("invite") {
            ev.state_key.as_deref().filter(|s| is_remote_mxid(s)).and_then(domain_of).map(str::to_string)
        } else {
            None
        };
        for d in &domains {
            if invitee_domain.as_deref() == Some(d.as_str()) {
                let payload = json!({ "event": pdu, "room_info": room_info(conn, &ev.room_id)?, "state": local_state_pdus(conn, &ev.room_id, local, now_ms)? });
                enqueue(conn, d, "invite", &ev.room_id, &ev.event_id, &payload, now_ms)?;
            } else {
                enqueue(conn, d, "send", &ev.room_id, &ev.event_id, &pdu, now_ms)?;
            }
        }
        exported += 1;
    }
    conn.execute("UPDATE fed_export_cursor SET stream_id = ?1 WHERE id = 1", params![max_seen]).map_err(db_err)?;
    Ok(exported)
}

// -------------------------------------------------------------- skeleton

/// Drop the content of an event but keep its place in the room: the row stays
/// with empty content and the stored PDU becomes its redacted form (which
/// still verifies). Used by retention for federated closed rooms.
pub fn skeletonize_event(conn: &Connection, event_id: &str) -> rusqlite::Result<()> {
    conn.execute("UPDATE events SET content = '{}' WHERE event_id = ?1", params![event_id])?;
    if let Some(s) = conn.query_row("SELECT pdu FROM fed_pdus WHERE event_id = ?1", params![event_id], |r| r.get::<_, String>(0)).optional()? {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            conn.execute("UPDATE fed_pdus SET pdu = ?2 WHERE event_id = ?1", params![event_id, redact_pdu(&v).to_string()])?;
        }
    }
    conn.execute("INSERT OR IGNORE INTO fed_skeleton (event_id) VALUES (?1)", params![event_id])?;
    Ok(())
}

// ------------------------------------------------------------ key serving

/// Local users whose keys `origin` may see: members/invitees of rooms that
/// also have a member on `origin`.
pub fn users_visible_to_origin(conn: &Connection, origin: &str) -> rusqlite::Result<HashSet<i64>> {
    let mut out = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT t.user_id FROM room_members r
           JOIN matrix_users ru ON ru.user_id = r.user_id
           JOIN room_members t ON t.room_id = r.room_id
          WHERE r.user_id < 0 AND r.membership IN ('join','invite') AND t.user_id > 0 AND t.membership IN ('join','invite')
            AND (ru.mxid LIKE ?1)",
    )?;
    let rows = stmt.query_map(params![format!("@%:{origin}")], |r| r.get::<_, i64>(0))?;
    for r in rows {
        out.insert(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::store::create_matrix_schema(&c).unwrap();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        c
    }

    #[test]
    fn redaction_keeps_membership_and_drops_ciphertext() {
        let pdu = json!({"type":"m.room.encrypted","content":{"ciphertext":"x"},"sender":"@a:b.example","event_id":"$1","room_id":"!r:b.example","origin_server_ts":1,"hashes":{"sha256":"h"},"unsigned":{"a":1}});
        let r = redact_pdu(&pdu);
        assert_eq!(r["content"], json!({}));
        assert!(r.get("unsigned").is_none());
        let m = redact_pdu(&json!({"type":"m.room.member","content":{"membership":"join","displayname":"x"}}));
        assert_eq!(m["content"], json!({"membership":"join"}));
    }

    #[test]
    fn signed_pdu_verifies_even_after_content_is_dropped() {
        let c = db();
        let mut o = Map::new();
        for (k, v) in [("event_id", json!("$1")), ("room_id", json!("!r:a.example")), ("sender", json!("@u:a.example")), ("type", json!("m.room.encrypted")), ("content", json!({"ciphertext":"secret"})), ("origin_server_ts", json!(5)), ("origin", json!("a.example"))] {
            o.insert(k.into(), v);
        }
        let pdu = finalize_pdu(&c, o, "a.example", 1).unwrap();
        let (server, key_id) = pdu_signer(&pdu).unwrap();
        let (_, key) = active_signing_key(&c, 1).unwrap();
        let pk = b64(key.verifying_key().as_bytes());
        assert_eq!(verify_pdu_with_key(&pdu, &server, &key_id, &pk), Ok(true));
        let mut tampered = pdu.clone();
        tampered["content"]["ciphertext"] = json!("other");
        assert_eq!(verify_pdu_with_key(&tampered, &server, &key_id, &pk), Ok(false), "signature holds, hash flags the content");
        let skeleton = redact_pdu(&pdu);
        assert_eq!(skeleton["content"], json!({}));
        assert!(verify_pdu_with_key(&skeleton, &server, &key_id, &pk).is_ok(), "skeleton still verifies the signature");
        let mut forged = pdu.clone();
        forged["sender"] = json!("@v:a.example");
        assert!(verify_pdu_with_key(&forged, &server, &key_id, &pk).is_err());
    }

    #[test]
    fn remote_users_get_negative_ids_and_domains_are_tracked() {
        let c = db();
        crate::store::ensure_matrix_user(&c, 1, "alice000000000000000000000000a1", "t").unwrap();
        let id = ensure_remote_user(&c, "@bob:b.example", "t").unwrap();
        assert!(id < 0);
        assert_eq!(ensure_remote_user(&c, "@bob:b.example", "t").unwrap(), id);
        assert_ne!(ensure_remote_user(&c, "@eve:b.example", "t").unwrap(), id);
        assert!(ensure_remote_user(&c, "@x:example.org", "t").is_err(), "own name is not remote");
        assert!(is_remote_mxid("@x:b.example:8448"));
        assert_eq!(domain_of("@x:b.example:8448"), Some("b.example:8448"));
    }

    #[test]
    fn retention_leaves_a_verifiable_skeleton_in_federated_rooms_and_deletes_in_local_ones() {
        let mut c = db();
        crate::retention::create_retention_schema(&c).unwrap();
        crate::store::ensure_matrix_user(&c, 1, "alice000000000000000000000000a1", "t").unwrap();
        let bob = ensure_remote_user(&c, "@bob:b.example", "t").unwrap();
        for room in ["!fed:example.org", "!loc:example.org"] {
            c.execute("INSERT INTO rooms (id, kind, creator_user_id, created_at, is_encrypted) VALUES (?1, 'group', 1, 't', 1)", params![room]).unwrap();
        }
        c.execute("INSERT INTO room_members (room_id, user_id, membership, updated_at) VALUES ('!fed:example.org', ?1, 'join', 't')", params![bob]).unwrap();
        let mut ids = Vec::new();
        for (i, room) in ["!fed:example.org", "!loc:example.org"].iter().enumerate() {
            let id = format!("$e{i}");
            store::insert_timeline_event(&mut c, &id, room, 1, "m.room.encrypted", r#"{"ciphertext":"secret"}"#, 1_000).unwrap();
            ids.push(id);
        }
        let ev = store::get_event(&c, &ids[0]).unwrap().unwrap();
        // the local server name is the process default here; sign as a stand-in origin
        let pdu = pdu_for_event(&c, &ev, "example.org", 1).unwrap();
        let policy = crate::retention::RetentionPolicy { ttl_ms: 5_000, ack_grace_ms: 0, keep_last: 0, stale_device_ms: 1 };
        assert_eq!(crate::retention::purge_delivered_events(&mut c, 1_000_000, &policy).unwrap(), 2);
        let fed: String = c.query_row("SELECT content FROM events WHERE event_id = '$e0'", [], |r| r.get(0)).unwrap();
        assert_eq!(fed, "{}", "federated closed room keeps a skeleton row, ciphertext gone");
        let gone: i64 = c.query_row("SELECT COUNT(*) FROM events WHERE event_id = '$e1'", [], |r| r.get(0)).unwrap();
        assert_eq!(gone, 0, "local-only room: event deleted as before");
        let stored: Value = serde_json::from_str(&c.query_row("SELECT pdu FROM fed_pdus WHERE event_id = '$e0'", [], |r| r.get::<_, String>(0)).unwrap()).unwrap();
        assert_eq!(stored["content"], json!({}));
        assert_eq!(stored["signatures"], pdu["signatures"], "signature and hash survive the purge");
        assert_eq!(stored["hashes"], pdu["hashes"]);
        let (server, key_id) = pdu_signer(&stored).unwrap();
        let (_, key) = active_signing_key(&c, 1).unwrap();
        assert!(verify_pdu_with_key(&stored, &server, &key_id, &b64(key.verifying_key().as_bytes())).is_ok());
        assert_eq!(crate::retention::purge_delivered_events(&mut c, 1_000_000, &policy).unwrap(), 0, "skeleton is not purged again");
    }
}
