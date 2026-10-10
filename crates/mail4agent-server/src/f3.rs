//! F3 (feature `f3-hash-ids`, off by default): rooms created while the feature is on are DAG rooms.
//! Every event in them (state, membership, messages) is a signed room-version-11 event with
//! `prev_events`, `auth_events`, `depth`, a content hash, this server's ed25519 signature and an id
//! that is the reference hash of the signed event. Legacy rooms are never touched.
//!
//! The rules live in `m4a-matrix-core` (storage-agnostic). This file is the store side:
//! * [`ConnDag`] answers the core's `DagRead` from the `dag_*` tables (`dag_schema.rs`);
//! * [`prepare_local`] is called from the two store write functions: it builds, checks, signs and
//!   stores the event inside the caller's transaction, so the DAG rows and the event/state
//!   projection commit or roll back together;
//! * [`receive_pdu`] takes an event from a peer (signature, hash, auth rules, soft-fail, forks
//!   merged by state resolution v2) and projects it in one transaction;
//! * [`import_snapshot`] starts a replica from a peer's state (invite, send_join);
//! * [`skeletonize`] erases the content of a delivered event and keeps its id and signatures.
//!
//! Not done here: redactions and public-channel (`pub_events`) messages keep legacy ids; gaps in
//! `prev_events` are refused rather than back-filled.

use std::collections::HashSet;

use ed25519_dalek::Signer as _;
use m4a_matrix_core::{dag, CanonicalJsonObject, CanonicalJsonValue, EventId, StateEventType, OwnedEventId, OwnedRoomId, Pdu, PublicKeyMap, RoomVersionRules, Signer, StateMap};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::Value;

use crate::error::MatrixError;
use crate::store::MatrixStoreError;

pub fn rules() -> RoomVersionRules {
    m4a_matrix_core::ROOM_VERSION.rules().expect("room version 11 rules")
}

fn rejected(r: dag::Reject) -> MatrixStoreError {
    MatrixStoreError::F3Rejected(r.to_string())
}

pub fn is_f3_room(conn: &Connection, room_id: &str) -> bool {
    conn.query_row("SELECT 1 FROM dag_rooms WHERE room_id = ?1", [room_id], |_| Ok(())).optional().ok().flatten().is_some()
}

pub fn mark_room(conn: &Connection, room_id: &str) -> rusqlite::Result<()> {
    conn.execute("INSERT OR IGNORE INTO dag_rooms (room_id, room_version) VALUES (?1, '11')", [room_id])?;
    Ok(())
}

/// A wire event of the DAG layer: hashed, no `event_id` of its own.
pub fn is_f3_wire(pdu: &Value) -> bool {
    pdu.get("event_id").is_none() && pdu.get("hashes").is_some() && pdu.get("prev_events").is_some()
}

fn json_obj(v: &Value) -> Result<CanonicalJsonObject, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

/// The DAG of one room as the core sees it.
pub struct ConnDag<'a> {
    pub conn: &'a Connection,
    pub room: &'a str,
}

impl dag::DagRead for ConnDag<'_> {
    fn pdu(&self, id: &EventId) -> Option<Pdu> {
        let s: String = self.conn.query_row("SELECT pdu FROM dag_events WHERE event_id = ?1", [id.as_str()], |r| r.get(0)).optional().ok()??;
        let obj: CanonicalJsonObject = serde_json::from_str(&s).ok()?;
        Pdu::from_wire(id.to_owned(), &obj).ok()
    }
    fn state_after(&self, id: &EventId) -> Option<StateMap<OwnedEventId>> {
        let gid: i64 = self.conn.query_row("SELECT group_id FROM dag_event_state WHERE event_id = ?1", [id.as_str()], |r| r.get(0)).optional().ok()??;
        let mut stmt = self.conn.prepare("SELECT event_type, state_key, event_id FROM dag_state_group_entries WHERE group_id = ?1").ok()?;
        let rows = stmt.query_map([gid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))).ok()?;
        let mut m = StateMap::new();
        for row in rows {
            let (t, k, e) = row.ok()?;
            m.insert((StateEventType::from(t), k), OwnedEventId::try_from(e).ok()?);
        }
        Some(m)
    }
    fn extremities(&self) -> Vec<OwnedEventId> {
        let Ok(mut stmt) = self.conn.prepare("SELECT event_id FROM dag_extremities WHERE room_id = ?1 ORDER BY event_id") else { return vec![] };
        let Ok(rows) = stmt.query_map([self.room], |r| r.get::<_, String>(0)) else { return vec![] };
        rows.filter_map(|r| r.ok()).filter_map(|e| OwnedEventId::try_from(e).ok()).collect()
    }
}

fn new_group(conn: &Connection, room: &str, state: &StateMap<OwnedEventId>) -> rusqlite::Result<i64> {
    conn.execute("INSERT INTO dag_state_groups (room_id) VALUES (?1)", [room])?;
    let gid = conn.last_insert_rowid();
    for ((t, k), e) in state {
        conn.execute("INSERT INTO dag_state_group_entries (group_id, event_type, state_key, event_id) VALUES (?1, ?2, ?3, ?4)", params![gid, t.to_string(), k, e.as_str()])?;
    }
    Ok(gid)
}

fn group_of(conn: &Connection, event_id: &str) -> Option<i64> {
    conn.query_row("SELECT group_id FROM dag_event_state WHERE event_id = ?1", [event_id], |r| r.get(0)).optional().ok().flatten()
}

/// Writes one accepted event: the row, its edges, its state group, and (unless soft-failed or an
/// outlier) the new forward extremities. The wire form is also kept in `fed_pdus`, which is what
/// the m4a federation export serves.
fn store_accepted(conn: &Connection, room: &str, acc: &dag::Accepted, outlier: bool) -> rusqlite::Result<()> {
    let pdu_json = serde_json::to_string(&acc.json).unwrap_or_default();
    conn.execute(
        "INSERT INTO dag_events (event_id, room_id, depth, event_type, sender, state_key, origin_server_ts, pdu, outlier, soft_failed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            acc.event_id.as_str(),
            room,
            acc.pdu.depth as i64,
            acc.pdu.kind.to_string(),
            acc.pdu.sender.as_str(),
            acc.pdu.state_key,
            u64::from(acc.pdu.origin_server_ts.0) as i64,
            pdu_json,
            outlier as i64,
            acc.soft_failed as i64
        ],
    )?;
    for p in &acc.pdu.prev_events {
        conn.execute("INSERT OR IGNORE INTO dag_edges (event_id, prev_event_id) VALUES (?1, ?2)", params![acc.event_id.as_str(), p.as_str()])?;
    }
    for a in &acc.pdu.auth_events {
        conn.execute("INSERT OR IGNORE INTO dag_auth (event_id, auth_event_id) VALUES (?1, ?2)", params![acc.event_id.as_str(), a.as_str()])?;
    }
    let shared = if acc.pdu.state_key.is_none() && acc.pdu.prev_events.len() == 1 { group_of(conn, acc.pdu.prev_events[0].as_str()) } else { None };
    let gid = match shared {
        Some(g) => g,
        None => new_group(conn, room, &acc.state_after)?,
    };
    conn.execute("INSERT OR REPLACE INTO dag_event_state (event_id, group_id) VALUES (?1, ?2)", params![acc.event_id.as_str(), gid])?;
    if !acc.soft_failed && !outlier {
        conn.execute("DELETE FROM dag_extremities WHERE room_id = ?1", [room])?;
        for e in &acc.extremities {
            conn.execute("INSERT INTO dag_extremities (room_id, event_id) VALUES (?1, ?2)", params![room, e.as_str()])?;
        }
    }
    conn.execute("INSERT OR REPLACE INTO fed_pdus (event_id, room_id, pdu) VALUES (?1, ?2, ?3)", params![acc.event_id.as_str(), room, pdu_json])?;
    Ok(())
}

/// The id and content a local event ended up with.
pub struct Prepared {
    pub event_id: String,
    pub content: String,
}

fn local_signer(conn: &Connection, now_ms: i64) -> Result<Signer, MatrixStoreError> {
    let (key_id, key) = crate::federation::active_signing_key(conn, now_ms).map_err(|e| MatrixStoreError::F3Rejected(e.to_string()))?;
    Ok(Signer::new(crate::store::matrix_server_name(), key_id, move |m| key.sign(m).to_bytes()))
}

/// Public key (standard base64) of one of our own signing keys, active or retired.
pub fn own_public_key(conn: &Connection, key_id: &str) -> Option<String> {
    let secret: Vec<u8> = conn.query_row("SELECT secret FROM fed_signing_keys WHERE key_id = ?1", [key_id], |r| r.get(0)).optional().ok()??;
    let bytes: [u8; 32] = secret.try_into().ok()?;
    let pk = ed25519_dalek::SigningKey::from_bytes(&bytes).verifying_key().to_bytes();
    Some(m4a_matrix_core::key_to_b64(&pk))
}

/// Called from the store's two write functions for every event a local user creates. `None`: the
/// room is legacy, the caller keeps its own id. `Some`: the event was built, checked against the
/// room's auth rules, signed and stored in `tx`; the caller writes its projection with this id.
pub fn prepare_local(tx: &Transaction, room_id: &str, sender_user_id: i64, kind: &str, state_key: Option<&str>, content: &str, ts: i64) -> Result<Option<Prepared>, MatrixStoreError> {
    if !is_f3_room(tx, room_id) {
        return Ok(None);
    }
    let sender = crate::store::mxid_of(tx, sender_user_id)?.ok_or_else(|| MatrixStoreError::UnknownMxid(sender_user_id.to_string()))?;
    let mut c: Value = serde_json::from_str(content)?;
    if kind == "m.room.create" && c.get("creator").is_none() {
        // Room version 11 still names the creator in the create content.
        c["creator"] = Value::String(sender.clone());
    }
    if kind == "m.room.member" && state_key == Some(sender.as_str()) && c.get("membership").and_then(Value::as_str) == Some("join") && c.get("join_authorised_via_users_server").is_none() {
        authorise_restricted_join(tx, room_id, &sender, &mut c)?;
    }
    let signer = local_signer(tx, ts)?;
    let room: OwnedRoomId = room_id.try_into().map_err(|e: m4a_matrix_core::IdError| MatrixStoreError::F3Rejected(e.to_string()))?;
    let db = ConnDag { conn: tx, room: room_id };
    let acc = dag::local_event(&rules(), &db, &signer, &room, ts.max(0) as u64, &sender, kind, state_key, c.clone()).map_err(rejected)?;
    store_accepted(tx, room_id, &acc, false)?;
    Ok(Some(Prepared { event_id: acc.event_id.to_string(), content: c.to_string() }))
}

/// A join into a restricted room by someone who is neither invited nor a member must name a local
/// member who may invite (`join_authorised_via_users_server`): the room version's rule for
/// space-member joins. The room creator is used when still joined, else any joined local member.
fn authorise_restricted_join(tx: &Transaction, room_id: &str, sender: &str, content: &mut Value) -> Result<(), MatrixStoreError> {
    let jr: Option<String> = tx
        .query_row("SELECT e.content FROM current_state s JOIN events e ON e.event_id = s.event_id WHERE s.room_id = ?1 AND s.event_type = 'm.room.join_rules' AND s.state_key = ''", [room_id], |r| r.get(0))
        .optional()?;
    let restricted = jr.and_then(|c| serde_json::from_str::<Value>(&c).ok()).and_then(|v| v.get("join_rule").and_then(Value::as_str).map(|s| s == "restricted")).unwrap_or(false);
    if !restricted {
        return Ok(());
    }
    let already: Option<String> = tx.query_row("SELECT m.membership FROM room_members m JOIN matrix_users u ON u.user_id = m.user_id WHERE m.room_id = ?1 AND u.mxid = ?2", params![room_id, sender], |r| r.get(0)).optional()?;
    if matches!(already.as_deref(), Some("invite") | Some("join")) {
        return Ok(());
    }
    let via: Option<String> = tx
        .query_row(
            "SELECT u.mxid FROM room_members m JOIN matrix_users u ON u.user_id = m.user_id JOIN rooms r ON r.id = m.room_id
              WHERE m.room_id = ?1 AND m.membership = 'join' AND u.user_id > 0 ORDER BY (u.user_id = r.creator_user_id) DESC, u.user_id LIMIT 1",
            [room_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(v) = via {
        content["join_authorised_via_users_server"] = Value::String(v);
    }
    Ok(())
}

/// What [`receive_pdu`] did.
#[derive(Debug, Default)]
pub struct Received {
    pub event_id: String,
    pub duplicate: bool,
    pub soft_failed: bool,
    /// More than one forward extremity after this event: branches are open, state was resolved.
    pub forked: bool,
    pub wake: HashSet<i64>,
}

fn bad(e: impl std::fmt::Display) -> MatrixError {
    MatrixError::forbidden(e.to_string())
}

fn str_of<'a>(v: &'a Value, k: &str) -> Result<&'a str, MatrixError> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| MatrixError::bad_json(k.to_string()))
}

fn ensure_users(conn: &Connection, pdu: &Value, now: &str) -> Result<i64, MatrixError> {
    let sender = str_of(pdu, "sender")?;
    // Events of this server's own users show up in a snapshot the peer sends back.
    let uid = if crate::fed_rooms::is_remote_mxid(sender) {
        crate::fed_rooms::ensure_remote_user(conn, sender, now).map_err(|_| MatrixError::bad_json("sender"))?
    } else {
        crate::store::user_id_of(conn, sender)?.ok_or_else(|| MatrixError::not_found("unknown local user"))?
    };
    if pdu.get("type").and_then(Value::as_str) == Some("m.room.member") {
        let sk = str_of(pdu, "state_key")?;
        if crate::fed_rooms::is_remote_mxid(sk) {
            crate::fed_rooms::ensure_remote_user(conn, sk, now).map_err(|_| MatrixError::bad_json("state_key"))?;
        } else if crate::store::user_id_of(conn, sk)?.is_none() {
            return Err(MatrixError::not_found("unknown local user"));
        }
    }
    Ok(uid)
}

/// Writes the room-visible rows (timeline row, current state, caches) of an accepted event.
fn project(tx: &Transaction, room: &str, acc: &dag::Accepted, prev_current: &StateMap<OwnedEventId>, sender_uid: i64, now: &str) -> Result<(), MatrixStoreError> {
    let content = acc.pdu.content.get().to_string();
    let ts = u64::from(acc.pdu.origin_server_ts.0) as i64;
    let id = acc.event_id.as_str();
    let kind = acc.pdu.kind.to_string();
    match &acc.pdu.state_key {
        Some(sk) => {
            crate::store::apply_state_event_raw_in_tx(tx, id, room, sender_uid, &kind, sk, &content, ts, now)?;
            // Resolution may have picked another winner for this slot, or flipped other slots.
            let mut slots: HashSet<(StateEventType, String)> = HashSet::new();
            slots.insert((StateEventType::from(kind.clone()), sk.clone()));
            for (k, v) in &acc.current_state {
                if prev_current.get(k) != Some(v) {
                    slots.insert(k.clone());
                }
            }
            for k in slots {
                match acc.current_state.get(&k) {
                    Some(w) => {
                        let have: Option<String> = tx.query_row("SELECT event_id FROM current_state WHERE room_id = ?1 AND event_type = ?2 AND state_key = ?3", params![room, k.0.to_string(), k.1], |r| r.get(0)).optional()?;
                        if have.as_deref() != Some(w.as_str()) {
                            crate::store::set_current_state_slot(tx, room, &k.0.to_string(), &k.1, w.as_str(), now)?;
                        }
                    }
                    None => {}
                }
            }
        }
        None => {
            let row = crate::store::TimelineEventRow { event_id: id, room_id: room, sender_user_id: sender_uid, event_type: &kind, content: &content, origin_server_ts: ts, txn_id: None };
            crate::store::insert_timeline_event_raw_in_tx(tx, &row)?;
        }
    }
    Ok(())
}

/// A peer's event for a DAG room. `keys` must hold the public key of every server that signed it
/// (the caller fetched them). Everything lands in one transaction.
pub fn receive_pdu(conn: &mut Connection, origin: &str, pdu: &Value, keys: &PublicKeyMap, now: &str) -> Result<Received, MatrixError> {
    let room = str_of(pdu, "room_id")?.to_string();
    let sender = str_of(pdu, "sender")?.to_string();
    if crate::fed_rooms::domain_of(&sender) != Some(origin) || !crate::fed_rooms::is_remote_mxid(&sender) {
        return Err(MatrixError::forbidden("sender is not a user of the sending server"));
    }
    if !is_f3_room(conn, &room) {
        return Err(MatrixError::not_found("unknown room"));
    }
    let obj = json_obj(pdu).map_err(MatrixError::bad_json)?;
    let rules = rules();
    let id = dag::compute_event_id(&rules, &obj).map_err(bad)?;
    let tx = conn.transaction().map_err(|_| MatrixError::internal())?;
    if tx.query_row("SELECT 1 FROM dag_events WHERE event_id = ?1", [id.as_str()], |_| Ok(())).optional().map_err(|_| MatrixError::internal())?.is_some() {
        return Ok(Received { event_id: id.to_string(), duplicate: true, ..Default::default() });
    }
    let sender_uid = ensure_users(&tx, pdu, now)?;
    let db = ConnDag { conn: &tx, room: &room };
    let prev_current = dag::current_state(&rules, &db).map_err(bad)?;
    let acc = dag::accept_wire(&rules, &db, obj, keys, None).map_err(bad)?;
    store_accepted(&tx, &room, &acc, false).map_err(|_| MatrixError::internal())?;
    if !acc.soft_failed {
        project(&tx, &room, &acc, &prev_current, sender_uid, now).map_err(MatrixError::from)?;
    }
    let wake = crate::rooms::member_and_invited_ids(&tx, &room).map_err(|_| MatrixError::internal())?;
    tx.commit().map_err(|_| MatrixError::internal())?;
    Ok(Received { event_id: id.to_string(), duplicate: false, soft_failed: acc.soft_failed, forked: acc.forked, wake })
}

/// The room as it was right after `at` (an event this server holds): the state events of that
/// state and the event itself, as stored wire JSON. A peer that is invited or joins starts its
/// replica from this, with `at` as its only forward extremity, so the events that follow cite
/// something it holds.
pub fn snapshot_json(conn: &Connection, room: &str, at: &str) -> Result<Value, MatrixError> {
    let db = ConnDag { conn, room };
    let id = OwnedEventId::try_from(at).map_err(|_| MatrixError::bad_json("event id"))?;
    let after = dag::DagRead::state_after(&db, &id).ok_or_else(|| MatrixError::not_found("unknown event"))?;
    let get = |id: &str| -> Option<Value> { conn.query_row("SELECT pdu FROM dag_events WHERE event_id = ?1", [id], |r| r.get::<_, String>(0)).ok().and_then(|s| serde_json::from_str(&s).ok()) };
    let state: Vec<Value> = after.values().filter_map(|i| get(i.as_str())).collect();
    let extremities: Vec<Value> = get(at).into_iter().collect();
    Ok(serde_json::json!({ "state": state, "extremities": extremities }))
}

/// Start (or complete) a replica of a DAG room from a peer's snapshot: every event is checked for
/// its signature and content hash, stored as an outlier, the state events are projected, and the
/// snapshot's extremities become this replica's forward extremities.
pub fn import_snapshot(conn: &mut Connection, room_id: &str, info: &Value, snap: &Value, keys: &PublicKeyMap, now: &str) -> Result<(), MatrixError> {
    let rules = rules();
    let list = |k: &str| snap.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let (state_v, ext_v) = (list("state"), list("extremities"));
    let tx = conn.transaction().map_err(|_| MatrixError::internal())?;
    crate::fed_rooms::create_replica_room(&tx, room_id, info, now)?;
    mark_room(&tx, room_id).map_err(|_| MatrixError::internal())?;
    let ext_ids: HashSet<OwnedEventId> = ext_v.iter().filter_map(|e| json_obj(e).ok()).filter_map(|o| dag::compute_event_id(&rules, &o).ok()).collect();
    let mut parsed: Vec<(OwnedEventId, CanonicalJsonObject, Value)> = Vec::new();
    for v in state_v.iter().chain(ext_v.iter()) {
        if v.get("room_id").and_then(Value::as_str) != Some(room_id) {
            return Err(MatrixError::bad_json("event of another room"));
        }
        let obj = json_obj(v).map_err(MatrixError::bad_json)?;
        dag::verify_wire(&rules, &obj, keys).map_err(bad)?;
        let id = dag::compute_event_id(&rules, &obj).map_err(bad)?;
        if parsed.iter().all(|(i, _, _)| *i != id) {
            parsed.push((id, obj, v.clone()));
        }
    }
    parsed.sort_by_key(|(_, o, _)| match o.get("depth") {
        Some(CanonicalJsonValue::Integer(i)) => i64::from(*i),
        _ => 0,
    });
    let mut state: StateMap<OwnedEventId> = StateMap::new();
    let state_ids: HashSet<OwnedEventId> = state_v.iter().filter_map(|e| json_obj(e).ok()).filter_map(|o| dag::compute_event_id(&rules, &o).ok()).collect();
    for (id, obj, v) in &parsed {
        let pdu = Pdu::from_wire(id.clone(), obj).map_err(MatrixError::bad_json)?;
        let uid = ensure_users(&tx, v, now)?;
        let known = tx.query_row("SELECT 1 FROM dag_events WHERE event_id = ?1", [id.as_str()], |_| Ok(())).optional().map_err(|_| MatrixError::internal())?.is_some();
        if !known {
            // Stored as an outlier: its own edges are not followed, the state group below is the snapshot.
            tx.execute(
                "INSERT INTO dag_events (event_id, room_id, depth, event_type, sender, state_key, origin_server_ts, pdu, outlier) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
                params![id.as_str(), room_id, pdu.depth as i64, pdu.kind.to_string(), pdu.sender.as_str(), pdu.state_key, u64::from(pdu.origin_server_ts.0) as i64, serde_json::to_string(obj).unwrap_or_default()],
            )
            .map_err(|_| MatrixError::internal())?;
            for p in &pdu.prev_events {
                let _ = tx.execute("INSERT OR IGNORE INTO dag_edges (event_id, prev_event_id) VALUES (?1, ?2)", params![id.as_str(), p.as_str()]);
            }
            for a in &pdu.auth_events {
                let _ = tx.execute("INSERT OR IGNORE INTO dag_auth (event_id, auth_event_id) VALUES (?1, ?2)", params![id.as_str(), a.as_str()]);
            }
            let _ = tx.execute("INSERT OR REPLACE INTO fed_pdus (event_id, room_id, pdu) VALUES (?1, ?2, ?3)", params![id.as_str(), room_id, serde_json::to_string(obj).unwrap_or_default()]);
        }
        if let Some(sk) = &pdu.state_key {
            if state_ids.contains(id) {
                state.insert((StateEventType::from(pdu.kind.to_string()), sk.clone()), id.clone());
                if !known {
                    let content = pdu.content.get().to_string();
                    crate::store::apply_state_event_raw_in_tx(&tx, id.as_str(), room_id, uid, &pdu.kind.to_string(), sk, &content, u64::from(pdu.origin_server_ts.0) as i64, now).map_err(MatrixError::from)?;
                }
            }
        }
    }
    // A replica that already exists (an invite came first) moves to the snapshot's state.
    for ((t, k), id) in &state {
        let have: Option<String> = tx.query_row("SELECT event_id FROM current_state WHERE room_id = ?1 AND event_type = ?2 AND state_key = ?3", params![room_id, t.to_string(), k], |r| r.get(0)).optional().map_err(|_| MatrixError::internal())?;
        if have.as_deref() != Some(id.as_str()) {
            crate::store::set_current_state_slot(&tx, room_id, &t.to_string(), k, id.as_str(), now).map_err(MatrixError::from)?;
        }
    }
    let gid = new_group(&tx, room_id, &state).map_err(|_| MatrixError::internal())?;
    tx.execute("DELETE FROM dag_extremities WHERE room_id = ?1", [room_id]).map_err(|_| MatrixError::internal())?;
    for (id, _, _) in &parsed {
        if ext_ids.contains(id) {
            tx.execute("INSERT OR REPLACE INTO dag_event_state (event_id, group_id) VALUES (?1, ?2)", params![id.as_str(), gid]).map_err(|_| MatrixError::internal())?;
            tx.execute("INSERT OR IGNORE INTO dag_extremities (room_id, event_id) VALUES (?1, ?2)", params![room_id, id.as_str()]).map_err(|_| MatrixError::internal())?;
        }
    }
    tx.commit().map_err(|_| MatrixError::internal())?;
    Ok(())
}

/// Event id of a wire event that has none of its own.
pub fn wire_id(pdu: &Value) -> Result<String, MatrixError> {
    let obj = json_obj(pdu).map_err(MatrixError::bad_json)?;
    Ok(dag::compute_event_id(&rules(), &obj).map_err(bad)?.to_string())
}

/// Public keys needed to check `pdus`, for signers whose keys are our own (the caller fills in
/// the rest). Returns the `(server, key id)` pairs that still need a key.
pub fn missing_keys(conn: &Connection, pdus: &[&Value], keys: &mut PublicKeyMap) -> Vec<(String, String)> {
    let mut need = Vec::new();
    for p in pdus {
        let Some(sigs) = p.get("signatures").and_then(Value::as_object) else { continue };
        for (server, ks) in sigs {
            for key_id in ks.as_object().into_iter().flat_map(|o| o.keys()) {
                if keys.get(server).is_some_and(|m| m.contains_key(key_id)) {
                    continue;
                }
                if crate::store::is_local_server_name(server) {
                    if let Some(pk) = own_public_key(conn, key_id).and_then(|b| m4a_matrix_core::key_from_b64(&b).ok()) {
                        keys.entry(server.clone()).or_default().insert(key_id.clone(), pk);
                        continue;
                    }
                }
                if !need.contains(&(server.clone(), key_id.clone())) {
                    need.push((server.clone(), key_id.clone()));
                }
            }
        }
    }
    need
}

/// Add one fetched remote key (standard base64) to `keys`.
pub fn add_key(keys: &mut PublicKeyMap, server: &str, key_id: &str, public_key_b64: &str) -> Result<(), MatrixError> {
    let pk = m4a_matrix_core::key_from_b64(public_key_b64).map_err(|_| MatrixError::bad_json("remote key"))?;
    keys.entry(server.to_owned()).or_default().insert(key_id.to_owned(), pk);
    Ok(())
}

/// Erase the content of a delivered event: the room row and the stored wire JSON become the
/// redacted form. Its id (a hash of the redacted form), edges, hashes and signatures stay, so peers
/// still validate it. Refuses while a federation delivery of the event is still queued.
pub fn skeletonize(conn: &Connection, event_id: &str) -> Result<bool, MatrixStoreError> {
    let pending: i64 = conn.query_row("SELECT COUNT(*) FROM fed_outbox WHERE event_id = ?1", [event_id], |r| r.get(0))?;
    if pending > 0 {
        return Ok(false);
    }
    let Some(s): Option<String> = conn.query_row("SELECT pdu FROM dag_events WHERE event_id = ?1", [event_id], |r| r.get(0)).optional()? else { return Ok(false) };
    let obj: CanonicalJsonObject = serde_json::from_str(&s)?;
    let sk = dag::skeleton(&rules(), &obj).map_err(rejected)?;
    let text = serde_json::to_string(&sk)?;
    conn.execute("UPDATE dag_events SET pdu = ?2, skeleton = 1 WHERE event_id = ?1", params![event_id, text])?;
    conn.execute("UPDATE fed_pdus SET pdu = ?2 WHERE event_id = ?1", params![event_id, text])?;
    conn.execute("UPDATE events SET content = '{}' WHERE event_id = ?1", [event_id])?;
    conn.execute("INSERT OR IGNORE INTO fed_skeleton (event_id) VALUES (?1)", [event_id])?;
    Ok(true)
}

/// Template for a peer's join (make_join): an unsigned event with this room's `prev_events`,
/// `auth_events` and `depth`.
pub fn join_template(conn: &Connection, room_id: &str, user_mxid: &str, ts: i64) -> Result<Value, MatrixError> {
    let room: OwnedRoomId = room_id.try_into().map_err(|_| MatrixError::bad_json("room id"))?;
    let db = ConnDag { conn, room: room_id };
    let t = dag::template(&rules(), &db, &room, ts.max(0) as u64, user_mxid, "m.room.member", Some(user_mxid), serde_json::json!({ "membership": "join" })).map_err(bad)?;
    serde_json::to_value(t).map_err(|_| MatrixError::internal())
}

/// Sign a filled-in template with this server's key. Returns the event id and the wire event.
pub fn sign_own(conn: &Connection, template: &Value, now_ms: i64) -> Result<(String, Value), MatrixError> {
    let signer = local_signer(conn, now_ms)?;
    let obj = json_obj(template).map_err(MatrixError::bad_json)?;
    let s = dag::sign_template(&rules(), &signer, obj).map_err(bad)?;
    Ok((s.event_id.to_string(), serde_json::to_value(&s.json).map_err(|_| MatrixError::internal())?))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::rooms::{apply_create_room, apply_invite, decide_and_apply_join, InviteTarget, RoomCreate, RoomCreation};
    use crate::store;
    use m4a_matrix_core::{key_to_b64, Signer};

    const NOW: &str = "2026-10-10T00:00:00+00:00";
    const TS: i64 = 1_760_000_000_000;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        store::create_matrix_schema(&c).unwrap();
        store::ensure_matrix_user(&c, 1, "alice000000000000000000000000001", NOW).unwrap();
        store::ensure_matrix_user(&c, 2, "bob00000000000000000000000000002", NOW).unwrap();
        c
    }

    fn create(c: &mut Connection, public: bool) -> String {
        let mxid = store::mxid_of(c, 1).unwrap().unwrap();
        match apply_create_room(c, RoomCreate { creator_user_id: 1, creator_mxid: &mxid, creator_displayname: "alice", is_direct: false, invitees: &[], visibility_public: public, power_level_content_override: None, name: Some("t"), topic: None, room_type: None }, NOW, TS).unwrap() {
            RoomCreation::Created { room_id, .. } => room_id,
            RoomCreation::Reused(_) => unreachable!(),
        }
    }

    fn ids(c: &Connection, room: &str) -> Vec<String> {
        c.prepare("SELECT event_id FROM events WHERE room_id = ?1 ORDER BY stream_id").unwrap().query_map([room], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    }

    fn count(c: &Connection, sql: &str) -> i64 {
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn is_hash_id(id: &str) -> bool {
        id.starts_with('$') && id.len() == 44 && !id.contains(['+', '/', '='])
    }

    fn send(c: &mut Connection, room: &str, txn: &str, ts: i64) -> store::MatrixEvent {
        let r = store::get_room(c, room).unwrap().unwrap();
        let mxid = store::mxid_of(c, 1).unwrap().unwrap();
        crate::messaging::apply_send(c, &r, 1, &mxid, "DEV", txn, &store::new_event_id(), "m.room.encrypted", r#"{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"c2VjcmV0","session_id":"s","sender_key":"k","device_id":"DEV"}"#, NOW, ts).unwrap().event
    }

    #[test]
    fn closed_room_lifecycle_events_all_get_hash_ids_and_dag_rows() {
        let mut c = conn();
        let room = create(&mut c, false);
        let alice = store::mxid_of(&c, 1).unwrap().unwrap();
        let bob = store::mxid_of(&c, 2).unwrap().unwrap();
        apply_invite(&mut c, &room, 1, &alice, InviteTarget { user_id: 2, displayname: "bob" }, NOW, TS + 10).unwrap();
        decide_and_apply_join(&mut c, &room, 2, &bob, "bob", NOW, TS + 20).unwrap();
        let m = send(&mut c, &room, "t1", TS + 30);
        crate::rooms::apply_leave(&mut c, &room, 2, &bob, NOW, TS + 40).unwrap();

        let all = ids(&c, &room);
        assert!(all.len() >= 9, "bootstrap + invite + join + message + leave: {all:?}");
        for id in &all {
            assert!(is_hash_id(id), "{id}");
            assert!(count(&c, &format!("SELECT COUNT(*) FROM dag_events WHERE event_id = '{id}' AND soft_failed = 0 AND outlier = 0")) == 1);
            let pdu: String = c.query_row("SELECT pdu FROM dag_events WHERE event_id = ?1", [id], |r| r.get(0)).unwrap();
            let v: Value = serde_json::from_str(&pdu).unwrap();
            assert!(v["hashes"]["sha256"].is_string() && v["signatures"][store::matrix_server_name()].is_object() && v.get("event_id").is_none());
            assert!(v["depth"].as_u64().unwrap() >= 1);
        }
        assert!(is_hash_id(&m.event_id), "the id the sender gets back is the computed one");
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_events"), all.len() as i64);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_extremities"), 1);
        let last: String = c.query_row("SELECT event_id FROM dag_extremities", [], |r| r.get(0)).unwrap();
        assert_eq!(&last, all.last().unwrap(), "linear history: the last event is the only extremity");
        // The projection the clients read equals the DAG's resolved state.
        let db = ConnDag { conn: &c, room: &room };
        let cur = dag::current_state(&rules(), &db).unwrap();
        let table: i64 = count(&c, &format!("SELECT COUNT(*) FROM current_state WHERE room_id = '{room}'"));
        assert_eq!(cur.len() as i64, table);
        for ((t, k), id) in &cur {
            let have: String = c.query_row("SELECT event_id FROM current_state WHERE room_id = ?1 AND event_type = ?2 AND state_key = ?3", params![room, t.to_string(), k], |r| r.get(0)).unwrap();
            assert_eq!(have, id.as_str());
        }
        let bob_state = store::room_member(&c, &room, 2).unwrap().unwrap().membership;
        assert_eq!(bob_state, store::Membership::Leave);
        // A repeated transaction id returns the same event, no second row.
        let again = send(&mut c, &room, "t1", TS + 31);
        assert_eq!(again.event_id, m.event_id);
    }

    #[test]
    fn the_event_write_and_the_dag_rows_roll_back_together() {
        let mut c = conn();
        let room = create(&mut c, false);
        let before = (count(&c, "SELECT COUNT(*) FROM dag_events"), count(&c, "SELECT COUNT(*) FROM events"));
        {
            let tx = c.transaction().unwrap();
            let p = prepare_local(&tx, &room, 1, "m.room.message", None, r#"{"body":"x"}"#, TS + 5).unwrap().unwrap();
            assert!(is_hash_id(&p.event_id));
            assert_eq!(count(&tx, "SELECT COUNT(*) FROM dag_events"), before.0 + 1);
            tx.rollback().unwrap();
        }
        assert_eq!((count(&c, "SELECT COUNT(*) FROM dag_events"), count(&c, "SELECT COUNT(*) FROM events")), before);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_extremities"), 1);
    }

    #[test]
    fn auth_rules_stop_an_event_in_the_same_transaction() {
        let mut c = conn();
        let room = create(&mut c, false);
        let before = count(&c, "SELECT COUNT(*) FROM dag_events");
        // bob is not a member: a state event from him is refused by the DAG's auth rules, nothing is written.
        let tx = c.transaction().unwrap();
        let r = prepare_local(&tx, &room, 2, "m.room.name", Some(""), r#"{"name":"x"}"#, TS + 6);
        assert!(matches!(r, Err(MatrixStoreError::F3Rejected(_))));
        drop(tx);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_events"), before);
    }

    #[test]
    fn legacy_rooms_and_public_channels_are_untouched() {
        let mut c = conn();
        let chan = create(&mut c, true);
        assert!(!is_f3_room(&c, &chan));
        for id in ids(&c, &chan) {
            assert!(!is_hash_id(&id) && id.len() < 30, "legacy random id: {id}");
        }
        // A room that exists without being marked keeps the id its caller chose.
        c.execute("INSERT INTO rooms (id, kind, creator_user_id, created_at) VALUES ('!old:example.org', 'group', 1, 't')", []).unwrap();
        store::apply_state_event(&mut c, &store::StateEventWrite { event_id: "$chosen", room_id: "!old:example.org", sender_user_id: 1, event_type: "m.room.topic", state_key: "", content: r#"{"topic":"t"}"#, origin_server_ts: TS, now: NOW }).unwrap();
        assert_eq!(ids(&c, "!old:example.org"), vec!["$chosen".to_string()]);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_events WHERE room_id = '!old:example.org'"), 0);
    }

    #[test]
    fn skeleton_erases_content_keeps_id_and_signatures() {
        let mut c = conn();
        let room = create(&mut c, false);
        let m = send(&mut c, &room, "t1", TS + 30);
        c.execute("INSERT INTO fed_outbox (destination, kind, room_id, event_id, payload, created_ms) VALUES ('b.example', 'send', ?1, ?2, '{}', 1)", params![room, m.event_id]).unwrap();
        assert!(!skeletonize(&c, &m.event_id).unwrap(), "refused while a delivery is queued");
        c.execute("DELETE FROM fed_outbox", []).unwrap();
        assert!(skeletonize(&c, &m.event_id).unwrap());
        let content: String = c.query_row("SELECT content FROM events WHERE event_id = ?1", [&m.event_id], |r| r.get(0)).unwrap();
        assert_eq!(content, "{}");
        let pdu: String = c.query_row("SELECT pdu FROM dag_events WHERE event_id = ?1", [&m.event_id], |r| r.get(0)).unwrap();
        let obj: CanonicalJsonObject = serde_json::from_str(&pdu).unwrap();
        assert_eq!(dag::compute_event_id(&rules(), &obj).unwrap().as_str(), m.event_id, "the skeleton still hashes to the same id");
        assert!(!pdu.contains("c2VjcmV0") && pdu.contains("signatures") && pdu.contains("prev_events"));
    }

    fn recv(c: &mut Connection, origin: &str, pdu: &Value) -> Result<Received, MatrixError> {
        let keys = peer_keys(c, pdu);
        receive_pdu(c, origin, pdu, &keys, NOW)
    }

    #[test]
    fn retention_turns_delivered_messages_of_dag_rooms_into_skeletons_instead_of_deleting_them() {
        let mut c = conn();
        crate::keys::create_matrix_keys_schema(&c).unwrap();
        crate::retention::create_retention_schema(&c).unwrap();
        let room = create(&mut c, false);
        let m = send(&mut c, &room, "t1", TS + 30);
        let policy = crate::retention::RetentionPolicy { ttl_ms: 1_000, ack_grace_ms: 0, keep_last: 0, stale_device_ms: 1 };
        let n = crate::retention::purge_delivered_events(&mut c, TS + 10_000_000, &policy).unwrap();
        assert_eq!(n, 1);
        // The row stays (its place in the room), the ciphertext is gone, the id still verifies.
        let content: String = c.query_row("SELECT content FROM events WHERE event_id = ?1", [&m.event_id], |r| r.get(0)).unwrap();
        assert_eq!(content, "{}");
        let skel: i64 = c.query_row("SELECT skeleton FROM dag_events WHERE event_id = ?1", [&m.event_id], |r| r.get(0)).unwrap();
        assert_eq!(skel, 1);
        // A second pass has nothing left to do.
        assert_eq!(crate::retention::purge_delivered_events(&mut c, TS + 10_000_000, &policy).unwrap(), 0);
    }

    fn peer_signer() -> Signer {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        Signer::new("b.example", "ed25519:b1", move |m| key.sign(m).to_bytes())
    }

    fn peer_keys(c: &Connection, pdu: &Value) -> PublicKeyMap {
        let mut keys = PublicKeyMap::new();
        let pk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key().to_bytes();
        add_key(&mut keys, "b.example", "ed25519:b1", &key_to_b64(&pk)).unwrap();
        assert!(missing_keys(c, &[pdu], &mut keys).is_empty(), "our own keys resolve locally, the peer's was supplied");
        keys
    }

    #[test]
    fn a_peers_join_is_checked_projected_and_a_stale_prev_forks_then_merges() {
        let mut c = conn();
        let room = create(&mut c, false);
        let alice = store::mxid_of(&c, 1).unwrap().unwrap();
        let bob = "@bob:b.example";
        let bob_uid = crate::fed_rooms::ensure_remote_user(&c, bob, NOW).unwrap();
        apply_invite(&mut c, &room, 1, &alice, InviteTarget { user_id: bob_uid, displayname: "bob" }, NOW, TS + 10).unwrap();

        // Bob's server takes a template now (prev = the invite) ...
        let mut tpl = join_template(&c, &room, bob, TS + 20).unwrap();
        tpl["content"]["displayname"] = Value::String("bob".into());
        // ... but alice's server moves on before the join arrives.
        let m = send(&mut c, &room, "t1", TS + 25);
        let signed = dag::sign_template(&rules(), &peer_signer(), json_obj(&tpl).unwrap()).unwrap();
        let wire = serde_json::to_value(&signed.json).unwrap();

        // A tampered copy and a copy signed by a stranger are refused and leave nothing behind.
        let rows = count(&c, "SELECT COUNT(*) FROM dag_events");
        let mut forged = wire.clone();
        forged["origin_server_ts"] = Value::from(1);
        assert!(recv(&mut c, "b.example", &forged).is_err());
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let other = Signer::new("b.example", "ed25519:b1", move |m| stranger.sign(m).to_bytes());
        let wrong = serde_json::to_value(&dag::sign_template(&rules(), &other, json_obj(&tpl).unwrap()).unwrap().json).unwrap();
        assert!(recv(&mut c, "b.example", &wrong).is_err());
        // Claiming another server's user is refused too.
        assert!(recv(&mut c, "c.example", &wire).is_err());
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_events"), rows);

        let got = recv(&mut c, "b.example", &wire).unwrap();
        assert_eq!(got.event_id, signed.event_id.as_str());
        assert!(got.forked && !got.soft_failed, "bob's join cites the invite, alice's message is a second branch");
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_extremities"), 2);
        assert_eq!(store::room_member(&c, &room, bob_uid).unwrap().unwrap().membership, store::Membership::Join, "projected into the room's membership");
        assert!(recv(&mut c, "b.example", &wire).unwrap().duplicate);

        // The next local event cites both branches and closes the fork.
        let m2 = send(&mut c, &room, "t2", TS + 50);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM dag_extremities"), 1);
        let pdu: String = c.query_row("SELECT pdu FROM dag_events WHERE event_id = ?1", [&m2.event_id], |r| r.get(0)).unwrap();
        let v: Value = serde_json::from_str(&pdu).unwrap();
        assert_eq!(v["prev_events"].as_array().unwrap().len(), 2);
        assert!(v["prev_events"].as_array().unwrap().iter().any(|p| p == m.event_id.as_str()));

        // The snapshot a peer would import carries the state and the extremity.
        let snap = snapshot_json(&c, &room, &m2.event_id).unwrap();
        assert!(snap["state"].as_array().unwrap().len() >= 7 && snap["extremities"].as_array().unwrap().len() == 1);
    }
}
