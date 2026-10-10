//! F3 spike (feature `f3-hash-ids`): the bootstrap events of a NEW room become real room-version-11
//! events. Ids are the reference hash of the signed event, every event carries `prev_events`,
//! `auth_events`, `depth`, a content hash and this server's ed25519 signature, and each one passed
//! the auth rules before it was accepted. The signed wire form is kept in `fed_pdus`.
//!
//! Scope of the spike: only the creation events. Later events in the room (joins, messages) still
//! get legacy ids; moving them is stage F3.1 (the DAG layer in `m4a-matrix-core` plus dag_* tables).

use ed25519_dalek::Signer as _;
use m4a_matrix_core::{OwnedRoomId, RoomBuilder, Signer};
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::store::NewStateEvent;

/// Re-issues `events` (the ordered creation events, all sent by `creator_mxid`) as signed v11 events.
/// Returns the same events with hash ids and with the content that was actually signed.
pub fn hash_bootstrap(conn: &Connection, room_id: &str, creator_mxid: &str, events: &[NewStateEvent], origin_ts_ms: i64) -> Result<Vec<NewStateEvent>, String> {
    let (key_id, key) = crate::federation::active_signing_key(conn, origin_ts_ms).map_err(|e| e.to_string())?;
    let signer = Signer::new(crate::store::matrix_server_name(), key_id, move |m| key.sign(m).to_bytes());
    let room: OwnedRoomId = room_id.try_into().map_err(|e: m4a_matrix_core::IdError| e.to_string())?;
    let mut builder = RoomBuilder::new(room, &signer, origin_ts_ms.max(0) as u64).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(events.len());
    for ev in events {
        let mut content: Value = serde_json::from_str(&ev.content).map_err(|e| e.to_string())?;
        if ev.event_type == "m.room.create" && content.get("creator").is_none() {
            // v11 still carries the creator in the create content; the legacy bootstrap omitted it.
            content["creator"] = Value::String(creator_mxid.to_owned());
        }
        let signed = builder.push(creator_mxid, &ev.event_type, Some(&ev.state_key), content.clone()).map_err(|e| e.to_string())?;
        let pdu = serde_json::to_string(&signed.json).map_err(|e| e.to_string())?;
        conn.execute("INSERT OR REPLACE INTO fed_pdus (event_id, room_id, pdu) VALUES (?1, ?2, ?3)", params![signed.event_id.as_str(), room_id, pdu]).map_err(|e| e.to_string())?;
        out.push(NewStateEvent {
            event_id: signed.event_id.to_string(),
            sender_user_id: ev.sender_user_id,
            event_type: ev.event_type.clone(),
            state_key: ev.state_key.clone(),
            content: content.to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rooms::{apply_create_room, RoomCreate, RoomCreation};
    use crate::store;

    const NOW: &str = "2026-10-10T00:00:00+00:00";

    #[test]
    fn a_new_room_gets_signed_events_with_reference_hash_ids() {
        let mut c = Connection::open_in_memory().unwrap();
        store::create_matrix_schema(&c).unwrap();
        store::ensure_matrix_user(&c, 1, "alice000000000000000000000000001", NOW).unwrap();
        store::ensure_matrix_user(&c, 2, "bob00000000000000000000000000002", NOW).unwrap();
        let mxid = store::mxid_of(&c, 1).unwrap().unwrap();
        let bob = store::mxid_of(&c, 2).unwrap().unwrap();
        for (direct, public, invitees) in [(false, true, vec![]), (true, false, vec![crate::rooms::RoomInvitee { user_id: 2, displayname: "bob" }])] {
            let _ = &bob;
            let RoomCreation::Created { room_id, .. } = apply_create_room(
                &mut c,
                RoomCreate {
                    creator_user_id: 1,
                    creator_mxid: &mxid,
                    creator_displayname: "alice",
                    is_direct: direct,
                    invitees: &invitees,
                    visibility_public: public,
                    power_level_content_override: None,
                    name: Some("spike"),
                    topic: None,
                    room_type: None,
                },
                NOW,
                1_760_000_000_000,
            )
            .unwrap() else { unreachable!() };

            let ids: Vec<String> = c.prepare("SELECT event_id FROM events WHERE room_id = ?1 ORDER BY rowid").unwrap().query_map([&room_id], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
            assert!(ids.len() >= 5, "bootstrap events: {ids:?}");
            for id in &ids {
                assert!(id.starts_with('$') && id.len() == 44, "hash id, not a random one: {id}");
                let pdu: String = c.query_row("SELECT pdu FROM fed_pdus WHERE event_id = ?1", [id], |r| r.get(0)).unwrap();
                let v: Value = serde_json::from_str(&pdu).unwrap();
                assert!(v["hashes"]["sha256"].is_string());
                assert!(v["signatures"][store::matrix_server_name()].is_object());
                assert!(v.get("event_id").is_none());
            }
        }
    }
}
