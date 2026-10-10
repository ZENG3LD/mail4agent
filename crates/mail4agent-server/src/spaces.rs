//! Domains with sub-rooms, the Matrix way: a domain is a Space (a room whose
//! `m.room.create` carries `type: m.space`), a sub-room is linked by an
//! `m.space.child` state event in the space (state_key = child room id,
//! content `via` = servers) and, optionally, a back-link `m.space.parent`
//! in the child. Everything here is derived from ordinary state events, so no
//! extra table exists and federation can later carry it unchanged.
//!
//! A space holds no chat. Child rooms keep their own store: DM/group stay in
//! the closed ciphertext pump, channels/forum in the public plaintext store.
//! Hierarchy is metadata only and is never purged.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::error::MatrixError;
use crate::store::{self, HistoryVisibility, JoinRule, Membership};

/// `m.room.create` `type` of a domain.
pub const SPACE_TYPE: &str = "m.space";

/// Rejects malformed `m.space.child` / `m.space.parent` content. Empty `{}`
/// is a removal and always valid; otherwise `via` must be a non-empty list of
/// strings, `order` (if any) a short string of printable ASCII, `suggested`
/// (if any) a bool.
pub fn validate_space_state(event_type: &str, content: &Value) -> Result<(), MatrixError> {
    if event_type != "m.space.child" && event_type != "m.space.parent" {
        return Ok(());
    }
    let Some(obj) = content.as_object() else {
        return Err(MatrixError::invalid_param("space link content must be an object"));
    };
    if obj.is_empty() {
        return Ok(());
    }
    let via_ok = obj.get("via").and_then(Value::as_array).is_some_and(|a| !a.is_empty() && a.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty())));
    if !via_ok {
        return Err(MatrixError::invalid_param("via must be a non-empty list of server names"));
    }
    if let Some(order) = obj.get("order") {
        let ok = order.as_str().is_some_and(|s| s.len() <= 50 && s.bytes().all(|b| (0x20..=0x7e).contains(&b)));
        if !ok {
            return Err(MatrixError::invalid_param("order must be a string of at most 50 printable ASCII characters"));
        }
    }
    if obj.get("suggested").is_some_and(|v| !v.is_boolean()) {
        return Err(MatrixError::invalid_param("suggested must be a boolean"));
    }
    Ok(())
}

fn state_content(conn: &Connection, room_id: &str, event_type: &str, key: &str) -> Result<Option<Value>, MatrixError> {
    Ok(store::current_state_event(conn, room_id, event_type, key)?.and_then(|e| serde_json::from_str(&e.content).ok()))
}

/// `type` from the room's `m.room.create`.
pub fn room_type(conn: &Connection, room_id: &str) -> Result<Option<String>, MatrixError> {
    Ok(state_content(conn, room_id, "m.room.create", "")?.and_then(|c| c.get("type").and_then(Value::as_str).map(str::to_string)))
}

/// Whether `m.room.join_rules` is `restricted` (or knock_restricted) and one
/// of its `allow` spaces has `user_id` joined. Join rule for restricted rooms
/// is read from state because the `rooms.join_rule` column only knows
/// invite/public.
pub fn restricted_allows(conn: &Connection, room_id: &str, user_id: i64) -> Result<bool, MatrixError> {
    let Some(rules) = state_content(conn, room_id, "m.room.join_rules", "")? else { return Ok(false) };
    if !matches!(rules.get("join_rule").and_then(Value::as_str), Some("restricted" | "knock_restricted")) {
        return Ok(false);
    }
    for allow in rules.get("allow").and_then(Value::as_array).into_iter().flatten() {
        if allow.get("type").and_then(Value::as_str) != Some("m.room_membership") {
            continue;
        }
        if let Some(space) = allow.get("room_id").and_then(Value::as_str) {
            if store::room_member(conn, space, user_id)?.is_some_and(|m| m.membership == Membership::Join) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn join_rule_wire(conn: &Connection, room: &store::Room) -> Result<String, MatrixError> {
    Ok(state_content(conn, &room.id, "m.room.join_rules", "")?
        .and_then(|c| c.get("join_rule").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| match room.join_rule {
            JoinRule::Public => "public".to_string(),
            JoinRule::Invite => "invite".to_string(),
        }))
}

fn caller_may_see(conn: &Connection, room: &store::Room, user_id: i64) -> Result<bool, MatrixError> {
    if store::room_member(conn, &room.id, user_id)?.is_some_and(|m| matches!(m.membership, Membership::Join | Membership::Invite)) {
        return Ok(true);
    }
    if room.join_rule == JoinRule::Public && room.history_visibility == HistoryVisibility::WorldReadable {
        return Ok(true);
    }
    if room.join_rule == JoinRule::Public {
        return Ok(true);
    }
    restricted_allows(conn, &room.id, user_id)
}

fn joined_count(conn: &Connection, room_id: &str) -> Result<i64, MatrixError> {
    let mut n = 0;
    for event in store::current_state_all(conn, room_id)? {
        if event.event_type == "m.room.member" {
            let c: Value = serde_json::from_str(&event.content)?;
            if c.get("membership").and_then(Value::as_str) == Some("join") {
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Valid children of `room_id`, ordered per the spec: `order` ascending
/// (rooms without one last), then origin_server_ts, then room id.
fn children(conn: &Connection, room_id: &str, suggested_only: bool) -> Result<Vec<(String, Value, i64, String)>, MatrixError> {
    let mut out = Vec::new();
    for event in store::current_state_all(conn, room_id)? {
        if event.event_type != "m.space.child" {
            continue;
        }
        let content: Value = serde_json::from_str(&event.content)?;
        let via_ok = content.get("via").and_then(Value::as_array).is_some_and(|a| !a.is_empty());
        if !via_ok {
            continue;
        }
        if suggested_only && content.get("suggested").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let sender = store::mxid_of(conn, event.sender_user_id)?.unwrap_or_default();
        out.push((event.state_key.clone().unwrap_or_default(), json!({
            "type": "m.space.child",
            "state_key": event.state_key,
            "content": content,
            "sender": sender,
            "origin_server_ts": event.origin_server_ts,
        }), event.origin_server_ts, content.get("order").and_then(Value::as_str).unwrap_or("\u{10ffff}").to_string()));
    }
    out.sort_by(|a, b| a.3.cmp(&b.3).then(a.2.cmp(&b.2)).then(a.0.cmp(&b.0)));
    Ok(out)
}

/// `GET /rooms/{roomId}/hierarchy` (CS API v1). Breadth-first from `root`,
/// each room once, only rooms the caller may see, `max_depth` levels below the
/// root. `from` is an opaque offset token (the page cut is deterministic for a
/// stable tree). `Ok(None)` when the root itself is not visible.
pub fn hierarchy(
    conn: &Connection,
    caller_user_id: i64,
    root: &str,
    suggested_only: bool,
    limit: usize,
    max_depth: Option<usize>,
    from: usize,
) -> Result<Option<Value>, MatrixError> {
    let Some(root_room) = store::get_room(conn, root)? else { return Ok(None) };
    if !caller_may_see(conn, &root_room, caller_user_id)? {
        return Ok(None);
    }
    let mut seen = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((root.to_string(), 0usize));
    seen.insert(root.to_string());
    let mut rooms = Vec::new();
    while let Some((room_id, depth)) = queue.pop_front() {
        let Some(room) = store::get_room(conn, &room_id)? else { continue };
        if !caller_may_see(conn, &room, caller_user_id)? {
            continue;
        }
        let kids = children(conn, &room_id, suggested_only)?;
        let is_space = room_type(conn, &room_id)?.as_deref() == Some(SPACE_TYPE);
        let name = state_content(conn, &room_id, "m.room.name", "")?.and_then(|c| c.get("name").and_then(Value::as_str).map(str::to_string));
        let topic = state_content(conn, &room_id, "m.room.topic", "")?.and_then(|c| c.get("topic").and_then(Value::as_str).map(str::to_string));
        let mut entry = json!({
            "room_id": room_id,
            "num_joined_members": joined_count(conn, &room_id)?,
            "world_readable": room.history_visibility == HistoryVisibility::WorldReadable,
            "guest_can_join": false,
            "join_rule": join_rule_wire(conn, &room)?,
            "children_state": kids.iter().map(|k| k.1.clone()).collect::<Vec<_>>(),
        });
        let obj = entry.as_object_mut().expect("object");
        if let Some(n) = name { obj.insert("name".into(), json!(n)); }
        if let Some(t) = topic { obj.insert("topic".into(), json!(t)); }
        if is_space { obj.insert("room_type".into(), json!(SPACE_TYPE)); }
        rooms.push(entry);
        if max_depth.is_none_or(|m| depth < m) {
            for (child, ..) in &kids {
                if seen.insert(child.clone()) {
                    queue.push_back((child.clone(), depth + 1));
                }
            }
        }
    }
    let total = rooms.len();
    let page: Vec<Value> = rooms.into_iter().skip(from).take(limit).collect();
    let mut resp = json!({ "rooms": page });
    if from + limit < total {
        resp["next_batch"] = json!(format!("h{}", from + limit));
    }
    Ok(Some(resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_link_validation() {
        assert!(validate_space_state("m.space.child", &json!({})).is_ok());
        assert!(validate_space_state("m.space.child", &json!({"via": ["a.example"], "order": "01", "suggested": true})).is_ok());
        assert!(validate_space_state("m.space.child", &json!({"via": []})).is_err());
        assert!(validate_space_state("m.space.parent", &json!({"nope": 1})).is_err());
        assert!(validate_space_state("m.space.child", &json!({"via": ["a"], "order": "é"})).is_err());
        assert!(validate_space_state("m.room.name", &json!("anything")).is_ok());
    }

    use crate::rooms::{apply_create_room, apply_put_state, decide_and_apply_join, RoomCreate, RoomCreation};

    const NOW: &str = "2026-10-09T00:00:00+00:00";

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        store::create_matrix_schema(&c).unwrap();
        store::ensure_matrix_user(&c, 1, "alice000000000000000000000000001", NOW).unwrap();
        store::ensure_matrix_user(&c, 2, "bob00000000000000000000000000002", NOW).unwrap();
        c
    }

    fn make(c: &mut Connection, public: bool, name: &str, room_type: Option<&str>) -> String {
        let mxid = store::mxid_of(c, 1).unwrap().unwrap();
        match apply_create_room(
            c,
            RoomCreate {
                creator_user_id: 1,
                creator_mxid: &mxid,
                creator_displayname: "alice",
                is_direct: false,
                invitees: &[],
                visibility_public: public,
                power_level_content_override: None,
                name: Some(name),
                topic: None,
                room_type,
                predecessor: None,
            },
            NOW,
            1,
        )
        .unwrap()
        {
            RoomCreation::Created { room_id, .. } => room_id,
            RoomCreation::Reused(_) => unreachable!(),
        }
    }

    fn put(c: &mut Connection, room: &str, ty: &str, key: &str, content: Value) {
        let mxid = store::mxid_of(c, 1).unwrap().unwrap();
        apply_put_state(c, room, 1, &mxid, ty, key, &content.to_string(), NOW, 2).unwrap();
    }

    #[test]
    fn domain_with_subrooms_hierarchy_and_visibility() {
        let mut c = conn();
        let domain = make(&mut c, true, "acme", Some(SPACE_TYPE));
        let chan = make(&mut c, true, "announce", None);
        let grp = make(&mut c, false, "ops", None);
        assert_eq!(room_type(&c, &domain).unwrap().as_deref(), Some(SPACE_TYPE));
        assert_eq!(room_type(&c, &chan).unwrap(), None);
        put(&mut c, &domain, "m.space.child", &chan, json!({"via": ["localhost"], "order": "a"}));
        put(&mut c, &domain, "m.space.child", &grp, json!({"via": ["localhost"], "order": "b", "suggested": true}));
        put(&mut c, &chan, "m.space.parent", &domain, json!({"via": ["localhost"], "canonical": true}));
        // Alice (member of all): sees all three, ordered, space typed.
        let h = hierarchy(&c, 1, &domain, false, 50, None, 0).unwrap().unwrap();
        let ids: Vec<&str> = h["rooms"].as_array().unwrap().iter().map(|r| r["room_id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec![domain.as_str(), chan.as_str(), grp.as_str()]);
        assert_eq!(h["rooms"][0]["room_type"], SPACE_TYPE);
        assert_eq!(h["rooms"][0]["children_state"].as_array().unwrap().len(), 2);
        // Bob (nobody): sees the public domain and public channel, not the closed group.
        let h = hierarchy(&c, 2, &domain, false, 50, None, 0).unwrap().unwrap();
        let ids: Vec<&str> = h["rooms"].as_array().unwrap().iter().map(|r| r["room_id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec![domain.as_str(), chan.as_str()]);
        // suggested_only, max_depth 0, pagination.
        assert_eq!(hierarchy(&c, 1, &domain, true, 50, None, 0).unwrap().unwrap()["rooms"].as_array().unwrap().len(), 2);
        assert_eq!(hierarchy(&c, 1, &domain, false, 50, Some(0), 0).unwrap().unwrap()["rooms"].as_array().unwrap().len(), 1);
        let p = hierarchy(&c, 1, &domain, false, 2, None, 0).unwrap().unwrap();
        assert_eq!(p["next_batch"], "h2");
        assert_eq!(hierarchy(&c, 1, &domain, false, 2, None, 2).unwrap().unwrap()["rooms"].as_array().unwrap().len(), 1);
        // A removed child (empty content) drops out.
        put(&mut c, &domain, "m.space.child", &chan, json!({}));
        assert_eq!(hierarchy(&c, 1, &domain, false, 50, None, 0).unwrap().unwrap()["rooms"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn restricted_room_admits_space_members_only() {
        let mut c = conn();
        let domain = make(&mut c, true, "acme", Some(SPACE_TYPE));
        let grp = make(&mut c, false, "ops", None);
        put(&mut c, &grp, "m.room.join_rules", "", json!({"join_rule": "restricted", "allow": [{"type": "m.room_membership", "room_id": domain}]}));
        let bob = store::mxid_of(&c, 2).unwrap().unwrap();
        // Bob is not in the domain yet: refused.
        assert!(decide_and_apply_join(&mut c, &grp, 2, &bob, "bob", NOW, 3).is_err());
        // Public domain: bob joins it, then the restricted room opens.
        decide_and_apply_join(&mut c, &domain, 2, &bob, "bob", NOW, 4).unwrap();
        assert!(restricted_allows(&c, &grp, 2).unwrap());
        decide_and_apply_join(&mut c, &grp, 2, &bob, "bob", NOW, 5).unwrap();
    }
}
