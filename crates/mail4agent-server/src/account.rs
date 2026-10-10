//! Account data, tags, filters, and public-room listing.
//! Profile nick lookup and any restricted user directory are product concerns, not in this crate.

use rusqlite::Connection;

use crate::error::MatrixError;
use crate::store::Membership;

// ============================================================================
// GET /_matrix/client/v3/account/whoami
// ============================================================================

/// `GET /account/whoami`'s wire shape: the caller's own mxid and the device
/// this credential resolved to (minting it on first use — see
/// [`auth::device_id_for`]'s own doc). This is how a client with no
/// `/login` flow (this server has none — plan §1) learns its own device id.
/// `is_guest` is always `false`: this server has no guest accounts.
pub fn whoami_response(mxid: &str, device_id: &str) -> serde_json::Value {
    serde_json::json!({ "user_id": mxid, "device_id": device_id, "is_guest": false })
}


// ============================================================================
// Shared DB-only gate helpers — own copies per this codebase's convention
// (mirror `routes::matrix::rooms`/`ephemeral`'s own `require_member` byte-
// for-byte).
// ============================================================================

pub fn require_member(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member of this room")),
    }
}


/// The tags gate (P8 brief item 3): joined OR invited, unlike plain
/// per-room account data (item 2), which requires a full join.
pub fn require_member_or_invited(membership: Option<Membership>) -> Result<(), MatrixError> {
    match membership {
        Some(Membership::Join) | Some(Membership::Invite) => Ok(()),
        _ => Err(MatrixError::forbidden("not a member or invitee of this room")),
    }
}


/// Every `/user/{userId}/...` route in this module: the path's `userId`
/// (a full mxid) must be the caller's own — this server has no notion of one
/// account managing another's account data/tags/filters.
pub fn check_caller_owns_user_id(path_user_id: &str, caller_mxid: &str) -> Result<(), MatrixError> {
    if path_user_id == caller_mxid {
        Ok(())
    } else {
        Err(MatrixError::forbidden("userId must be the caller's own mxid"))
    }
}


// ============================================================================
// Account data (global + per-room)
// ============================================================================

/// `m.fully_read` is refused on both the global and per-room account-data
/// endpoints (P8 brief items 1/2): it belongs to room account data via
/// `POST .../read_markers` ([`crate::ephemeral::apply_read_markers`]), which
/// is the only writer this server ever lets touch it — a raw `PUT` here
/// would let a client desync it from the receipt bookkeeping that route also
/// updates in the same call.
pub fn check_account_data_type_allowed(event_type: &str) -> Result<(), MatrixError> {
    if event_type == "m.fully_read" {
        Err(MatrixError::managed_account_data_type(
            "m.fully_read is managed through POST .../read_markers, not raw account data",
        ))
    } else {
        Ok(())
    }
}


/// `PUT` account-data content must be a JSON object (Matrix's own shape for
/// every account-data type) within [`crate::store::MATRIX_EVENT_CONTENT_MAX_BYTES`]
/// once serialized — same ceiling `routes::matrix::rooms::put_state` applies
/// to state-event content. Returns the serialized string ready to store.
pub fn validate_account_data_content(value: &serde_json::Value) -> Result<String, MatrixError> {
    if !value.is_object() {
        return Err(MatrixError::bad_json("account data content must be a JSON object"));
    }
    let serialized = value.to_string();
    if serialized.len() > crate::store::MATRIX_EVENT_CONTENT_MAX_BYTES {
        return Err(MatrixError::invalid_param("account data content too large"));
    }
    Ok(serialized)
}


// ============================================================================
// Tags — a thin view over room account data type `m.tag`
// ============================================================================

pub const MAX_TAG_NAME_BYTES: usize = 255;

pub const MAX_TAGS_PER_ROOM: usize = 100;


#[derive(serde::Deserialize, Default)]
pub struct TagBody {
    #[serde(default)]
    pub order: Option<f64>,
}


pub fn validate_tag_name(tag: &str) -> Result<(), MatrixError> {
    if tag.is_empty() || tag.len() > MAX_TAG_NAME_BYTES {
        Err(MatrixError::invalid_param("tag name must be 1-255 bytes"))
    } else {
        Ok(())
    }
}


/// `order` (P8 brief item 3): when present, must be in `[0, 1]`.
pub fn validate_tag_order(order: Option<f64>) -> Result<(), MatrixError> {
    match order {
        Some(v) if !(0.0..=1.0).contains(&v) => Err(MatrixError::invalid_param("tag order must be between 0 and 1")),
        _ => Ok(()),
    }
}


/// `{"tags": {...}}`'s `tags` object, or empty when the room has no `m.tag`
/// account-data row yet.
pub fn read_tags(conn: &Connection, user_id: i64, room_id: &str) -> Result<serde_json::Map<String, serde_json::Value>, MatrixError> {
    match crate::store::get_account_data(conn, user_id, room_id, "m.tag")? {
        Some(row) => {
            let content: serde_json::Value = serde_json::from_str(&row.content)?;
            Ok(content.get("tags").and_then(|v| v.as_object()).cloned().unwrap_or_default())
        }
        None => Ok(serde_json::Map::new()),
    }
}


pub fn write_tags(conn: &mut Connection, user_id: i64, room_id: &str, tags: serde_json::Map<String, serde_json::Value>) -> Result<(), MatrixError> {
    let content = serde_json::json!({ "tags": tags }).to_string();
    crate::store::upsert_account_data(conn, user_id, room_id, "m.tag", &content)?;
    Ok(())
}


/// `PUT .../tags/{tag}`'s whole DB-side decision: validate the tag name and
/// `order`, refuse growing past [`MAX_TAGS_PER_ROOM`] on a genuinely NEW tag
/// (re-setting an existing tag's `order` never counts against the cap), then
/// upsert. Membership is checked by the route handler, not here (this
/// function takes no caller/room-membership context at all — the "testable
/// cores" convention this module states).
pub fn apply_tag_put(conn: &mut Connection, user_id: i64, room_id: &str, tag: &str, order: Option<f64>) -> Result<(), MatrixError> {
    validate_tag_name(tag)?;
    validate_tag_order(order)?;

    let mut tags = read_tags(conn, user_id, room_id)?;
    if !tags.contains_key(tag) && tags.len() >= MAX_TAGS_PER_ROOM {
        return Err(MatrixError::invalid_param("too many tags on this room"));
    }
    let mut entry = serde_json::Map::new();
    if let Some(order) = order {
        entry.insert("order".to_string(), serde_json::json!(order));
    }
    tags.insert(tag.to_string(), serde_json::Value::Object(entry));
    write_tags(conn, user_id, room_id, tags)
}


/// `DELETE .../tags/{tag}` — idempotent: removing an absent tag is a
/// silent no-op, matching Matrix's own DELETE semantics.
pub fn apply_tag_delete(conn: &mut Connection, user_id: i64, room_id: &str, tag: &str) -> Result<(), MatrixError> {
    let mut tags = read_tags(conn, user_id, room_id)?;
    tags.remove(tag);
    write_tags(conn, user_id, room_id, tags)
}


// ============================================================================
// Filters
// ============================================================================

/// Ceiling on a stored Filter JSON object (P8 brief item 4).
pub const FILTER_MAX_BYTES: usize = 64 * 1024;


/// A Filter must be a JSON object within [`FILTER_MAX_BYTES`] once
/// serialized — stored verbatim, opaque, interpreted only by a later `/sync`
/// piece. Returns the serialized string ready to store.
pub fn validate_filter_definition(value: &serde_json::Value) -> Result<String, MatrixError> {
    if !value.is_object() {
        return Err(MatrixError::bad_json("filter must be a JSON object"));
    }
    let serialized = value.to_string();
    if serialized.len() > FILTER_MAX_BYTES {
        return Err(MatrixError::invalid_param("filter definition too large"));
    }
    Ok(serialized)
}


// ============================================================================
// POST /_matrix/client/v3/user_directory/search
// ============================================================================

/// A trimmed, lowercased `search_term` longer than this is truncated rather
/// than refused — matches `routes::dm::lookup_recipients`'s own
/// `MAX_LOOKUP_QUERY_LEN`.
pub const MAX_SEARCH_TERM_LEN: usize = 64;


/// `limit`'s default when the client omits it — matches
/// `routes::dm::lookup_recipients`'s own `MAX_LOOKUP_RESULTS`.
pub const DEFAULT_DIRECTORY_RESULTS: usize = 10;


/// Ceiling a client-supplied `limit` is clamped to — the DM lookup has no
/// client-facing `limit` at all (always 10); the Matrix endpoint's own spec
/// shape does take one, so this is the abuse-prevention ceiling on it.
pub const MAX_DIRECTORY_RESULTS: usize = 50;


#[derive(serde::Deserialize)]
pub struct UserDirectorySearchRequest {
    pub search_term: String,
    #[serde(default)]
    pub limit: Option<i64>,
}


#[derive(serde::Serialize)]
pub struct UserDirectoryResult {
    pub user_id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}


#[derive(serde::Serialize)]
pub struct UserDirectorySearchResponse {
    pub results: Vec<UserDirectoryResult>,
    pub limited: bool,
}


/// One ranked, labeled match — [`rank_directory_candidates`]'s own output
/// row, carrying `public_id` along so the route handler can
/// [`crate::store::ensure_matrix_user`] it into an mxid without a second
/// identity-database round trip.
pub struct DirectoryMatch {
    pub user_id: i64,
    pub public_id: String,
    pub label: String,
}


// ============================================================================
// GET/POST /_matrix/client/v3/publicRooms
// ============================================================================

pub const DEFAULT_PUBLIC_ROOMS_LIMIT: i64 = 20;

pub const MAX_PUBLIC_ROOMS_LIMIT: i64 = 100;


pub fn clamp_public_rooms_limit(limit: Option<i64>) -> usize {
    limit.unwrap_or(DEFAULT_PUBLIC_ROOMS_LIMIT).clamp(1, MAX_PUBLIC_ROOMS_LIMIT) as usize
}


#[derive(serde::Deserialize, Default)]
pub struct PublicRoomsQuery {
    pub limit: Option<i64>,
    pub since: Option<String>,
}


#[derive(serde::Deserialize, Default)]
pub struct PublicRoomsFilter {
    #[serde(default)]
    pub generic_search_term: Option<String>,
}


#[derive(serde::Deserialize, Default)]
pub struct PublicRoomsRequestBody {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub filter: PublicRoomsFilter,
}


/// One `chunk` entry's wire shape (P8 brief item 7) — `name`/`topic` are
/// omitted entirely (not `null`) when the room never set them, matching
/// Matrix's own convention of omitting rather than nulling absent profile
/// fields.
pub fn public_room_json(room: &crate::store::PublicRoomSummary) -> serde_json::Value {
    let mut value = serde_json::json!({
        "room_id": room.room_id,
        "num_joined_members": room.num_joined_members,
        "world_readable": room.world_readable,
        "guest_can_join": false,
        "join_rule": "public",
    });
    if let Some(name) = &room.name {
        value["name"] = serde_json::Value::String(name.clone());
    }
    if let Some(topic) = &room.topic {
        value["topic"] = serde_json::Value::String(topic.clone());
    }
    value
}


/// One page of public rooms from the messenger database alone.
pub fn list_public_rooms(
    conn: &Connection,
    since: Option<&str>,
    limit: Option<i64>,
    search_term: Option<&str>,
) -> Result<serde_json::Value, MatrixError> {
    let limit = clamp_public_rooms_limit(limit);
    let (page, has_more, total) = crate::store::public_rooms_page(conn, since, limit, search_term)?;
    let chunk: Vec<serde_json::Value> = page.iter().map(public_room_json).collect();
    let mut response = serde_json::json!({ "chunk": chunk, "total_room_count_estimate": total });
    if has_more {
        if let Some(last) = page.last() {
            response["next_batch"] = serde_json::Value::String(last.room_id.clone());
        }
    }
    Ok(response)
}

/// Match an mxid localpart stored in this database. No nick index and no
/// restricted directory: a product owns both of those.
pub fn search_users_by_localpart(conn: &Connection, query: &str, limit: usize) -> rusqlite::Result<Vec<String>> {
    let limit = limit.clamp(1, 50) as i64;
    let pattern = format!("%{query}%");
    let mut stmt = conn.prepare(
        "SELECT mxid FROM matrix_users WHERE mxid LIKE ?1 ORDER BY mxid LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![pattern, limit], |row| row.get(0))?;
    rows.collect()
}
