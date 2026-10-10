//! Client routes stock clients (Element and others) ask for beyond the core set: room aliases,
//! event context, search, profile avatar and remote profiles, OpenID tokens, reports, threads,
//! room upgrade, and the account routes this server leaves to the product (registration, password,
//! third-party ids). Paths have no `/_matrix` prefix.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use super::{resolve_caller, with_conn_pub, with_read_pub, Homeserver};
use crate::error::MatrixError;
use crate::store::{self, HistoryWindow, Membership};

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    Router::new()
        .route("/client/v3/directory/room/{alias}", put(put_alias).get(get_alias).delete(delete_alias))
        .route("/client/v3/rooms/{room_id}/aliases", get(room_aliases))
        .route("/client/v3/rooms/{room_id}/context/{event_id}", get(context))
        .route("/client/v3/search", post(search))
        .route("/client/v3/profile/{user_id}/avatar_url", get(get_avatar).put(put_avatar).delete(delete_avatar))
        .route("/client/v3/user/{user_id}/openid/request_token", post(openid_request_token))
        .route("/client/v3/rooms/{room_id}/report/{event_id}", post(report_event))
        .route("/client/v3/rooms/{room_id}/report", post(report_room))
        .route("/client/v1/rooms/{room_id}/threads", get(threads))
        .route("/client/v3/rooms/{room_id}/upgrade", post(upgrade))
        .route("/client/v3/register", post(product_owns))
        .route("/client/v3/register/available", get(product_owns))
        .route("/client/v3/account/password", post(product_owns))
        .route("/client/v3/account/deactivate", post(product_owns))
        .route("/client/v3/account/3pid", get(no_threepids))
        .route("/client/v3/account/3pid/add", post(product_owns))
        .route("/client/v3/account/3pid/bind", post(product_owns))
        .route("/client/v3/account/3pid/delete", post(product_owns))
        .route("/client/v3/account/3pid/unbind", post(product_owns))
}

pub fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS room_aliases (
            alias TEXT PRIMARY KEY,
            room_id TEXT NOT NULL,
            creator_user_id INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_room_aliases_room ON room_aliases(room_id);
        CREATE TABLE IF NOT EXISTS user_avatar (
            user_id INTEGER PRIMARY KEY,
            avatar_url TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS openid_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS event_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            event_id TEXT,
            reporter_user_id INTEGER NOT NULL,
            reason TEXT,
            score INTEGER,
            created_at TEXT NOT NULL
        );
        ",
    )
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ----------------------------------------------------------------- account routes left to the product

/// Registration, password and third-party ids belong to the product layer; the messenger core says
/// so in Matrix terms.
async fn product_owns() -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::forbidden("accounts are managed at the product server, not here"))
}

async fn no_threepids(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!({ "threepids": [] })))
}

// ----------------------------------------------------------------- aliases

fn valid_alias(alias: &str) -> bool {
    alias.starts_with('#') && alias.len() <= 255 && alias.split_once(':').is_some_and(|(l, d)| l.len() > 1 && !d.is_empty())
}

fn alias_domain(alias: &str) -> &str {
    alias.split_once(':').map(|(_, d)| d).unwrap_or("")
}

async fn put_alias(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(alias): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    if !valid_alias(&alias) || !store::is_local_server_name(alias_domain(&alias)) {
        return Err(MatrixError::invalid_param("a local alias looks like #name:this-server"));
    }
    let room = body.get("room_id").and_then(Value::as_str).ok_or_else(|| MatrixError::bad_json("room_id"))?.to_string();
    with_conn_pub(&state, move |c| {
        store::get_room(c, &room)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        if store::room_member(c, &room, caller.user_id)?.map(|m| m.membership) != Some(Membership::Join) {
            return Err(MatrixError::forbidden("only a member can name a room"));
        }
        let n = c.execute("INSERT OR IGNORE INTO room_aliases (alias, room_id, creator_user_id) VALUES (?1, ?2, ?3)", params![alias, room, caller.user_id]).map_err(|_| MatrixError::internal())?;
        if n == 0 {
            return Err(MatrixError::new(409, "M_UNKNOWN", "that alias is taken"));
        }
        Ok(Json(json!({})))
    })
    .await
}

/// Local lookup.
pub(crate) fn resolve_local_alias(conn: &Connection, alias: &str) -> Option<String> {
    conn.query_row("SELECT room_id FROM room_aliases WHERE alias = ?1", [alias], |r| r.get(0)).optional().ok().flatten()
}

/// Alias to `(room id, servers)`, asking the alias's own server when it is another one.
pub(crate) async fn resolve_alias(state: &Arc<Homeserver>, alias: &str) -> Result<(String, Vec<String>), MatrixError> {
    if !valid_alias(alias) {
        return Err(MatrixError::invalid_param("not an alias"));
    }
    let domain = alias_domain(alias).to_string();
    if store::is_local_server_name(&domain) {
        let a = alias.to_string();
        let room = with_read_pub(state, move |c| Ok(resolve_local_alias(c, &a))).await?.ok_or_else(|| MatrixError::not_found("no such alias"))?;
        return Ok((room, vec![store::matrix_server_name().to_string()]));
    }
    if state.federation_enabled.get().is_none() {
        return Err(MatrixError::not_found("no such alias"));
    }
    let q = format!("/federation/v1/query/directory?room_alias={}", crate::federation::enc(alias));
    let (status, v) = super::fed_net::fed_request(state, &domain, "GET", &q, None).await?;
    if status != 200 {
        return Err(MatrixError::not_found("no such alias"));
    }
    let room = v.get("room_id").and_then(Value::as_str).ok_or_else(|| MatrixError::not_found("no such alias"))?.to_string();
    let servers = v.get("servers").and_then(Value::as_array).map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()).unwrap_or_else(|| vec![domain]);
    Ok((room, servers))
}

async fn get_alias(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(alias): Path<String>) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    let (room, servers) = resolve_alias(&state, &alias).await?;
    Ok(Json(json!({ "room_id": room, "servers": servers })))
}

async fn delete_alias(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(alias): Path<String>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    with_conn_pub(&state, move |c| {
        let row: Option<(String, i64)> = c.query_row("SELECT room_id, creator_user_id FROM room_aliases WHERE alias = ?1", [&alias], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(|_| MatrixError::internal())?;
        let (room, creator) = row.ok_or_else(|| MatrixError::not_found("no such alias"))?;
        let room_creator = store::get_room(c, &room)?.map(|r| r.creator_user_id);
        if creator != caller.user_id && room_creator != Some(caller.user_id) {
            return Err(MatrixError::forbidden("only the one who made the alias or the room's creator can remove it"));
        }
        c.execute("DELETE FROM room_aliases WHERE alias = ?1", [&alias]).map_err(|_| MatrixError::internal())?;
        Ok(Json(json!({})))
    })
    .await
}

async fn room_aliases(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(room_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    with_read_pub(&state, move |c| {
        if store::room_member(c, &room_id, caller.user_id)?.map(|m| m.membership) != Some(Membership::Join) {
            return Err(MatrixError::forbidden("only a member can list a room's aliases"));
        }
        let mut st = c.prepare("SELECT alias FROM room_aliases WHERE room_id = ?1 ORDER BY alias").map_err(|_| MatrixError::internal())?;
        let list: Vec<String> = st.query_map([&room_id], |r| r.get(0)).map_err(|_| MatrixError::internal())?.flatten().collect();
        Ok(Json(json!({ "aliases": list })))
    })
    .await
}

// ----------------------------------------------------------------- context

#[derive(serde::Deserialize)]
struct ContextQuery {
    limit: Option<i64>,
}

async fn context(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((room_id, event_id)): Path<(String, String)>, Query(q): Query<ContextQuery>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let (user_id, device_id) = (caller.user_id, caller.device_id);
    let half = (q.limit.unwrap_or(10).clamp(0, 100) / 2).max(1);
    with_read_pub(&state, move |c| {
        let room = store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = store::visible_upper_bound(c, &room, user_id)?;
        if window == HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }
        let ev = store::get_event(c, &event_id)?.filter(|e| e.room_id == room_id).ok_or_else(|| MatrixError::not_found("no such event"))?;
        if !window.contains(ev.stream_id) {
            return Err(MatrixError::forbidden("event is outside your visible history"));
        }
        let public = crate::public_channels::is_public_room(c, &room_id)?;
        let mut before = if public { crate::public_channels::events_before(c, &room_id, ev.stream_id, half)? } else { store::events_in_room_before(c, &room_id, ev.stream_id, half)? };
        let mut after = if public { crate::public_channels::events_after(c, &room_id, ev.stream_id, half)? } else { store::events_in_room_after(c, &room_id, ev.stream_id, half)? };
        before.retain(|e| window.contains(e.stream_id));
        after.retain(|e| window.contains(e.stream_id));
        let json_of = |e: &store::MatrixEvent| -> Result<Value, MatrixError> {
            let txn = store::txn_id_for_event(c, user_id, &device_id, &e.event_id)?;
            crate::events::client_event_json(c, e, txn.as_deref())
        };
        let mut state_events = Vec::new();
        let senders: std::collections::HashSet<i64> = before.iter().chain(after.iter()).chain(std::iter::once(&ev)).map(|e| e.sender_user_id).collect();
        for s in store::current_state_all(c, &room_id)? {
            let keep = s.event_type != "m.room.member" || store::user_id_of(c, s.state_key.as_deref().unwrap_or("")).ok().flatten().is_some_and(|u| senders.contains(&u));
            if keep {
                state_events.push(json_of(&s)?);
            }
        }
        let mut out = json!({
            "event": json_of(&ev)?,
            "events_before": before.iter().map(&json_of).collect::<Result<Vec<_>, _>>()?,
            "events_after": after.iter().map(&json_of).collect::<Result<Vec<_>, _>>()?,
            "state": state_events,
        });
        out["start"] = json!(format!("t{}", before.last().map(|e| e.stream_id).unwrap_or(ev.stream_id)));
        out["end"] = json!(format!("t{}", after.last().map(|e| e.stream_id).unwrap_or(ev.stream_id)));
        Ok(Json(out))
    })
    .await
}

// ----------------------------------------------------------------- search

#[derive(serde::Deserialize)]
struct SearchQuery {
    next_batch: Option<String>,
}

/// Room-event search over the text rooms the caller can read (public channels; encrypted rooms hold
/// ciphertext and are searched by the client). Newest first, substring match, case-insensitive.
async fn search(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Query(q): Query<SearchQuery>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let re = body.pointer("/search_categories/room_events").cloned().ok_or_else(|| MatrixError::bad_json("search_categories.room_events"))?;
    let term = re.get("search_term").and_then(Value::as_str).unwrap_or("").trim().to_lowercase();
    if term.is_empty() {
        return Err(MatrixError::invalid_param("search_term must not be empty"));
    }
    let only_rooms: Option<Vec<String>> = re.pointer("/filter/rooms").and_then(Value::as_array).map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect());
    let limit = re.pointer("/filter/limit").and_then(Value::as_i64).unwrap_or(10).clamp(1, 100) as usize;
    let skip: usize = q.next_batch.as_deref().and_then(|s| s.strip_prefix('n')).and_then(|s| s.parse().ok()).unwrap_or(0);
    let (user_id, device_id) = (caller.user_id, caller.device_id);
    with_read_pub(&state, move |c| {
        let mut hits: Vec<(i64, store::MatrixEvent)> = Vec::new();
        for room_id in store::rooms_for_user(c, user_id, Some(Membership::Join))? {
            if only_rooms.as_ref().is_some_and(|r| !r.contains(&room_id)) {
                continue;
            }
            let room = match store::get_room(c, &room_id)? {
                Some(r) => r,
                None => continue,
            };
            if room.is_encrypted {
                continue;
            }
            let window = store::visible_upper_bound(c, &room, user_id)?;
            let public = crate::public_channels::is_public_room(c, &room_id)?;
            let events = if public { crate::public_channels::events_before(c, &room_id, i64::MAX, 2000)? } else { store::events_in_room_before(c, &room_id, i64::MAX, 2000)? };
            for e in events {
                if e.event_type != "m.room.message" || !window.contains(e.stream_id) {
                    continue;
                }
                let body = serde_json::from_str::<Value>(&e.content).ok().and_then(|v| v.get("body").and_then(Value::as_str).map(str::to_lowercase)).unwrap_or_default();
                if body.contains(&term) {
                    hits.push((e.origin_server_ts, e));
                }
            }
        }
        hits.sort_by(|a, b| b.0.cmp(&a.0));
        let total = hits.len();
        let mut results = Vec::new();
        for (_, e) in hits.iter().skip(skip).take(limit) {
            let txn = store::txn_id_for_event(c, user_id, &device_id, &e.event_id)?;
            results.push(json!({ "rank": 1.0, "result": crate::events::client_event_json(c, e, txn.as_deref())? }));
        }
        let mut out = json!({ "search_categories": { "room_events": { "count": total, "results": results, "highlights": [term] } } });
        if skip + limit < total {
            out["search_categories"]["room_events"]["next_batch"] = json!(format!("n{}", skip + limit));
        }
        Ok(Json(out))
    })
    .await
}

// ----------------------------------------------------------------- profile

/// Display name and avatar of a user of this server.
pub(crate) fn local_profile(conn: &Connection, mxid: &str) -> Result<Option<Value>, MatrixError> {
    let Some(uid) = store::user_id_of(conn, mxid)? else { return Ok(None) };
    let mut v = json!({ "displayname": crate::nick::effective_label(conn, uid)? });
    if let Some(a) = conn.query_row("SELECT avatar_url FROM user_avatar WHERE user_id = ?1", [uid], |r| r.get::<_, String>(0)).optional().map_err(|_| MatrixError::internal())? {
        v["avatar_url"] = json!(a);
    }
    Ok(Some(v))
}

/// A user's profile, from this server or (federation on) the user's own.
pub(crate) async fn profile_of(state: &Arc<Homeserver>, mxid: &str) -> Result<Value, MatrixError> {
    let domain = crate::fed_rooms::domain_of(mxid).ok_or_else(|| MatrixError::invalid_param("not a user id"))?.to_string();
    if store::is_local_server_name(&domain) {
        let m = mxid.to_string();
        return with_read_pub(state, move |c| local_profile(c, &m)).await?.ok_or_else(|| MatrixError::not_found("unknown user"));
    }
    if state.federation_enabled.get().is_none() {
        return Err(MatrixError::not_found("unknown user"));
    }
    let q = format!("/federation/v1/query/profile?user_id={}", crate::federation::enc(mxid));
    let (status, v) = super::fed_net::fed_request(state, &domain, "GET", &q, None).await?;
    if status != 200 {
        return Err(MatrixError::not_found("unknown user"));
    }
    Ok(v)
}

async fn get_avatar(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(user_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    let p = profile_of(&state, &user_id).await?;
    Ok(Json(match p.get("avatar_url") {
        Some(a) => json!({ "avatar_url": a }),
        None => json!({}),
    }))
}

async fn put_avatar(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(user_id): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    crate::account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let url = body.get("avatar_url").and_then(Value::as_str).ok_or_else(|| MatrixError::bad_json("avatar_url"))?.to_string();
    if !url.starts_with("mxc://") || url.len() > 512 {
        return Err(MatrixError::invalid_param("avatar_url must be an mxc:// uri"));
    }
    with_conn_pub(&state, move |c| {
        c.execute("INSERT INTO user_avatar (user_id, avatar_url) VALUES (?1, ?2) ON CONFLICT(user_id) DO UPDATE SET avatar_url = excluded.avatar_url", params![caller.user_id, url]).map_err(|_| MatrixError::internal())?;
        Ok(Json(json!({})))
    })
    .await
}

async fn delete_avatar(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(user_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    crate::account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    with_conn_pub(&state, move |c| {
        c.execute("DELETE FROM user_avatar WHERE user_id = ?1", [caller.user_id]).map_err(|_| MatrixError::internal())?;
        Ok(Json(json!({})))
    })
    .await
}

// ----------------------------------------------------------------- openid

async fn openid_request_token(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(user_id): Path<String>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    crate::account::check_caller_owns_user_id(&user_id, &caller.mxid)?;
    let token = store::new_event_id().trim_start_matches('$').to_string() + &store::new_room_id().trim_start_matches('!').replace(':', "");
    let t2 = token.clone();
    with_conn_pub(&state, move |c| {
        let now = now_ms();
        let _ = c.execute("DELETE FROM openid_tokens WHERE expires_at_ms < ?1", [now]);
        c.execute("INSERT INTO openid_tokens (token, user_id, expires_at_ms) VALUES (?1, ?2, ?3)", params![t2, caller.user_id, now + 3_600_000]).map_err(|_| MatrixError::internal())?;
        Ok(())
    })
    .await?;
    Ok(Json(json!({ "access_token": token, "token_type": "Bearer", "matrix_server_name": store::matrix_server_name(), "expires_in": 3600 })))
}

/// The user an OpenID token was issued to, if it is still valid.
pub(crate) fn openid_subject(conn: &Connection, token: &str) -> Option<String> {
    let uid: i64 = conn.query_row("SELECT user_id FROM openid_tokens WHERE token = ?1 AND expires_at_ms > ?2", params![token, now_ms()], |r| r.get(0)).optional().ok().flatten()?;
    store::mxid_of(conn, uid).ok().flatten()
}

// ----------------------------------------------------------------- reports

#[derive(serde::Deserialize, Default)]
struct ReportBody {
    reason: Option<String>,
    score: Option<i64>,
}

async fn do_report(state: Arc<Homeserver>, headers: HeaderMap, room_id: String, event_id: Option<String>, body: ReportBody) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    with_conn_pub(&state, move |c| {
        store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        if let Some(e) = &event_id {
            store::get_event(c, e)?.filter(|ev| ev.room_id == room_id).ok_or_else(|| MatrixError::not_found("no such event"))?;
        }
        c.execute("INSERT INTO event_reports (room_id, event_id, reporter_user_id, reason, score, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![room_id, event_id, caller.user_id, body.reason, body.score, rfc3339()]).map_err(|_| MatrixError::internal())?;
        Ok(Json(json!({})))
    })
    .await
}

async fn report_event(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((room_id, event_id)): Path<(String, String)>, body: Option<Json<ReportBody>>) -> Result<Json<Value>, MatrixError> {
    do_report(state, headers, room_id, Some(event_id), body.map(|b| b.0).unwrap_or_default()).await
}

async fn report_room(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(room_id): Path<String>, body: Option<Json<ReportBody>>) -> Result<Json<Value>, MatrixError> {
    do_report(state, headers, room_id, None, body.map(|b| b.0).unwrap_or_default()).await
}

// ----------------------------------------------------------------- threads

async fn threads(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(room_id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let (user_id, device_id) = (caller.user_id, caller.device_id);
    let participated = q.get("include").map(String::as_str) == Some("participated");
    let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(20).clamp(1, 100);
    with_read_pub(&state, move |c| {
        let room = store::get_room(c, &room_id)?.ok_or_else(|| MatrixError::not_found("no such room"))?;
        let window = store::visible_upper_bound(c, &room, user_id)?;
        if window == HistoryWindow::Nothing {
            return Err(MatrixError::forbidden("no read access to this room"));
        }
        let mut st = c
            .prepare("SELECT r.target_id, MAX(e.stream_id), COUNT(*) FROM relations r JOIN events e ON e.event_id = r.event_id WHERE e.room_id = ?1 AND r.rel_type = 'm.thread' GROUP BY r.target_id ORDER BY MAX(e.stream_id) DESC")
            .map_err(|_| MatrixError::internal())?;
        let rows: Vec<(String, i64, i64)> = st.query_map([&room_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(|_| MatrixError::internal())?.flatten().collect();
        let mut chunk = Vec::new();
        for (root, latest_stream, count) in rows {
            let Some(root_ev) = store::get_event(c, &root)?.filter(|e| window.contains(e.stream_id)) else { continue };
            let mine: bool = root_ev.sender_user_id == user_id
                || c.query_row("SELECT 1 FROM relations r JOIN events e ON e.event_id = r.event_id WHERE r.target_id = ?1 AND r.rel_type = 'm.thread' AND e.sender_user_id = ?2 LIMIT 1", params![root, user_id], |_| Ok(())).optional().map_err(|_| MatrixError::internal())?.is_some();
            if participated && !mine {
                continue;
            }
            let latest: Option<store::MatrixEvent> = c
                .query_row("SELECT e.event_id FROM relations r JOIN events e ON e.event_id = r.event_id WHERE r.target_id = ?1 AND r.rel_type = 'm.thread' AND e.stream_id = ?2", params![root, latest_stream], |r| r.get::<_, String>(0))
                .optional()
                .map_err(|_| MatrixError::internal())?
                .and_then(|id| store::get_event(c, &id).ok().flatten());
            let txn = store::txn_id_for_event(c, user_id, &device_id, &root_ev.event_id)?;
            let mut j = crate::events::client_event_json(c, &root_ev, txn.as_deref())?;
            let mut summary = json!({ "count": count, "current_user_participated": mine });
            if let Some(l) = latest {
                summary["latest_event"] = crate::events::client_event_json(c, &l, None)?;
            }
            j["unsigned"]["m.relations"]["m.thread"] = summary;
            chunk.push(j);
            if chunk.len() >= limit {
                break;
            }
        }
        Ok(Json(json!({ "chunk": chunk })))
    })
    .await
}

// ----------------------------------------------------------------- upgrade

async fn upgrade(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path(room_id): Path<String>, Json(body): Json<Value>) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    let want = body.get("new_version").and_then(Value::as_str).ok_or_else(|| MatrixError::bad_json("new_version"))?;
    if want != store::MATRIX_ROOM_VERSION {
        return Err(MatrixError::new(400, "M_UNSUPPORTED_ROOM_VERSION", format!("only room version {} is available", store::MATRIX_ROOM_VERSION)));
    }
    let (new_room, wake) = with_conn_pub(&state, move |c| {
        let label = crate::nick::effective_label(c, caller.user_id)?;
        let now = rfc3339();
        crate::rooms::apply_upgrade(c, &room_id, caller.user_id, &caller.mxid, &label, &now, now_ms())
    })
    .await?;
    super::wake_users(&state, wake);
    Ok(Json(json!({ "replacement_room": new_room })))
}
