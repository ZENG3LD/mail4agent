//! Outgoing federation: signed requests, outbox delivery, PDU verification,
//! remote join, and the remote halves of key query/claim and to-device.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Value};

use super::{with_conn_pub, Homeserver};
use crate::error::MatrixError;
use crate::fed_rooms as fr;
use crate::federation::{self as fed, enc};

fn internal<E>(_: E) -> MatrixError {
    MatrixError::internal()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Send one signed request to `dest` (path without the `/_matrix` prefix, query included).
pub(crate) async fn fed_request(state: &Arc<Homeserver>, dest: &str, method: &str, path: &str, body: Option<Value>) -> Result<(u16, Value), MatrixError> {
    let transport = state.fed_transport.get().cloned().ok_or_else(|| MatrixError::unknown("federation transport is not configured"))?;
    let local = crate::store::matrix_server_name();
    let uri = format!("/_matrix{path}");
    let (key_id, key) = with_conn_pub(state, |c| fed::active_signing_key(c, fed::now_ms()).map_err(internal)).await?;
    let auth = fed::build_x_matrix_header(local, dest, &key_id, &key, method, &uri, body.as_ref());
    transport.request(dest, method, &uri, &auth, body.as_ref()).await.map_err(|e| MatrixError::unknown(format!("federation to {dest}: {e}")))
}

/// A signed GET whose answer is binary (media); `path` is without the `/_matrix` prefix.
pub(crate) async fn fed_request_raw(state: &Arc<Homeserver>, dest: &str, path: &str, max_bytes: usize) -> Result<crate::federation::RawResponse, MatrixError> {
    let transport = state.fed_transport.get().cloned().ok_or_else(|| MatrixError::unknown("federation transport is not configured"))?;
    let local = crate::store::matrix_server_name();
    let uri = format!("/_matrix{path}");
    let (key_id, key) = with_conn_pub(state, |c| fed::active_signing_key(c, fed::now_ms()).map_err(internal)).await?;
    let auth = fed::build_x_matrix_header(local, dest, &key_id, &key, "GET", &uri, None);
    transport.request_raw(dest, "GET", &uri, &auth, max_bytes).await.map_err(|e| MatrixError::unknown(format!("federation to {dest}: {e}")))
}

/// Verify a PDU's signature with its signer's keys. `Ok(false)`: signature
/// good, content hash wrong (keep only the redacted form).
pub(crate) async fn verify_pdu(state: &Arc<Homeserver>, pdu: &Value) -> Result<bool, MatrixError> {
    let (signer, key_id) = fr::pdu_signer(pdu).ok_or_else(|| MatrixError::bad_json("pdu is not signed by its sender's server"))?;
    if crate::store::is_local_server_name(&signer) {
        let id = pdu.get("event_id").and_then(Value::as_str).unwrap_or_default().to_string();
        let known = with_conn_pub(state, move |c| Ok(crate::store::get_event(c, &id)?.is_some())).await?;
        return if known { Ok(true) } else { Err(MatrixError::forbidden("pdu claims to be ours but is unknown")) };
    }
    let pk = super::federation::remote_key(state, &signer, &key_id).await?;
    fr::verify_pdu_with_key(pdu, &signer, &key_id, &pk).map_err(|_| MatrixError::forbidden("bad pdu signature"))
}

/// Public keys of everyone who signed `pdus` (our own from the database, peers' fetched).
#[cfg(feature = "f3-hash-ids")]
pub(crate) async fn f3_keys(state: &Arc<Homeserver>, pdus: &[Value]) -> Result<m4a_matrix_core::PublicKeyMap, MatrixError> {
    let owned = pdus.to_vec();
    let (mut keys, need) = with_conn_pub(state, move |c| {
        let mut keys = m4a_matrix_core::PublicKeyMap::new();
        let refs: Vec<&Value> = owned.iter().collect();
        let need = crate::f3::missing_keys(c, &refs, &mut keys);
        Ok((keys, need))
    })
    .await?;
    for (server, key_id) in need {
        let pk = super::federation::remote_key(state, &server, &key_id).await?;
        crate::f3::add_key(&mut keys, &server, &key_id, &pk)?;
    }
    Ok(keys)
}

/// A peer's live event for a DAG room. When it cites events this server does not hold, they are
/// fetched from `origin` (get_missing_events), verified and stored first, then the event is
/// processed again; the fork this makes is merged by state resolution.
#[cfg(feature = "f3-hash-ids")]
pub(crate) async fn f3_receive_live(state: &Arc<Homeserver>, origin: &str, pdu: &Value) -> Result<crate::f3::Received, MatrixError> {
    for _ in 0..3 {
        let keys = f3_keys(state, std::slice::from_ref(pdu)).await?;
        let (p, o) = (pdu.clone(), origin.to_string());
        let res = with_conn_pub(state, move |c| Ok(crate::f3::receive_detail(c, Some(&o), &p, &keys, &now_rfc3339()))).await?;
        match res {
            Ok(r) => return Ok(r),
            Err(crate::f3::RecvErr::Other(e)) => return Err(e),
            Err(crate::f3::RecvErr::Missing(_)) => f3_fetch_missing(state, origin, pdu).await?,
        }
    }
    Err(MatrixError::forbidden("the event still cites unknown events after fetching"))
}

/// Ask `origin` for the events between our forward extremities and `pdu`, check and store them.
#[cfg(feature = "f3-hash-ids")]
async fn f3_fetch_missing(state: &Arc<Homeserver>, origin: &str, pdu: &Value) -> Result<(), MatrixError> {
    let room = pdu.get("room_id").and_then(Value::as_str).ok_or_else(|| MatrixError::bad_json("room_id"))?.to_string();
    let latest = crate::f3::wire_id(pdu)?;
    let r2 = room.clone();
    let earliest = with_conn_pub(state, move |c| Ok(crate::f3::extremity_ids(c, &r2))).await?;
    let body = json!({ "earliest_events": earliest, "latest_events": [latest], "limit": 50, "min_depth": 0 });
    let (status, resp) = fed_request(state, origin, "POST", &format!("/federation/v1/get_missing_events/{}", enc(&room)), Some(body)).await?;
    if status != 200 {
        return Err(map_status(status, "get_missing_events"));
    }
    let events = resp.get("events").and_then(Value::as_array).cloned().unwrap_or_default();
    if events.is_empty() {
        return Err(MatrixError::forbidden("the origin returned no missing events"));
    }
    f3_store_history(state, &room, events).await.map(|_| ())
}

/// Verify (keys fetched as needed) and store events of the past.
#[cfg(feature = "f3-hash-ids")]
pub(crate) async fn f3_store_history(state: &Arc<Homeserver>, room: &str, events: Vec<Value>) -> Result<usize, MatrixError> {
    let keys = f3_keys(state, &events).await?;
    let room = room.to_string();
    with_conn_pub(state, move |c| crate::f3::process_historic(c, &room, &events, &keys, &now_rfc3339())).await
}

fn backoff_ms(attempts: i64) -> i64 {
    (1000i64 << attempts.clamp(0, 10)).min(600_000)
}

struct Row {
    id: i64,
    kind: String,
    room_id: String,
    event_id: String,
    payload: Value,
    attempts: i64,
}

/// Export new local events and deliver everything due. Returns the number of delivered items.
pub async fn drain_outbox(state: &Arc<Homeserver>) -> usize {
    if state.federation_enabled.get().is_none() || state.fed_transport.get().is_none() {
        return 0;
    }
    let local = crate::store::matrix_server_name().to_string();
    let now = fed::now_ms();
    let l2 = local.clone();
    let rows = with_conn_pub(state, move |c| {
        if let Err(e) = fr::export_local_events(c, &l2, now) {
            tracing::warn!("federation export: {e}");
        }
        let mut stmt = c
            .prepare("SELECT id, destination, kind, room_id, event_id, payload, attempts FROM fed_outbox WHERE next_try_ms <= ?1 ORDER BY id LIMIT 300")
            .map_err(internal)?;
        let it = stmt
            .query_map([now], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    Row { id: r.get(0)?, kind: r.get(2)?, room_id: r.get(3)?, event_id: r.get(4)?, payload: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or(Value::Null), attempts: r.get(6)? },
                ))
            })
            .map_err(internal)?;
        it.collect::<Result<Vec<_>, _>>().map_err(internal)
    })
    .await
    .unwrap_or_default();
    let mut by_dest: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for (d, r) in rows {
        by_dest.entry(d).or_default().push(r);
    }
    let mut delivered = 0;
    for (dest, items) in by_dest {
        let mut batch: Vec<Row> = Vec::new();
        let mut failed_from: Option<usize> = None;
        let mut idx = 0;
        let total = items.len();
        let mut items = items.into_iter().peekable();
        while let Some(item) = items.next() {
            let is_invite = item.kind == "invite";
            if is_invite {
                // flush the batch first to keep order
                if !batch.is_empty() {
                    let b = std::mem::take(&mut batch);
                    match send_batch(state, &local, &dest, &b).await {
                        Ok(n) => delivered += n,
                        Err(_) => {
                            mark_failed(state, &b).await;
                            mark_failed(state, std::slice::from_ref(&item)).await;
                            failed_from = Some(idx);
                            break;
                        }
                    }
                }
                #[allow(unused_mut)]
                let mut body = json!({ "room_version": "11", "event": item.payload["event"], "room_info": item.payload["room_info"], "invite_room_state": item.payload["state"] });
                if let Some(snap) = item.payload.get("f3") {
                    body["f3"] = snap.clone();
                }
                let path = format!("/federation/v2/invite/{}/{}", enc(&item.room_id), enc(&item.event_id));
                match fed_request(state, &dest, "PUT", &path, Some(body)).await {
                    Ok((200, _)) | Ok((403, _)) => {
                        delete_rows(state, &[item.id]).await;
                        delivered += 1;
                    }
                    _ => {
                        mark_failed(state, std::slice::from_ref(&item)).await;
                        failed_from = Some(idx);
                        break;
                    }
                }
            } else {
                batch.push(item);
                if batch.len() >= 20 || items.peek().is_none_or(|n| n.kind == "invite") {
                    let b = std::mem::take(&mut batch);
                    match send_batch(state, &local, &dest, &b).await {
                        Ok(n) => delivered += n,
                        Err(_) => {
                            mark_failed(state, &b).await;
                            failed_from = Some(idx);
                            break;
                        }
                    }
                }
            }
            idx += 1;
        }
        let _ = (failed_from, total);
    }
    delivered
}

async fn delete_rows(state: &Arc<Homeserver>, ids: &[i64]) {
    let ids = ids.to_vec();
    let _ = with_conn_pub(state, move |c| {
        for id in ids {
            c.execute("DELETE FROM fed_outbox WHERE id = ?1", [id]).map_err(internal)?;
        }
        Ok(())
    })
    .await;
}

async fn mark_failed(state: &Arc<Homeserver>, rows: &[Row]) {
    let now = fed::now_ms();
    let data: Vec<(i64, i64)> = rows.iter().map(|r| (r.id, r.attempts)).collect();
    let _ = with_conn_pub(state, move |c| {
        for (id, attempts) in data {
            c.execute("UPDATE fed_outbox SET attempts = attempts + 1, next_try_ms = ?2 WHERE id = ?1", rusqlite::params![id, now + backoff_ms(attempts)]).map_err(internal)?;
        }
        Ok(())
    })
    .await;
}

async fn send_batch(state: &Arc<Homeserver>, local: &str, dest: &str, rows: &[Row]) -> Result<usize, MatrixError> {
    let (mut pdus, mut edus) = (Vec::new(), Vec::new());
    for r in rows {
        if r.kind == "edu" {
            edus.push(r.payload.clone());
        } else {
            pdus.push(r.payload.clone());
        }
    }
    let txn = format!("m4a{}", rows[0].id);
    let body = json!({ "origin": local, "origin_server_ts": fed::now_ms(), "pdus": pdus, "edus": edus });
    let (status, _) = fed_request(state, dest, "PUT", &format!("/federation/v1/send/{}", enc(&txn)), Some(body)).await?;
    if status != 200 {
        return Err(MatrixError::unknown(format!("destination answered {status}")));
    }
    delete_rows(state, &rows.iter().map(|r| r.id).collect::<Vec<_>>()).await;
    Ok(rows.len())
}

/// Background worker: drains whenever poked or every few seconds.
pub fn spawn_outbox_worker(state: Arc<Homeserver>) {
    tokio::spawn(async move {
        loop {
            drain_outbox(&state).await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), state.fed_notify.notified()).await;
        }
    });
}

// -------------------------------------------------------------- remote join

/// Whether `room_id` belongs to another server's namespace.
pub(crate) fn room_domain_is_remote(room_id: &str) -> bool {
    room_id.split_once(':').is_some_and(|(_, d)| !crate::store::is_local_server_name(d))
}

fn map_status(status: u16, what: &str) -> MatrixError {
    match status {
        403 => MatrixError::forbidden(format!("{what}: refused by the remote server")),
        404 => MatrixError::not_found(format!("{what}: not found on the remote server")),
        _ => MatrixError::unknown(format!("{what}: remote server answered {status}")),
    }
}

/// Join a room that lives on another server (make_join, send_join, ingest).
pub(crate) async fn federated_join(state: &Arc<Homeserver>, caller: &super::Caller, room_id: &str) -> Result<Vec<i64>, MatrixError> {
    let dest = room_id.split_once(':').map(|(_, d)| d.to_string()).ok_or_else(|| MatrixError::invalid_param("room id"))?;
    let local = crate::store::matrix_server_name().to_string();
    let (status, tmpl) = fed_request(state, &dest, "GET", &format!("/federation/v1/make_join/{}/{}{}", enc(room_id), enc(&caller.mxid), if cfg!(feature = "f3-hash-ids") { "?ver=11" } else { "" }), None).await?;
    if status != 200 {
        return Err(map_status(status, "make_join"));
    }
    #[cfg(feature = "f3-hash-ids")]
    if tmpl.get("m4a_f3").and_then(Value::as_bool) == Some(true) {
        return federated_join_f3(state, caller, room_id, &dest, &tmpl).await;
    }
    #[cfg(feature = "f3-hash-ids")]
    if tmpl.get("room_version").and_then(Value::as_str).is_some() && tmpl.pointer("/event/prev_events").is_some() && tmpl.get("m4a_f3").is_none() {
        return federated_join_spec(state, caller, room_id, &dest, &tmpl).await;
    }
    let mut ev = tmpl.get("event").and_then(Value::as_object).cloned().ok_or_else(|| MatrixError::unknown("make_join: no event"))?;
    let uid = caller.user_id;
    let label = with_conn_pub(state, move |c| crate::nick::effective_label(c, uid).map_err(internal)).await?;
    let event_id = crate::store::new_event_id();
    ev.insert("event_id".into(), json!(event_id));
    ev.insert("origin".into(), json!(local));
    let mut content = ev.get("content").cloned().unwrap_or_else(|| json!({}));
    if !label.is_empty() {
        content["displayname"] = json!(label);
    }
    content["membership"] = json!("join");
    ev.insert("content".into(), content);
    if ev.get("sender").and_then(Value::as_str) != Some(caller.mxid.as_str()) || ev.get("room_id").and_then(Value::as_str) != Some(room_id) {
        return Err(MatrixError::unknown("make_join: template does not match the request"));
    }
    let l2 = local.clone();
    let pdu = with_conn_pub(state, move |c| fr::finalize_pdu(c, ev, &l2, fed::now_ms()).map_err(internal)).await?;
    let (status, resp) = fed_request(state, &dest, "PUT", &format!("/federation/v2/send_join/{}/{}", enc(room_id), enc(&event_id)), Some(pdu.clone())).await?;
    if status != 200 {
        return Err(map_status(status, "send_join"));
    }
    let list = |k: &str| resp.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let (state_pdus, timeline) = (list("state"), list("m4a_timeline"));
    let info = resp.get("m4a_room").cloned().ok_or_else(|| MatrixError::unknown("send_join: no room info"))?;
    let mut verified: Vec<(Value, bool)> = Vec::new();
    for p in state_pdus.iter().chain(timeline.iter()) {
        if p.get("event_id").and_then(Value::as_str) == Some(event_id.as_str()) {
            continue; // our own join, echoed back; stored below
        }
        let ok = verify_pdu(state, p).await?;
        verified.push((p.clone(), ok));
    }
    let room = room_id.to_string();
    let (mxid, user_id) = (caller.mxid.clone(), caller.user_id);
    let ids = with_conn_pub(state, move |c| {
        let now = now_rfc3339();
        fr::create_replica_room(c, &room, &info, &now)?;
        for (p, ok) in &verified {
            fr::ingest_pdu(c, p, *ok, fr::Mode::Trusted, &now)?;
        }
        fr::store_own_pdu(c, &pdu, user_id, &mxid, &now)?;
        let ids = crate::rooms::member_and_invited_ids(c, &room).map_err(internal)?;
        Ok(ids.into_iter().collect::<Vec<_>>())
    })
    .await?;
    Ok(ids)
}

/// Join a DAG room: the peer's template (with `prev_events`/`auth_events`/`depth`) is filled in and
/// signed here; the answer is the room as it stood right after the join, from which the replica starts.
#[cfg(feature = "f3-hash-ids")]
async fn federated_join_f3(state: &Arc<Homeserver>, caller: &super::Caller, room_id: &str, dest: &str, tmpl: &Value) -> Result<Vec<i64>, MatrixError> {
    let mut ev = tmpl.get("event").cloned().ok_or_else(|| MatrixError::unknown("make_join: no event"))?;
    if ev.get("sender").and_then(Value::as_str) != Some(caller.mxid.as_str()) || ev.get("room_id").and_then(Value::as_str) != Some(room_id) {
        return Err(MatrixError::unknown("make_join: template does not match the request"));
    }
    let uid = caller.user_id;
    let label = with_conn_pub(state, move |c| crate::nick::effective_label(c, uid).map_err(internal)).await?;
    if !label.is_empty() {
        ev["content"]["displayname"] = json!(label);
    }
    let (event_id, pdu) = with_conn_pub(state, move |c| crate::f3::sign_own(c, &ev, fed::now_ms())).await?;
    let (status, resp) = fed_request(state, dest, "PUT", &format!("/federation/v2/send_join/{}/{}", enc(room_id), enc(&event_id)), Some(pdu)).await?;
    if status != 200 {
        return Err(map_status(status, "send_join"));
    }
    let snap = resp.get("m4a_f3").cloned().ok_or_else(|| MatrixError::unknown("send_join: no room snapshot"))?;
    let info = resp.get("m4a_room").cloned().ok_or_else(|| MatrixError::unknown("send_join: no room info"))?;
    let all = crate::f3::snapshot_events(&snap);
    let keys = f3_keys(state, &all).await?;
    let room = room_id.to_string();
    let shared = matches!(info.get("history_visibility").and_then(Value::as_str), Some("shared") | Some("world_readable"));
    let ids = with_conn_pub(state, move |c| {
        crate::f3::import_snapshot(c, &room, &info, &snap, &keys, &now_rfc3339())?;
        let ids = crate::rooms::member_and_invited_ids(c, &room).map_err(internal)?;
        Ok(ids.into_iter().collect::<Vec<_>>())
    })
    .await?;
    // A late joiner catches up the history, parallel branches included, when the room shares it.
    if shared {
        let q = format!("/federation/v1/backfill/{}?v={}&limit=100", enc(room_id), enc(&event_id));
        match fed_request(state, dest, "GET", &q, None).await {
            Ok((200, resp)) => {
                let events = resp.get("pdus").and_then(Value::as_array).cloned().unwrap_or_default();
                if let Err(e) = f3_store_history(state, room_id, events).await {
                    tracing::warn!("backfill after join: {}", e.error);
                }
            }
            other => tracing::warn!("backfill after join: {:?}", other.map(|x| x.0)),
        }
    }
    Ok(ids)
}

/// Join a room of a spec-following server (Synapse and kin): their make_join template is filled in
/// and signed here, their send_join answer (state before the join, plus auth chain) is verified in
/// full, and the replica starts from that state plus our own join. Room version 11 only.
#[cfg(feature = "f3-hash-ids")]
async fn federated_join_spec(state: &Arc<Homeserver>, caller: &super::Caller, room_id: &str, dest: &str, tmpl: &Value) -> Result<Vec<i64>, MatrixError> {
    if tmpl.get("room_version").and_then(Value::as_str) != Some("11") {
        return Err(MatrixError::new(400, "M_INCOMPATIBLE_ROOM_VERSION", "only room version 11 can be joined over federation"));
    }
    let t = tmpl.get("event").cloned().unwrap_or_default();
    if t.get("sender").and_then(Value::as_str) != Some(caller.mxid.as_str()) || t.get("room_id").and_then(Value::as_str) != Some(room_id) {
        return Err(MatrixError::unknown("make_join: template does not match the request"));
    }
    let uid = caller.user_id;
    let label = with_conn_pub(state, move |c| crate::nick::effective_label(c, uid).map_err(internal)).await?;
    let mut content = t.get("content").cloned().unwrap_or_else(|| json!({}));
    content["membership"] = json!("join");
    if !label.is_empty() {
        content["displayname"] = json!(label);
    }
    let mut ev = json!({ "content": content, "origin_server_ts": fed::now_ms() });
    for k in ["room_id", "sender", "type", "state_key", "prev_events", "auth_events", "depth"] {
        if let Some(v) = t.get(k) {
            ev[k] = v.clone();
        }
    }
    let (event_id, pdu) = with_conn_pub(state, move |c| crate::f3::sign_own(c, &ev, fed::now_ms())).await?;
    let (status, resp) = fed_request(state, dest, "PUT", &format!("/federation/v2/send_join/{}/{}", enc(room_id), enc(&event_id)), Some(pdu.clone())).await?;
    if status != 200 {
        return Err(map_status(status, "send_join"));
    }
    let list = |k: &str| resp.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let st = list("state");
    if resp.get("members_omitted").and_then(Value::as_bool) == Some(true) {
        return Err(MatrixError::unknown("send_join: partial state is not supported"));
    }
    let find = |ty: &str| st.iter().find(|e| e.get("type").and_then(Value::as_str) == Some(ty) && e.get("state_key").and_then(Value::as_str) == Some("")).cloned();
    let content_of = |ty: &str, k: &str| find(ty).and_then(|e| e.pointer(&format!("/content/{k}")).and_then(Value::as_str).map(str::to_string));
    let info = json!({
        "kind": "group",
        "is_encrypted": find("m.room.encryption").is_some(),
        "join_rule": content_of("m.room.join_rules", "join_rule").unwrap_or_else(|| "invite".into()),
        "history_visibility": content_of("m.room.history_visibility", "history_visibility").unwrap_or_else(|| "shared".into()),
        "room_version": "11",
        "creator": find("m.room.create").and_then(|e| e.get("sender").and_then(Value::as_str).map(str::to_string)).unwrap_or_default(),
    });
    let mut state_v = st.clone();
    state_v.push(pdu.clone());
    let snap = json!({ "state": state_v, "extremities": [pdu], "auth_chain": list("auth_chain") });
    let all = crate::f3::snapshot_events(&snap);
    let keys = f3_keys(state, &all).await?;
    let room = room_id.to_string();
    let shared = matches!(info["history_visibility"].as_str(), Some("shared") | Some("world_readable"));
    let ids = with_conn_pub(state, move |c| {
        crate::f3::import_snapshot(c, &room, &info, &snap, &keys, &now_rfc3339())?;
        let ids = crate::rooms::member_and_invited_ids(c, &room).map_err(internal)?;
        Ok(ids.into_iter().collect::<Vec<_>>())
    })
    .await?;
    if shared {
        let q = format!("/federation/v1/backfill/{}?v={}&limit=100", enc(room_id), enc(&event_id));
        if let Ok((200, resp)) = fed_request(state, dest, "GET", &q, None).await {
            let events = resp.get("pdus").and_then(Value::as_array).cloned().unwrap_or_default();
            if let Err(e) = f3_store_history(state, room_id, events).await {
                tracing::warn!("backfill after join: {}", e.error);
            }
        }
    }
    Ok(ids)
}

// ------------------------------------------------------------ remote keys

/// Split `{mxid: v}` into (local part, per-remote-domain part).
pub(crate) fn split_by_domain<V: Clone>(map: &BTreeMap<String, V>) -> (BTreeMap<String, V>, BTreeMap<String, BTreeMap<String, V>>) {
    let (mut local, mut remote): (BTreeMap<String, V>, BTreeMap<String, BTreeMap<String, V>>) = (BTreeMap::new(), BTreeMap::new());
    for (k, v) in map {
        if fr::is_remote_mxid(k) {
            if let Some(d) = fr::domain_of(k) {
                remote.entry(d.to_string()).or_default().insert(k.clone(), v.clone());
            }
        } else {
            local.insert(k.clone(), v.clone());
        }
    }
    (local, remote)
}

/// Query remote servers for device keys and merge into `out` (a client keys/query response).
pub(crate) async fn merge_remote_keys_query(state: &Arc<Homeserver>, remote: BTreeMap<String, BTreeMap<String, Vec<String>>>, out: &mut Value) {
    for (domain, users) in remote {
        let body = json!({ "device_keys": users });
        match fed_request(state, &domain, "POST", "/federation/v1/user/keys/query", Some(body)).await {
            Ok((200, resp)) => {
                for k in ["device_keys", "master_keys", "self_signing_keys"] {
                    if let (Some(dst), Some(src)) = (out[k].as_object_mut(), resp.get(k).and_then(Value::as_object)) {
                        for (u, v) in src {
                            dst.insert(u.clone(), v.clone());
                        }
                    }
                }
            }
            _ => {
                out["failures"][&domain] = json!({ "status": 502, "errcode": "M_UNREACHABLE" });
            }
        }
    }
}

/// Claim one-time keys from remote servers and merge into `out`.
pub(crate) async fn merge_remote_keys_claim(state: &Arc<Homeserver>, remote: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>, out: &mut Value) {
    for (domain, users) in remote {
        let body = json!({ "one_time_keys": users });
        match fed_request(state, &domain, "POST", "/federation/v1/user/keys/claim", Some(body)).await {
            Ok((200, resp)) => {
                if let (Some(dst), Some(src)) = (out["one_time_keys"].as_object_mut(), resp.get("one_time_keys").and_then(Value::as_object)) {
                    for (u, v) in src {
                        dst.insert(u.clone(), v.clone());
                    }
                }
            }
            _ => {
                out["failures"][&domain] = json!({ "status": 502, "errcode": "M_UNREACHABLE" });
            }
        }
    }
}

/// Queue a `m.direct_to_device` EDU for a remote server.
pub(crate) fn enqueue_to_device_edu(conn: &rusqlite::Connection, domain: &str, sender: &str, event_type: &str, message_id: &str, messages: &Value) -> Result<(), MatrixError> {
    let edu = json!({ "edu_type": "m.direct_to_device", "content": { "sender": sender, "type": event_type, "message_id": message_id, "messages": messages } });
    fr::enqueue(conn, domain, "edu", "", "", &edu, fed::now_ms()).map_err(internal)
}
