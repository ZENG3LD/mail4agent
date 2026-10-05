//! Format one stored event the way a Client-Server response carries it.

use crate::error::MatrixError;
use crate::store::{self, MatrixEvent};

pub fn client_event_json(
    conn: &rusqlite::Connection,
    event: &MatrixEvent,
    own_txn_id: Option<&str>,
) -> Result<serde_json::Value, MatrixError> {
    let sender = store::mxid_of(conn, event.sender_user_id)?.ok_or_else(|| {
        tracing::error!("client_event_json: sender {} has no matrix_users row", event.sender_user_id);
        MatrixError::internal()
    })?;
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap_or_else(|_| serde_json::json!({}));
    let now_ms = chrono::Utc::now().timestamp_millis();
    let age = (now_ms - event.origin_server_ts).max(0);

    let mut unsigned = serde_json::json!({ "age": age });
    if let Some(redaction_event_id) = &event.redacted_by {
        if let Some(redaction_event) = store::get_event(conn, redaction_event_id)? {
            unsigned["redacted_because"] = client_event_json(conn, &redaction_event, None)?;
        }
    }
    if event.event_type == "m.room.member" {
        if let Ok(member_content) = serde_json::from_str::<serde_json::Value>(&event.content) {
            if member_content.get("membership").and_then(|v| v.as_str()) == Some("invite") {
                let stripped = store::stripped_invite_state(conn, &event.room_id, event.sender_user_id)?;
                unsigned["invite_room_state"] = serde_json::Value::Array(stripped);
            }
        }
    }
    if let Some(txn_id) = own_txn_id {
        unsigned["transaction_id"] = serde_json::Value::String(txn_id.to_string());
    }

    let mut value = serde_json::json!({
        "event_id": event.event_id,
        "type": event.event_type,
        "sender": sender,
        "origin_server_ts": event.origin_server_ts,
        "content": content,
        "room_id": event.room_id,
        "unsigned": unsigned,
    });
    if let Some(state_key) = &event.state_key {
        value["state_key"] = serde_json::Value::String(state_key.clone());
    }
    if let Some(redacts) = &event.redacts {
        value["redacts"] = serde_json::Value::String(redacts.clone());
    }
    Ok(value)
}
