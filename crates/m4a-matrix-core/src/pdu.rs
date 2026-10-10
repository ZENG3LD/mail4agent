use ruma_common::{CanonicalJsonObject, EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UserId};
use ruma_events::TimelineEventType;
use ruma_state_res::events::Event;
use serde_json::value::RawValue;

/// A persistent data unit with the fields state resolution and the auth rules read.
#[derive(Clone, Debug)]
pub struct Pdu {
    pub event_id: OwnedEventId,
    pub room_id: OwnedRoomId,
    pub sender: OwnedUserId,
    pub origin_server_ts: MilliSecondsSinceUnixEpoch,
    pub kind: TimelineEventType,
    pub content: Box<RawValue>,
    pub state_key: Option<String>,
    pub prev_events: Vec<OwnedEventId>,
    pub auth_events: Vec<OwnedEventId>,
    pub depth: u64,
    pub redacts: Option<OwnedEventId>,
    pub rejected: bool,
}

impl Pdu {
    /// Reads a wire-format PDU (no `event_id` inside; the caller computed it).
    pub fn from_wire(event_id: OwnedEventId, obj: &CanonicalJsonObject) -> Result<Self, String> {
        let v = serde_json::to_value(obj).map_err(|e| e.to_string())?;
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
        let ids = |k: &str| -> Result<Vec<OwnedEventId>, String> {
            v.get(k)
                .and_then(|x| x.as_array())
                .map(|a| a.iter().map(|e| e.as_str().ok_or("event id".to_string()).and_then(|e| EventId::parse(e).map_err(|e| e.to_string()))).collect())
                .unwrap_or_else(|| Ok(vec![]))
        };
        Ok(Self {
            event_id,
            room_id: RoomId::parse(s("room_id").ok_or("room_id")?).map_err(|e| e.to_string())?,
            sender: UserId::parse(s("sender").ok_or("sender")?).map_err(|e| e.to_string())?,
            origin_server_ts: MilliSecondsSinceUnixEpoch(
                js_int::UInt::try_from(v.get("origin_server_ts").and_then(|x| x.as_u64()).ok_or("origin_server_ts")?).map_err(|e| e.to_string())?,
            ),
            kind: TimelineEventType::from(s("type").ok_or("type")?),
            content: RawValue::from_string(v.get("content").ok_or("content")?.to_string()).map_err(|e| e.to_string())?,
            state_key: s("state_key"),
            prev_events: ids("prev_events")?,
            auth_events: ids("auth_events")?,
            depth: v.get("depth").and_then(|x| x.as_u64()).unwrap_or(0),
            redacts: None,
            rejected: false,
        })
    }
}

impl Event for Pdu {
    type Id = OwnedEventId;
    fn event_id(&self) -> &Self::Id {
        &self.event_id
    }
    fn room_id(&self) -> Option<&RoomId> {
        Some(&self.room_id)
    }
    fn sender(&self) -> &UserId {
        &self.sender
    }
    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch {
        self.origin_server_ts
    }
    fn event_type(&self) -> &TimelineEventType {
        &self.kind
    }
    fn content(&self) -> &RawValue {
        &self.content
    }
    fn state_key(&self) -> Option<&str> {
        self.state_key.as_deref()
    }
    fn prev_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.prev_events.iter())
    }
    fn auth_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.auth_events.iter())
    }
    fn redacts(&self) -> Option<&Self::Id> {
        self.redacts.as_ref()
    }
    fn rejected(&self) -> bool {
        self.rejected
    }
}
