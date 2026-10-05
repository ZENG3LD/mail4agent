//! Wire-boundary data types: the shapes that cross this crate's async
//! boundary as plain data (see the crate doc's "Contract" section). This
//! module never performs an HTTP call itself — it only builds the request
//! description and parses the response description a shell hands back.

pub mod events;
mod requests;
pub mod sync;

pub use events::{
    BasicEvent, DirectContent, DummyContent, ForwardedRoomKeyContent, FullyReadContent, HistoryVisibility,
    InReplyTo, JoinRule, JoinRuleAllow, MegolmEncryptedContent, Membership,
    OlmCiphertextInfo, OlmEncryptedContent, ReactionContent, ReceiptContent, ReceiptEntry, RedactionContent,
    RelatesTo, RoomCreateContent, RoomCreatePredecessor, RoomEncryptedContent, RoomEncryptionContent,
    RoomHistoryVisibilityContent, RoomJoinRulesContent, RoomKeyContent, RoomKeyRequestAction, RoomKeyRequestBody,
    RoomKeyRequestContent, RoomKeyWithheldContent, RoomMemberContent, RoomMessageContent, RoomNameContent,
    RoomPinnedEventsContent, RoomPowerLevelsContent, RoomPowerLevelsNotifications, RoomTopicContent, RawEvent,
    StrippedStateEvent, TagContent, TagInfo, TextLikeMessageContent, ToDeviceEvent, TypingContent, Unsigned,
    WithheldCode,
};
pub use requests::{HttpMethod, HttpResponseDescriptor, OutgoingRequest, OutgoingRequestKind};
pub use sync::{
    parse_sync_response, AccountDataSection, DeviceListsSection, EphemeralSection, InvitedRoom, InviteStateSection,
    JoinedRoom, LeftRoom, RoomSummary, RoomsSection, StateSection, SyncResponse, TimelineSection,
    ToDeviceSection, UnreadNotifications,
};
// Crate-internal only: `store`'s record-key builder/parser reuses this
// module's own escaping scheme rather than inventing a second one.
pub(crate) use requests::{percent_decode_segment, percent_encode_segment};
