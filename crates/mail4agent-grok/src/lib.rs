//! Courier logic for pushing one mail4agent letter into a Grok session.
//!
//! The mailbox stays provider-agnostic. This crate is the consumer of the
//! existing account doorbell (`DeliveryNotification`): it decides whether
//! the letter is for one session, then delivers it one of two ways. The CLI
//! path says the letter as an ACP `session/prompt` on the leader pipe, and
//! only when the operator has already turned `[cli] use_leader` on and the
//! destination process was started after that config was written. The web
//! path POSTs the same letter once to the webhook bound to that session id
//! in `mail4agent-webhooks.toml`. When that file or `MAIL4AGENT_WEBHOOK_BEARER`
//! has a local key, the POST carries `Authorization: Bearer`. No key sends
//! the same POST with no Authorization header. It does not start `grok`.
//! Room and direct mail are dropped before either path runs.
//!
//! Room mail on the messenger path does not come through this doorbell. A
//! messenger shell that already decrypted a room text calls
//! [`wake_decrypted_room`] when a leader socket is configured. That is the
//! same `session/prompt` push. It does not register a listener and it does
//! not read the mailbox.

mod acp;
mod frame;
mod gate;
mod index;
mod leader;
mod pipe;
mod web;

pub use acp::{acp_request, classify_inbound, register_message, registered_is_ready, Inbound};
pub use frame::{encode_frame, MAX_FRAME_BYTES};
pub use gate::{
    process_may_use_leader, prompt_text, screen, screen_session, use_leader_enabled, Screen,
};
pub use index::{
    config_mtime_unix_ms, locate, parse_active_sessions, ActiveSession, LocateError, Target,
};
pub use leader::{push_into_session, wake_decrypted_room, wake_decrypted_room_blocking};
pub use pipe::{grok_home, leader_is_listening, leader_pipe_name, leader_socket, PushError};
pub use web::{
    bearer_token, choose_route, effective_bearer, parse_webhooks, post_letter, validate_webhook_url, webhook_for,
    webhooks_path, DeliveryRoute, WebPostError, WebhookBinding, WebhookError, WEBHOOKS_FILE,
    WEBHOOK_BEARER_ENV,
};
