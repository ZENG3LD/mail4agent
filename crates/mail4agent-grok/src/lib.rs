//! Courier logic for pushing one mail4agent letter into a Grok session.
//!
//! The mailbox stays provider-agnostic. This crate is the consumer of the
//! existing account doorbell (`DeliveryNotification`): it decides whether
//! the letter is for one Grok session, which Grok session id that process
//! is, and how to say the letter as an ACP `session/prompt`. It does not
//! start `grok`. The leader pipe is the only inlet, and only when the
//! operator has already turned `[cli] use_leader` on and the destination
//! process was started after that config was written.
//!
//! Room mail does not come through this doorbell. A messenger shell that
//! already decrypted a room text calls [`wake_decrypted_room`] when a
//! leader socket is configured. That is the same `session/prompt` push.
//! It does not register a listener and it does not read the mailbox.

mod acp;
mod frame;
mod gate;
mod index;
mod leader;
mod pipe;

pub use acp::{acp_request, classify_inbound, register_message, registered_is_ready, Inbound};
pub use frame::{encode_frame, MAX_FRAME_BYTES};
pub use gate::{process_may_use_leader, prompt_text, screen, use_leader_enabled, Screen};
pub use index::{
    config_mtime_unix_ms, locate, parse_active_sessions, ActiveSession, LocateError, Target,
};
pub use leader::{push_into_session, wake_decrypted_room, wake_decrypted_room_blocking};
pub use pipe::{grok_home, leader_is_listening, leader_pipe_name, leader_socket, PushError};
