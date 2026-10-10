//! Stand-in for the in-process bus when the `local-bus` feature is off: no local homeserver, no
//! `mail4agent-server` in the build; every request goes to the real server.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use mail4agent_messenger::{HttpResponseDescriptor, OutgoingRequest};

use crate::machine::Prepared;
use crate::{perform_http, ShellError};

pub(crate) struct LocalBus {
    local_only: AtomicBool,
    hits: AtomicU64,
}

impl LocalBus {
    pub(crate) fn open(_prepared: &[Prepared]) -> Result<Self, ShellError> {
        Ok(Self { local_only: AtomicBool::new(false), hits: AtomicU64::new(0) })
    }
    pub(crate) fn seed(&self, _user_row: i64, _item: &Prepared) -> Result<(), ShellError> {
        Ok(())
    }
    pub(crate) fn set_local_only(&self, enabled: bool) {
        self.local_only.store(enabled, Ordering::Relaxed);
    }
    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
    pub(crate) fn local_only(&self) -> bool {
        self.local_only.load(Ordering::Relaxed)
    }
    pub(crate) fn fulfill(
        &self,
        client: &reqwest::blocking::Client,
        base_url: &reqwest::Url,
        device_token: &str,
        _user_id: &str,
        request: &OutgoingRequest,
        force_local: Option<bool>,
    ) -> Result<(HttpResponseDescriptor, bool), ShellError> {
        if force_local.unwrap_or_else(|| self.local_only()) {
            return Err(ShellError::Http("this build has no local bus".into()));
        }
        self.hits.fetch_add(1, Ordering::Relaxed);
        Ok((perform_http(client, base_url, device_token, request)?, true))
    }
}

pub(crate) fn ensure_server_name(_name: &str) -> Result<(), ShellError> {
    Ok(())
}
