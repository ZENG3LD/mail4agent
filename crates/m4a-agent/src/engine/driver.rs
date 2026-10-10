//! One session's engine run: requests the core releases are executed by the backend, `/sync` runs
//! on a worker so a long poll does not stall everything else, answers go back into the core.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mail4agent_messenger::{
    HttpResponseDescriptor, MessengerCore, MessengerEvent, OutgoingRequest, OutgoingRequestKind, RecordCodec, RequestId,
};

use super::http::clip_public;
use crate::backend::Backend;
use crate::error::{AgentError, Result};

struct SyncFlight {
    id: RequestId,
    rx: Receiver<std::result::Result<HttpResponseDescriptor, String>>,
    /// Not joined on drop: a blocked poll must not hold the process.
    _worker: JoinHandle<()>,
}

/// Flushes the core's sealed records to wherever the host keeps them.
pub type Persist<C> = Box<dyn FnMut(&mut MessengerCore<C>) -> Result<()> + Send>;

pub struct Driver<C: RecordCodec> {
    pub core: MessengerCore<C>,
    backend: Arc<dyn Backend>,
    persist: Persist<C>,
    flight: Option<SyncFlight>,
    /// Kind and status of calls made. No bodies.
    pub http_trace: Vec<(OutgoingRequestKind, u16)>,
    /// Peer device key changes seen on `/keys/query`.
    pub security_alerts: Vec<String>,
}

pub fn sync_timeout_ms(request: &OutgoingRequest) -> u64 {
    request.query.iter().find(|(n, _)| n == "timeout").and_then(|(_, v)| v.parse().ok()).unwrap_or(0)
}

impl<C: RecordCodec> Driver<C> {
    pub fn new(core: MessengerCore<C>, backend: Arc<dyn Backend>, persist: Persist<C>) -> Self {
        Self { core, backend, persist, flight: None, http_trace: Vec::new(), security_alerts: Vec::new() }
    }

    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    /// Puts another transport under the same core (the shell's in-process bus does this).
    pub fn set_backend(&mut self, backend: Arc<dyn Backend>) {
        self.backend = backend;
    }

    pub fn sync_inflight(&self) -> bool {
        self.flight.is_some()
    }

    pub fn persist(&mut self) -> Result<()> {
        (self.persist)(&mut self.core)
    }

    /// Drops a sync that is still on the wire (its answer is never read).
    pub fn abandon_sync(&mut self, now_ms: i64) {
        if let Some(f) = self.flight.take() {
            self.core.on_transport_error(&f.id, now_ms);
        }
    }

    fn note_security_events(&mut self, events: &[MessengerEvent]) {
        for event in events {
            if let MessengerEvent::DeviceKeyChanged { user_id, device_id } = event {
                self.security_alerts.push(format!("{} reset its keys (device {}); trust cleared, room keys re-shared", user_id.as_str(), device_id.as_str()));
            }
        }
    }

    pub fn release_after_flush(&mut self, now_ms: i64) -> Result<Vec<OutgoingRequest>> {
        self.persist()?;
        let mut released = self.core.releasable_requests(now_ms);
        if released.is_empty() {
            self.persist()?;
            released = self.core.releasable_requests(now_ms);
        }
        Ok(released)
    }

    pub fn roundtrip(&mut self, request: &OutgoingRequest, now_ms: i64) -> Result<()> {
        match self.backend.execute(request) {
            Ok(response) => {
                self.http_trace.push((request.kind, response.status));
                let events = self.core.on_response(request.id.clone(), response, now_ms);
                self.note_security_events(&events);
                Ok(())
            }
            Err(err) => {
                self.core.on_transport_error(&request.id, now_ms);
                Err(err)
            }
        }
    }

    pub fn spawn_sync(&mut self, request: OutgoingRequest) -> Result<()> {
        if self.flight.is_some() {
            self.core.on_transport_error(&request.id, 0);
            return Err(AgentError::Transport("a sync was already on the wire".into()));
        }
        let backend = self.backend.frozen().unwrap_or_else(|| Arc::clone(&self.backend));
        let id = request.id.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = backend.execute(&request).map_err(|e| match e {
                AgentError::Transport(t) => t,
                other => clip_public(other.to_string()),
            });
            let _ = tx.send(result);
        });
        self.flight = Some(SyncFlight { id, rx, _worker: worker });
        Ok(())
    }

    fn drop_flight(&mut self, now_ms: i64, why: &str) -> AgentError {
        if let Some(f) = self.flight.take() {
            self.core.on_transport_error(&f.id, now_ms);
        }
        AgentError::Transport(why.to_string())
    }

    /// `Ok(true)` only when this call blocked on a poll that had not already finished. An
    /// already-buffered answer is `Ok(false)`.
    pub fn harvest_sync(&mut self, now_ms: i64, wait: bool) -> Result<bool> {
        let Some(flight) = self.flight.as_ref() else { return Ok(false) };
        let (received, blocked) = match flight.rx.try_recv() {
            Ok(r) => (Some(r), false),
            Err(mpsc::TryRecvError::Disconnected) => return Err(self.drop_flight(now_ms, "sync worker dropped")),
            Err(mpsc::TryRecvError::Empty) if !wait => (None, false),
            Err(mpsc::TryRecvError::Empty) => match flight.rx.recv_timeout(Duration::from_secs(45)) {
                Ok(r) => (Some(r), true),
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(self.drop_flight(now_ms, "sync timed out")),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.drop_flight(now_ms, "sync worker dropped")),
            },
        };
        let Some(result) = received else { return Ok(false) };
        let flight = self.flight.take().expect("flight present");
        match result {
            Ok(response) => {
                self.http_trace.push((OutgoingRequestKind::Sync, response.status));
                let events = self.core.on_response(flight.id, response, now_ms);
                self.note_security_events(&events);
            }
            Err(err) => {
                self.core.on_transport_error(&flight.id, now_ms);
                return Err(AgentError::Transport(err));
            }
        }
        self.persist()?;
        if let Some(err) = self.core.take_ingest_error() {
            return Err(AgentError::Ingest(clip_public(err)));
        }
        Ok(blocked)
    }

    /// One round of the drive loop: what the core releases is executed, syncs on the worker, the
    /// state persisted. `Ok(false)` when nothing was released (the loop is done). `waited` tells
    /// whether a long poll was already waited for in this drive.
    pub fn step(&mut self, now_ms: i64, wait_for_sync: bool, waited: &mut bool) -> Result<bool> {
        let released = self.release_after_flush(now_ms)?;
        if released.is_empty() {
            return Ok(false);
        }
        let (syncs, others): (Vec<_>, Vec<_>) = released.into_iter().partition(|r| r.kind == OutgoingRequestKind::Sync);
        for request in &syncs {
            self.spawn_sync(request.clone())?;
        }
        for request in others {
            self.roundtrip(&request, now_ms)?;
        }
        self.persist()?;
        for request in &syncs {
            let timeout = sync_timeout_ms(request);
            if timeout == 0 || (wait_for_sync && !*waited) {
                self.harvest_sync(now_ms, true)?;
                if timeout != 0 {
                    *waited = true;
                }
            }
        }
        self.persist()?;
        if let Some(err) = self.core.take_ingest_error() {
            return Err(AgentError::Ingest(clip_public(err)));
        }
        Ok(true)
    }
}
