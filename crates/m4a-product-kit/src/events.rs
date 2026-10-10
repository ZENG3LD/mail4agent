//! Lifecycle event publisher: product -> messenger. Events go through an [`Outbox`] first and
//! are delivered strictly in order with backoff; the event id makes redelivery harmless. With
//! [`SqliteOutbox`] a queued event survives a crash or restart of the product; nothing is
//! dropped because the messenger is down, only because it refuses an event outright (4xx), and
//! then the row is kept marked `dead` for inspection.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use m4a_seam::{sign_body, Event, Reconcile};
use tokio::sync::Notify;

use crate::edge_link::EdgeLink;

/// Where the messenger serves events, as seen through the edge.
pub const EVENTS_PATH: &str = "/_matrix/account-source/v1/events";
/// Where the messenger takes the startup snapshot of live credentials.
pub const RECONCILE_PATH: &str = "/_matrix/account-source/v1/reconcile";
const MAX_DELAY: Duration = Duration::from_secs(300);

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// One queued delivery.
#[derive(Debug, Clone)]
pub struct Queued {
    pub seq: i64,
    pub event: Event,
    pub attempts: u32,
    /// Earliest delivery time (ms since the epoch).
    pub next_ms: i64,
}

/// Ordered, durable-or-not queue of events waiting for delivery.
pub trait Outbox: Send + Sync + 'static {
    fn enqueue(&self, ev: &Event) -> Result<(), String>;
    /// The oldest pending delivery.
    fn head(&self) -> Result<Option<Queued>, String>;
    /// Delivered: remove.
    fn ack(&self, seq: i64) -> Result<(), String>;
    fn retry(&self, seq: i64, attempts: u32, next_ms: i64) -> Result<(), String>;
    /// Refused for good: keep out of the line.
    fn dead(&self, seq: i64) -> Result<(), String>;
    fn pending(&self) -> usize;
}

/// Volatile queue, for tests and for products that accept loss on a crash (reconcile heals it).
#[derive(Default)]
pub struct MemoryOutbox {
    inner: Mutex<(i64, VecDeque<Queued>)>,
}

impl Outbox for MemoryOutbox {
    fn enqueue(&self, ev: &Event) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 += 1;
        let seq = g.0;
        g.1.push_back(Queued { seq, event: ev.clone(), attempts: 0, next_ms: 0 });
        Ok(())
    }
    fn head(&self) -> Result<Option<Queued>, String> {
        Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.front().cloned())
    }
    fn ack(&self, seq: i64) -> Result<(), String> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.retain(|q| q.seq != seq);
        Ok(())
    }
    fn retry(&self, seq: i64, attempts: u32, next_ms: i64) -> Result<(), String> {
        for q in self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.iter_mut().filter(|q| q.seq == seq) {
            q.attempts = attempts;
            q.next_ms = next_ms;
        }
        Ok(())
    }
    fn dead(&self, seq: i64) -> Result<(), String> {
        self.ack(seq)
    }
    fn pending(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.len()
    }
}

#[cfg(feature = "sqlite-outbox")]
pub use sqlite::SqliteOutbox;

#[cfg(feature = "sqlite-outbox")]
mod sqlite {
    use super::*;
    use rusqlite::{params, Connection, OptionalExtension};

    /// Durable queue in a SQLite file (its own table; may share the product's database file).
    pub struct SqliteOutbox {
        c: Mutex<Connection>,
    }

    const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS event_outbox (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_ms INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT 'pending'
    );";

    fn be(e: rusqlite::Error) -> String {
        e.to_string()
    }

    impl SqliteOutbox {
        pub fn open(path: &str) -> Result<Self, String> {
            let c = Connection::open(path).map_err(be)?;
            c.pragma_update(None, "journal_mode", "WAL").map_err(be)?;
            c.busy_timeout(Duration::from_secs(5)).map_err(be)?;
            c.execute_batch(SCHEMA).map_err(be)?;
            Ok(Self { c: Mutex::new(c) })
        }
        pub fn memory() -> Result<Self, String> {
            let c = Connection::open_in_memory().map_err(be)?;
            c.execute_batch(SCHEMA).map_err(be)?;
            Ok(Self { c: Mutex::new(c) })
        }
        /// Rows refused for good (kept for inspection).
        pub fn dead_count(&self) -> usize {
            self.c.lock().unwrap_or_else(|e| e.into_inner()).query_row("SELECT COUNT(*) FROM event_outbox WHERE state = 'dead'", [], |r| r.get::<_, i64>(0)).unwrap_or(0) as usize
        }
    }

    impl Outbox for SqliteOutbox {
        fn enqueue(&self, ev: &Event) -> Result<(), String> {
            let body = serde_json::to_string(ev).map_err(|e| e.to_string())?;
            self.c.lock().unwrap_or_else(|e| e.into_inner()).execute("INSERT INTO event_outbox (event) VALUES (?1)", params![body]).map_err(be).map(|_| ())
        }
        fn head(&self) -> Result<Option<Queued>, String> {
            let row: Option<(i64, String, i64, i64)> = self
                .c
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .query_row("SELECT seq, event, attempts, next_ms FROM event_outbox WHERE state = 'pending' ORDER BY seq LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .optional()
                .map_err(be)?;
            row.map(|(seq, body, attempts, next_ms)| serde_json::from_str(&body).map(|event| Queued { seq, event, attempts: attempts as u32, next_ms }).map_err(|e| e.to_string())).transpose()
        }
        fn ack(&self, seq: i64) -> Result<(), String> {
            self.c.lock().unwrap_or_else(|e| e.into_inner()).execute("DELETE FROM event_outbox WHERE seq = ?1", params![seq]).map_err(be).map(|_| ())
        }
        fn retry(&self, seq: i64, attempts: u32, next_ms: i64) -> Result<(), String> {
            self.c.lock().unwrap_or_else(|e| e.into_inner()).execute("UPDATE event_outbox SET attempts = ?2, next_ms = ?3 WHERE seq = ?1", params![seq, attempts, next_ms]).map_err(be).map(|_| ())
        }
        fn dead(&self, seq: i64) -> Result<(), String> {
            self.c.lock().unwrap_or_else(|e| e.into_inner()).execute("UPDATE event_outbox SET state = 'dead' WHERE seq = ?1", params![seq]).map_err(be).map(|_| ())
        }
        fn pending(&self) -> usize {
            self.c.lock().unwrap_or_else(|e| e.into_inner()).query_row("SELECT COUNT(*) FROM event_outbox WHERE state = 'pending'", [], |r| r.get::<_, i64>(0)).unwrap_or(0) as usize
        }
    }
}

#[derive(Clone)]
pub struct EventPublisher {
    outbox: Arc<dyn Outbox>,
    wake: Arc<Notify>,
}

impl EventPublisher {
    /// In-memory queue (see [`MemoryOutbox`]). `base_delay` is the first retry delay (doubles per attempt, capped at 5 min).
    pub fn spawn(link: EdgeLink, event_sig_header: Option<String>, base_delay: Duration) -> Self {
        Self::spawn_with(link, event_sig_header, base_delay, Arc::new(MemoryOutbox::default()))
    }

    /// Deliver from `outbox`, which may already hold events from a previous run.
    pub fn spawn_with(link: EdgeLink, event_sig_header: Option<String>, base_delay: Duration, outbox: Arc<dyn Outbox>) -> Self {
        let header = event_sig_header.unwrap_or_else(|| m4a_seam::DEFAULT_EVENT_SIG_HEADER.into()).to_ascii_lowercase();
        let wake = Arc::new(Notify::new());
        let this = Self { outbox: Arc::clone(&outbox), wake: Arc::clone(&wake) };
        tokio::spawn(async move {
            loop {
                let q = match outbox.head() {
                    Ok(Some(q)) => q,
                    Ok(None) => {
                        wake.notified().await;
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "event outbox unreadable");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                let wait = q.next_ms - now_ms();
                if wait > 0 {
                    tokio::select! { _ = tokio::time::sleep(Duration::from_millis(wait as u64)) => {}, _ = wake.notified() => {} }
                    continue;
                }
                let body = serde_json::to_vec(&q.event).expect("event serializes");
                let sig = sign_body(&link.secret, &body);
                match link.post(EVENTS_PATH, &[(header.as_str(), sig)], body).await {
                    Ok(200) => {
                        let _ = outbox.ack(q.seq);
                    }
                    Ok(s) if (400..500).contains(&s) && s != 429 => {
                        tracing::error!(event = %q.event.id, status = s, "messenger refused the event; parked as dead");
                        let _ = outbox.dead(q.seq);
                    }
                    other => {
                        let attempts = q.attempts + 1;
                        let delay = (base_delay * 2u32.saturating_pow(q.attempts.min(16))).min(MAX_DELAY);
                        tracing::warn!(event = %q.event.id, attempts, ?other, "event delivery failed; will retry");
                        let _ = outbox.retry(q.seq, attempts, now_ms() + delay.as_millis() as i64);
                    }
                }
            }
        });
        this
    }

    pub fn publish(&self, events: Vec<Event>) {
        for e in events {
            if let Err(err) = self.outbox.enqueue(&e) {
                tracing::error!(event = %e.id, error = %err, "could not queue the event");
            }
        }
        self.wake.notify_one();
    }

    /// Events still waiting for delivery.
    pub fn pending(&self) -> usize {
        self.outbox.pending()
    }
}

/// Send the startup snapshot of live credentials, retrying with backoff until the messenger
/// accepts it (or refuses it with a 4xx, which is returned as an error).
pub async fn send_reconcile(link: &EdgeLink, event_sig_header: Option<String>, snap: &Reconcile, base_delay: Duration, max_attempts: u32) -> Result<(), String> {
    let header = event_sig_header.unwrap_or_else(|| m4a_seam::DEFAULT_EVENT_SIG_HEADER.into()).to_ascii_lowercase();
    let body = serde_json::to_vec(snap).map_err(|e| e.to_string())?;
    let sig = sign_body(&link.secret, &body);
    let mut delay = base_delay;
    for attempt in 1..=max_attempts {
        match link.post(RECONCILE_PATH, &[(header.as_str(), sig.clone())], body.clone()).await {
            Ok(200) => return Ok(()),
            Ok(s) if (400..500).contains(&s) && s != 429 => return Err(format!("messenger refused the reconcile snapshot: {s}")),
            other => {
                tracing::warn!(attempt, ?other, "reconcile delivery failed");
                if attempt < max_attempts {
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(MAX_DELAY);
                }
            }
        }
    }
    Err("messenger unreachable for reconcile".into())
}

#[cfg(all(test, feature = "sqlite-outbox"))]
mod tests {
    use super::*;
    use axum::routing::post;
    use m4a_seam::EventKind;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ev(id: &str) -> Event {
        Event { id: id.into(), kind: EventKind::CredentialRevoked { cred_ref: format!("c-{id}") } }
    }

    #[tokio::test]
    async fn queued_events_survive_a_restart_and_are_delivered_in_order_after_the_messenger_comes_back() {
        let file = std::env::temp_dir().join(format!("m4a-outbox-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let path = file.to_str().unwrap().to_string();
        // Run 1: the messenger is unreachable; two events are queued and retried in vain.
        {
            let dead = EdgeLink::new("http://127.0.0.1:9", b"0123456789abcdef".to_vec(), None);
            let outbox = Arc::new(SqliteOutbox::open(&path).unwrap());
            let p = EventPublisher::spawn_with(dead, None, Duration::from_millis(20), outbox);
            p.publish(vec![ev("e1"), ev("e2")]);
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(p.pending(), 2, "nothing is dropped while the messenger is down");
        }
        // Run 2 (a restart): a fresh publisher over the same file delivers both, oldest first.
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (s2, h2) = (Arc::clone(&seen), Arc::clone(&hits));
        let app = axum::Router::new().route(
            "/_matrix/account-source/v1/events",
            post(move |body: axum::body::Bytes| {
                let (s2, h2) = (Arc::clone(&s2), Arc::clone(&h2));
                async move {
                    // The first attempt after the restart fails, the retry is accepted.
                    if h2.fetch_add(1, Ordering::SeqCst) == 0 {
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE;
                    }
                    let e: Event = serde_json::from_slice(&body).unwrap();
                    s2.lock().unwrap().push(e.id);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let link = EdgeLink::new(&format!("http://{addr}"), b"0123456789abcdef".to_vec(), None);
        let p = EventPublisher::spawn_with(link, None, Duration::from_millis(20), Arc::new(SqliteOutbox::open(&path).unwrap()));
        p.publish(vec![]); // wakes the worker; the old rows are already in the file
        for _ in 0..100 {
            if p.pending() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert_eq!(*seen.lock().unwrap(), vec!["e1".to_string(), "e2".to_string()]);
        assert!(hits.load(Ordering::SeqCst) >= 3, "one failure then two deliveries");
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_refused_event_is_parked_not_retried_forever() {
        let o = SqliteOutbox::memory().unwrap();
        o.enqueue(&ev("x")).unwrap();
        let q = o.head().unwrap().unwrap();
        o.dead(q.seq).unwrap();
        assert!(o.head().unwrap().is_none());
        assert_eq!((o.pending(), o.dead_count()), (0, 1));
    }
}
