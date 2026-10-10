//! Lifecycle event publisher: product -> messenger. Events are queued and
//! delivered in order with retries; the event id makes redelivery harmless.

use std::time::Duration;

use m4a_seam::{sign_body, Event};
use tokio::sync::mpsc;

use crate::edge_link::EdgeLink;

/// Where the messenger serves events, as seen through the edge.
pub const EVENTS_PATH: &str = "/_matrix/account-source/v1/events";
const ATTEMPTS: u32 = 8;

#[derive(Clone)]
pub struct EventPublisher {
    tx: mpsc::UnboundedSender<Event>,
}

impl EventPublisher {
    /// Start the delivery task on the current runtime. `base_delay` is the first retry delay (doubles, capped at 60 s).
    pub fn spawn(link: EdgeLink, event_sig_header: Option<String>, base_delay: Duration) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        let header = event_sig_header.unwrap_or_else(|| m4a_seam::DEFAULT_EVENT_SIG_HEADER.into()).to_ascii_lowercase();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                let body = serde_json::to_vec(&ev).expect("event serializes");
                let sig = sign_body(&link.secret, &body);
                let mut delay = base_delay;
                for attempt in 1..=ATTEMPTS {
                    match link.post(EVENTS_PATH, &[(header.as_str(), sig.clone())], body.clone()).await {
                        Ok(200) => break,
                        Ok(s) if (400..500).contains(&s) && s != 429 => {
                            tracing::error!(event = %ev.id, status = s, "messenger refused the event; dropped");
                            break;
                        }
                        other => {
                            tracing::warn!(event = %ev.id, attempt, ?other, "event delivery failed");
                            if attempt == ATTEMPTS {
                                tracing::error!(event = %ev.id, "event delivery given up (in-memory queue; reconcile on next start)");
                            } else {
                                tokio::time::sleep(delay).await;
                                delay = (delay * 2).min(Duration::from_secs(60));
                            }
                        }
                    }
                }
            }
        });
        Self { tx }
    }

    pub fn publish(&self, events: Vec<Event>) {
        for e in events {
            let _ = self.tx.send(e);
        }
    }
}
