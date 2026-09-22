//! `GET /health` -- the only route without authentication, as it is in
//! every nemo service. Answers the same rich shape this daemon has always
//! answered (previously assembled by an internal build framework's own
//! detail-health helper, before this crate's open-sourcing dropped it):
//!
//! ```json
//! {
//!   "ok": true,
//!   "service": "mail4agent",
//!   "version": "0.1.0",
//!   "started_at": "2026-09-23T12:00:00Z",
//!   "uptime_secs": 14821,
//!   "dependencies": [],
//!   "background_tasks": []
//! }
//! ```
//!
//! `dependencies` and `background_tasks` are always empty -- this daemon
//! registers neither a dependency probe nor a background task -- so `ok`
//! is always `true` in practice; the status-code branch below is kept
//! anyway rather than hard-coded, so adding either later does not also
//! require rediscovering this logic.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthReport {
    pub ok: bool,
    pub service: String,
    pub version: Option<String>,
    pub started_at: String,
    pub uptime_secs: u64,
    pub dependencies: Vec<serde_json::Value>,
    pub background_tasks: Vec<String>,
}

pub struct HealthState {
    service: &'static str,
    version: &'static str,
    started_at: SystemTime,
    started_at_instant: Instant,
}

impl HealthState {
    pub fn new(service: &'static str, version: &'static str) -> Self {
        Self { service, version, started_at: SystemTime::now(), started_at_instant: Instant::now() }
    }

    pub fn report(&self) -> HealthReport {
        HealthReport {
            ok: true,
            service: self.service.to_string(),
            version: Some(self.version.to_string()),
            started_at: iso8601(self.started_at),
            uptime_secs: self.started_at_instant.elapsed().as_secs(),
            dependencies: Vec::new(),
            background_tasks: Vec::new(),
        }
    }
}

pub async fn handle(state: std::sync::Arc<HealthState>) -> impl IntoResponse {
    let report = state.report();
    let status = if report.ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(report))
}

/// Minimal RFC 3339 / ISO 8601 formatter (UTC). Civil-from-days algorithm
/// (Howard Hinnant) -- avoids pulling `chrono`/`time` into this daemon for
/// one timestamp field.
fn iso8601(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let sod = secs % 86_400;
    let h = sod / 3600;
    let mi = (sod % 3600) / 60;
    let s = sod % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_ok_with_no_dependencies_or_background_tasks() {
        let state = HealthState::new("mail4agent", "0.1.0");
        let report = state.report();
        assert!(report.ok);
        assert_eq!(report.service, "mail4agent");
        assert_eq!(report.version.as_deref(), Some("0.1.0"));
        assert!(report.dependencies.is_empty());
        assert!(report.background_tasks.is_empty());
    }

    #[test]
    fn iso8601_known_date() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_779_796_800);
        assert_eq!(iso8601(t), "2026-05-26T12:00:00Z");
    }

    #[test]
    fn iso8601_epoch() {
        assert_eq!(iso8601(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }
}
