//! Wake-only long-poll plumbing for `GET /client/v3/sync`, plus the
//! per-caller token bucket for `POST /client/v3/keys/claim`.
//!
//! `/sync` is pull, not push. A client polls with `since`, the server blocks
//! up to `timeout`, and on wake it rebuilds the response from the database.
//! The registry carries no payloads. A burst of writes against one key
//! coalesces into one rebuilt response.
//!
//! Register, then read the database, then wait. [`LiveRegistry::register`]
//! snapshots the generation before the read, so a wake that lands during
//! the read is still observed by [`Registration::wait`]. Wake keys are
//! `user:{user_id}`. Call [`LiveRegistry::wake_many`] only after the
//! connection mutex is released.
//!
//! `Notify::notify_waiters` has no memory. [`Registration::wait`] enables
//! its `Notified` future and then re-checks the generation, so a wake that
//! fired before `wait` is not lost.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

const CLAIM_RATE_CAPACITY: f64 = 100.0;
const CLAIM_RATE_REFILL_PER_SEC: f64 = CLAIM_RATE_CAPACITY / 60.0;

/// Per-caller token bucket for `POST /client/v3/keys/claim`. One token per
/// requested device. A batch that would exceed the cap is refused whole.
pub struct ClaimRateLimiter {
    buckets: Mutex<HashMap<i64, (f64, Instant)>>,
}

impl Default for ClaimRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaimRateLimiter {
    pub fn new() -> Self {
        Self { buckets: Mutex::new(HashMap::new()) }
    }

    pub fn try_consume(&self, user_id: i64, cost: f64, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let (tokens, last_refill) = buckets.entry(user_id).or_insert((CLAIM_RATE_CAPACITY, now));
        let elapsed = now.saturating_duration_since(*last_refill).as_secs_f64();
        *tokens = (*tokens + elapsed * CLAIM_RATE_REFILL_PER_SEC).min(CLAIM_RATE_CAPACITY);
        *last_refill = now;
        if *tokens >= cost {
            *tokens -= cost;
            true
        } else {
            false
        }
    }
}

struct KeyEntry {
    notify: Notify,
    generation: AtomicU64,
    interest: AtomicUsize,
}

impl KeyEntry {
    fn new() -> Self {
        Self { notify: Notify::new(), generation: AtomicU64::new(0), interest: AtomicUsize::new(0) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Woken,
    TimedOut,
}

/// Registry of wake-only long-poll keys.
pub struct LiveRegistry {
    keys: Mutex<HashMap<String, Arc<KeyEntry>>>,
}

impl Default for LiveRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveRegistry {
    pub fn new() -> Self {
        Self { keys: Mutex::new(HashMap::new()) }
    }

    /// Register interest in `key` before reading the database.
    pub fn register(&self, key: &str) -> Registration<'_> {
        let entry = {
            let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            let entry = Arc::clone(keys.entry(key.to_string()).or_insert_with(|| Arc::new(KeyEntry::new())));
            entry.interest.fetch_add(1, Ordering::AcqRel);
            entry
        };
        let seen_generation = entry.generation.load(Ordering::Acquire);
        Registration { registry: self, key: key.to_string(), entry, seen_generation }
    }

    pub fn wake(&self, key: &str) {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = keys.get(key) {
            entry.generation.fetch_add(1, Ordering::AcqRel);
            entry.notify.notify_waiters();
        }
    }

    pub fn wake_many(&self, keys_to_wake: impl IntoIterator<Item = String>) {
        for key in keys_to_wake {
            self.wake(&key);
        }
    }

    pub fn key_count(&self) -> usize {
        self.keys.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

pub struct Registration<'a> {
    registry: &'a LiveRegistry,
    key: String,
    entry: Arc<KeyEntry>,
    seen_generation: u64,
}

impl Registration<'_> {
    pub async fn wait(&self, timeout: Duration) -> WaitOutcome {
        let notified = self.entry.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self.entry.generation.load(Ordering::Acquire) != self.seen_generation {
            return WaitOutcome::Woken;
        }
        match tokio::time::timeout(timeout, notified).await {
            Ok(()) => WaitOutcome::Woken,
            Err(_) => WaitOutcome::TimedOut,
        }
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if self.entry.interest.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut keys = self.registry.keys.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(current) = keys.get(&self.key) {
                if Arc::ptr_eq(current, &self.entry) && current.interest.load(Ordering::Acquire) == 0 {
                    keys.remove(&self.key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waking_one_user_key_does_not_wake_a_different_users_waiter() {
        let registry = LiveRegistry::new();
        let w1 = registry.register("user:1");
        let w2 = registry.register("user:2");
        registry.wake("user:1");
        assert_eq!(w1.wait(Duration::from_secs(5)).await, WaitOutcome::Woken);
        assert_eq!(w2.wait(Duration::from_millis(20)).await, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn two_concurrent_waiters_on_the_same_key_both_wake() {
        let registry = LiveRegistry::new();
        let w1 = registry.register("user:1");
        let w2 = registry.register("user:1");
        let (o1, o2, ()) = tokio::join!(w1.wait(Duration::from_secs(5)), w2.wait(Duration::from_secs(5)), async {
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            registry.wake("user:1");
        });
        assert_eq!(o1, WaitOutcome::Woken);
        assert_eq!(o2, WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn wake_between_register_and_wait_is_not_lost() {
        let registry = LiveRegistry::new();
        let w = registry.register("user:1");
        registry.wake("user:1");
        let outcome = tokio::time::timeout(Duration::from_millis(50), w.wait(Duration::from_secs(5)))
            .await
            .expect("wake must not be lost");
        assert_eq!(outcome, WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn a_previous_wake_is_not_replayed_onto_the_next_registration() {
        let registry = LiveRegistry::new();
        let w1 = registry.register("user:1");
        registry.wake("user:1");
        assert_eq!(w1.wait(Duration::from_secs(5)).await, WaitOutcome::Woken);
        drop(w1);
        let w2 = registry.register("user:1");
        registry.wake("user:1");
        assert_eq!(w2.wait(Duration::from_secs(5)).await, WaitOutcome::Woken);
    }

    #[tokio::test]
    async fn wait_times_out_without_a_wake() {
        let registry = LiveRegistry::new();
        let w = registry.register("user:1");
        assert_eq!(w.wait(Duration::from_millis(20)).await, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn idle_keys_are_pruned() {
        let registry = LiveRegistry::new();
        assert_eq!(registry.key_count(), 0);
        let w = registry.register("user:1");
        assert_eq!(registry.key_count(), 1);
        assert_eq!(w.wait(Duration::from_millis(20)).await, WaitOutcome::TimedOut);
        drop(w);
        assert_eq!(registry.key_count(), 0);
        registry.wake("user:1");
    }

    #[test]
    fn entry_pruned_after_last_guard_drops() {
        let registry = LiveRegistry::new();
        let w1 = registry.register("user:1");
        let w2 = registry.register("user:1");
        assert_eq!(registry.key_count(), 1);
        drop(w1);
        assert_eq!(registry.key_count(), 1);
        drop(w2);
        assert_eq!(registry.key_count(), 0);
    }
}
