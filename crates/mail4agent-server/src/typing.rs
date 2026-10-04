//! In-memory typing set. Never written to the messenger database.
//! The builder seeds [`TypingRegistry::with_seed`] from a clock and notifies
//! clients itself when `set_typing` or `rooms_with_expired_typing` report a change.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A repeat `typing: true` PUT for the same `(room, user)` inside this
/// window is throttled — accepted independently of the IP rate limiter
/// (§3.6/§3.8), so a chatty client cannot force a wake on every keystroke.
const TYPING_THROTTLE_WINDOW: Duration = Duration::from_secs(3);

/// A client-supplied typing timeout above this is clamped down to it.
const TYPING_MAX_TIMEOUT_MS: u64 = 30_000;

/// One `(room, user)`'s typing state: `expires_at` is when a currently-true
/// typing flag auto-clears; `is_active` caches whether this user currently
/// counts as typing (kept in sync by every touch and by the lazy reap, so a
/// membership transition is detected exactly once); `last_true_accepted_at`
/// is `None` until the first accepted `typing: true`, purely for the
/// throttle above — a `typing: false` never touches it.
struct TypingUserState {
    expires_at: Instant,
    is_active: bool,
    last_true_accepted_at: Option<Instant>,
}

/// One room's typing state plus a serial stamped from [`TypingRegistry`]'s
/// GLOBAL `next_gen` counter on every EFFECTIVE change (a user starting or
/// stopping counting as typing) — a refreshed-but-still-active `typing:
/// true`, or a throttled repeat, bumps nothing, since nothing about what a
/// peer would see has changed. See the module doc's "The typing generation
/// is GLOBAL, not per-room" section for why this is not a local counter.
#[derive(Default)]
struct RoomTyping {
    users: HashMap<i64, TypingUserState>,
    serial: u64,
}

/// Marks every entry in `room` whose typing flag has timed out as no
/// longer active (stamping `room.serial` from `next_gen` once if at least
/// one did), then drops entries that are both inactive and outside the
/// throttle memory window (nothing left worth remembering). Returns whether
/// the serial bumped, so callers can report "this room's typing set just
/// changed" without the caller re-deriving it.
fn reap_room(room: &mut RoomTyping, now: Instant, next_gen: &AtomicU64) -> bool {
    let mut bumped = false;
    for state in room.users.values_mut() {
        if state.is_active && state.expires_at <= now {
            state.is_active = false;
            bumped = true;
        }
    }
    if bumped {
        room.serial = next_gen.fetch_add(1, Ordering::AcqRel) + 1;
    }
    room.users.retain(|_, state| {
        state.is_active
            || state
                .last_true_accepted_at
                .is_some_and(|last| now.saturating_duration_since(last) <= TYPING_THROTTLE_WINDOW)
    });
    bumped
}

/// In-memory, per-room typing indicator state (§3.6) — deliberately never
/// written to `messenger.db` (see the module doc). Not related to
/// [`LiveRegistry`]'s own keys; a caller that gets `changed == true` back
/// from [`Self::set_typing`] (or a non-empty room list back from
/// [`Self::rooms_with_expired_typing`]) is the one that decides which
/// `LiveRegistry` keys to wake for it.
pub struct TypingRegistry {
    rooms: Mutex<HashMap<String, RoomTyping>>,
    /// The one counter every room's [`RoomTyping::serial`] is stamped from —
    /// see the module doc's "The typing generation is GLOBAL, not per-room"
    /// section.
    next_gen: AtomicU64,
}

impl Default for TypingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TypingRegistry {
    /// A fresh registry whose typing generation starts at `0` — this
    /// codebase's own tests use this (deterministic small values are easy
    /// to assert against); production boot uses [`Self::with_seed`] instead
    /// (see that constructor's own doc for why).
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    /// A fresh registry whose typing generation starts at `seed` (the FIRST
    /// effective change stamps `seed + 1`, matching [`Self::new`]'s own
    /// "first change stamps 1" behavior when `seed == 0`). Production boot
    /// (`main.rs`) seeds this from the current Unix time in milliseconds —
    /// see the module doc's "The typing generation is GLOBAL, not per-room"
    /// section: an in-memory counter starting at `0` on every restart can
    /// under-report a typing change to a client still holding a
    /// higher-`typing_gen` token from before that restart. Seeding from a
    /// wall-clock reading that only ever increases makes a POST-restart
    /// seed reliably higher than anything a PRE-restart process could ever
    /// have reached (an `AtomicU64` counter incrementing once per typing
    /// change, even at an implausible sustained rate, cannot climb into the
    /// same range as milliseconds-since-1970 within any real process
    /// lifetime) — closing the under-reporting gap [`Self::current_typing_gen`]'s
    /// own doc used to accept as a known limitation.
    pub fn with_seed(seed: u64) -> Self {
        Self { rooms: Mutex::new(HashMap::new()), next_gen: AtomicU64::new(seed) }
    }

    /// Apply one `PUT /rooms/{roomId}/typing/{userId}` call. `timeout_ms`
    /// (only meaningful when `typing == true`) is clamped to
    /// [`TYPING_MAX_TIMEOUT_MS`]. Returns whether this call actually
    /// changed who counts as typing in `room_id` — `false` for a throttled
    /// repeat `true` (§3.6), a refresh of an already-active `true`, or a
    /// `false` for a user who was not counted as typing — callers should
    /// skip waking anyone when this returns `false`.
    pub fn set_typing(
        &self,
        room_id: &str,
        user_id: i64,
        typing: bool,
        timeout_ms: u64,
        now: Instant,
    ) -> bool {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let room = rooms.entry(room_id.to_string()).or_default();

        let changed = if typing {
            let timeout = Duration::from_millis(timeout_ms.min(TYPING_MAX_TIMEOUT_MS));
            let state = room.users.entry(user_id).or_insert_with(|| TypingUserState {
                expires_at: now,
                is_active: false,
                last_true_accepted_at: None,
            });
            let throttled = state
                .last_true_accepted_at
                .is_some_and(|last| now.saturating_duration_since(last) < TYPING_THROTTLE_WINDOW);
            if throttled {
                false
            } else {
                state.last_true_accepted_at = Some(now);
                state.expires_at = now + timeout;
                let was_active = state.is_active;
                state.is_active = true;
                !was_active
            }
        } else {
            match room.users.get_mut(&user_id) {
                Some(state) if state.is_active => {
                    state.is_active = false;
                    state.expires_at = now;
                    true
                }
                _ => false,
            }
        };

        if changed {
            room.serial = self.next_gen.fetch_add(1, Ordering::AcqRel) + 1;
        }
        changed
    }

    /// The current global typing generation — every effective typing change
    /// across every room takes its own room's [`RoomTyping::serial`] from
    /// this SAME counter (see the module doc), so "room serial > token's
    /// typing_gen" identifies exactly the rooms whose typing changed since
    /// that token was issued. `0` means no typing change has EVER been
    /// accepted by this registry instance — a fresh boot, or simply an idle
    /// server; a token carrying `typing_gen: 0` (the bare `s{stream_id}`
    /// legacy form `routes::matrix::sync_token` still accepts, or a token
    /// issued before this server ever saw a single typing PUT) never
    /// wrongly suppresses a real future change, since every real change
    /// stamps a value `>= 1`.
    ///
    /// In-memory only, like every other fact this registry holds — a plain
    /// `TypingRegistry::new()` restarts this counter at `0` on every
    /// process restart. Production boot avoids the resulting under-report
    /// risk (a token issued before a restart carrying a `typing_gen` LARGER
    /// than anything a freshly-zeroed registry has assigned yet) by
    /// constructing via [`Self::with_seed`] instead, seeded from a
    /// wall-clock reading that is always higher than any pre-restart value
    /// — see that constructor's own doc.
    pub fn current_typing_gen(&self) -> u64 {
        self.next_gen.load(Ordering::Acquire)
    }

    /// Current (non-expired) typers in `room_id`, sorted for a deterministic
    /// response — expired entries are dropped lazily as a side effect.
    /// Empty (including for a room this registry has never heard of) rather
    /// than an error — matches `m.typing`'s own "no event at all if nobody
    /// is typing" convention (§3.6).
    pub fn typing_users(&self, room_id: &str, now: Instant) -> Vec<i64> {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let mut users = Vec::new();
        let mut room_now_empty = false;
        if let Some(room) = rooms.get_mut(room_id) {
            reap_room(room, now, &self.next_gen);
            users.extend(room.users.iter().filter(|(_, state)| state.is_active).map(|(id, _)| *id));
            room_now_empty = room.users.is_empty();
        }
        if room_now_empty {
            rooms.remove(room_id);
        }
        users.sort_unstable();
        users
    }

    /// `room_id`'s current typing serial — stamped from the SAME global
    /// counter [`Self::current_typing_gen`] reads (see the module doc) on
    /// every effective change; `0` for a room this registry has never heard
    /// of, or one whose typing set has never actually changed since boot.
    /// Reaps expired entries first, so this is never stale relative to
    /// `now`. `routes::matrix::sync`'s own per-room condition is `is_initial
    /// || typing_serial(room, now) > token.typing_gen`.
    pub fn typing_serial(&self, room_id: &str, now: Instant) -> u64 {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let mut serial = 0;
        let mut room_now_empty = false;
        if let Some(room) = rooms.get_mut(room_id) {
            reap_room(room, now, &self.next_gen);
            serial = room.serial;
            room_now_empty = room.users.is_empty();
        }
        if room_now_empty {
            rooms.remove(room_id);
        }
        serial
    }

    /// Sweep every room, reaping any typing flag that has timed out since
    /// it was last touched, and return the `room_id`s whose typing set
    /// changed as a result. A periodic tick (or the `/sync` path itself)
    /// calls this and wakes the returned rooms' members — without it, a
    /// member who stops typing and never sends another `/sync`-triggering
    /// action would never have their typing flag cleared for anyone
    /// currently blocked in a long poll.
    pub fn rooms_with_expired_typing(&self, now: Instant) -> Vec<String> {
        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let mut changed = Vec::new();
        rooms.retain(|room_id, room| {
            if reap_room(room, now, &self.next_gen) {
                changed.push(room_id.clone());
            }
            !room.users.is_empty()
        });
        changed
    }
}
