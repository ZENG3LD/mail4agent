//! Short-lived one-time login tokens (`m.login.token`, the Matrix `login/get_token` flow): a
//! signed-in client asks for one, another client redeems it for its own session. Kept in memory:
//! they live seconds, and a restart simply invalidates the unredeemed ones.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Default)]
pub struct LoginTokens {
    live: Mutex<HashMap<String, (String, i64)>>,
}

impl LoginTokens {
    /// Mints a token for `nick`, valid for `ttl_ms`.
    pub fn issue(&self, nick: &str, now_ms: i64, ttl_ms: i64) -> String {
        let mut raw = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = hex::encode(raw);
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.retain(|_, (_, exp)| *exp > now_ms);
        if live.len() > 10_000 {
            live.clear();
        }
        live.insert(hex::encode(Sha256::digest(token.as_bytes())), (nick.to_string(), now_ms + ttl_ms));
        token
    }

    /// Spends a token: the nick it was minted for, once, and only before it expires.
    pub fn redeem(&self, token: &str, now_ms: i64) -> Option<String> {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.remove(&hex::encode(Sha256::digest(token.as_bytes()))).filter(|(_, exp)| *exp > now_ms).map(|(n, _)| n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_works_once_and_only_in_time() {
        let t = LoginTokens::default();
        let a = t.issue("zoe", 1_000, 120_000);
        assert_eq!(t.redeem(&a, 2_000).as_deref(), Some("zoe"));
        assert_eq!(t.redeem(&a, 2_000), None, "one use");
        let b = t.issue("zoe", 1_000, 120_000);
        assert_eq!(t.redeem(&b, 200_000), None, "expired");
        assert_eq!(t.redeem("nonsense", 0), None);
    }
}
