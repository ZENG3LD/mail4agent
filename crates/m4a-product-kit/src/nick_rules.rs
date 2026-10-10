//! Nick grammar, deployment lists and the placeholder generator. These are
//! PRODUCT rules; the messenger server only checks that a nick is a legal
//! Matrix localpart.

use std::collections::HashSet;

use rand::Rng;

pub const NICK_MIN: usize = 3;
pub const NICK_MAX: usize = 24;
pub const PLACEHOLDER_TRIES: usize = 64;
/// Days between nick changes after the first (free) one.
pub const DEFAULT_COOLDOWN_DAYS: i64 = 30;

const CONSONANTS: &[u8] = b"bdfgklmnprstvz";
const VOWELS: &[u8] = b"aeiou";

/// Why a nick was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NickError(pub String);

/// Forbidden / reserved lists, supplied by the deployment.
#[derive(Debug, Clone, Default)]
pub struct NickLists {
    exact: HashSet<String>,
    substrings: Vec<String>,
}

impl NickLists {
    /// One entry per line, `#` comments; `name` forbids that nick, `~part` any nick containing it.
    pub fn parse(text: &str) -> Self {
        let mut l = Self::default();
        for line in text.lines().map(str::trim).filter(|x| !x.is_empty() && !x.starts_with('#')) {
            match line.strip_prefix('~') {
                Some(p) if !p.is_empty() => l.substrings.push(p.to_ascii_lowercase()),
                Some(_) => {}
                None => {
                    l.exact.insert(line.to_ascii_lowercase());
                }
            }
        }
        l
    }
    pub fn forbids(&self, nick: &str) -> bool {
        let lower = nick.to_ascii_lowercase();
        self.exact.contains(&lower) || self.substrings.iter().any(|s| lower.contains(s.as_str()))
    }
}

/// Rules of one deployment.
#[derive(Debug, Clone)]
pub struct NickRules {
    pub lists: NickLists,
    pub cooldown_days: i64,
}

impl Default for NickRules {
    fn default() -> Self {
        Self { lists: NickLists::default(), cooldown_days: DEFAULT_COOLDOWN_DAYS }
    }
}

impl NickRules {
    /// `M4A_PRODUCT_NICK_LISTS` (file), `M4A_PRODUCT_NICK_COOLDOWN_DAYS`.
    pub fn from_env() -> Result<Self, String> {
        let lists = match std::env::var("M4A_PRODUCT_NICK_LISTS") {
            Ok(p) if !p.is_empty() => NickLists::parse(&std::fs::read_to_string(&p).map_err(|e| format!("M4A_PRODUCT_NICK_LISTS: cannot read {p}: {e}"))?),
            _ => NickLists::default(),
        };
        let cooldown_days = match std::env::var("M4A_PRODUCT_NICK_COOLDOWN_DAYS") {
            Ok(v) => v.parse().map_err(|_| "M4A_PRODUCT_NICK_COOLDOWN_DAYS must be a number".to_string())?,
            Err(_) => DEFAULT_COOLDOWN_DAYS,
        };
        Ok(Self { lists, cooldown_days })
    }
}

fn is_sep(c: char) -> bool {
    matches!(c, '_' | '-' | '.')
}

/// 3-24 chars of `A-Za-z0-9_-.`; first and last alphanumeric; no two adjacent
/// separators; not all digits; not 12+ hex; no `http`/`www.`; no digit run over
/// 6; no TLD-shaped suffix; not in the lists.
pub fn validate_nick(nick: &str, lists: &NickLists) -> Result<(), NickError> {
    let bad = |m: &str| Err(NickError(m.to_string()));
    let n = nick.len();
    if !nick.is_ascii() || !(NICK_MIN..=NICK_MAX).contains(&n) {
        return bad("nick must be 3-24 ASCII characters");
    }
    if !nick.chars().all(|c| c.is_ascii_alphanumeric() || is_sep(c)) {
        return bad("nick may contain only letters, digits, '_', '-' and '.'");
    }
    let chars: Vec<char> = nick.chars().collect();
    if !chars[0].is_ascii_alphanumeric() || !chars[n - 1].is_ascii_alphanumeric() {
        return bad("nick must start and end with a letter or digit");
    }
    if chars.windows(2).any(|w| is_sep(w[0]) && is_sep(w[1])) {
        return bad("nick must not contain two separators in a row");
    }
    if chars.iter().all(|c| c.is_ascii_digit()) {
        return bad("nick must not be all digits");
    }
    if n >= 12 && chars.iter().all(|c| c.is_ascii_hexdigit()) {
        return bad("nick must not look like a hex string");
    }
    let lower = nick.to_ascii_lowercase();
    if lower.contains("http") || lower.contains("www.") {
        return bad("nick must not look like a link");
    }
    let mut run = 0;
    for c in &chars {
        run = if c.is_ascii_digit() { run + 1 } else { 0 };
        if run > 6 {
            return bad("nick must not contain a long digit run");
        }
    }
    if let Some((_, suffix)) = nick.rsplit_once('.') {
        if suffix.len() >= 2 && suffix.chars().all(|c| c.is_ascii_alphabetic()) {
            return bad("nick must not end like a domain name");
        }
    }
    if lists.forbids(nick) {
        return bad("nick is not allowed");
    }
    Ok(())
}

/// Four consonant-vowel pairs.
pub fn placeholder_candidate<R: Rng>(rng: &mut R) -> String {
    let mut s = String::with_capacity(8);
    for _ in 0..4 {
        s.push(CONSONANTS[rng.gen_range(0..CONSONANTS.len())] as char);
        s.push(VOWELS[rng.gen_range(0..VOWELS.len())] as char);
    }
    s
}

/// A placeholder that passes grammar and lists and for which `is_free` (lowercase) holds.
pub fn generate_placeholder<R: Rng>(rng: &mut R, lists: &NickLists, is_free: impl Fn(&str) -> bool) -> Result<String, NickError> {
    for _ in 0..PLACEHOLDER_TRIES {
        let c = placeholder_candidate(rng);
        if validate_nick(&c, lists).is_ok() && is_free(&c) {
            return Ok(c);
        }
    }
    Err(NickError("placeholder generation exhausted".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_vectors() {
        let l = NickLists::default();
        for n in ["abc", "Bob_1", "a-b.c", "x".repeat(24).as_str(), "user.name9", "a123456b"] {
            assert!(validate_nick(n, &l).is_ok(), "{n}");
        }
        for n in ["ab", &"x".repeat(25), "a:b", "bob.com", "bob.io", "_abc", "abc_", "a__b", "a-.b", "123456", "deadbeef0123", "httpbob", "mywww.x1", "a1234567b", "bob smith", "bobé", "", ".abc"] {
            assert!(validate_nick(n, &l).is_err(), "{n}");
        }
    }

    #[test]
    fn lists_and_placeholders() {
        let l = NickLists::parse("# c\nAdmin\n~badword\n\n");
        assert!(validate_nick("ADMIN", &l).is_err());
        assert!(validate_nick("xBadWordx", &l).is_err());
        assert!(validate_nick("administrator", &l).is_ok());
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let p = generate_placeholder(&mut rng, &l, |_| true).unwrap();
            assert_eq!(p.len(), 8);
            assert!(p.bytes().enumerate().all(|(i, b)| if i % 2 == 0 { CONSONANTS.contains(&b) } else { VOWELS.contains(&b) }));
        }
        let calls = std::cell::Cell::new(0);
        assert!(generate_placeholder(&mut rng, &l, |_| { calls.set(calls.get() + 1); false }).is_err());
        assert_eq!(calls.get(), PLACEHOLDER_TRIES);
    }
}
