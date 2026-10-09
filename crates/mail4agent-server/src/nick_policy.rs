//! Nick grammar, deployment-supplied lists and the placeholder generator.
//!
//! Pure functions, no database. Both a chart-side issuer and this server can
//! run the same accept/reject vectors against [`validate_nick`].

use std::collections::HashSet;

use rand::Rng;

use crate::error::MatrixError;

pub const NICK_MIN: usize = 3;
pub const NICK_MAX: usize = 24;
/// Placeholder generation gives up after this many collisions.
pub const PLACEHOLDER_TRIES: usize = 64;

const CONSONANTS: &[u8] = b"bdfgklmnprstvz";
const VOWELS: &[u8] = b"aeiou";

/// Forbidden / reserved nick lists. Content is supplied by the deployment
/// (file or text); this crate ships none.
#[derive(Debug, Clone, Default)]
pub struct NickLists {
    exact: HashSet<String>,
    substrings: Vec<String>,
}

impl NickLists {
    /// Text format: one entry per line, `#` comments, blank lines ignored.
    /// `name` forbids that exact nick (case-insensitive); `~part` forbids any
    /// nick containing `part`.
    pub fn parse(text: &str) -> Self {
        let mut lists = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.strip_prefix('~') {
                Some(part) if !part.is_empty() => lists.substrings.push(part.to_ascii_lowercase()),
                Some(_) => {}
                None => {
                    lists.exact.insert(line.to_ascii_lowercase());
                }
            }
        }
        lists
    }

    /// Reads the file named by `M4A_NICK_LISTS`; an unset variable means empty lists,
    /// an unreadable file is an error (startup must not silently drop a policy).
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("M4A_NICK_LISTS") {
            Ok(path) if !path.is_empty() => std::fs::read_to_string(&path)
                .map(|t| Self::parse(&t))
                .map_err(|e| format!("M4A_NICK_LISTS: cannot read {path}: {e}")),
            _ => Ok(Self::default()),
        }
    }

    pub fn forbids(&self, nick: &str) -> bool {
        let lower = nick.to_ascii_lowercase();
        self.exact.contains(&lower) || self.substrings.iter().any(|s| lower.contains(s.as_str()))
    }
}

fn is_sep(c: char) -> bool {
    matches!(c, '_' | '-' | '.')
}

/// Grammar: 3-24 chars of `A-Za-z0-9_-.`; first and last alphanumeric; no two
/// adjacent separators; not all digits; not a hex string of 12+ chars; no
/// `http` / `www.`; no digit run longer than 6; no TLD-shaped suffix (a `.`
/// followed by 2+ letters at the end); not in the lists.
pub fn validate_nick(nick: &str, lists: &NickLists) -> Result<(), MatrixError> {
    let bad = |m: &str| Err(MatrixError::invalid_nick(m.to_string()));
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

/// One candidate: four consonant-vowel pairs.
pub fn placeholder_candidate<R: Rng>(rng: &mut R) -> String {
    let mut s = String::with_capacity(8);
    for _ in 0..4 {
        s.push(CONSONANTS[rng.gen_range(0..CONSONANTS.len())] as char);
        s.push(VOWELS[rng.gen_range(0..VOWELS.len())] as char);
    }
    s
}

/// A placeholder that passes grammar and lists and for which `is_free`
/// (lowercase) holds. Hard error after [`PLACEHOLDER_TRIES`] tries.
pub fn generate_placeholder<R: Rng>(
    rng: &mut R,
    lists: &NickLists,
    is_free: impl Fn(&str) -> bool,
) -> Result<String, MatrixError> {
    for _ in 0..PLACEHOLDER_TRIES {
        let cand = placeholder_candidate(rng);
        if validate_nick(&cand, lists).is_ok() && is_free(&cand) {
            return Ok(cand);
        }
    }
    tracing::error!("placeholder nick generation exhausted {PLACEHOLDER_TRIES} tries");
    Err(MatrixError::internal())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(n: &str) {
        validate_nick(n, &NickLists::default()).unwrap_or_else(|e| panic!("{n}: {}", e.error));
    }
    fn no(n: &str) {
        assert!(validate_nick(n, &NickLists::default()).is_err(), "{n} should be rejected");
    }

    #[test]
    fn grammar_vectors() {
        for n in ["abc", "Bob_1", "a-b.c", "x".repeat(24).as_str(), "user.name9", "a1234567b".replace("1234567", "123456").as_str()] {
            ok(n);
        }
        for n in [
            "ab", &"x".repeat(25), "a:b", "bob.com", "bob.io", "_abc", "abc_", "a__b", "a-.b", "123456",
            "deadbeef0123", "httpbob", "mywww.x1", "a1234567b", "bob smith", "bobé", "", ".abc",
        ] {
            no(n);
        }
    }

    #[test]
    fn lists_forbid_exact_and_substring_case_insensitively() {
        let l = NickLists::parse("# c\nAdmin\n~badword\n\n");
        assert!(validate_nick("admin", &l).is_err());
        assert!(validate_nick("ADMIN", &l).is_err());
        assert!(validate_nick("xBadWordx", &l).is_err());
        assert!(validate_nick("administrator", &l).is_ok());
    }

    #[test]
    fn placeholder_shape_and_collision_retry() {
        let mut rng = rand::thread_rng();
        let lists = NickLists::default();
        for _ in 0..200 {
            let p = generate_placeholder(&mut rng, &lists, |_| true).unwrap();
            assert_eq!(p.len(), 8);
            let b = p.as_bytes();
            for i in 0..4 {
                assert!(CONSONANTS.contains(&b[2 * i]) && VOWELS.contains(&b[2 * i + 1]), "{p}");
            }
        }
        let calls = std::cell::Cell::new(0);
        let p = generate_placeholder(&mut rng, &lists, |_| { calls.set(calls.get() + 1); calls.get() > 5 }).unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(calls.get(), 6);
        let calls = std::cell::Cell::new(0);
        assert!(generate_placeholder(&mut rng, &lists, |_| { calls.set(calls.get() + 1); false }).is_err());
        assert_eq!(calls.get(), PLACEHOLDER_TRIES);
    }
}
