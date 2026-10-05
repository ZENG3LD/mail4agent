//! Nick derived from a Grok Bot web session's display name.
//!
//! The host passes the name it already shows (`Hostbot`, `Привет мир`).
//! This module turns that into the session nick. It is not a slug a person
//! types, and it does not read `M4A_NICK`. Local grok CLI sessions are not
//! named here.

use crate::ShellError;

/// Cyrillic (and a few adjacent letters) to Latin, then the nick shape.
///
/// Spaces become `_`. Anything that is not ASCII alphanumeric is dropped
/// after transliteration, including `ь` and `ъ`. Repeated `_` collapse.
/// The result is trimmed and cut to 32 characters. ASCII letters are
/// lowercased so `Hostbot` and `hostbot` are one nick.
pub fn nick_from_display_name(display_name: &str) -> Result<String, ShellError> {
    let mut out = String::new();
    let mut word_break = false;
    for ch in display_name.chars() {
        if ch.is_whitespace() {
            word_break = true;
            continue;
        }
        let Some(piece) = latin_piece(ch) else {
            continue;
        };
        if piece.is_empty() {
            continue;
        }
        if word_break && !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
        word_break = false;
        out.push_str(piece);
    }
    let mut nick: String = out.chars().take(32).collect();
    while nick.ends_with('_') {
        nick.pop();
    }
    if !is_nick_token(&nick) {
        return Err(ShellError::Nick);
    }
    Ok(nick)
}

/// A directory lookup key. A string that is already a nick is used as-is
/// (the server compares case-insensitively). Anything else is treated as a
/// display name and derived, so `Привет мир` finds `privet_mir`.
pub fn lookup_nick(raw: &str) -> Result<String, ShellError> {
    let trimmed = raw.trim();
    if is_nick_token(trimmed) {
        return Ok(trimmed.to_string());
    }
    nick_from_display_name(trimmed)
}

fn is_nick_token(nick: &str) -> bool {
    !nick.is_empty()
        && nick.len() <= 32
        && nick
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn latin_piece(ch: char) -> Option<&'static str> {
    if ch.is_ascii_alphanumeric() {
        return Some(ascii_lower(ch));
    }
    let lower = ch.to_lowercase().next()?;
    Some(match lower {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' => "e",
        'ё' => "yo",
        'ж' => "zh",
        'з' => "z",
        'и' => "i",
        'й' => "i",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' | 'ь' => "",
        'ы' => "y",
        'э' => "e",
        'ю' => "yu",
        'я' => "ya",
        // Ukrainian / Belarusian letters that are not in the Russian set above.
        'є' => "ye",
        'і' => "i",
        'ї' => "yi",
        'ґ' => "g",
        'ў' => "u",
        _ => return None,
    })
}

fn ascii_lower(ch: char) -> &'static str {
    match ch {
        'A' | 'a' => "a",
        'B' | 'b' => "b",
        'C' | 'c' => "c",
        'D' | 'd' => "d",
        'E' | 'e' => "e",
        'F' | 'f' => "f",
        'G' | 'g' => "g",
        'H' | 'h' => "h",
        'I' | 'i' => "i",
        'J' | 'j' => "j",
        'K' | 'k' => "k",
        'L' | 'l' => "l",
        'M' | 'm' => "m",
        'N' | 'n' => "n",
        'O' | 'o' => "o",
        'P' | 'p' => "p",
        'Q' | 'q' => "q",
        'R' | 'r' => "r",
        'S' | 's' => "s",
        'T' | 't' => "t",
        'U' | 'u' => "u",
        'V' | 'v' => "v",
        'W' | 'w' => "w",
        'X' | 'x' => "x",
        'Y' | 'y' => "y",
        'Z' | 'z' => "z",
        '0' => "0",
        '1' => "1",
        '2' => "2",
        '3' => "3",
        '4' => "4",
        '5' => "5",
        '6' => "6",
        '7' => "7",
        '8' => "8",
        '9' => "9",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_become_nicks() {
        assert_eq!(nick_from_display_name("Hostbot").unwrap(), "hostbot");
        assert_eq!(nick_from_display_name("  Hostbot  ").unwrap(), "hostbot");
        assert_eq!(
            nick_from_display_name("Привет мир").unwrap(),
            "privet_mir"
        );
        assert_eq!(
            nick_from_display_name("Свой браузер").unwrap(),
            "svoi_brauzer"
        );
        assert_ne!(
            nick_from_display_name("Привет мир").unwrap(),
            "nachshtab"
        );
        assert_eq!(nick_from_display_name("Foo   Bar!!").unwrap(), "foo_bar");
        assert_eq!(
            nick_from_display_name(&"A".repeat(40)).unwrap(),
            "a".repeat(32)
        );
        assert!(nick_from_display_name("...").is_err());
        assert_eq!(lookup_nick("Привет мир").unwrap(), "privet_mir");
        assert_eq!(lookup_nick("Hostbot").unwrap(), "Hostbot");
    }
}
