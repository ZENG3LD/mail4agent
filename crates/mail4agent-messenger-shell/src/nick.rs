//! Nick derived from a Grok Bot web session's display name.
//!
//! The host passes the name it already shows (`Hostbot`, `Привет мир`).
//! This module turns that into the session nick. It is not a slug a person
//! types, and it does not read `M4A_NICK`. Local grok CLI sessions are not
//! named here.

use crate::ShellError;

/// Cyrillic (and a few adjacent letters) to Latin, then the host's routine
/// slug rule, so a bot's nick, its wake routine name, and that routine's
/// folder id are one string.
///
/// Letters are transliterated and lowercased; `ь` and `ъ` vanish. Every run
/// of anything else (spaces, punctuation, letters with no mapping) becomes
/// one `-`. Leading and trailing `-` are trimmed. The result is cut to 32
/// characters (the server's nick limit) and trimmed again, so
/// [`routine_folder_id`] of the nick is the nick itself.
/// `Привет мир` -> `privet-mir`, `foo+bar` ->
/// `foo-bar`, `Hostbot` -> `hostbot`.
pub fn nick_from_display_name(display_name: &str) -> Result<String, ShellError> {
    let mut out = String::new();
    let mut pending_dash = false;
    for ch in display_name.chars() {
        match latin_piece(ch) {
            Some("") => {}
            Some(piece) => {
                if pending_dash && !out.is_empty() {
                    out.push('-');
                }
                pending_dash = false;
                out.push_str(piece);
            }
            None => pending_dash = true,
        }
    }
    let nick: String = out.chars().take(32).collect();
    let nick = nick.trim_end_matches('-').to_string();
    if !is_nick_token(&nick) {
        return Err(ShellError::Nick);
    }
    Ok(nick)
}

/// Folder id the Grok Bot routine store gives a routine named `name`.
///
/// Same rule as the host's routine slug, used both by the bot's own
/// `UpdateRoutine` and by the gateway's `createAgentAutomation`: lowercase,
/// every run of characters outside `[a-z0-9]` becomes one `-`, leading and
/// trailing `-` are trimmed, then the result is cut to 48 characters. So a
/// routine named `privet_mir` would live in folder `privet-mir`;
/// wake routines avoid the mismatch by using the hyphen nick as the name.
/// The host falls back to a timestamped name when the slug is empty; that
/// is not reproducible, so this returns `None` instead.
/// A second routine with the same name gets `-2`, `-3`, ...; callers treat
/// that as a mismatch, not as the bot's routine.
///
/// For a nick from [`nick_from_display_name`] this returns the nick
/// unchanged: nick, routine name, and folder id are one string.
pub fn routine_folder_id(name: &str) -> Option<String> {
    let mut slug = String::new();
    let mut pending_dash = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(ch);
        } else {
            pending_dash = true;
        }
    }
    // The host trims before it cuts, so a cut can end on `-`. Keep it.
    let slug: String = slug.chars().take(48).collect();
    if slug.is_empty() {
        None
    } else {
        Some(slug)
    }
}

/// A directory lookup key. A string that is already a nick is used as-is
/// (the server compares case-insensitively; older nicks with `_` still
/// resolve). Anything else is treated as a display name and derived, so
/// `Привет мир` finds `privet-mir`.
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
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
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
            "privet-mir"
        );
        assert_eq!(
            nick_from_display_name("Свой браузер").unwrap(),
            "svoi-brauzer"
        );
        assert_eq!(
            nick_from_display_name("foo+bar").unwrap(),
            "foo-bar"
        );
        assert_eq!(nick_from_display_name("Sample Bot").unwrap(), "sample-bot");
        assert_eq!(
            nick_from_display_name("Объём, данные").unwrap(),
            "obyom-dannye"
        );
        assert_eq!(
            nick_from_display_name(&("x".repeat(31) + " y")).unwrap(),
            "x".repeat(31)
        );
        assert_ne!(
            nick_from_display_name("Привет мир").unwrap(),
            "nachshtab"
        );
        assert_eq!(nick_from_display_name("Foo   Bar!!").unwrap(), "foo-bar");
        assert_eq!(nick_from_display_name("__a__b__").unwrap(), "a-b");
        assert_eq!(
            nick_from_display_name(&"A".repeat(40)).unwrap(),
            "a".repeat(32)
        );
        assert!(nick_from_display_name("...").is_err());
        assert_eq!(lookup_nick("Привет мир").unwrap(), "privet-mir");
        assert_eq!(lookup_nick("privet_mir").unwrap(), "privet_mir");
        assert_eq!(lookup_nick("Hostbot").unwrap(), "Hostbot");
    }

    #[test]
    fn routine_folder_matches_the_host_slug() {
        // nick -> folder, the way UpdateRoutine and createAgentAutomation name it.
        assert_eq!(routine_folder_id("hostbot").as_deref(), Some("hostbot"));
        assert_eq!(
            routine_folder_id("privet_mir").as_deref(),
            Some("privet-mir")
        );
        assert_eq!(
            routine_folder_id("sample_bot").as_deref(),
            Some("sample-bot")
        );
        assert_eq!(
            routine_folder_id("foobar").as_deref(),
            Some("foobar")
        );
        assert_eq!(
            routine_folder_id("foo+bar").as_deref(),
            Some("foo-bar")
        );
        assert_eq!(routine_folder_id("Hostbot").as_deref(), Some("hostbot"));
        assert_eq!(routine_folder_id("__a__b__").as_deref(), Some("a-b"));
        assert_eq!(routine_folder_id("Привет"), None);
        assert_eq!(routine_folder_id("___"), None);
        assert_eq!(
            routine_folder_id(&"x".repeat(60)).map(|s| s.len()),
            Some(48)
        );
        assert_eq!(
            routine_folder_id(&format!("{}_b", "a".repeat(47))).as_deref(),
            Some(format!("{}-", "a".repeat(47)).as_str())
        );
        // Display name -> nick -> folder: the folder is the nick itself.
        let chain = |name: &str| routine_folder_id(&nick_from_display_name(name).unwrap());
        for name in [
            "Hostbot",
            "Привет мир",
            "foo+bar",
            "Sample Bot",
            "carol",
        ] {
            let nick = nick_from_display_name(name).unwrap();
            assert_eq!(routine_folder_id(&nick).as_deref(), Some(nick.as_str()));
        }
        assert_eq!(
            chain("Привет мир").as_deref(),
            Some("privet-mir")
        );
        assert_eq!(chain("foo+bar").as_deref(), Some("foo-bar"));
        assert_eq!(chain("Sample Bot").as_deref(), Some("sample-bot"));
        assert_eq!(chain("carol").as_deref(), Some("carol"));
    }
}
