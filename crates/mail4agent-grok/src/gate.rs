//! What a doorbell is allowed to become. Room mail and account-direct mail
//! ring the same account listener and must not be copied into every session.

use mail4agent_api::{Address, DeliveryNotification};

#[derive(Debug, PartialEq, Eq)]
pub enum Screen {
    /// Accepted for a later locate. `mail_session` is the mailbox session id,
    /// not the Grok UUID.
    Proceed { mail_session: String },
    /// Seen and dropped. The letter stays where the mailbox put it.
    Drop(&'static str),
}

pub fn use_leader_enabled(toml_text: &str) -> bool {
    let Ok(value) = toml_text.parse::<toml::Value>() else {
        return false;
    };
    value
        .get("cli")
        .and_then(|cli| cli.get("use_leader"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

/// The process cannot be a leader client if it was already running when
/// `config.toml` was last written. Fail closed: a later unrelated edit of
/// the config also refuses until that process is started again.
pub fn process_may_use_leader(process_started_unix_ms: u64, config_modified_unix_ms: u64) -> bool {
    process_started_unix_ms > 0
        && config_modified_unix_ms > 0
        && process_started_unix_ms >= config_modified_unix_ms
}

pub fn screen(note: &DeliveryNotification, account: &str, use_leader: bool, leader_ready: bool) -> Screen {
    let Address::Session { participant, session } = &note.to else {
        return Screen::Drop("not-session");
    };
    if participant.as_str() != account || note.account.as_str() != account {
        return Screen::Drop("other-account");
    }
    if !use_leader {
        return Screen::Drop("leader-off");
    }
    if !leader_ready {
        return Screen::Drop("leader-absent");
    }
    Screen::Proceed { mail_session: session.as_str().to_string() }
}

pub fn prompt_text(from: &str, to: &str, subject: &str, message_id: &str, body: &str) -> String {
    format!("from: {from}\nto: {to}\nsubject: {subject}\nmessage_id: {message_id}\n\n{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail4agent_api::{Address, ParticipantId, SessionId};

    fn note(to: Address) -> DeliveryNotification {
        DeliveryNotification {
            account: ParticipantId::new("grok").unwrap(),
            to,
            message_id: "m4a_0123456789abcdef01234567".parse().unwrap(),
            from: Address::Direct { participant: ParticipantId::new("alice").unwrap() },
        }
    }

    fn session_to() -> Address {
        Address::Session {
            participant: ParticipantId::new("grok").unwrap(),
            session: SessionId::new("s-01234567").unwrap(),
        }
    }

    #[test]
    fn use_leader_is_only_the_cli_bool() {
        assert!(!use_leader_enabled(""));
        assert!(!use_leader_enabled("[cli]\nuse_leader = false\n"));
        assert!(use_leader_enabled("[cli]\nuse_leader = true\n"));
        assert!(!use_leader_enabled("this is not toml"));
        assert!(!use_leader_enabled("[cli]\nother = true\n"));
    }

    #[test]
    fn a_process_older_than_the_config_is_refused() {
        assert!(!process_may_use_leader(0, 10));
        assert!(!process_may_use_leader(10, 0));
        assert!(!process_may_use_leader(10, 11));
        assert!(process_may_use_leader(11, 10));
        assert!(process_may_use_leader(10, 10));
    }

    #[test]
    fn only_a_session_letter_for_the_account_proceeds() {
        assert_eq!(
            screen(&note(session_to()), "grok", true, true),
            Screen::Proceed { mail_session: "s-01234567".to_string() }
        );
        assert_eq!(
            screen(&note(Address::Direct { participant: ParticipantId::new("grok").unwrap() }), "grok", true, true),
            Screen::Drop("not-session")
        );
        assert_eq!(
            screen(&note(Address::Room { room: "agents".parse().unwrap() }), "grok", true, true),
            Screen::Drop("not-session")
        );
        let mut other = note(session_to());
        other.account = ParticipantId::new("claude").unwrap();
        assert_eq!(screen(&other, "grok", true, true), Screen::Drop("other-account"));
        assert_eq!(screen(&note(session_to()), "grok", false, true), Screen::Drop("leader-off"));
        assert_eq!(screen(&note(session_to()), "grok", true, false), Screen::Drop("leader-absent"));
    }

    #[test]
    fn the_prompt_is_the_letter_and_nothing_else() {
        let text = prompt_text("alice", "grok/s-01234567", "hello", "m4a_0123456789abcdef01234567", "body line");
        assert_eq!(
            text,
            "from: alice\nto: grok/s-01234567\nsubject: hello\nmessage_id: m4a_0123456789abcdef01234567\n\nbody line"
        );
    }
}
