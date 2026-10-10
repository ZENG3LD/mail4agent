//! The two checks a webhook delivery makes before anything is sent: the operator's URL and the
//! bearer. With `wake-grok` they are the Grok crate's own (one rule for both delivery paths); a
//! build without that feature carries the same rules here.

#[cfg(feature = "wake-grok")]
pub(crate) fn url_ok(url: &str) -> bool {
    mail4agent_grok::validate_webhook_url(url).is_ok()
}

/// `Some(token)` for a usable bearer, `None` for a blank or unsafe one.
#[cfg(feature = "wake-grok")]
pub(crate) fn bearer_token(token: &str) -> Option<&str> {
    mail4agent_grok::bearer_token(Some(token)).ok().flatten()
}

#[cfg(not(feature = "wake-grok"))]
pub(crate) fn url_ok(url: &str) -> bool {
    if url.is_empty() || url.len() > 2048 || url.chars().any(char::is_control) {
        return false;
    }
    let Some(after) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) else { return false };
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains(char::is_whitespace) {
        return false;
    }
    let host = authority.rsplit_once(']').map(|(h, _)| h).unwrap_or(authority);
    let host = host.strip_prefix('[').unwrap_or_else(|| host.split(':').next().unwrap_or(""));
    !host.is_empty()
}

#[cfg(not(feature = "wake-grok"))]
pub(crate) fn bearer_token(token: &str) -> Option<&str> {
    let token = token.trim();
    (!token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic())).then_some(token)
}
