//! The two checks made on routine/gateway config before it is stored or used: the operator's URL
//! and the bearer. m4a itself never POSTs to a routine.

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

pub(crate) fn bearer_token(token: &str) -> Option<&str> {
    let token = token.trim();
    (!token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic())).then_some(token)
}
