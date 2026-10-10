//! `m4a-agent element-open (--as <nick>|--session <id>) --element <url>`: open an Element Web in
//! the browser, logged in as this identity, with no password.
//!
//! The command signs a fresh challenge with the identity key at the product door, receives a
//! one-time, short-lived Matrix login token (`m.login.token`), and hands Element the page
//! `<element>/?loginToken=<token>` through the browser opener. The token is never printed and never
//! written to a file; the identity's own session is untouched. The opener is the command named by
//! `M4A_BROWSER` (the URL is its only argument), else `xdg-open` (`open` on macOS).
//!
//! Element must be configured for this server (its `default_server_config` or `default_hs_url`).
//! The login gives that device access to the account's rooms; the history of encrypted rooms stays
//! unreadable on a new device unless the owner brings keys over (key backup, or verification from a
//! device that has them).
//!
//! The one place the token can be seen is the opener's argument list for the moment the browser
//! starts, by processes of the same user; it expires in two minutes and works once.

use super::session_arg::{resolve, take_flag};

pub fn run(args: Vec<String>) {
    match go(args) {
        Ok(()) => println!("element opened (login token not shown)"),
        Err(e) => {
            eprintln!("element-open: {e}");
            std::process::exit(if e.starts_with("usage") { 64 } else { 1 });
        }
    }
}

const USAGE: &str = "usage: m4a-agent element-open (--as <nick>|--session <id>) --element <url>   (env: M4A_STORE_ROOT, M4A_PRODUCT_URL, M4A_TIER, M4A_BROWSER)";

/// The page to open, from the Element base and a token. The token is percent-encoded.
pub(crate) fn page(element: &str, token: &str) -> String {
    let enc: String = token.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
    format!("{}/?loginToken={enc}", element.trim_end_matches('/'))
}

fn go(mut args: Vec<String>) -> Result<(), String> {
    let element = take_flag(&mut args, "--element")?.or_else(|| std::env::var("M4A_ELEMENT_URL").ok().filter(|v| !v.is_empty())).ok_or(USAGE)?;
    let target = resolve(&mut args)?;
    if !args.is_empty() || !(element.starts_with("https://") || element.starts_with("http://")) {
        return Err(USAGE.into());
    }
    let url = std::env::var("M4A_PRODUCT_URL").or_else(|_| std::env::var(crate::HOMESERVER_URL_ENV)).ok().filter(|v| !v.is_empty()).ok_or("M4A_PRODUCT_URL is not set")?;
    let token = login_token(&target.store_root, &target.session_id, &url)?;
    let opener = std::env::var("M4A_BROWSER").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| if cfg!(target_os = "macos") { "open".into() } else { "xdg-open".into() });
    let st = std::process::Command::new(&opener).arg(page(&element, &token)).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map_err(|_| format!("the browser opener {opener:?} could not be started (set M4A_BROWSER)"))?;
    if st.success() {
        Ok(())
    } else {
        Err("the browser opener failed".into())
    }
}

fn login_token(store_root: &std::path::Path, session_id: &str, url: &str) -> Result<String, String> {
    use m4a_agent::backend::Backend;
    let fail = |e: m4a_agent::AgentError| e.to_string();
    let ids = m4a_agent::IdentityStore::new(crate::store_key::vault(store_root).map_err(|e| e.to_string())?);
    let backend = m4a_agent::backend::server::ServerBackend::new(url).map_err(fail)?;
    let id = ids.resolve(session_id, m4a_agent::BackendKind::Server, backend.server_ref()).map_err(fail)?;
    if !id.enrolled {
        return Err("this identity is not enrolled on that server yet".into());
    }
    let wire = m4a_agent::backend::wire::HttpWire::new(url).map_err(fail)?;
    m4a_agent::keyauth::login_token(&wire, &ids, &id).map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::page;

    #[test]
    fn the_page_carries_the_token_in_the_query_encoded() {
        assert_eq!(page("https://chat.example/", "abc-DEF_1.2~x"), "https://chat.example/?loginToken=abc-DEF_1.2~x");
        assert_eq!(page("http://localhost:8080", "a b/c"), "http://localhost:8080/?loginToken=a%20b%2Fc");
    }
}
