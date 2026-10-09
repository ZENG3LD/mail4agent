//! The door for external logins: a federated Matrix address (OpenID
//! userinfo), and pluggable others (mail link, OAuth provider). Every door
//! reduces its proof to `(source, subject)`; the messenger then runs
//! [`crate::accounts::resolve_account`]. A foreign name is a login key, never a nick.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

use crate::account_source::Asserted;
use crate::error::MatrixError;
use crate::federation::{FedError, HttpKeyFetcher};

/// Source id of the Matrix-address door.
pub const MATRIX_SOURCE: &str = "matrix";

pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<(String, String), MatrixError>> + Send + 'a>>;

/// One kind of external proof.
pub trait ExternalLogin: Send + Sync {
    /// Source id stored in `external_identities.source`.
    fn id(&self) -> &str;
    /// Check the client's proof and return `(source, subject)`.
    fn verify<'a>(&'a self, proof: &'a Value) -> VerifyFuture<'a>;
}

pub type UserinfoFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, FedError>> + Send + 'a>>;

/// Fetches `GET /_matrix/federation/v1/openid/userinfo?access_token=..` from a server.
pub trait OpenIdUserinfo: Send + Sync {
    fn userinfo<'a>(&'a self, server: &'a str, access_token: &'a str) -> UserinfoFuture<'a>;
}

impl OpenIdUserinfo for HttpKeyFetcher {
    fn userinfo<'a>(&'a self, server: &'a str, access_token: &'a str) -> UserinfoFuture<'a> {
        Box::pin(async move {
            let uri = format!("/_matrix/federation/v1/openid/userinfo?access_token={}", crate::federation::enc(access_token));
            // Unauthenticated endpoint: no X-Matrix header.
            let (status, body) = self.get_unsigned(server, &uri).await?;
            if status != 200 {
                return Err(FedError::Network(format!("userinfo status {status}")));
            }
            Ok(body)
        })
    }
}

/// Proof: `{"matrix_server_name": "...", "access_token": "..."}` as returned by the
/// user's own server from `request_token`. The userinfo answer must come from the same
/// server that the returned address belongs to, and that server must not be one of ours.
pub struct MatrixOpenIdLogin {
    fetcher: std::sync::Arc<dyn OpenIdUserinfo>,
    /// Extra local names (besides [`crate::store::matrix_server_name`] and its aliases) refused as subjects.
    refuse_domains: Vec<String>,
}

impl MatrixOpenIdLogin {
    pub fn new(fetcher: std::sync::Arc<dyn OpenIdUserinfo>) -> Self {
        Self { fetcher, refuse_domains: Vec::new() }
    }
    pub fn refusing(mut self, domains: impl IntoIterator<Item = String>) -> Self {
        self.refuse_domains.extend(domains);
        self
    }
}

impl ExternalLogin for MatrixOpenIdLogin {
    fn id(&self) -> &str {
        MATRIX_SOURCE
    }

    fn verify<'a>(&'a self, proof: &'a Value) -> VerifyFuture<'a> {
        Box::pin(async move {
            let server = proof.get("matrix_server_name").and_then(Value::as_str).unwrap_or("");
            let token = proof.get("access_token").and_then(Value::as_str).unwrap_or("");
            if server.is_empty() || token.is_empty() {
                return Err(MatrixError::bad_json("matrix_server_name and access_token are required"));
            }
            if crate::store::is_local_server_name(server) || self.refuse_domains.iter().any(|d| d.eq_ignore_ascii_case(server)) {
                return Err(MatrixError::forbidden("this address belongs to this server; log in with your own credentials"));
            }
            let info = self
                .fetcher
                .userinfo(server, token)
                .await
                .map_err(|_| MatrixError::unauthorized("could not verify the OpenID token"))?;
            let sub = info.get("sub").and_then(Value::as_str).unwrap_or("");
            let domain = crate::fed_rooms::domain_of(sub).unwrap_or("");
            if !sub.starts_with('@') || !domain.eq_ignore_ascii_case(server) {
                return Err(MatrixError::unauthorized("OpenID answer does not match the server"));
            }
            if crate::store::is_local_server_name(domain) || self.refuse_domains.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
                return Err(MatrixError::forbidden("this address belongs to this server"));
            }
            Ok((MATRIX_SOURCE.to_string(), sub.to_string()))
        })
    }
}

/// Shape a verified door login as an assertion for `resolve_account`.
pub fn door_assertion(source: &str, subject: &str, cred_ref: &str, expires_ms: i64) -> Asserted {
    Asserted {
        source: source.to_string(),
        subject: subject.to_string(),
        nick: None,
        placeholder: true,
        authenticated: true,
        paid: false,
        cred_ref: cred_ref.to_string(),
        expires_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    struct Fake(Result<Value, ()>);
    impl OpenIdUserinfo for Fake {
        fn userinfo<'a>(&'a self, _s: &'a str, _t: &'a str) -> UserinfoFuture<'a> {
            Box::pin(async move { self.0.clone().map_err(|_| FedError::Network("x".into())) })
        }
    }
    fn login(r: Result<Value, ()>) -> MatrixOpenIdLogin {
        MatrixOpenIdLogin::new(Arc::new(Fake(r)))
    }
    fn run<T>(f: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn success_returns_full_foreign_address() {
        let l = login(Ok(json!({"sub":"@x:other.example"})));
        let r = run(l.verify(&json!({"matrix_server_name":"other.example","access_token":"t"}))).unwrap();
        assert_eq!(r, ("matrix".to_string(), "@x:other.example".to_string()));
    }

    #[test]
    fn wrong_server_expired_token_and_local_domain_are_refused() {
        let l = login(Ok(json!({"sub":"@x:evil.example"})));
        assert_eq!(run(l.verify(&json!({"matrix_server_name":"other.example","access_token":"t"}))).unwrap_err().errcode, "M_UNAUTHORIZED");
        let l = login(Err(()));
        assert_eq!(run(l.verify(&json!({"matrix_server_name":"other.example","access_token":"t"}))).unwrap_err().errcode, "M_UNAUTHORIZED");
        let l = login(Ok(json!({"sub":"@x:example.org"})));
        assert_eq!(run(l.verify(&json!({"matrix_server_name":"example.org","access_token":"t"}))).unwrap_err().errcode, "M_FORBIDDEN");
        let l = login(Ok(json!({"sub":"nonsense"})));
        assert!(run(l.verify(&json!({"matrix_server_name":"other.example","access_token":"t"}))).is_err());
        assert_eq!(run(l.verify(&json!({}))).unwrap_err().errcode, "M_BAD_JSON");
        let l = login(Ok(json!({"sub":"@x:other.example"}))).refusing(["other.example".to_string()]);
        assert!(run(l.verify(&json!({"matrix_server_name":"other.example","access_token":"t"}))).is_err());
    }
}
