//! Login doors of the product layer. A door reduces a proof to
//! `(source, subject)`; the product maps that to a user. A foreign name is a
//! login key, never a nick.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoorError {
    BadProof(String),
    Refused(String),
    Unverified(String),
}

pub type DoorFuture<'a> = Pin<Box<dyn Future<Output = Result<(String, String), DoorError>> + Send + 'a>>;

pub trait LoginDoor: Send + Sync {
    fn id(&self) -> &str;
    fn verify<'a>(&'a self, proof: &'a Value) -> DoorFuture<'a>;
}

#[cfg(feature = "matrix-address-door")]
pub use matrix_address::*;

#[cfg(feature = "matrix-address-door")]
mod matrix_address {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;

    /// Source id of the door.
    pub const MATRIX_SOURCE: &str = "matrix";

    pub type UserinfoFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;

    /// Fetches the OpenID userinfo of `access_token` from the user's own server.
    pub trait OpenIdUserinfo: Send + Sync {
        fn userinfo<'a>(&'a self, server: &'a str, access_token: &'a str) -> UserinfoFuture<'a>;
    }

    /// HTTP implementation: `.well-known` delegation, else `name:8448`;
    /// `overrides` maps a server name to a base URL (staging, tests).
    pub struct HttpUserinfo {
        client: reqwest::Client,
        overrides: HashMap<String, String>,
    }

    impl HttpUserinfo {
        pub fn new() -> Self {
            Self { client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build().expect("client"), overrides: HashMap::new() }
        }
        /// `name=base,name2=base2`.
        pub fn with_overrides(mut self, spec: &str) -> Self {
            for p in spec.split(',').filter_map(|p| p.split_once('=')) {
                self.overrides.insert(p.0.trim().to_string(), p.1.trim().trim_end_matches('/').to_string());
            }
            self
        }
        async fn base(&self, server: &str) -> Result<String, String> {
            if let Some(b) = self.overrides.get(server) {
                return Ok(b.clone());
            }
            if server.contains('/') || server.contains('@') || server.is_empty() {
                return Err("bad server name".into());
            }
            if !server.contains(':') && !server.chars().all(|c| c.is_ascii_digit() || c == '.') {
                if let Ok(r) = self.client.get(format!("https://{server}/.well-known/matrix/server")).send().await {
                    if let Ok(v) = r.json::<Value>().await {
                        if let Some(t) = v.get("m.server").and_then(Value::as_str) {
                            let t = t.trim();
                            if !t.is_empty() && !t.contains('/') {
                                return Ok(format!("https://{}", if t.contains(':') { t.to_string() } else { format!("{t}:8448") }));
                            }
                        }
                    }
                }
            }
            Ok(format!("https://{}", if server.contains(':') { server.to_string() } else { format!("{server}:8448") }))
        }
    }

    impl Default for HttpUserinfo {
        fn default() -> Self {
            Self::new()
        }
    }

    fn enc(s: &str) -> String {
        s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
    }

    impl OpenIdUserinfo for HttpUserinfo {
        fn userinfo<'a>(&'a self, server: &'a str, access_token: &'a str) -> UserinfoFuture<'a> {
            Box::pin(async move {
                let base = self.base(server).await?;
                let r = self.client.get(format!("{base}/_matrix/federation/v1/openid/userinfo?access_token={}", enc(access_token))).send().await.map_err(|e| e.to_string())?;
                if r.status().as_u16() != 200 {
                    return Err(format!("userinfo status {}", r.status()));
                }
                r.json::<Value>().await.map_err(|e| e.to_string())
            })
        }
    }

    /// Proof: `{"matrix_server_name": "...", "access_token": "..."}`. The answer
    /// must belong to the same server and that server must not be one of ours.
    pub struct MatrixAddressDoor {
        userinfo: Arc<dyn OpenIdUserinfo>,
        local_names: Vec<String>,
    }

    impl MatrixAddressDoor {
        /// `local_names`: this deployment's own server names, refused as subjects.
        pub fn new(userinfo: Arc<dyn OpenIdUserinfo>, local_names: Vec<String>) -> Self {
            Self { userinfo, local_names }
        }
        fn is_local(&self, name: &str) -> bool {
            self.local_names.iter().any(|d| d.eq_ignore_ascii_case(name))
        }
    }

    impl LoginDoor for MatrixAddressDoor {
        fn id(&self) -> &str {
            MATRIX_SOURCE
        }
        fn verify<'a>(&'a self, proof: &'a Value) -> DoorFuture<'a> {
            Box::pin(async move {
                let server = proof.get("matrix_server_name").and_then(Value::as_str).unwrap_or("");
                let token = proof.get("access_token").and_then(Value::as_str).unwrap_or("");
                if server.is_empty() || token.is_empty() {
                    return Err(DoorError::BadProof("matrix_server_name and access_token are required".into()));
                }
                if self.is_local(server) {
                    return Err(DoorError::Refused("this address belongs to this deployment; use your own credentials".into()));
                }
                let info = self.userinfo.userinfo(server, token).await.map_err(|_| DoorError::Unverified("could not verify the OpenID token".into()))?;
                let sub = info.get("sub").and_then(Value::as_str).unwrap_or("");
                let domain = sub.split_once(':').map(|x| x.1).unwrap_or("");
                if !sub.starts_with('@') || !domain.eq_ignore_ascii_case(server) {
                    return Err(DoorError::Unverified("OpenID answer does not match the server".into()));
                }
                if self.is_local(domain) {
                    return Err(DoorError::Refused("this address belongs to this deployment".into()));
                }
                Ok((MATRIX_SOURCE.to_string(), sub.to_string()))
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        struct Fake(Result<Value, ()>);
        impl OpenIdUserinfo for Fake {
            fn userinfo<'a>(&'a self, _s: &'a str, _t: &'a str) -> UserinfoFuture<'a> {
                Box::pin(async move { self.0.clone().map_err(|_| "x".to_string()) })
            }
        }
        fn door(r: Result<Value, ()>) -> MatrixAddressDoor {
            MatrixAddressDoor::new(Arc::new(Fake(r)), vec!["example.org".into()])
        }
        fn run<T>(f: impl Future<Output = T>) -> T {
            tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
        }
        const P: fn() -> Value = || json!({"matrix_server_name":"other.example","access_token":"t"});

        #[test]
        fn success_returns_the_full_foreign_address() {
            let r = run(door(Ok(json!({"sub":"@x:other.example"}))).verify(&P())).unwrap();
            assert_eq!(r, ("matrix".to_string(), "@x:other.example".to_string()));
        }

        #[test]
        fn mismatched_expired_local_and_malformed_are_refused() {
            assert!(matches!(run(door(Ok(json!({"sub":"@x:evil.example"}))).verify(&P())), Err(DoorError::Unverified(_))));
            assert!(matches!(run(door(Err(())).verify(&P())), Err(DoorError::Unverified(_))));
            assert!(matches!(run(door(Ok(json!({"sub":"@x:example.org"}))).verify(&json!({"matrix_server_name":"example.org","access_token":"t"}))), Err(DoorError::Refused(_))));
            assert!(run(door(Ok(json!({"sub":"nonsense"}))).verify(&P())).is_err());
            assert!(matches!(run(door(Ok(json!({}))).verify(&json!({}))), Err(DoorError::BadProof(_))));
        }
    }
}
