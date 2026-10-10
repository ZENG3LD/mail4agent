//! What every tier shares once it has a token: executing the engine's requests with the bearer,
//! one retry after a refresh when the server forgot the token, and the push socket as the news
//! channel.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use mail4agent_messenger::{HttpResponseDescriptor, OutgoingRequest};
use zeroize::Zeroizing;

use crate::engine::{HttpExec, News, PushLink};
use crate::error::{AgentError, Result};

/// Logs in again (by signature) and returns the new token.
pub type Refresher = Arc<dyn Fn() -> Result<String> + Send + Sync>;

pub struct Live {
    exec: RwLock<HttpExec>,
    token: Mutex<Option<Zeroizing<String>>>,
    push: Mutex<Option<PushLink>>,
    push_unavailable: Mutex<Option<Instant>>,
    refresher: Mutex<Option<Refresher>>,
}

fn unknown_token(r: &HttpResponseDescriptor) -> bool {
    r.status == 401 && serde_json::from_slice::<serde_json::Value>(&r.body).ok().and_then(|v| v.get("errcode").and_then(|c| c.as_str()).map(|c| c == "M_UNKNOWN_TOKEN")).unwrap_or(false)
}

impl Live {
    pub fn new(exec: HttpExec) -> Self {
        Self { exec: RwLock::new(exec), token: Mutex::new(None), push: Mutex::new(None), push_unavailable: Mutex::new(None), refresher: Mutex::new(None) }
    }

    pub fn with_exec<T>(&self, f: impl FnOnce(&mut HttpExec) -> T) -> T {
        f(&mut self.exec.write().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn exec(&self) -> HttpExec {
        self.exec.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn keep_prefix(&self) -> bool {
        self.exec.read().unwrap_or_else(|e| e.into_inner()).keep_prefix()
    }

    pub fn set_token(&self, token: &str) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(Zeroizing::new(token.to_string()));
        // A push socket registered with the old token is of no use any more.
        *self.push.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn set_refresher(&self, r: Refresher) {
        *self.refresher.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
    }

    fn token(&self) -> Result<Zeroizing<String>> {
        self.token.lock().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(|| AgentError::Identity("no session yet: ensure_session first".into()))
    }

    pub fn execute(&self, request: &OutgoingRequest) -> Result<HttpResponseDescriptor> {
        let token = self.token()?;
        let exec = self.exec();
        let first = exec.perform(&token, request)?;
        if !unknown_token(&first) {
            return Ok(first);
        }
        let refresher = self.refresher.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(refresh) = refresher else { return Ok(first) };
        match refresh() {
            Ok(fresh) => {
                self.set_token(&fresh);
                exec.perform(&fresh, request)
            }
            Err(_) => Ok(first),
        }
    }

    /// Who this token is: `(user_id, device_id)`.
    pub fn whoami(&self) -> Result<(String, String)> {
        let token = self.token()?;
        let (st, v) = self.exec().get_json_as(&token, "/_matrix/client/v3/account/whoami")?;
        if st != 200 {
            return Err(AgentError::Protocol(format!("whoami: status {st}")));
        }
        let get = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string).ok_or_else(|| AgentError::Protocol(format!("whoami without {k}")));
        Ok((get("user_id")?, get("device_id")?))
    }

    /// Blocks until the server pushes news for this session or `timeout` passes. A server without
    /// a push channel answers `Idle` at once; the caller's sync long poll is then the wait.
    pub fn wait_for_news(&self, timeout: Duration) -> Result<News> {
        {
            let mut slot = self.push.lock().unwrap_or_else(|e| e.into_inner());
            if slot.is_none() {
                // A failed attempt is not repeated for a while.
                if self.push_unavailable.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                    return Ok(News::Idle);
                }
                let token = self.token()?;
                let (base, keep) = {
                    let e = self.exec.read().unwrap_or_else(|e| e.into_inner());
                    (e.base().as_str().to_string(), e.keep_prefix())
                };
                match PushLink::open(&base, keep, vec![token.to_string()], true) {
                    Ok(link) => *slot = Some(link),
                    Err(_) => {
                        *self.push_unavailable.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
                        return Ok(News::Idle);
                    }
                }
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            let got: Vec<_> = self.push.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|p| p.drain().into_iter().map(|(_, e)| e).collect()).unwrap_or_default();
            if !got.is_empty() {
                return Ok(News::Pushed(got));
            }
            if Instant::now() >= deadline {
                return Ok(News::Idle);
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }
}
