//! Bridges to other messengers, inside the client, on the user's machine, nowhere else.
//!
//! A bridge maps decrypted events of a room to another messenger's client protocol and back. The
//! rules are structural, not a convention:
//! - A bridge only ever sees events of rooms the user opted in ([`ConsentStore`]); everything else
//!   is dropped before the bridge is called. Nothing is bridged implicitly.
//! - A bridge reads and writes credentials only through its [`ScopedVault`], a view of the
//!   client's vault limited to `bridge/<name>/`. It cannot reach identity keys, session tokens or
//!   another bridge's secrets. No credential is ever read from the environment or from the repo.
//! - [`LocalEvent`] carries plaintext, has no `Serialize`, and prints without its body: it exists
//!   only in this process. There is no server-side bridge, appservice or hosted relay.
//! - A bridge compiles only with its own feature `bridge-<name>`; `bridges` is the framework.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::error::{AgentError, Result};
use crate::vault::KeyVault;

#[cfg(feature = "bridge-loopback")]
pub mod loopback;

/// A decrypted event on its way out to another messenger.
#[derive(Clone)]
pub struct LocalEvent {
    pub room_id: String,
    pub sender: String,
    pub body: String,
    pub event_id: String,
}

impl std::fmt::Debug for LocalEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEvent").field("room_id", &self.room_id).field("event_id", &self.event_id).field("body", &"<plaintext hidden>").finish()
    }
}

/// A message that arrived from the other messenger for one of our rooms.
pub struct RemoteMessage {
    pub room_id: String,
    pub author: String,
    pub body: String,
}

/// The vault as one bridge sees it.
#[derive(Clone)]
pub struct ScopedVault {
    inner: Arc<dyn KeyVault>,
    prefix: String,
}

impl ScopedVault {
    fn label(&self, l: &str) -> Result<String> {
        if l.is_empty() || l.len() > 64 || !l.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            return Err(AgentError::Vault("bridge credential label must be 1-64 characters of [A-Za-z0-9._-]".into()));
        }
        Ok(format!("{}{l}", self.prefix))
    }
    pub fn get(&self, l: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.inner.get(&self.label(l)?)
    }
    pub fn put(&self, l: &str, v: &[u8]) -> Result<()> {
        self.inner.put(&self.label(l)?, v)
    }
    pub fn delete(&self, l: &str) -> Result<bool> {
        self.inner.delete(&self.label(l)?)
    }
}

pub trait Bridge: Send {
    /// Registry key and feature name (`bridge-<name>`).
    fn name(&self) -> &'static str;
    /// Open the connection to the other messenger with credentials from `vault`.
    fn connect(&mut self, vault: &ScopedVault) -> Result<()>;
    /// A consented room's event, to be sent on the other messenger. `remote_room` is the other
    /// side's room the user linked.
    fn outgoing(&mut self, remote_room: &str, ev: &LocalEvent) -> Result<()>;
    /// Messages that arrived on the other messenger for `(remote_room)`; each is routed to the
    /// linked local room only if consent still holds.
    fn incoming(&mut self) -> Result<Vec<(String, String, String)>>; // (remote_room, author, body)
}

/// Per-room opt-in, kept in the vault so it survives restarts and travels with the identity.
pub struct ConsentStore {
    vault: Arc<dyn KeyVault>,
}

fn consent_label(bridge: &str) -> String {
    format!("bridge-consent/{bridge}")
}

impl ConsentStore {
    pub fn new(vault: Arc<dyn KeyVault>) -> Self {
        Self { vault }
    }

    fn load(&self, bridge: &str) -> Result<BTreeMap<String, String>> {
        match self.vault.get(&consent_label(bridge))? {
            Some(raw) => serde_json::from_slice(&raw).map_err(|e| AgentError::Vault(format!("bridge consent: {e}"))),
            None => Ok(BTreeMap::new()),
        }
    }

    fn store(&self, bridge: &str, m: &BTreeMap<String, String>) -> Result<()> {
        self.vault.put(&consent_label(bridge), &serde_json::to_vec(m).map_err(|e| AgentError::Vault(e.to_string()))?)
    }

    /// The user opts `room_id` in and links it to `remote_room`. Explicit, per room, per bridge.
    pub fn grant(&self, bridge: &str, room_id: &str, remote_room: &str) -> Result<()> {
        let mut m = self.load(bridge)?;
        m.insert(room_id.to_string(), remote_room.to_string());
        self.store(bridge, &m)
    }

    /// Opts out; nothing of the room is bridged from this moment.
    pub fn revoke(&self, bridge: &str, room_id: &str) -> Result<bool> {
        let mut m = self.load(bridge)?;
        let had = m.remove(room_id).is_some();
        if had {
            self.store(bridge, &m)?;
        }
        Ok(had)
    }

    pub fn remote_of(&self, bridge: &str, room_id: &str) -> Result<Option<String>> {
        Ok(self.load(bridge)?.get(room_id).cloned())
    }

    pub fn local_of(&self, bridge: &str, remote_room: &str) -> Result<Option<String>> {
        Ok(self.load(bridge)?.into_iter().find(|(_, r)| r == remote_room).map(|(l, _)| l))
    }

    pub fn rooms(&self, bridge: &str) -> Result<BTreeSet<String>> {
        Ok(self.load(bridge)?.into_keys().collect())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ForwardReport {
    pub forwarded: Vec<String>,
    /// Bridges that failed (name, reason); never contains message text.
    pub failed: Vec<(String, String)>,
}

/// The bridges of one session and the rules that connect them to its rooms.
pub struct BridgeRegistry {
    vault: Arc<dyn KeyVault>,
    consent: ConsentStore,
    bridges: BTreeMap<&'static str, Box<dyn Bridge>>,
}

impl BridgeRegistry {
    pub fn new(vault: Arc<dyn KeyVault>) -> Self {
        Self { consent: ConsentStore::new(vault.clone()), vault, bridges: BTreeMap::new() }
    }

    pub fn consent(&self) -> &ConsentStore {
        &self.consent
    }

    /// Adds a bridge and connects it with its own scoped credentials.
    pub fn register(&mut self, mut bridge: Box<dyn Bridge>) -> Result<()> {
        let name = bridge.name();
        if self.bridges.contains_key(name) {
            return Err(AgentError::Identity(format!("bridge {name} is already registered")));
        }
        bridge.connect(&ScopedVault { inner: self.vault.clone(), prefix: format!("bridge/{name}/") })?;
        self.bridges.insert(name, bridge);
        Ok(())
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.bridges.keys().copied().collect()
    }

    /// Offers a decrypted event to every bridge that the room has consented to.
    pub fn forward(&mut self, ev: &LocalEvent) -> ForwardReport {
        let mut report = ForwardReport::default();
        for (name, bridge) in self.bridges.iter_mut() {
            match self.consent.remote_of(name, &ev.room_id) {
                Ok(Some(remote)) => match bridge.outgoing(&remote, ev) {
                    Ok(()) => report.forwarded.push(name.to_string()),
                    Err(e) => report.failed.push((name.to_string(), e.to_string())),
                },
                Ok(None) => {}
                Err(e) => report.failed.push((name.to_string(), e.to_string())),
            }
        }
        report
    }

    /// Messages from the other messengers for rooms that still have consent: `(local_room, bridge,
    /// author, body)`. Anything for an unlinked or revoked room is discarded here.
    pub fn collect(&mut self) -> Vec<(String, &'static str, String, String)> {
        let mut out = Vec::new();
        for (name, bridge) in self.bridges.iter_mut() {
            let Ok(msgs) = bridge.incoming() else { continue };
            for (remote, author, body) in msgs {
                if let Ok(Some(local)) = self.consent.local_of(name, &remote) {
                    out.push((local, *name, author, body));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MemoryVault;

    #[cfg(feature = "bridge-loopback")]
    #[test]
    fn only_consented_rooms_reach_the_bridge_and_credentials_are_scoped() {
        use loopback::{LoopbackBridge, LoopbackRemote, TOKEN_LABEL};
        let vault: Arc<dyn KeyVault> = Arc::new(MemoryVault::new());
        vault.put("identity-key/s1", b"never-visible").unwrap();
        let remote = Arc::new(LoopbackRemote::default());
        let mut reg = BridgeRegistry::new(vault.clone());
        // No credential in the vault: the bridge does not connect.
        assert!(reg.register(Box::new(LoopbackBridge::new(remote.clone()))).is_err());
        vault.put(&format!("bridge/loopback/{TOKEN_LABEL}"), b"t").unwrap();
        reg.register(Box::new(LoopbackBridge::new(remote.clone()))).unwrap();
        assert!(reg.register(Box::new(LoopbackBridge::new(remote.clone()))).is_err(), "twice");

        let ev = |room: &str, body: &str| LocalEvent { room_id: room.into(), sender: "@a:x".into(), body: body.into(), event_id: "$1".into() };
        // Nothing is bridged until the user opts the room in.
        assert_eq!(reg.forward(&ev("!r1", "secret")), ForwardReport::default());
        assert!(remote.sent.lock().unwrap().is_empty());
        reg.consent().grant("loopback", "!r1", "remote-1").unwrap();
        assert_eq!(reg.forward(&ev("!r1", "hello")).forwarded, vec!["loopback"]);
        assert_eq!(reg.forward(&ev("!r2", "other room")), ForwardReport::default());
        assert_eq!(remote.sent.lock().unwrap().as_slice(), &[("remote-1".to_string(), "@a:x: hello".to_string())]);

        // Incoming only for linked rooms; revoking stops both directions.
        remote.inbox.lock().unwrap().push_back(("remote-1".into(), "bob".into(), "hi".into()));
        remote.inbox.lock().unwrap().push_back(("unlinked".into(), "eve".into(), "x".into()));
        assert_eq!(reg.collect(), vec![("!r1".to_string(), "loopback", "bob".to_string(), "hi".to_string())]);
        assert!(reg.consent().revoke("loopback", "!r1").unwrap());
        remote.inbox.lock().unwrap().push_back(("remote-1".into(), "bob".into(), "again".into()));
        assert!(reg.collect().is_empty());
        assert_eq!(reg.forward(&ev("!r1", "after")), ForwardReport::default());
        assert_eq!(remote.sent.lock().unwrap().len(), 1);

        // The scoped vault cannot name anything outside the bridge's own prefix.
        let sv = ScopedVault { inner: vault.clone(), prefix: "bridge/loopback/".into() };
        assert!(sv.get("../identity-key/s1").is_err() && sv.get("a/b").is_err());
        assert!(sv.get("identity-key").unwrap().is_none());
    }

    #[test]
    fn plaintext_does_not_print() {
        let e = LocalEvent { room_id: "!r".into(), sender: "@a:x".into(), body: "very secret words".into(), event_id: "$1".into() };
        assert!(!format!("{e:?}").contains("secret"));
        let _ = MemoryVault::new();
    }
}
