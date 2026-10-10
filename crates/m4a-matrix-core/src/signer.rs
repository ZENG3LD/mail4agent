use ruma_signatures::{KeyPair, Signature};

/// An ed25519 signer: server name, key id (`ed25519:<version>`) and a signing closure.
/// The closure signs the exact bytes it is given and returns the 64-byte signature.
pub struct Signer {
    server: String,
    key_id: String,
    sign: Box<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>,
}

impl Signer {
    pub fn new(server: impl Into<String>, key_id: impl Into<String>, sign: impl Fn(&[u8]) -> [u8; 64] + Send + Sync + 'static) -> Self {
        Self { server: server.into(), key_id: key_id.into(), sign: Box::new(sign) }
    }
    pub fn server(&self) -> &str {
        &self.server
    }
}

impl KeyPair for Signer {
    fn sign(&self, message: &[u8]) -> Signature {
        let key_id = self.key_id.as_str().try_into().expect("key id is `ed25519:<version>`");
        Signature::new(key_id, (self.sign)(message).to_vec())
    }
}
