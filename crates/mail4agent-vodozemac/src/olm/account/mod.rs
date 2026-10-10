// Modified from vodozemac 0.10.0 by the mail4agent authors (this file differs from upstream; see FORK.md).
// Copyright 2021 Damir Jelić, Denis Kasak
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Modified for mail4agent-vodozemac (see FORK.md).

mod fallback_keys;
mod one_time_keys;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use self::one_time_keys::OneTimeKeyGenerationResult;
use self::{
    fallback_keys::FallbackKeys,
    one_time_keys::{OneTimeKeys, OneTimeKeysPickle},
};
use super::{
    SessionConfig,
    messages::PreKeyMessage,
    session::{DecryptionError, Session},
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
};
use crate::{
    Ed25519Signature, PickleError, olm,
    types::{
        Curve25519Keypair, Curve25519KeypairPickle, Curve25519PublicKey, Curve25519SecretKey,
        Ed25519Keypair, Ed25519KeypairPickle, Ed25519PublicKey, KeyId,
    },
    utilities::{pickle, unpickle},
};

const PUBLIC_MAX_ONE_TIME_KEYS: usize = 50;

/// Error describing failure modes when creating a Olm [`Session`] from an
/// incoming Olm message.
#[derive(Error, Debug)]
pub enum SessionCreationError {
    /// The pre-key message contained an unknown one-time key. This happens
    /// either because we never had such a one-time key, or because it has
    /// already been used up.
    #[error("The pre-key message contained an unknown one-time key: {0}")]
    MissingOneTimeKey(Curve25519PublicKey),
    /// The pre-key message contains a Curve25519 identity key that doesn't
    /// match to the identity key that was given.
    #[error(
        "The given identity key doesn't match the one in the pre-key message: \
        expected {0}, got {1}"
    )]
    MismatchedIdentityKey(Curve25519PublicKey, Curve25519PublicKey),
    /// The pre-key message was encrypted with a Session which used an
    /// unexpected SessionConfig.
    #[error(
        "The session config doesn't match the one used for the pre-key message: expected {expected:?}, got {got:?}"
    )]
    MismatchedSessionConfig {
        /// The [`SessionConfig`] we expected.
        expected: SessionConfig,
        /// The [`SessionConfig`] the pre-key message was encrypted with.
        ///
        /// Will be `None` if we don't understand the received config.
        got: Option<SessionConfig>,
    },
    /// The pre-key message that was used to establish the [`Session`] couldn't
    /// be decrypted. The message needs to be decryptable, otherwise we will
    /// have created a Session that wasn't used to encrypt the pre-key
    /// message.
    #[error("The message that was used to establish the Session couldn't be decrypted")]
    Decryption(#[from] DecryptionError),
    /// One or more keys lacked contributory behavior in the Diffie-Hellman
    /// operation, resulting in an insecure shared secret.
    ///
    /// For more details on contributory behavior please refer to the
    /// [`x25519_dalek::SharedSecret::was_contributory()`] method.
    #[error(
        "The shared secret was derived from an insecure key exchange (non-contributory behaviour)"
    )]
    NonContributoryKey,
}

/// Struct holding the two public identity keys of an [`Account`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKeys {
    /// The Ed25519 key, used for signing.
    pub ed25519: Ed25519PublicKey,
    /// The Curve25519 key, used for to establish shared secrets.
    pub curve25519: Curve25519PublicKey,
}

/// Return type for the creation of inbound [`Session`] objects.
#[derive(Debug)]
pub struct InboundCreationResult {
    /// The [`Session`] that was created from a pre-key message.
    pub session: Session,
    /// The plaintext of the pre-key message.
    pub plaintext: Vec<u8>,
}

/// An Olm [`Account`] manages all cryptographic keys used on a device.
pub struct Account {
    /// A permanent Ed25519 key used for signing. Also known as the fingerprint
    /// key.
    signing_key: Ed25519Keypair,
    /// The permanent Curve25519 key used for triple Diffie-Hellman (3DH). Also
    /// known as the sender key or the identity key.
    diffie_hellman_key: Curve25519Keypair,
    /// The ephemeral (one-time) Curve25519 keys used as part of the triple
    /// Diffie-Hellman (3DH).
    one_time_keys: OneTimeKeys,
    /// The ephemeral Curve25519 keys used in lieu of a one-time key as part of
    /// the 3DH, in case we run out of those. We keep track of both the current
    /// and the previous fallback key in any given moment.
    fallback_keys: FallbackKeys,
}

impl Account {
    /// Create a new [`Account`] with new random identity keys.
    pub fn new() -> Self {
        Self {
            signing_key: Ed25519Keypair::new(),
            diffie_hellman_key: Curve25519Keypair::new(),
            one_time_keys: OneTimeKeys::new(),
            fallback_keys: FallbackKeys::new(),
        }
    }

    /// Get the [`IdentityKeys`] of this Account
    pub const fn identity_keys(&self) -> IdentityKeys {
        IdentityKeys { ed25519: self.ed25519_key(), curve25519: self.curve25519_key() }
    }

    /// Get a copy of the account's public Ed25519 key
    pub const fn ed25519_key(&self) -> Ed25519PublicKey {
        self.signing_key.public_key()
    }

    /// Get a copy of the account's public Curve25519 key
    pub const fn curve25519_key(&self) -> Curve25519PublicKey {
        self.diffie_hellman_key.public_key()
    }

    /// Sign the given message using our Ed25519 fingerprint key.
    pub fn sign(&self, message: impl AsRef<[u8]>) -> Ed25519Signature {
        self.signing_key.sign(message.as_ref())
    }

    /// Get the maximum number of one-time keys the client should keep on the
    /// server.
    ///
    /// **Note**: this differs from the libolm method of the same name, the
    /// libolm method returned the maximum amount of one-time keys the
    /// [`Account`] could hold and only half of those should be uploaded.
    pub const fn max_number_of_one_time_keys(&self) -> usize {
        // We tell clients to upload a limited amount of one-time keys, this
        // amount is smaller than what we can store.
        //
        // We do this because a client might receive the count of uploaded keys
        // from the server before they receive all the pre-key messages that
        // used some of our one-time keys. This would mean that we would forget
        // private one-time keys, since we're generating new ones, while we
        // didn't yet receive the pre-key messages that used those one-time
        // keys.
        PUBLIC_MAX_ONE_TIME_KEYS
    }

    /// Create a [`Session`] with the given identity key and one-time key.
    pub fn create_outbound_session(
        &self,
        session_config: SessionConfig,
        identity_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> Result<Session, SessionCreationError> {
        let base_key = Curve25519SecretKey::new();
        let public_base_key = Curve25519PublicKey::from(&base_key);

        let shared_secret = Shared3DHSecret::new(
            self.diffie_hellman_key.secret_key(),
            &base_key,
            &identity_key,
            &one_time_key,
        )
        .ok_or(SessionCreationError::NonContributoryKey)?;

        let session_keys = SessionKeys {
            identity_key: self.curve25519_key(),
            base_key: public_base_key,
            one_time_key,
        };

        Ok(Session::new(session_config, shared_secret, session_keys))
    }

    /// Try to find a [`Curve25519SecretKey`] that forms a pair with the given
    /// [`Curve25519PublicKey`].
    fn find_one_time_key(&self, public_key: &Curve25519PublicKey) -> Option<&Curve25519SecretKey> {
        self.one_time_keys
            .get_secret_key(public_key)
            .or_else(|| self.fallback_keys.get_secret_key(public_key))
    }

    /// Remove a one-time key that has previously been published but not yet
    /// used.
    ///
    /// **Note**: This function is only rarely useful and you'll know if you
    /// need it. Notably, you do *not* need to call it manually when using up
    /// a key via [`Account::create_inbound_session`] since the key is
    /// automatically removed in that case.
    #[cfg(feature = "low-level-api")]
    pub fn remove_one_time_key(
        &mut self,
        public_key: Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.remove_one_time_key_helper(public_key)
    }

    fn remove_one_time_key_helper(
        &mut self,
        public_key: Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.one_time_keys.remove_secret_key(&public_key)
    }

    /// Create a [`Session`] from the given [`PreKeyMessage`] message and
    /// identity key
    pub fn create_inbound_session(
        &mut self,
        expected_config: SessionConfig,
        their_identity_key: Curve25519PublicKey,
        pre_key_message: &PreKeyMessage,
    ) -> Result<InboundCreationResult, SessionCreationError> {
        if their_identity_key != pre_key_message.identity_key() {
            Err(SessionCreationError::MismatchedIdentityKey(
                their_identity_key,
                pre_key_message.identity_key(),
            ))
        } else {
            let config = match pre_key_message.message.version() {
                olm::messages::message::MAC_TRUNCATED_VERSION => SessionConfig::version_1(),
                #[cfg(feature = "experimental-session-config")]
                olm::messages::message::VERSION => SessionConfig::version_2(),
                _ => {
                    return Err(SessionCreationError::MismatchedSessionConfig {
                        expected: expected_config,
                        got: None,
                    });
                }
            };

            if config != expected_config {
                return Err(SessionCreationError::MismatchedSessionConfig {
                    expected: expected_config,
                    got: Some(config),
                });
            }

            // Find the matching private part of the OTK that the message claims
            // was used to create the session that encrypted it.
            let public_otk = pre_key_message.one_time_key();
            let private_otk = self
                .find_one_time_key(&public_otk)
                .ok_or(SessionCreationError::MissingOneTimeKey(public_otk))?;

            // Construct a 3DH shared secret from the various curve25519 keys.
            let shared_secret = RemoteShared3DHSecret::new(
                self.diffie_hellman_key.secret_key(),
                private_otk,
                &pre_key_message.identity_key(),
                &pre_key_message.base_key(),
            )
            .ok_or(SessionCreationError::NonContributoryKey)?;

            // These will be used to uniquely identify the Session.
            let session_keys = SessionKeys {
                identity_key: pre_key_message.identity_key(),
                base_key: pre_key_message.base_key(),
                one_time_key: pre_key_message.one_time_key(),
            };

            // Create a Session, AKA a double ratchet, this one will have an
            // inactive sending chain until we decide to encrypt a message.
            let mut session = Session::new_remote(
                config,
                shared_secret,
                pre_key_message.message.ratchet_key,
                session_keys,
            );

            // Decrypt the message to check if the Session is actually valid.
            let plaintext = session.decrypt_decoded(&pre_key_message.message)?;

            // We only drop the one-time key now, this is why we can't use a
            // one-time key type that takes `self`. If we didn't do this,
            // someone could maliciously pretend to use up our one-time key and
            // make us drop the private part. Unsuspecting users that actually
            // try to use such an one-time key won't be able to communicate with
            // us. This is strictly worse than the one-time key exhaustion
            // scenario.
            self.remove_one_time_key_helper(pre_key_message.one_time_key());

            Ok(InboundCreationResult { session, plaintext })
        }
    }

    /// Generates the supplied number of one time keys.
    /// Returns the public parts of the one-time keys that were created and
    /// discarded.
    ///
    /// Our one-time key store inside the [`Account`] has a limited amount of
    /// places for one-time keys, If we try to generate new ones while the store
    /// is completely populated, the oldest one-time keys will get discarded
    /// to make place for new ones.
    pub fn generate_one_time_keys(&mut self, count: usize) -> OneTimeKeyGenerationResult {
        self.one_time_keys.generate(count)
    }

    /// Get the number of one-time keys we have stored locally.
    ///
    /// This will be equal or greater to the number of one-time keys we have
    /// published. Each time a new [`Session`] is created using the
    /// [`Account::create_inbound_session()`] a one-time key will be used up
    /// and removed.
    pub fn stored_one_time_key_count(&self) -> usize {
        self.one_time_keys.private_keys.len()
    }

    /// Get the currently unpublished one-time keys.
    ///
    /// The one-time keys should be published to a server and marked as
    /// published using the `mark_keys_as_published()` method.
    pub fn one_time_keys(&self) -> HashMap<KeyId, Curve25519PublicKey> {
        self.one_time_keys
            .unpublished_public_keys
            .iter()
            .map(|(key_id, key)| (*key_id, *key))
            .collect()
    }

    /// Generate a single new fallback key.
    ///
    /// The fallback key will be used by other users to establish a [`Session`]
    /// if all the one-time keys on the server have been used up.
    ///
    /// Returns the public Curve25519 key of the *previous* fallback key, that
    /// is, the one that will get removed from the [`Account`] when this method
    /// is called. This return value is mostly useful for logging purposes.
    pub fn generate_fallback_key(&mut self) -> Option<Curve25519PublicKey> {
        self.fallback_keys.generate_fallback_key()
    }

    /// Get the currently unpublished fallback key.
    ///
    /// The fallback key should be published just like the one-time keys, after
    /// it has been successfully published it needs to be marked as published
    /// using the `mark_keys_as_published()` method as well.
    pub fn fallback_key(&self) -> HashMap<KeyId, Curve25519PublicKey> {
        let fallback_key = self.fallback_keys.unpublished_fallback_key();

        if let Some(fallback_key) = fallback_key {
            HashMap::from([(fallback_key.key_id(), fallback_key.public_key())])
        } else {
            HashMap::new()
        }
    }

    /// The [`Account`] stores at most two private parts of the fallback key.
    /// This method lets us forget the previously used fallback key.
    pub fn forget_fallback_key(&mut self) -> bool {
        self.fallback_keys.forget_previous_fallback_key().is_some()
    }

    /// Mark all currently unpublished one-time and fallback keys as published.
    pub fn mark_keys_as_published(&mut self) {
        self.one_time_keys.mark_as_published();
        self.fallback_keys.mark_as_published();
    }

    /// Convert the account into a struct which implements [`serde::Serialize`]
    /// and [`serde::Deserialize`].
    pub fn pickle(&self) -> AccountPickle {
        AccountPickle {
            signing_key: self.signing_key.clone().into(),
            diffie_hellman_key: self.diffie_hellman_key.clone().into(),
            one_time_keys: self.one_time_keys.clone().into(),
            fallback_keys: self.fallback_keys.clone(),
        }
    }

    /// Restore an [`Account`] from a previously saved [`AccountPickle`].
    pub fn from_pickle(pickle: AccountPickle) -> Self {
        pickle.into()
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::new()
    }
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`Account::pickle`].
#[derive(Serialize, Deserialize)]
pub struct AccountPickle {
    signing_key: Ed25519KeypairPickle,
    diffie_hellman_key: Curve25519KeypairPickle,
    one_time_keys: OneTimeKeysPickle,
    fallback_keys: FallbackKeys,
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`Account::pickle`].
impl AccountPickle {
    /// Serialize and encrypt the pickle using the given key.
    ///
    /// This is the inverse of [`AccountPickle::from_encrypted`].
    pub fn encrypt(self, pickle_key: &[u8; 32]) -> String {
        pickle(&self, pickle_key)
    }

    /// Obtain a pickle from a ciphertext by decrypting and deserializing using
    /// the given key.
    ///
    /// This is the inverse of [`AccountPickle::encrypt`].
    pub fn from_encrypted(ciphertext: &str, pickle_key: &[u8; 32]) -> Result<Self, PickleError> {
        unpickle(ciphertext, pickle_key)
    }
}

impl From<AccountPickle> for Account {
    fn from(pickle: AccountPickle) -> Self {
        Self {
            signing_key: pickle.signing_key.into(),
            diffie_hellman_key: pickle.diffie_hellman_key.into(),
            one_time_keys: pickle.one_time_keys.into(),
            fallback_keys: pickle.fallback_keys,
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::{Context, Result, bail};

    use super::{Account, InboundCreationResult, SessionConfig, SessionCreationError};
    use crate::{
        cipher::Mac,
        olm::{
            AccountPickle,
            account::PUBLIC_MAX_ONE_TIME_KEYS,
            messages::{OlmMessage, PreKeyMessage},
        },
    };

    const PICKLE_KEY: [u8; 32] = [0u8; 32];

    #[test]
    fn max_number_of_one_time_keys_matches_global_constant() {
        assert_eq!(Account::new().max_number_of_one_time_keys(), PUBLIC_MAX_ONE_TIME_KEYS);
    }

    #[test]
    #[cfg(feature = "low-level-api")]
    fn generate_and_remove_one_time_key() {
        let mut alice = Account::new();
        assert_eq!(alice.stored_one_time_key_count(), 0);

        alice.generate_one_time_keys(1);
        assert_eq!(alice.stored_one_time_key_count(), 1);

        let public_key = alice
            .one_time_keys()
            .values()
            .next()
            .copied()
            .expect("Should have an unpublished one-time key");
        let secret_key_bytes = alice
            .find_one_time_key(&public_key)
            .expect("Should find secret key for public one-time key")
            .to_bytes();
        let removed_key_bytes = alice
            .remove_one_time_key(public_key)
            .expect("Should be able to remove one-time key")
            .to_bytes();

        assert_eq!(removed_key_bytes, secret_key_bytes);
        assert_eq!(alice.stored_one_time_key_count(), 0);
    }

    #[test]
    fn generate_and_forget_fallback_keys() {
        let mut alice = Account::default();
        assert!(!alice.forget_fallback_key());
        alice.generate_fallback_key();
        assert!(!alice.forget_fallback_key());
        alice.generate_fallback_key();
        assert!(alice.forget_fallback_key());
    }

    fn vodozemac_vodozemac_communication(session_config: SessionConfig) -> Result<()> {
        // Both of these are vodozemac accounts.
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);

        let mut alice_session = alice.create_outbound_session(
            session_config,
            bob.curve25519_key(),
            *bob.one_time_keys()
                .iter()
                .next()
                .context("Failed getting bob's OTK, which should never happen here.")?
                .1,
        )?;

        assert!(!bob.one_time_keys().is_empty());
        bob.mark_keys_as_published();
        assert!(bob.one_time_keys().is_empty());

        let message = "It's a secret to everybody";
        let olm_message = alice_session.encrypt(message).unwrap();

        if let OlmMessage::PreKey(m) = olm_message {
            assert_eq!(m.session_keys(), alice_session.session_keys());
            assert_eq!(m.session_id(), alice_session.session_id());

            let InboundCreationResult { session: mut bob_session, plaintext } =
                bob.create_inbound_session(session_config, alice.curve25519_key(), &m)?;
            assert_eq!(alice_session.session_id(), bob_session.session_id());
            assert_eq!(m.session_keys(), bob_session.session_keys());

            assert_eq!(message.as_bytes(), plaintext);

            let second_text = "Here's another secret to everybody";
            let olm_message = alice_session.encrypt(second_text).unwrap();

            let plaintext = bob_session.decrypt(&olm_message)?;
            assert_eq!(second_text.as_bytes(), plaintext);

            let reply_plain = "Yes, take this, it's dangerous out there";
            let reply = bob_session.encrypt(reply_plain).unwrap();
            let plaintext = alice_session.decrypt(&reply)?;

            assert_eq!(plaintext, reply_plain.as_bytes());

            let another_reply = "Last one";
            let reply = bob_session.encrypt(another_reply).unwrap();
            let plaintext = alice_session.decrypt(&reply)?;
            assert_eq!(plaintext, another_reply.as_bytes());

            let last_text = "Nope, I'll have the last word";
            let olm_message = alice_session.encrypt(last_text).unwrap();

            let plaintext = bob_session.decrypt(&olm_message)?;
            assert_eq!(last_text.as_bytes(), plaintext);
        }

        Ok(())
    }

    #[test]
    fn vodozemac_vodozemac_communication_session_config_v1() -> Result<()> {
        vodozemac_vodozemac_communication(SessionConfig::version_1())
    }

    #[test]
    #[cfg(feature = "experimental-session-config")]
    fn vodozemac_vodozemac_communication_session_config_v2() -> Result<()> {
        vodozemac_vodozemac_communication(SessionConfig::version_2())
    }

    #[test]
    fn account_pickling_roundtrip_is_identity() -> Result<()> {
        let mut account = Account::new();

        account.generate_one_time_keys(50);

        // Generate two fallback keys so the previous fallback key field gets populated.
        account.generate_fallback_key();
        account.generate_fallback_key();

        let pickle = account.pickle().encrypt(&PICKLE_KEY);

        let decrypted_pickle = AccountPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let unpickled_account = Account::from_pickle(decrypted_pickle);
        let repickle = unpickled_account.pickle();

        assert_eq!(account.identity_keys(), unpickled_account.identity_keys());

        let decrypted_pickle = AccountPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let pickle = serde_json::to_value(decrypted_pickle)?;
        let repickle = serde_json::to_value(repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    fn invalid_session_creation_does_not_remove_otk() -> Result<()> {
        let mut alice = Account::new();
        let malory = Account::new();
        alice.generate_one_time_keys(1);

        let mut session = malory.create_outbound_session(
            SessionConfig::default(),
            alice.curve25519_key(),
            *alice.one_time_keys().values().next().expect("Should have one-time key"),
        )?;

        let message = session.encrypt("Test").unwrap();

        if let OlmMessage::PreKey(m) = message {
            let mut message = m.to_bytes();
            let message_len = message.len();

            // We mangle the MAC so decryption fails but creating a Session
            // succeeds.
            message[message_len - Mac::TRUNCATED_LEN..message_len]
                .copy_from_slice(&[0u8; Mac::TRUNCATED_LEN]);

            let message = PreKeyMessage::try_from(message)?;

            match alice.create_inbound_session(
                SessionConfig::version_1(),
                malory.curve25519_key(),
                &message,
            ) {
                Err(SessionCreationError::Decryption(_)) => {}
                e => bail!("Expected a decryption error, got {:?}", e),
            }
            assert!(
                !alice.one_time_keys.private_keys.is_empty(),
                "The one-time key was removed when it shouldn't"
            );

            Ok(())
        } else {
            bail!("Invalid message type");
        }
    }

    #[test]
    #[cfg(feature = "experimental-session-config")]
    fn create_session_with_incorrect_session_config_upgrade() {
        // Both of these are vodozemac accounts.
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);
        let one_time_key =
            *bob.one_time_keys().values().next().expect("Bob should have generated a one-time key");

        let mut alice_session = alice
            .create_outbound_session(SessionConfig::version_1(), bob.curve25519_key(), one_time_key)
            .expect("We should be able to create an outbound session with bob.");

        let message = "It's a secret to everybody";
        let pre_key_message =
            alice_session.encrypt(message).expect("We should be able to encrypt the first message");

        let OlmMessage::PreKey(pre_key_message) = pre_key_message else {
            panic!("Expected a pre-key message");
        };

        let result = bob.create_inbound_session(
            SessionConfig::version_2(),
            alice.curve25519_key(),
            &pre_key_message,
        );

        assert!(
            matches!(result, Err(SessionCreationError::MismatchedSessionConfig { .. })),
            "We should not create a session if the incorrect session config was used"
        );
    }

    #[test]
    #[cfg(feature = "experimental-session-config")]
    fn create_session_with_incorrect_session_config_downgrade() {
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);
        let one_time_key =
            *bob.one_time_keys().values().next().expect("Bob should have generated a one-time key");

        let mut alice_session = alice
            .create_outbound_session(SessionConfig::version_2(), bob.curve25519_key(), one_time_key)
            .expect("We should be able to create an outbound session with bob.");

        let message = "It's a secret to everybody";
        let pre_key_message =
            alice_session.encrypt(message).expect("We should be able to encrypt the first message");

        let OlmMessage::PreKey(pre_key_message) = pre_key_message else {
            panic!("Expected a pre-key message");
        };

        let result = bob.create_inbound_session(
            SessionConfig::version_1(),
            alice.curve25519_key(),
            &pre_key_message,
        );

        assert!(
            matches!(result, Err(SessionCreationError::MismatchedSessionConfig { .. })),
            "We should not create a session if the incorrect session config was used"
        );
    }

    #[test]
    fn create_session_with_unsupported_session_config() {
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);
        let one_time_key =
            *bob.one_time_keys().values().next().expect("Bob should have generated a one-time key");

        let mut alice_session = alice
            .create_outbound_session(SessionConfig::version_1(), bob.curve25519_key(), one_time_key)
            .expect("We should be able to create an outbound session with bob.");

        let message = "It's a secret to everybody";
        let pre_key_message =
            alice_session.encrypt(message).expect("We should be able to encrypt the first message");

        let OlmMessage::PreKey(mut pre_key_message) = pre_key_message else {
            panic!("Expected a pre-key message");
        };

        // Technically this can't happen as the pre-key message parsing will reject such
        // a version, but let's double check if our session creation is robust against
        // unknown versions.
        pre_key_message.message.version = 0xFF;

        let result = bob.create_inbound_session(
            SessionConfig::version_1(),
            alice.curve25519_key(),
            &pre_key_message,
        );

        assert!(
            matches!(result, Err(SessionCreationError::MismatchedSessionConfig { got: None, .. })),
            "We should not create a session if an unknown session config was used for the pre-key message"
        );
    }
}

