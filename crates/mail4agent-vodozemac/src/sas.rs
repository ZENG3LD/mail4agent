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

//! User-friendly key verification using short authentication strings (SAS).
//!
//! The verification process is heavily inspired by Phil Zimmermann’s [ZRTP]
//! key agreement handshake. A core part of key agreement in [ZRTP] is the
//! *hash commitment*: the party that begins the key sharing process sends
//! a *hash* of their part of the Diffie-Hellman exchange but does not send the
//! part itself exchange until they had received the other party’s part.
//!
//! The verification process can be used to verify the Ed25519 identity key of
//! an [`Account`].
//!
//! # Examples
//!
//! ```rust
//! use mail4agent_vodozemac::sas::Sas;
//! # use anyhow::Result;
//! # fn main() -> Result<()> {
//! let alice = Sas::new();
//! let bob = Sas::new();
//!
//! let bob_public_key = bob.public_key();
//!
//! let bob = bob.diffie_hellman(alice.public_key())?;
//! let alice = alice.diffie_hellman(bob_public_key)?;
//!
//! let alice_bytes = alice.bytes("AGREED_INFO");
//! let bob_bytes = bob.bytes("AGREED_INFO");
//!
//! let alice_emojis = alice_bytes.emoji_indices();
//! let bob_emojis = bob_bytes.emoji_indices();
//!
//! assert_eq!(alice_emojis, bob_emojis);
//! # Ok(())
//! # }
//! ```
//!
//! [`Account`]: crate::olm::Account
//! [ZRTP]: https://tools.ietf.org/html/rfc6189#section-4.4.1

use hkdf::Hkdf;
use hmac::{Hmac, Mac as _, digest::MacError};
use rand::thread_rng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, SharedSecret};

use crate::{
    Curve25519PublicKey, KeyError,
    utilities::{base64_decode, base64_encode},
};

type HmacSha256Key = Box<[u8; 32]>;

/// The output type for the SAS MAC calculation.
pub struct Mac(Vec<u8>);

impl Mac {
    /// Convert the MAC to a base64 encoded string.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.0)
    }

    /// Get the byte slice of the MAC.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a new `Mac` object from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Create a new `Mac` object from a base64 encoded string.
    pub fn from_base64(mac: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64_decode(mac)?;

        Ok(Self(bytes))
    }
}

/// Error type for the case when we try to generate too many SAS bytes.
#[derive(Debug, Clone, Error)]
#[error("The given count of bytes was too large")]
pub struct InvalidCount;

/// Error type describing failures that can happen during the key verification.
#[derive(Debug, Error)]
pub enum SasError {
    /// The MAC failed to be validated.
    #[error("The SAS MAC validation didn't succeed: {0}")]
    Mac(#[from] MacError),
}

/// A struct representing a short auth string verification object.
///
/// This object can be used to establish a shared secret to perform the short
/// auth string based key verification.
pub struct Sas {
    secret_key: EphemeralSecret,
    public_key: Curve25519PublicKey,
}

/// A struct representing a short auth string verification object where the
/// shared secret has been established.
///
/// This object can be used to generate the short auth string and calculate and
/// verify a MAC that protects information about the keys being verified.
pub struct EstablishedSas {
    shared_secret: SharedSecret,
    our_public_key: Curve25519PublicKey,
    their_public_key: Curve25519PublicKey,
}

impl std::fmt::Debug for EstablishedSas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedSas")
            .field("our_public_key", &self.our_public_key.to_base64())
            .field("their_public_key", &self.their_public_key.to_base64())
            .finish_non_exhaustive()
    }
}

/// Bytes generated from an shared secret that can be used as the short auth
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasBytes {
    bytes: [u8; 6],
}

impl SasBytes {
    /// Get the index of 7 emojis that can be presented to users to perform the
    /// key verification
    ///
    /// The table that maps the index to an emoji can be found in the [spec].
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#sas-method-emoji
    pub fn emoji_indices(&self) -> [u8; 7] {
        Self::bytes_to_emoji_index(&self.bytes)
    }

    /// Get the three decimal numbers that can be presented to users to perform
    /// the key verification, as described in the [spec]
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#sas-method-emoji
    pub fn decimals(&self) -> (u16, u16, u16) {
        Self::bytes_to_decimal(&self.bytes)
    }

    /// Get the raw bytes of the short auth string that can be converted to an
    /// emoji, or decimal representation.
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.bytes
    }

    /// Split the first 42 bits of our 6 bytes into 7 groups of 6 bits. The 7
    /// groups of 6 bits represent an emoji index from the [spec].
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#sas-method-emoji
    fn bytes_to_emoji_index(bytes: &[u8; 6]) -> [u8; 7] {
        let bytes: Vec<u64> = bytes.iter().map(|b| *b as u64).collect();
        // Join the 6 bytes into one 64 bit unsigned int. This u64 will contain 48
        // bits from our 6 bytes.
        let mut num: u64 = bytes[0] << 40;
        num += bytes[1] << 32;
        num += bytes[2] << 24;
        num += bytes[3] << 16;
        num += bytes[4] << 8;
        num += bytes[5];

        // Take the top 42 bits of our 48 bits from the u64 and convert each 6 bits
        // into a 6 bit number.
        [
            ((num >> 42) & 63) as u8,
            ((num >> 36) & 63) as u8,
            ((num >> 30) & 63) as u8,
            ((num >> 24) & 63) as u8,
            ((num >> 18) & 63) as u8,
            ((num >> 12) & 63) as u8,
            ((num >> 6) & 63) as u8,
        ]
    }

    /// Convert the given bytes into three decimals. The 6th byte is ignored,
    /// it's used for the emoji index conversion.
    fn bytes_to_decimal(bytes: &[u8; 6]) -> (u16, u16, u16) {
        let bytes: Vec<u16> = bytes.iter().map(|b| *b as u16).collect();

        // This bitwise operation is taken from the [spec]
        // [spec]: https://matrix.org/docs/spec/client_server/latest#sas-method-decimal
        let first = (bytes[0] << 5) | (bytes[1] >> 3);
        let second = ((bytes[1] & 0x7) << 10) | (bytes[2] << 2) | (bytes[3] >> 6);
        let third = ((bytes[3] & 0x3F) << 7) | (bytes[4] >> 1);

        (first + 1000, second + 1000, third + 1000)
    }
}

impl Default for Sas {
    fn default() -> Self {
        Self::new()
    }
}

impl Sas {
    /// Create a new random verification object
    ///
    /// This creates an ephemeral curve25519 keypair that can be used to
    /// establish a shared secret.
    pub fn new() -> Self {
        let rng = thread_rng();

        let secret_key = EphemeralSecret::random_from_rng(rng);
        let public_key = Curve25519PublicKey::from(&secret_key);

        Self { secret_key, public_key }
    }

    /// Get the public key that can be used to establish a shared secret.
    pub const fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }

    /// Establishes a SAS secret by performing a DH handshake with another
    /// public key.
    ///
    /// Returns an [`EstablishedSas`] object which can be used to generate
    /// [`SasBytes`] if the given public key was valid, otherwise `None`.
    pub fn diffie_hellman(
        self,
        their_public_key: Curve25519PublicKey,
    ) -> Result<EstablishedSas, KeyError> {
        let shared_secret = self.secret_key.diffie_hellman(&their_public_key.inner);

        if shared_secret.was_contributory() {
            Ok(EstablishedSas { shared_secret, our_public_key: self.public_key, their_public_key })
        } else {
            Err(KeyError::NonContributoryKey)
        }
    }

    /// Establishes a SAS secret by performing a DH handshake with another
    /// public key in "raw", base64-encoded form.
    ///
    /// Returns an [`EstablishedSas`] object which can be used to generate
    /// [`SasBytes`] if the received public key is valid, otherwise `None`.
    pub fn diffie_hellman_with_raw(
        self,
        other_public_key: &str,
    ) -> Result<EstablishedSas, KeyError> {
        let other_public_key = Curve25519PublicKey::from_base64(other_public_key)?;
        self.diffie_hellman(other_public_key)
    }
}

impl EstablishedSas {
    /// Generate [`SasBytes`] using HKDF with the shared secret as the input key
    /// material.
    ///
    /// The info string should be agreed upon beforehand, both parties need to
    /// use the same info string.
    pub fn bytes(&self, info: &str) -> SasBytes {
        let mut bytes = [0u8; 6];
        #[allow(clippy::expect_used)]
        let byte_vec =
            self.bytes_raw(info, 6).expect("HKDF should always be able to generate 6 bytes");

        bytes.copy_from_slice(&byte_vec);

        SasBytes { bytes }
    }

    /// Generate the given number of bytes using HKDF with the shared secret
    /// as the input key material.
    ///
    /// The info string should be agreed upon beforehand, both parties need to
    /// use the same info string.
    ///
    /// The number of bytes we can generate is limited, we can generate up to
    /// 32 * 255 bytes. The function will not fail if the given count is smaller
    /// than the limit.
    pub fn bytes_raw(&self, info: &str, count: usize) -> Result<Vec<u8>, InvalidCount> {
        let mut output = vec![0u8; count];
        let hkdf = self.get_hkdf();

        hkdf.expand(info.as_bytes(), &mut output[0..count]).map_err(|_| InvalidCount)?;

        Ok(output)
    }

    /// Calculate a MAC for the given input using the info string as additional
    /// data.
    ///
    ///
    /// This should be used to calculate a MAC of the ed25519 identity key of an
    /// [`Account`]
    ///
    /// The MAC is returned as a base64 encoded string.
    ///
    /// [`Account`]: crate::olm::Account
    pub fn calculate_mac(&self, input: &str, info: &str) -> Mac {
        let mut mac = self.get_mac(info);

        mac.update(input.as_ref());

        Mac(mac.finalize().into_bytes().to_vec())
    }

    /// Verify a MAC that was previously created using the
    /// [`EstablishedSas::calculate_mac()`] method.
    ///
    /// Users should calculate a MAC and send it to the other side, they should
    /// then verify each other's MAC using this method.
    pub fn verify_mac(&self, input: &str, info: &str, tag: &Mac) -> Result<(), SasError> {
        let mut mac = self.get_mac(info);
        mac.update(input.as_bytes());

        Ok(mac.verify_slice(&tag.0)?)
    }

    /// Get the public key that was created by us, that was used to establish
    /// the shared secret.
    pub const fn our_public_key(&self) -> Curve25519PublicKey {
        self.our_public_key
    }

    /// Get the public key that was created by the other party, that was used to
    /// establish the shared secret.
    pub const fn their_public_key(&self) -> Curve25519PublicKey {
        self.their_public_key
    }

    fn get_hkdf(&self) -> Hkdf<Sha256> {
        Hkdf::new(None, self.shared_secret.as_bytes())
    }

    fn get_mac_key(&self, info: &str) -> HmacSha256Key {
        let mut mac_key = Box::new([0u8; 32]);
        let hkdf = self.get_hkdf();

        #[allow(clippy::expect_used)]
        hkdf.expand(info.as_bytes(), mac_key.as_mut_slice())
            .expect("We should be able to expand the shared SAS secret into a MAC key");

        mac_key
    }

    fn get_mac(&self, info: &str) -> Hmac<Sha256> {
        let mac_key = self.get_mac_key(info);

        #[allow(clippy::expect_used)]
        Hmac::<Sha256>::new_from_slice(mac_key.as_slice())
            .expect("We should be able to create a HMAC object from a 32-byte slice")
    }
}

#[cfg(test)]
mod test {
    use super::{Mac, Sas, SasBytes};
    use crate::Curve25519PublicKey;

    const ALICE_MXID: &str = "@alice:example.com";
    const ALICE_DEVICE_ID: &str = "AAAAAAAAAA";
    const BOB_MXID: &str = "@bob:example.com";
    const BOB_DEVICE_ID: &str = "BBBBBBBBBB";

    #[test]
    fn as_bytes_is_identity() {
        let bytes = [0u8, 1, 2, 3, 4, 5];
        assert_eq!(SasBytes { bytes }.as_bytes(), &bytes);
    }

    #[test]
    fn mac_from_slice_as_bytes_is_identity() {
        let bytes = "ABCDEFGH".as_bytes();
        assert_eq!(
            Mac::from_slice(bytes).as_bytes(),
            bytes,
            "as_bytes() after from_slice() is not identity"
        );
    }

    #[test]
    fn snapshot_debug() {
        let key = Curve25519PublicKey::from_bytes([0; 32]);

        let alice = Sas::default();
        let bob = Sas::default();

        let mut established = alice
            .diffie_hellman(bob.public_key())
            .expect("We should be able to establish a SAS session");

        established.our_public_key = key;
        established.their_public_key = key;

        assert_eq!(
            format!("{established:#?}"),
            "EstablishedSas {\n    our_public_key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\n    their_public_key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\n    ..\n}"
        );
    }

    #[test]
    fn vodozemac_and_vodozemac_generate_same_bytes() {
        let alice = Sas::default();
        let bob = Sas::default();

        let alice_public_key_encoded = alice.public_key().to_base64();
        let alice_public_key = alice.public_key().to_owned();
        let bob_public_key_encoded = bob.public_key().to_base64();
        let bob_public_key = bob.public_key();

        let alice_established = alice
            .diffie_hellman_with_raw(&bob_public_key_encoded)
            .expect("Couldn't establish SAS secret for Alice");
        let bob_established = bob
            .diffie_hellman_with_raw(&alice_public_key_encoded)
            .expect("Couldn't establish SAS secret for Bob");

        assert_eq!(alice_established.our_public_key(), alice_public_key);
        assert_eq!(alice_established.their_public_key(), bob_public_key);
        assert_eq!(bob_established.our_public_key(), bob_public_key);
        assert_eq!(bob_established.their_public_key(), alice_public_key);

        let alice_bytes = alice_established.bytes("TEST");
        let bob_bytes = bob_established.bytes("TEST");

        assert_eq!(alice_bytes, bob_bytes, "The two sides calculated different bytes.");
        assert_eq!(
            alice_bytes.emoji_indices(),
            bob_bytes.emoji_indices(),
            "The two sides calculated different emoji indices."
        );
        assert_eq!(
            alice_bytes.decimals(),
            bob_bytes.decimals(),
            "The two sides calculated different decimals."
        );
        assert_eq!(alice_bytes.as_bytes(), bob_bytes.as_bytes());
    }

    #[test]
    fn calculate_mac_vodozemac_vodozemac() {
        let alice = Sas::new();
        let bob = Sas::new();

        let alice_public_key = alice.public_key().to_base64();
        let bob_public_key = bob.public_key().to_base64();

        let message = format!("ed25519:{BOB_DEVICE_ID}");
        let extra_info = format!(
            "MATRIX_KEY_VERIFICATION_MAC\
             {BOB_MXID}{BOB_DEVICE_ID}\
             {ALICE_MXID}{ALICE_DEVICE_ID}\
             $1234567890\
             KEY_IDS",
        );

        let alice_established = alice
            .diffie_hellman_with_raw(&bob_public_key)
            .expect("Couldn't establish SAS secret for Alice");
        let bob_established = bob
            .diffie_hellman_with_raw(&alice_public_key)
            .expect("Couldn't establish SAS secret for Bob");

        let alice_mac = alice_established.calculate_mac(&message, &extra_info);
        let bob_mac = bob_established.calculate_mac(&message, &extra_info);

        assert_eq!(
            alice_mac.to_base64(),
            bob_mac.to_base64(),
            "Two vodozemac devices calculated different SAS MACs."
        );

        alice_established
            .verify_mac(&message, &extra_info, &bob_mac)
            .expect("Alice couldn't verify Bob's MAC");
        bob_established
            .verify_mac(&message, &extra_info, &alice_mac)
            .expect("Bob couldn't verify Alice's MAC");

        let invalid_mac = Mac::from_slice(&[
            0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 0, 1,
        ]);
        alice_established
            .verify_mac(&message, &extra_info, &invalid_mac)
            .expect_err("Alice verified an invalid MAC");
        bob_established
            .verify_mac(&message, &extra_info, &invalid_mac)
            .expect_err("Bob verified an invalid MAC");
    }

    #[test]
    fn emoji_generation() {
        let bytes: [u8; 6] = [0, 0, 0, 0, 0, 0];
        let index: [u8; 7] = [0, 0, 0, 0, 0, 0, 0];
        assert_eq!(SasBytes::bytes_to_emoji_index(&bytes), index.as_ref());
        assert_eq!(SasBytes { bytes }.emoji_indices(), index.as_ref());

        let bytes: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let index: [u8; 7] = [63, 63, 63, 63, 63, 63, 63];
        assert_eq!(SasBytes::bytes_to_emoji_index(&bytes), index.as_ref());
        assert_eq!(SasBytes { bytes }.emoji_indices(), index.as_ref());
    }

    #[test]
    fn decimal_generation() {
        let bytes: [u8; 6] = [0, 0, 0, 0, 0, 0];
        let decimal: (u16, u16, u16) = (1000, 1000, 1000);
        assert_eq!(SasBytes::bytes_to_decimal(&bytes), decimal);
        assert_eq!(SasBytes { bytes }.decimals(), decimal);

        let bytes: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let decimal: (u16, u16, u16) = (9191, 9191, 9191);
        assert_eq!(SasBytes::bytes_to_decimal(&bytes), decimal);
        assert_eq!(SasBytes { bytes }.decimals(), decimal);
    }

    #[test]
    fn emoji_indices_are_in_range() {
        use rand::{RngCore, SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(0);

        for _ in 0..500 {
            let mut bytes = [0u8; 6];
            rng.fill_bytes(&mut bytes);

            let numbers = SasBytes::bytes_to_emoji_index(&bytes);

            for number in numbers.iter() {
                assert!(*number < 64);
            }
        }
    }

    #[test]
    fn decimal_values_are_in_range() {
        use rand::{RngCore, SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(1);

        for _ in 0..500 {
            let mut bytes = [0u8; 6];
            rng.fill_bytes(&mut bytes);

            let (first, second, third) = SasBytes::bytes_to_decimal(&bytes);

            assert!((1000..=9191).contains(&first));
            assert!((1000..=9191).contains(&second));
            assert!((1000..=9191).contains(&third));
        }
    }
}
