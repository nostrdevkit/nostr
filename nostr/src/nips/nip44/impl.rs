// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;

use base64::engine::{Engine, general_purpose};
#[cfg(feature = "rand")]
use rand::Rng;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rand_core::UnwrapErr;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rngs::SysRng;

use super::v2::{self, ConversationKey};
use crate::error::{Error, ErrorKind};
use crate::key::{PublicKey, SecretKey};
#[cfg(feature = "rand")]
use crate::util;

/// Payload version
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Version {
    /// V2 - Secp256k1 ECDH, HKDF, padding, ChaCha20, HMAC-SHA256 and base64
    #[default]
    V2 = 0x02,
}

impl Version {
    /// Get [`Version`] as `u8`
    #[inline]
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    fn max_encoded_payload_size(self) -> u64 {
        match self {
            Self::V2 => v2::MAX_ENCODED_PAYLOAD_SIZE,
        }
    }

    fn validate_encoded_payload_size(self, len: u64) -> Result<(), Error> {
        if len > self.max_encoded_payload_size() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "message too long",
            ));
        }

        Ok(())
    }
}

fn unsupported_platform_size() -> Error {
    Error::with_static_message(
        ErrorKind::Unsupported,
        "NIP-44 payload size is not supported on this platform",
    )
}

fn allocation_failed() -> Error {
    Error::with_static_message(ErrorKind::Other, "failed to allocate NIP-44 payload buffer")
}

fn supported_allocation_size(len: usize) -> Result<usize, Error> {
    if len > isize::MAX as usize {
        return Err(unsupported_platform_size());
    }

    Ok(len)
}

fn decode_payload_version(payload: &[u8]) -> Result<Version, Error> {
    // Decode one Base64 quantum so the version-specific limit runs before full allocation.
    let encoded_prefix = payload.get(..4).unwrap_or(payload);
    let decoded_prefix = general_purpose::STANDARD
        .decode(encoded_prefix)
        .map_err(Error::malformed_display)?;
    let version = decoded_prefix
        .first()
        .copied()
        .ok_or_else(|| Error::with_static_message(ErrorKind::Missing, "version not found"))?;

    Version::try_from(version)
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(version: u8) -> Result<Self, Self::Error> {
        match version {
            0x02 => Ok(Self::V2),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                format!("unknown version: {version}"),
            )),
        }
    }
}

/// NIP-44 nonce
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nonce {
    /// V2 - 32-byte nonce
    V2([u8; 32]),
}

/// Encrypt
#[inline]
#[cfg(all(feature = "std", feature = "os-rng"))]
pub fn encrypt<T>(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    content: T,
    version: Version,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    encrypt_with_rng(
        secret_key,
        public_key,
        content,
        version,
        &mut UnwrapErr(SysRng),
    )
}

/// Encrypt
#[cfg(feature = "rand")]
pub fn encrypt_with_rng<R, T>(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    content: T,
    version: Version,
    rng: &mut R,
) -> Result<String, Error>
where
    R: Rng,
    T: AsRef<[u8]>,
{
    let nonce: Nonce = match version {
        Version::V2 => {
            let nonce: [u8; 32] = util::random_32_bytes(rng);
            Nonce::V2(nonce)
        }
    };

    encrypt_with_nonce(secret_key, public_key, content, nonce)
}

/// Encrypt
pub fn encrypt_with_nonce<T>(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    content: T,
    nonce: Nonce,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let payload: Vec<u8> = encrypt_to_bytes_with_nonce(secret_key, public_key, content, nonce)?;
    let encoded_len: usize = base64::encoded_len(payload.len(), true)
        .ok_or_else(unsupported_platform_size)
        .and_then(supported_allocation_size)?;

    let mut encoded: String = String::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| allocation_failed())?;
    general_purpose::STANDARD.encode_string(payload, &mut encoded);
    Ok(encoded)
}

/// Encrypt to bytes (**not base64 encoded!**)
pub fn encrypt_to_bytes_with_nonce<T>(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    content: T,
    nonce: Nonce,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    match nonce {
        Nonce::V2(nonce) => {
            let conversation_key: ConversationKey =
                ConversationKey::derive(secret_key, public_key)?;
            let payload: Vec<u8> =
                v2::encrypt_to_bytes_with_nonce(&conversation_key, content.as_ref(), nonce)?;
            Ok(payload)
        }
    }
}

/// Decrypt
///
/// NIP-44 permits payloads containing up to [`u32::MAX`] plaintext bytes.
/// Decrypting payloads near that limit requires several gigabytes of contiguous
/// memory. Applications should enforce a smaller encoded-payload limit when
/// processing untrusted events on resource-constrained systems.
#[inline]
pub fn decrypt<T>(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    payload: T,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let bytes: Vec<u8> = decrypt_to_bytes(secret_key, public_key, payload)?;
    String::from_utf8(bytes).map_err(Error::malformed)
}

/// Decrypt **without** converting bytes to UTF-8 string
///
/// NIP-44 permits payloads containing up to [`u32::MAX`] plaintext bytes.
/// Decrypting payloads near that limit requires several gigabytes of contiguous
/// memory. Applications should enforce a smaller encoded-payload limit when
/// processing untrusted events on resource-constrained systems.
pub fn decrypt_to_bytes<T>(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    payload: T,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    let payload = payload.as_ref();
    let version = decode_payload_version(payload)?;
    version.validate_encoded_payload_size(payload.len() as u64)?;

    // Decode base64 payload
    let decoded_len: usize =
        supported_allocation_size(base64::decoded_len_estimate(payload.len()))?;
    let mut decoded: Vec<u8> = Vec::new();
    decoded
        .try_reserve_exact(decoded_len)
        .map_err(|_| allocation_failed())?;
    general_purpose::STANDARD
        .decode_vec(payload, &mut decoded)
        .map_err(Error::malformed_display)?;

    match version {
        Version::V2 => {
            let conversation_key: ConversationKey =
                ConversationKey::derive(secret_key, public_key)?;
            v2::decrypt_to_bytes(&conversation_key, &decoded)
        }
    }
}

#[cfg(test)]
#[cfg(all(feature = "std", feature = "os-rng"))]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::key::Keys;

    #[test]
    fn test_nip44_encryption_decryption() {
        // Alice keys
        let alice_sk =
            SecretKey::from_str("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a")
                .unwrap();
        let alice_keys = Keys::new(alice_sk);
        let alice_pk = alice_keys.public_key();

        // Bob keys
        let bob_sk =
            SecretKey::from_str("4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d")
                .unwrap();
        let bob_keys = Keys::new(bob_sk);
        let bob_pk = bob_keys.public_key();

        let content = String::from("hello");
        let encrypted_content =
            encrypt(alice_keys.secret_key(), &bob_pk, &content, Version::V2).unwrap();
        assert_eq!(
            decrypt(bob_keys.secret_key(), &alice_pk, encrypted_content).unwrap(),
            content
        );
    }

    #[test]
    fn test_oversized_base64_payload_is_rejected_before_decoding() {
        let err = Version::V2
            .validate_encoded_payload_size(v2::MAX_ENCODED_PAYLOAD_SIZE + 1)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "message too long");
    }

    #[test]
    fn test_allocation_errors() {
        let err = supported_allocation_size(usize::MAX).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "NIP-44 payload size is not supported on this platform"
        );

        let err = allocation_failed();
        assert_eq!(err.kind(), ErrorKind::Other);
        assert_eq!(err.to_string(), "failed to allocate NIP-44 payload buffer");
    }
}
