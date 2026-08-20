// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP44 (v2)
//!
//! <https://github.com/nostr-protocol/nips/blob/master/44.md>

use alloc::vec::Vec;
use core::fmt;
use core::ops::{Deref, Range};

use bitcoin_hashes::hmac::{Hmac, HmacEngine};
use bitcoin_hashes::sha256::{self, Hash as Sha256Hash};
use bitcoin_hashes::{Hash, HashEngine};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind};
use crate::key::{PublicKey, SecretKey};
use crate::util::{self, hkdf};

const VERSION_SIZE: usize = 1;
const NONCE_SIZE: usize = 32;
const LEGACY_LENGTH_PREFIX_SIZE: usize = 2;
const EXTENDED_LENGTH_PREFIX_SIZE: usize = 6;
const EXTENDED_PREFIX_THRESHOLD: u64 = 65_536;
const MAX_PLAINTEXT_SIZE: u64 = u32::MAX as u64;
const MIN_CIPHERTEXT_SIZE: usize = LEGACY_LENGTH_PREFIX_SIZE + 32;
const HMAC_SIZE: usize = 32;
const MIN_PAYLOAD_SIZE: usize = VERSION_SIZE + NONCE_SIZE + MIN_CIPHERTEXT_SIZE + HMAC_SIZE;
const MAX_CIPHERTEXT_SIZE: u64 =
    EXTENDED_LENGTH_PREFIX_SIZE as u64 + calc_padding(MAX_PLAINTEXT_SIZE);
pub(super) const MAX_PAYLOAD_SIZE: u64 =
    VERSION_SIZE as u64 + NONCE_SIZE as u64 + MAX_CIPHERTEXT_SIZE + HMAC_SIZE as u64;
pub(super) const MAX_ENCODED_PAYLOAD_SIZE: u64 = MAX_PAYLOAD_SIZE.div_ceil(3) * 4;

const MESSAGE_KEYS_SIZE: usize = 76;
const MESSAGES_KEYS_ENCRYPTION_SIZE: usize = 32;
const MESSAGES_KEYS_NONCE_SIZE: usize = 12;
const MESSAGES_KEYS_ENCRYPTION_RANGE: Range<usize> = 0..MESSAGES_KEYS_ENCRYPTION_SIZE;
const MESSAGES_KEYS_NONCE_RANGE: Range<usize> =
    MESSAGES_KEYS_ENCRYPTION_SIZE..MESSAGES_KEYS_ENCRYPTION_SIZE + MESSAGES_KEYS_NONCE_SIZE;
const MESSAGES_KEYS_AUTH_RANGE: Range<usize> =
    MESSAGES_KEYS_ENCRYPTION_SIZE + MESSAGES_KEYS_NONCE_SIZE..MESSAGE_KEYS_SIZE;

#[derive(Debug)]
enum ErrorV2 {
    PayloadTooShort,
    NotFound(&'static str),
    MessageEmpty,
    MessageTooLong,
    PlatformSizeUnsupported,
    AllocationFailed,
    InvalidHmac,
    InvalidPadding,
}

impl From<ErrorV2> for Error {
    fn from(e: ErrorV2) -> Self {
        match e {
            ErrorV2::PayloadTooShort => {
                Error::with_static_message(ErrorKind::Invalid, "payload size is too short")
            }
            ErrorV2::NotFound(value) => Error::with_static_message(ErrorKind::Missing, value),
            ErrorV2::MessageEmpty => {
                Error::with_static_message(ErrorKind::Invalid, "message empty")
            }
            ErrorV2::MessageTooLong => {
                Error::with_static_message(ErrorKind::Invalid, "message too long")
            }
            ErrorV2::PlatformSizeUnsupported => Error::with_static_message(
                ErrorKind::Unsupported,
                "NIP-44 payload size is not supported on this platform",
            ),
            ErrorV2::AllocationFailed => Error::with_static_message(
                ErrorKind::Other,
                "failed to allocate NIP-44 payload buffer",
            ),
            ErrorV2::InvalidHmac => Error::with_static_message(ErrorKind::Crypto, "invalid HMAC"),
            ErrorV2::InvalidPadding => {
                Error::with_static_message(ErrorKind::Invalid, "invalid padding")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PayloadLayout {
    prefix_len: u64,
    ciphertext_len: u64,
    payload_len: u64,
}

impl PayloadLayout {
    fn new(plaintext_len: u64) -> Result<Self, ErrorV2> {
        if plaintext_len == 0 {
            return Err(ErrorV2::MessageEmpty);
        }

        if plaintext_len > MAX_PLAINTEXT_SIZE {
            return Err(ErrorV2::MessageTooLong);
        }

        let prefix_len: u64 = if plaintext_len < EXTENDED_PREFIX_THRESHOLD {
            LEGACY_LENGTH_PREFIX_SIZE as u64
        } else {
            EXTENDED_LENGTH_PREFIX_SIZE as u64
        };
        let padded_len: u64 = calc_padding(plaintext_len);
        let ciphertext_len: u64 = prefix_len
            .checked_add(padded_len)
            .ok_or(ErrorV2::MessageTooLong)?;
        let payload_len: u64 = (VERSION_SIZE as u64)
            .checked_add(NONCE_SIZE as u64)
            .and_then(|len| len.checked_add(ciphertext_len))
            .and_then(|len| len.checked_add(HMAC_SIZE as u64))
            .ok_or(ErrorV2::MessageTooLong)?;

        Ok(Self {
            prefix_len,
            ciphertext_len,
            payload_len,
        })
    }
}

struct MessageKeys([u8; MESSAGE_KEYS_SIZE]);

impl MessageKeys {
    #[inline]
    pub fn encryption(&self) -> &[u8] {
        &self.0[MESSAGES_KEYS_ENCRYPTION_RANGE]
    }

    #[inline]
    pub fn nonce(&self) -> &[u8] {
        &self.0[MESSAGES_KEYS_NONCE_RANGE]
    }

    #[inline]
    pub fn auth(&self) -> &[u8] {
        &self.0[MESSAGES_KEYS_AUTH_RANGE]
    }
}

/// NIP44 v2 Conversation Key
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConversationKey(Hmac<Sha256Hash>);

impl fmt::Debug for ConversationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Conversation key: <sensitive>")
    }
}

impl Deref for ConversationKey {
    type Target = Hmac<Sha256Hash>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConversationKey {
    /// Construct conversation key from 32-byte array
    #[inline]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Hmac::from_byte_array(bytes))
    }

    /// Derive Conversation Key
    #[inline]
    pub fn derive(secret_key: &SecretKey, public_key: &PublicKey) -> Result<Self, Error> {
        let shared_key: Zeroizing<[u8; 32]> = util::generate_shared_key(secret_key, public_key)?;
        Ok(Self(hkdf::extract(b"nip44-v2", shared_key.as_slice())))
    }

    /// Compose Conversation Key from bytes
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| {
            Error::with_static_message(
                ErrorKind::Malformed,
                "conversation key must be 32 bytes long",
            )
        })?;
        Ok(Self(Hmac::from_byte_array(bytes)))
    }

    /// Get Conversation Key as bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.deref().as_byte_array()
    }
}

/// Encrypt with NIP44 (v2) using custom nonce
///
/// The nonce must be **UNIQUE** for each message.
///
/// **The result is NOT encoded in base64!**
pub fn encrypt_to_bytes_with_nonce(
    conversation_key: &ConversationKey,
    plaintext: &[u8],
    nonce: [u8; 32],
) -> Result<Vec<u8>, Error> {
    let len: usize = plaintext.len();
    let layout: PayloadLayout = PayloadLayout::new(len as u64)?;
    let payload_len: usize = supported_allocation_size(layout.payload_len)?;
    let ciphertext_len: usize = supported_allocation_size(layout.ciphertext_len)?;

    // Get Message Keys
    let keys: MessageKeys = get_message_keys(conversation_key, &nonce);

    // Build the payload in place, as [version | nonce | length | plaintext |
    // padding | MAC], then encrypt the ciphertext region where it already sits.
    // Padding and MAC are zero-filled by `resize` and overwritten below.
    let mac_start: usize = VERSION_SIZE + NONCE_SIZE + ciphertext_len;
    let mut payload: Vec<u8> = Vec::new();
    payload
        .try_reserve_exact(payload_len)
        .map_err(|_| ErrorV2::AllocationFailed)?;
    payload.push(2); // Version
    payload.extend_from_slice(&nonce);
    if layout.prefix_len == LEGACY_LENGTH_PREFIX_SIZE as u64 {
        payload.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        payload.extend_from_slice(&[0, 0]);
        payload.extend_from_slice(&(len as u32).to_be_bytes());
    }
    payload.extend_from_slice(plaintext);
    payload.resize(payload_len, 0);

    // Compose cipher and encrypt in place
    let ciphertext: &mut [u8] = &mut payload[VERSION_SIZE + NONCE_SIZE..mac_start];
    let mut cipher = ChaCha20::new(keys.encryption().into(), keys.nonce().into());
    cipher.apply_keystream(ciphertext);

    // HMAC-SHA256 over nonce | ciphertext, both already contiguous in `payload`
    let mut engine: HmacEngine<sha256::HashEngine> = HmacEngine::new(keys.auth());
    engine.input(&payload[VERSION_SIZE..mac_start]);
    let hmac: [u8; 32] = engine.finalize().to_byte_array();
    payload[mac_start..].copy_from_slice(&hmac);

    Ok(payload)
}

/// Decrypt with NIP44 (v2)
///
/// **The payload MUST be already decoded from base64**
///
/// NIP-44 permits payloads containing up to [`u32::MAX`] plaintext bytes.
/// Callers on resource-constrained systems should reject oversized payloads
/// before invoking this function.
pub fn decrypt_to_bytes(
    conversation_key: &ConversationKey,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let len: usize = payload.len();

    if len < MIN_PAYLOAD_SIZE {
        return Err(ErrorV2::PayloadTooShort.into());
    }
    // Reject before HMAC and ciphertext allocation using the largest payload we can emit.
    validate_payload_size(len as u64)?;

    // Extract nonce, buffer and hmac from payload
    let nonce: &[u8] = payload
        .get(VERSION_SIZE..VERSION_SIZE + NONCE_SIZE)
        .ok_or(ErrorV2::NotFound("nonce"))?;
    let buffer: &[u8] = payload
        .get(VERSION_SIZE + NONCE_SIZE..len - HMAC_SIZE)
        .ok_or(ErrorV2::NotFound("buffer"))?;
    let mac: &[u8] = payload
        .get(len - HMAC_SIZE..)
        .ok_or(ErrorV2::NotFound("hmac"))?;

    // Compose Message Keys
    let keys: MessageKeys = get_message_keys(conversation_key, nonce);

    // Check HMAC-SHA256
    let mut engine: HmacEngine<sha256::HashEngine> = HmacEngine::new(keys.auth());
    engine.input(nonce);
    engine.input(buffer);
    let calculated_mac: [u8; HMAC_SIZE] = engine.finalize().to_byte_array();
    if mac != calculated_mac.as_slice() {
        return Err(ErrorV2::InvalidHmac.into());
    }

    // Compose cipher
    let mut cipher = ChaCha20::new(keys.encryption().into(), keys.nonce().into());
    let mut decrypted: Vec<u8> = Vec::new();
    decrypted
        .try_reserve_exact(buffer.len())
        .map_err(|_| ErrorV2::AllocationFailed)?;
    decrypted.extend_from_slice(buffer);
    cipher.apply_keystream(&mut decrypted);

    let (prefix_len, unpadded_len) = parse_plaintext_length(&decrypted)?;
    let plaintext_end: usize = prefix_len
        .checked_add(unpadded_len)
        .ok_or(ErrorV2::InvalidPadding)?;

    let unpadded: &[u8] = decrypted
        .get(prefix_len..plaintext_end)
        .ok_or(ErrorV2::InvalidPadding)?;

    if unpadded.is_empty() {
        return Err(ErrorV2::MessageEmpty.into());
    }

    if unpadded.len() != unpadded_len {
        return Err(ErrorV2::InvalidPadding.into());
    }

    let expected_len: u64 = (prefix_len as u64)
        .checked_add(calc_padding(unpadded_len as u64))
        .ok_or(ErrorV2::InvalidPadding)?;
    if decrypted.len() as u64 != expected_len {
        return Err(ErrorV2::InvalidPadding.into());
    }

    decrypted.copy_within(prefix_len..plaintext_end, 0);
    decrypted.truncate(unpadded_len);
    Ok(decrypted)
}

#[inline]
fn validate_payload_size(len: u64) -> Result<(), ErrorV2> {
    if len > MAX_PAYLOAD_SIZE {
        return Err(ErrorV2::MessageTooLong);
    }

    Ok(())
}

fn parse_plaintext_length(buffer: &[u8]) -> Result<(usize, usize), ErrorV2> {
    let first_two: [u8; 2] = buffer
        .get(..LEGACY_LENGTH_PREFIX_SIZE)
        .ok_or(ErrorV2::InvalidPadding)?
        .try_into()
        .map_err(|_| ErrorV2::InvalidPadding)?;
    let legacy_len: u16 = u16::from_be_bytes(first_two);

    if legacy_len != 0 {
        return Ok((LEGACY_LENGTH_PREFIX_SIZE, legacy_len as usize));
    }

    let extended_bytes: [u8; 4] = buffer
        .get(LEGACY_LENGTH_PREFIX_SIZE..EXTENDED_LENGTH_PREFIX_SIZE)
        .ok_or(ErrorV2::InvalidPadding)?
        .try_into()
        .map_err(|_| ErrorV2::InvalidPadding)?;
    let extended_len: u32 = u32::from_be_bytes(extended_bytes);
    if (extended_len as u64) < EXTENDED_PREFIX_THRESHOLD {
        return Err(ErrorV2::InvalidPadding);
    }

    let plaintext_len: usize =
        usize::try_from(extended_len).map_err(|_| ErrorV2::PlatformSizeUnsupported)?;
    Ok((EXTENDED_LENGTH_PREFIX_SIZE, plaintext_len))
}

#[inline]
fn supported_allocation_size(len: u64) -> Result<usize, ErrorV2> {
    if len > isize::MAX as u64 {
        return Err(ErrorV2::PlatformSizeUnsupported);
    }

    usize::try_from(len).map_err(|_| ErrorV2::PlatformSizeUnsupported)
}

#[inline]
fn get_message_keys(conversation_key: &ConversationKey, nonce: &[u8]) -> MessageKeys {
    let mut keys: [u8; MESSAGE_KEYS_SIZE] = [0u8; MESSAGE_KEYS_SIZE];
    hkdf::expand_into(conversation_key.as_bytes(), nonce, &mut keys);
    MessageKeys(keys)
}

#[inline]
const fn calc_padding(len: u64) -> u64 {
    if len <= 32 {
        return 32;
    }
    let nextpower: u64 = 1 << (log2_round_down(len - 1) + 1);
    let chunk: u64 = if nextpower <= 256 { 32 } else { nextpower / 8 };
    chunk * (((len - 1) / chunk) + 1)
}

/// Returns the base 2 logarithm of the number, rounded down.
#[inline]
const fn log2_round_down(x: u64) -> u32 {
    if x == 0 {
        0
    } else {
        // This is equivalent to floor(log2(x))
        (u64::BITS - 1) - x.leading_zeros()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    #![allow(dead_code)]

    use alloc::vec;
    use core::str::FromStr;

    use base64::engine::{Engine, general_purpose};

    use super::*;
    use crate::key::Keys;

    /// Straightforward reference padding, kept as an oracle for the in-place
    /// payload construction in `encrypt_to_bytes_with_nonce`.
    fn pad(unpadded: &[u8]) -> Result<Vec<u8>, ErrorV2> {
        let len: usize = unpadded.len();
        let layout: PayloadLayout = PayloadLayout::new(len as u64)?;
        let padded_len: usize = usize::try_from(calc_padding(len as u64)).unwrap();
        let take: usize = padded_len - len;
        let prefix_len: usize = usize::try_from(layout.prefix_len).unwrap();
        let mut padded: Vec<u8> = Vec::with_capacity(prefix_len + padded_len);
        if len < EXTENDED_PREFIX_THRESHOLD as usize {
            padded.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            padded.extend_from_slice(&[0, 0]);
            padded.extend_from_slice(&(len as u32).to_be_bytes());
        }
        padded.extend_from_slice(unpadded);
        padded.extend(core::iter::repeat_n(0, take));
        Ok(padded)
    }
    use crate::nips::nip44;

    const JSON_VECTORS: &str = include_str!("nip44.vectors.json");

    fn val(c: u8, idx: usize) -> u8 {
        match c {
            b'A'..=b'F' => c - b'A' + 10,
            b'a'..=b'f' => c - b'a' + 10,
            b'0'..=b'9' => c - b'0',
            _ => panic!("Invalid character {} at position {}", c as char, idx),
        }
    }

    pub fn hex_decode<T>(hex: T) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        let hex = hex.as_ref();
        let len = hex.len();

        if len % 2 != 0 {
            panic!("Odd number of digits");
        }

        let mut bytes: Vec<u8> = Vec::with_capacity(len / 2);

        for i in (0..len).step_by(2) {
            let high = val(hex[i], i);
            let low = val(hex[i + 1], i + 1);
            bytes.push((high << 4) | low);
        }

        bytes
    }

    // Check if out manual implementation work in the same way as the std one.
    #[test]
    fn test_log2_round_down() {
        let f = |x: u64| -> u32 {
            let x: f64 = x as f64;
            x.log2().floor() as u32
        };

        assert_eq!(log2_round_down(0), f(0));
        assert_eq!(log2_round_down(1), f(1));
        assert_eq!(log2_round_down(2), f(2));
        assert_eq!(log2_round_down(3), f(3));
        assert_eq!(log2_round_down(4), f(4));
        assert_eq!(log2_round_down(5), f(5));
        assert_eq!(log2_round_down(6), f(6));
        assert_eq!(log2_round_down(7), f(7));
        assert_eq!(log2_round_down(8), f(8));
        assert_eq!(log2_round_down(9), f(9));
        assert_eq!(log2_round_down(10), f(10));
    }

    #[test]
    fn test_valid_get_conversation_key() {
        let json: serde_json::Value = serde_json::from_str(JSON_VECTORS).unwrap();

        for vectorobj in json
            .as_object()
            .unwrap()
            .get("v2")
            .unwrap()
            .as_object()
            .unwrap()
            .get("valid")
            .unwrap()
            .as_object()
            .unwrap()
            .get("get_conversation_key")
            .unwrap()
            .as_array()
            .unwrap()
        {
            let vector = vectorobj.as_object().unwrap();

            let sec1 = {
                let sec1hex = vector.get("sec1").unwrap().as_str().unwrap();
                SecretKey::from_str(sec1hex).unwrap()
            };
            let pub2 = {
                let pub2hex = vector.get("pub2").unwrap().as_str().unwrap();
                PublicKey::from_str(pub2hex).unwrap()
            };
            let conversation_key: [u8; 32] = {
                let ckeyhex = vector.get("conversation_key").unwrap().as_str().unwrap();
                hex_decode(ckeyhex).try_into().unwrap()
            };
            let note = vector.get("note").unwrap().as_str().unwrap();

            let computed_conversation_key = ConversationKey::derive(&sec1, &pub2).unwrap();

            assert_eq!(
                conversation_key,
                computed_conversation_key.to_byte_array(),
                "Conversation key failure on {}",
                note
            );
        }
    }

    #[test]
    fn test_valid_calc_padded_len() {
        let json: serde_json::Value = serde_json::from_str(JSON_VECTORS).unwrap();

        for elem in json
            .as_object()
            .unwrap()
            .get("v2")
            .unwrap()
            .as_object()
            .unwrap()
            .get("valid")
            .unwrap()
            .as_object()
            .unwrap()
            .get("calc_padded_len")
            .unwrap()
            .as_array()
            .unwrap()
        {
            let len = elem[0].as_number().unwrap().as_u64().unwrap();
            let pad = elem[1].as_number().unwrap().as_u64().unwrap();
            assert_eq!(calc_padding(len), pad);
        }
    }

    #[test]
    fn test_valid_encrypt_decrypt() {
        let json: serde_json::Value = serde_json::from_str(JSON_VECTORS).unwrap();

        for (i, vectorobj) in json
            .as_object()
            .unwrap()
            .get("v2")
            .unwrap()
            .as_object()
            .unwrap()
            .get("valid")
            .unwrap()
            .as_object()
            .unwrap()
            .get("encrypt_decrypt")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let vector = vectorobj.as_object().unwrap();

            let sec1 = {
                let sec1hex = vector.get("sec1").unwrap().as_str().unwrap();
                SecretKey::from_str(sec1hex).unwrap()
            };
            let pub2 = {
                let sec2hex = vector.get("sec2").unwrap().as_str().unwrap();
                let secret_key = SecretKey::from_str(sec2hex).unwrap();
                Keys::new(secret_key).public_key()
            };
            let conversation_key: ConversationKey = {
                let ckeyhex = vector.get("conversation_key").unwrap().as_str().unwrap();
                ConversationKey::from_slice(&hex_decode(ckeyhex)).unwrap()
            };
            let nonce: [u8; 32] = {
                let noncehex = vector.get("nonce").unwrap().as_str().unwrap();
                hex_decode(noncehex).try_into().unwrap()
            };
            let plaintext = vector.get("plaintext").unwrap().as_str().unwrap();
            let ciphertext = vector.get("ciphertext").unwrap().as_str().unwrap();

            // Test conversation key
            let computed_conversation_key = ConversationKey::derive(&sec1, &pub2).unwrap();
            assert_eq!(
                computed_conversation_key, conversation_key,
                "Conversation key failure on ValidSec #{}",
                i
            );

            // Test encryption with an overridden nonce
            let computed_ciphertext =
                encrypt_to_bytes_with_nonce(&conversation_key, plaintext.as_bytes(), nonce)
                    .unwrap();
            let computed_ciphertext = general_purpose::STANDARD.encode(computed_ciphertext);
            assert_eq!(
                computed_ciphertext, ciphertext,
                "Encryption does not match on ValidSec #{}",
                i
            );

            // Test decryption
            let computed_plaintext = nip44::decrypt(&sec1, &pub2, ciphertext).unwrap();
            assert_eq!(
                computed_plaintext, plaintext,
                "Decryption does not match on ValidSec #{}",
                i
            );
        }
    }

    #[test]
    fn test_invalid_get_conversation_key() {
        let json: serde_json::Value = serde_json::from_str(JSON_VECTORS).unwrap();

        for vectorobj in json
            .as_object()
            .unwrap()
            .get("v2")
            .unwrap()
            .as_object()
            .unwrap()
            .get("invalid")
            .unwrap()
            .as_object()
            .unwrap()
            .get("get_conversation_key")
            .unwrap()
            .as_array()
            .unwrap()
        {
            let vector = vectorobj.as_object().unwrap();

            let sec1result = {
                let sec1hex = vector.get("sec1").unwrap().as_str().unwrap();
                SecretKey::from_str(sec1hex)
            };
            let pub2result = {
                let pub2hex = vector.get("pub2").unwrap().as_str().unwrap();
                PublicKey::from_str(pub2hex).unwrap().xonly()
            };
            let note = vector.get("note").unwrap().as_str().unwrap();

            assert!(
                sec1result.is_err() || pub2result.is_err(),
                "One of the keys should have failed: {}",
                note
            );
        }
    }

    #[test]
    fn test_invalid_decrypt() {
        let json: serde_json::Value = serde_json::from_str(JSON_VECTORS).unwrap();

        let known_error_kinds = [
            ErrorKind::Crypto,
            ErrorKind::Crypto,
            ErrorKind::Invalid,
            ErrorKind::Invalid,
            ErrorKind::Invalid,
            ErrorKind::Invalid,
        ];

        for (i, vectorobj) in json
            .as_object()
            .unwrap()
            .get("v2")
            .unwrap()
            .as_object()
            .unwrap()
            .get("invalid")
            .unwrap()
            .as_object()
            .unwrap()
            .get("decrypt")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let vector = vectorobj.as_object().unwrap();
            let conversation_key: ConversationKey = {
                let ckeyhex = vector.get("conversation_key").unwrap().as_str().unwrap();
                ConversationKey::from_slice(&hex_decode(ckeyhex)).unwrap()
            };
            let ciphertext = vector.get("ciphertext").unwrap().as_str().unwrap();
            let note = vector.get("note").unwrap().as_str().unwrap();

            let payload: Vec<u8> = general_purpose::STANDARD.decode(ciphertext).unwrap();
            let result = decrypt_to_bytes(&conversation_key, &payload);
            assert!(result.is_err(), "Should not have decrypted: {}", note);

            let err = result.unwrap_err();
            assert_eq!(
                err.kind(),
                known_error_kinds[i],
                "Unexpected error in invalid decrypt #{}",
                i
            );
        }
    }

    fn make_authenticated_short_v2_payload(
        conversation_key: &ConversationKey,
        ciphertext_len: usize,
    ) -> Vec<u8> {
        assert!(
            ciphertext_len <= 1,
            "this helper is intended for the 65/66-byte regression cases"
        );

        let nonce: [u8; 32] = [0x42; 32];

        let keys: MessageKeys = get_message_keys(conversation_key, &nonce);

        // Zero or one encrypted byte. ChaCha20 preserves the buffer length,
        // therefore the decrypted buffer will also contain zero or one byte.
        let ciphertext: Vec<u8> = vec![0u8; ciphertext_len];

        // Produce a valid MAC, as a legitimate conversation participant can do.
        let mut engine: HmacEngine<sha256::HashEngine> = HmacEngine::new(keys.auth());
        engine.input(&nonce);
        engine.input(&ciphertext);
        let mac: [u8; 32] = engine.finalize().to_byte_array();

        let mut payload: Vec<u8> = Vec::with_capacity(65 + ciphertext_len);
        payload.push(2); // NIP-44 v2
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&mac);

        payload
    }

    fn make_authenticated_v2_payload(
        conversation_key: &ConversationKey,
        mut padded_plaintext: Vec<u8>,
    ) -> Vec<u8> {
        let nonce: [u8; 32] = [0x42; 32];
        let keys: MessageKeys = get_message_keys(conversation_key, &nonce);
        let mut cipher = ChaCha20::new(keys.encryption().into(), keys.nonce().into());
        cipher.apply_keystream(&mut padded_plaintext);

        let mut engine: HmacEngine<sha256::HashEngine> = HmacEngine::new(keys.auth());
        engine.input(&nonce);
        engine.input(&padded_plaintext);
        let mac: [u8; 32] = engine.finalize().to_byte_array();

        let mut payload: Vec<u8> = Vec::with_capacity(65 + padded_plaintext.len());
        payload.push(2);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&padded_plaintext);
        payload.extend_from_slice(&mac);
        payload
    }

    #[test]
    fn test_short_authenticated_payloads_return_error_instead_of_panicking() {
        // Alice is the sender; Bob is the recipient.
        let alice_sk =
            SecretKey::from_str("5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a")
                .unwrap();
        let alice_keys = Keys::new(alice_sk);
        let alice_pk = alice_keys.public_key();

        let bob_sk =
            SecretKey::from_str("4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d")
                .unwrap();
        let bob_keys = Keys::new(bob_sk);

        let conversation_key = ConversationKey::derive(bob_keys.secret_key(), &alice_pk).unwrap();

        for ciphertext_len in [0, 1] {
            let payload = make_authenticated_short_v2_payload(&conversation_key, ciphertext_len);

            // 1 version + 32 nonce + N ciphertext + 32 MAC.
            assert_eq!(payload.len(), 65 + ciphertext_len);

            let encoded = general_purpose::STANDARD.encode(&payload);

            let err = nip44::decrypt_to_bytes(bob_keys.secret_key(), &alice_pk, encoded.as_bytes())
                .unwrap_err();

            assert_eq!(err.kind(), ErrorKind::Invalid);
            assert_eq!(err.to_string(), "payload size is too short");
        }
    }

    #[test]
    fn test_oversized_binary_payload_is_rejected() {
        assert!(matches!(
            validate_payload_size(MAX_PAYLOAD_SIZE + 1),
            Err(ErrorV2::MessageTooLong)
        ));
    }

    #[test]
    fn test_maximum_payload_arithmetic() {
        let layout = PayloadLayout::new(MAX_PLAINTEXT_SIZE).unwrap();
        assert_eq!(calc_padding(MAX_PLAINTEXT_SIZE), 4_294_967_296);
        assert_eq!(layout.prefix_len, 6);
        assert_eq!(layout.ciphertext_len, 4_294_967_302);
        assert_eq!(layout.payload_len, 4_294_967_367);
        assert_eq!(MAX_PAYLOAD_SIZE, 4_294_967_367);
        assert_eq!(MAX_ENCODED_PAYLOAD_SIZE, 5_726_623_156);

        assert!(matches!(
            PayloadLayout::new(MAX_PLAINTEXT_SIZE + 1),
            Err(ErrorV2::MessageTooLong)
        ));

        let err: Error = supported_allocation_size(u64::MAX).unwrap_err().into();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "NIP-44 payload size is not supported on this platform"
        );

        let err: Error = ErrorV2::AllocationFailed.into();
        assert_eq!(err.kind(), ErrorKind::Other);
        assert_eq!(err.to_string(), "failed to allocate NIP-44 payload buffer");

        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            supported_allocation_size(MAX_PAYLOAD_SIZE).unwrap(),
            MAX_PAYLOAD_SIZE as usize
        );
        #[cfg(target_pointer_width = "32")]
        assert!(matches!(
            supported_allocation_size(MAX_PAYLOAD_SIZE),
            Err(ErrorV2::PlatformSizeUnsupported)
        ));
    }

    #[test]
    fn test_encrypt_rejects_invalid_plaintext_len() {
        let conversation_key = ConversationKey::new([0x42; 32]);
        let nonce: [u8; 32] = [0x11; 32];

        let err = encrypt_to_bytes_with_nonce(&conversation_key, b"", nonce).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "message empty");

        assert!(matches!(
            PayloadLayout::new(MAX_PLAINTEXT_SIZE + 1),
            Err(ErrorV2::MessageTooLong)
        ));
    }

    /// Composing the payload in place must be byte-identical to the
    /// pad-encrypt-append form it replaced.
    #[test]
    fn test_encrypt_matches_reference_construction() {
        let conversation_key = ConversationKey::new([0x42; 32]);
        let nonce: [u8; 32] = [0x11; 32];

        for len in [
            1usize, 2, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1000, 4096, 4097, 65_535,
            65_536, 65_537, 100_000,
        ] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

            let keys: MessageKeys = get_message_keys(&conversation_key, &nonce);
            let mut buffer: Vec<u8> = pad(&plaintext).unwrap();
            let mut cipher = ChaCha20::new(keys.encryption().into(), keys.nonce().into());
            cipher.apply_keystream(&mut buffer);

            let mut engine: HmacEngine<sha256::HashEngine> = HmacEngine::new(keys.auth());
            engine.input(&nonce);
            engine.input(&buffer);
            let mac: [u8; 32] = engine.finalize().to_byte_array();

            let mut expected: Vec<u8> = vec![2];
            expected.extend_from_slice(&nonce);
            expected.extend_from_slice(&buffer);
            expected.extend_from_slice(&mac);

            let payload: Vec<u8> =
                encrypt_to_bytes_with_nonce(&conversation_key, &plaintext, nonce).unwrap();
            assert_eq!(payload, expected, "payload mismatch at plaintext len {len}");
        }
    }

    #[test]
    fn test_extended_length_prefix_vectors() {
        let conversation_key = ConversationKey::from_slice(&hex_decode(
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
        ))
        .unwrap();
        let nonce: [u8; 32] =
            hex_decode("0000000000000000000000000000000000000000000000000000000000000001")
                .try_into()
                .unwrap();

        for (len, plaintext_hash, payload_hash) in [
            (
                65_535usize,
                "6e1bebca6a8229364a162a72ef064826c4cd7457bf54f190ef782bd9deff3e42",
                "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84",
            ),
            (
                65_536,
                "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a",
                "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616",
            ),
            (
                65_537,
                "008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430",
                "eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435",
            ),
        ] {
            let plaintext: Vec<u8> = vec![b'a'; len];
            assert_eq!(Sha256Hash::hash(&plaintext).to_string(), plaintext_hash);

            let payload =
                encrypt_to_bytes_with_nonce(&conversation_key, &plaintext, nonce).unwrap();
            let encoded = general_purpose::STANDARD.encode(&payload);
            assert_eq!(
                Sha256Hash::hash(encoded.as_bytes()).to_string(),
                payload_hash
            );
            assert_eq!(
                decrypt_to_bytes(&conversation_key, &payload).unwrap(),
                plaintext
            );

            let padded = pad(&plaintext).unwrap();
            if len < EXTENDED_PREFIX_THRESHOLD as usize {
                assert_eq!(&padded[..2], &(len as u16).to_be_bytes());
            } else {
                assert_eq!(&padded[..2], &[0, 0]);
                assert_eq!(&padded[2..6], &(len as u32).to_be_bytes());
            }
        }
    }

    #[test]
    fn test_invalid_extended_length_prefixes() {
        assert!(matches!(
            parse_plaintext_length(&[0, 0]),
            Err(ErrorV2::InvalidPadding)
        ));

        let conversation_key = ConversationKey::new([0x42; 32]);

        let mut noncanonical = vec![0u8; MIN_CIPHERTEXT_SIZE];
        noncanonical[2..6].copy_from_slice(&1u32.to_be_bytes());
        let payload = make_authenticated_v2_payload(&conversation_key, noncanonical);
        let err = decrypt_to_bytes(&conversation_key, &payload).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "invalid padding");

        let mut mismatched = vec![0u8; MIN_CIPHERTEXT_SIZE];
        mismatched[2..6].copy_from_slice(&65_536u32.to_be_bytes());
        let payload = make_authenticated_v2_payload(&conversation_key, mismatched);
        let err = decrypt_to_bytes(&conversation_key, &payload).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "invalid padding");
    }

    #[test]
    fn test_conversation_key_from_slice() {
        let bytes: [u8; 32] = [0x42; 32];
        let conversation_key = ConversationKey::from_slice(&bytes).unwrap();
        assert_eq!(conversation_key.as_bytes(), &bytes[..]);

        for len in [0, 31, 33, 64] {
            let err = ConversationKey::from_slice(&vec![0x42; len]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Malformed);
            assert_eq!(err.to_string(), "conversation key must be 32 bytes long");
        }
    }
}
