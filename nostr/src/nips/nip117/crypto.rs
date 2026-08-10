// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use base64::Engine;
use base64::engine::general_purpose;
use bitcoin_hashes::Hash;
use rand::{CryptoRng, Rng};
use secp256k1::Secp256k1;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use super::Header;
use crate::error::{Error, ErrorKind};
use crate::event::{Event, EventId, Kind, Tags, UnsignedEvent};
use crate::key::{Keys, PublicKey, SecretKey};
use crate::nips::nip44::v2::ConversationKey;
use crate::types::Timestamp;
use crate::util::hkdf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rumor {
    id: EventId,
    pubkey: PublicKey,
    created_at: Timestamp,
    kind: Kind,
    tags: Tags,
    content: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct SecretBytes(pub(super) [u8; 32]);

impl SecretBytes {
    #[inline]
    pub(super) fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = Zeroizing::new(faster_hex::hex_string(&self.0));
        serializer.serialize_str(&value)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Zeroizing::new(String::deserialize(deserializer)?);
        let bytes = crate::util::hex_decode::<32>(&value).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

pub(super) struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[inline]
pub(super) fn invalid(message: &'static str) -> Error {
    Error::with_static_message(ErrorKind::Invalid, message)
}

pub(in crate::nips) fn validate_encoded_payload_size(payload: &[u8]) -> Result<(), Error> {
    if payload.len() > crate::nips::nip44::v2::MAX_ENCODED_PAYLOAD_SIZE {
        return Err(invalid("NIP-44 payload is too large"));
    }
    Ok(())
}

pub(super) fn validate_rumor(rumor: &UnsignedEvent) -> Result<(), Error> {
    let id = rumor
        .id
        .ok_or_else(|| invalid("double-ratchet rumor is missing its ID"))?;
    if rumor.compute_id() != id {
        return Err(invalid("invalid double-ratchet rumor ID"));
    }
    Ok(())
}

/// Parse the exact unsigned-event wire shape used for encrypted rumors.
///
/// `UnsignedEvent` is intentionally permissive when used as a general API type. Ratchet rumors
/// must be strict so signed-event fields such as `sig`, or any other extension not represented by
/// the returned type, cannot be silently discarded before the rumor ID is validated.
pub(in crate::nips) fn parse_rumor(payload: &[u8]) -> Result<UnsignedEvent, Error> {
    let rumor: Rumor = serde_json::from_slice(payload)?;
    let rumor = UnsignedEvent {
        id: Some(rumor.id),
        pubkey: rumor.pubkey,
        created_at: rumor.created_at,
        kind: rumor.kind,
        tags: rumor.tags,
        content: rumor.content,
    };
    validate_rumor(&rumor)?;
    Ok(rumor)
}

pub(super) fn validate_outer_event(event: &Event) -> Result<(), Error> {
    if event.kind != Kind::DoubleRatchetMessage {
        return Err(invalid("invalid double-ratchet event kind"));
    }
    let secp = Secp256k1::verification_only();
    event.verify_with_ctx(&secp)
}

pub(super) fn encrypted_header(event: &Event) -> Result<&str, Error> {
    let mut headers = event.tags.iter().filter(|tag| tag.kind() == "header");
    let header = headers
        .next()
        .ok_or_else(|| invalid("missing double-ratchet header"))?;
    if headers.next().is_some() {
        return Err(invalid("multiple double-ratchet headers"));
    }
    if header.len() != 2 {
        return Err(invalid("malformed double-ratchet header tag"));
    }
    header
        .content()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("empty double-ratchet header"))
}

pub(super) fn derive_conversation_key(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<SecretBytes, Error> {
    let key = ConversationKey::derive(secret_key, public_key)?;
    let bytes: [u8; 32] = key
        .as_bytes()
        .try_into()
        .map_err(|_| invalid("invalid conversation key length"))?;
    Ok(SecretBytes(bytes))
}

pub(super) fn kdf(input1: &[u8], input2: &[u8]) -> (SecretBytes, SecretBytes) {
    // NIP-117 defines input2 as the HKDF salt and input1 as the input key material. Each output
    // is an independent one-block expansion with info [1] or [2], not a split 64-byte expansion.
    let prk = hkdf::extract(input2, input1);
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    hkdf::expand_into(prk.as_byte_array(), &[1], &mut first);
    hkdf::expand_into(prk.as_byte_array(), &[2], &mut second);
    (SecretBytes(first), SecretBytes(second))
}

pub(super) fn decrypt_header_with_key(
    key: &[u8; 32],
    encrypted_header: &str,
) -> Result<Header, Error> {
    let plaintext = decrypt_conversation_key(key, encrypted_header)?;
    Ok(serde_json::from_str(&plaintext)?)
}

/// Generate a valid secp256k1 secret key with caller-supplied randomness.
pub(in crate::nips) fn random_secret_key_with_rng<R>(rng: &mut R) -> SecretKey
where
    R: Rng + CryptoRng,
{
    SecretKey::generate_with_rng(rng)
}

/// Sign an unsigned event with caller-supplied randomness.
pub(in crate::nips) fn sign_event_with_rng<R>(
    unsigned: UnsignedEvent,
    secret_key: &SecretKey,
    rng: &mut R,
) -> Result<Event, Error>
where
    R: Rng + CryptoRng,
{
    unsigned.verify_id()?;
    let secp = Secp256k1::new();
    let keys = Keys::new_with_ctx(&secp, secret_key.clone());
    if unsigned.pubkey != keys.public_key() {
        return Err(invalid("event author does not match signing key"));
    }
    let id = unsigned.compute_id();
    let signature = keys.sign_schnorr_with_rng(&secp, id.as_bytes(), rng);
    unsigned.add_signature_with_ctx(&secp, signature)
}

/// NIP-44 encrypt with an already-derived raw conversation key.
pub(in crate::nips) fn encrypt_conversation_key_with_rng<R, T>(
    conversation_key: &[u8; 32],
    plaintext: T,
    rng: &mut R,
) -> Result<String, Error>
where
    R: Rng + CryptoRng,
    T: AsRef<[u8]>,
{
    let mut nonce: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let key = ConversationKey::new(*conversation_key);
    let payload =
        crate::nips::nip44::v2::encrypt_to_bytes_with_nonce(&key, plaintext.as_ref(), nonce)?;
    Ok(general_purpose::STANDARD.encode(payload))
}

/// NIP-44 decrypt UTF-8 text with an already-derived raw conversation key.
pub(in crate::nips) fn decrypt_conversation_key<T>(
    conversation_key: &[u8; 32],
    payload: T,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let plaintext = decrypt_conversation_key_bytes(conversation_key, payload)?;
    String::from_utf8(plaintext).map_err(Error::malformed)
}

pub(super) fn decrypt_conversation_key_bytes<T>(
    conversation_key: &[u8; 32],
    payload: T,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    let payload = payload.as_ref();
    validate_encoded_payload_size(payload)?;
    let decoded = general_purpose::STANDARD
        .decode(payload)
        .map_err(Error::malformed_display)?;
    let key = ConversationKey::new(*conversation_key);
    crate::nips::nip44::v2::decrypt_to_bytes(&key, &decoded)
}
