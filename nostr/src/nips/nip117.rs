// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-117: Double Ratchet
//!
//! <https://github.com/nostr-protocol/nips/pull/1813>
//!
//! If a user's main Nostr private key is compromised, an attacker can decrypt stored NIP-17
//! messages received in the past and messages received in the future. An established NIP-117
//! session instead uses independent keys that rotate after every message, so compromising the main
//! key alone does not reveal the session's past or future traffic.
//!
//! A [`Session`] encrypts arbitrary [`UnsignedEvent`] rumors into signed kind `1060` events and
//! decrypts them while advancing its ratchet state. Persist the newest session after every
//! successful operation; after sending, store it together with the returned event and republish
//! that same event on retry. Use [`Session::remote_public_keys`] and [`Session::matches_sender`] to
//! route fetched events. NIP-118 provides an optional invite handshake; callers can instead create
//! matching sessions after exchanging the ephemeral public keys and shared secret through another
//! authenticated channel.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use base64::Engine;
use base64::engine::general_purpose;
use bitcoin_hashes::Hash;
use rand::{CryptoRng, Rng};
use secp256k1::Secp256k1;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use super::nip44::v2::ConversationKey;
use crate::error::{Error, ErrorKind};
use crate::event::{Event, Kind, Tag, UnsignedEvent};
use crate::key::{Keys, PublicKey, SecretKey};
use crate::types::Timestamp;
use crate::util::{hkdf, impl_json_methods};

/// The largest permitted gap in a receiving chain.
pub const MAX_SKIP: usize = 1_000;

/// An encrypted Double Ratchet message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Header {
    /// The zero-based message number in the current sending chain.
    pub number: u32,
    /// The number of messages in the sender's previous sending chain.
    pub previous_chain_length: u32,
    /// The public key the sender will use after its next DH ratchet step.
    pub next_public_key: PublicKey,
}

/// A persistable NIP-117 Double Ratchet session.
///
/// Sending and receiving are transactional: session state is committed only after the complete
/// event has been encrypted, authenticated, parsed, and validated.
///
/// # Security
///
/// Serialized session state contains private, root, chain, header, and skipped message keys. It
/// must be treated as secret material and stored with appropriate encryption and access control.
/// Use a single current copy of a session: concurrently using clones or restoring an older
/// snapshot can reuse ratchet state, lose messages, or fork the conversation.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Session {
    root_key: SecretBytes,
    their_current_public_key: Option<PublicKey>,
    their_next_public_key: PublicKey,
    our_current_key: Option<LocalKey>,
    our_next_key: LocalKey,
    receiving_chain_key: Option<SecretBytes>,
    sending_chain_key: Option<SecretBytes>,
    sending_chain_message_number: u32,
    receiving_chain_message_number: u32,
    previous_sending_chain_message_count: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    skipped_keys: BTreeMap<PublicKey, SkippedKeys>,
    #[serde(default, skip_serializing_if = "is_zero")]
    next_cache_sequence: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionData {
    root_key: SecretBytes,
    their_current_public_key: Option<PublicKey>,
    their_next_public_key: PublicKey,
    our_current_key: Option<LocalKey>,
    our_next_key: LocalKey,
    receiving_chain_key: Option<SecretBytes>,
    sending_chain_key: Option<SecretBytes>,
    sending_chain_message_number: u32,
    receiving_chain_message_number: u32,
    previous_sending_chain_message_count: u32,
    #[serde(default)]
    skipped_keys: BTreeMap<PublicKey, SkippedKeys>,
    #[serde(default)]
    next_cache_sequence: u64,
}

impl<'de> Deserialize<'de> for Session {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = SessionData::deserialize(deserializer)?;
        let session = Self {
            root_key: data.root_key,
            their_current_public_key: data.their_current_public_key,
            their_next_public_key: data.their_next_public_key,
            our_current_key: data.our_current_key,
            our_next_key: data.our_next_key,
            receiving_chain_key: data.receiving_chain_key,
            sending_chain_key: data.sending_chain_key,
            sending_chain_message_number: data.sending_chain_message_number,
            receiving_chain_message_number: data.receiving_chain_message_number,
            previous_sending_chain_message_count: data.previous_sending_chain_message_count,
            skipped_keys: data.skipped_keys,
            next_cache_sequence: data.next_cache_sequence,
        };
        session
            .validate_persisted_state()
            .map_err(serde::de::Error::custom)?;
        Ok(session)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("root_key", &Redacted)
            .field("remote_keys", &Redacted)
            .field("local_keys", &Redacted)
            .field("receiving_chain_key", &Redacted)
            .field("sending_chain_key", &Redacted)
            .field(
                "sending_chain_message_number",
                &self.sending_chain_message_number,
            )
            .field(
                "receiving_chain_message_number",
                &self.receiving_chain_message_number,
            )
            .field(
                "previous_sending_chain_message_count",
                &self.previous_sending_chain_message_count,
            )
            .field("skipped_message_count", &self.skipped_message_count())
            .finish()
    }
}

impl Session {
    /// Start a session as the initiator using caller-supplied randomness.
    ///
    /// The newly generated `next` key is used for the initial sending-chain derivation. This is
    /// the interoperable construction used by current NIP-117 implementations.
    ///
    /// This constructor can be used without NIP-118 when participants exchange their ephemeral
    /// public keys and shared secret over another authenticated channel. The peer initializes the
    /// matching side with [`Session::new_responder`].
    pub fn new_initiator_with_rng<R>(
        their_ephemeral_public_key: PublicKey,
        our_ephemeral_secret_key: SecretKey,
        shared_secret: [u8; 32],
        rng: &mut R,
    ) -> Result<Self, Error>
    where
        R: Rng + CryptoRng,
    {
        let shared_secret = SecretBytes(shared_secret);
        let our_current_key = LocalKey::new(our_ephemeral_secret_key);
        let our_next_key = LocalKey::new(random_secret_key_with_rng(rng));
        let conversation_key =
            derive_conversation_key(&our_next_key.secret_key()?, &their_ephemeral_public_key)?;
        let (root_key, sending_chain_key) = kdf(shared_secret.as_ref(), conversation_key.as_ref());

        Ok(Self {
            root_key,
            their_current_public_key: None,
            their_next_public_key: their_ephemeral_public_key,
            our_current_key: Some(our_current_key),
            our_next_key,
            receiving_chain_key: None,
            sending_chain_key: Some(sending_chain_key),
            sending_chain_message_number: 0,
            receiving_chain_message_number: 0,
            previous_sending_chain_message_count: 0,
            skipped_keys: BTreeMap::new(),
            next_cache_sequence: 0,
        })
    }

    /// Start a session as the responder.
    ///
    /// This constructor can be used without NIP-118 when participants exchange their ephemeral
    /// public keys and shared secret over another authenticated channel.
    ///
    /// A responder cannot send until it has successfully received the initiator's first message.
    pub fn new_responder(
        their_ephemeral_public_key: PublicKey,
        our_ephemeral_secret_key: SecretKey,
        shared_secret: [u8; 32],
    ) -> Result<Self, Error> {
        // Unlike initiator construction, responder construction does not perform ECDH yet.
        // Validate now so malformed x-only keys cannot be persisted in a session.
        their_ephemeral_public_key.xonly()?;
        Ok(Self {
            root_key: SecretBytes(shared_secret),
            their_current_public_key: None,
            their_next_public_key: their_ephemeral_public_key,
            our_current_key: None,
            our_next_key: LocalKey::new(our_ephemeral_secret_key),
            receiving_chain_key: None,
            sending_chain_key: None,
            sending_chain_message_number: 0,
            receiving_chain_message_number: 0,
            previous_sending_chain_message_count: 0,
            skipped_keys: BTreeMap::new(),
            next_cache_sequence: 0,
        })
    }

    /// Return whether this session currently has a sending chain.
    #[inline]
    pub fn can_send(&self) -> bool {
        self.our_current_key.is_some() && self.sending_chain_key.is_some()
    }

    /// Return the public key used to author the next outgoing message.
    #[inline]
    pub fn current_public_key(&self) -> Option<PublicKey> {
        self.our_current_key.as_ref().map(|key| key.public_key)
    }

    /// Return all remote author keys for which the session can currently receive a message.
    ///
    /// Use these keys to build relay subscriptions, refreshing them after successful receives.
    pub fn remote_public_keys(&self) -> Vec<PublicKey> {
        let mut keys: Vec<PublicKey> = Vec::with_capacity(2 + self.skipped_keys.len());
        if let Some(public_key) = self.their_current_public_key {
            keys.push(public_key);
        }
        if !keys.contains(&self.their_next_public_key) {
            keys.push(self.their_next_public_key);
        }
        for public_key in self.skipped_keys.keys().copied() {
            if self.their_current_public_key != Some(public_key)
                && self.their_next_public_key != public_key
            {
                keys.push(public_key);
            }
        }
        keys
    }

    /// Return whether `sender` belongs to a current or cached receiving chain.
    ///
    /// This can route a fetched kind `1060` event to a candidate session before decryption.
    #[inline]
    pub fn matches_sender(&self, sender: PublicKey) -> bool {
        self.their_current_public_key == Some(sender)
            || self.their_next_public_key == sender
            || self.skipped_keys.contains_key(&sender)
    }

    /// Encrypt a rumor into a signed kind `1060` event using caller-supplied randomness.
    ///
    /// On success the session has advanced. Durably store the new session state together with the
    /// returned event before publishing it. Publication retries must reuse that event instead of
    /// encrypting the rumor again from older state.
    pub fn send_message_with_rng<R>(
        &mut self,
        mut rumor: UnsignedEvent,
        created_at: Timestamp,
        rng: &mut R,
    ) -> Result<Event, Error>
    where
        R: Rng + CryptoRng,
    {
        rumor.ensure_id();
        validate_rumor(&rumor)?;
        if !self.can_send() {
            return Err(invalid("the session cannot send yet"));
        }

        let plaintext: String = serde_json::to_string(&rumor)?;
        let mut next: Self = self.clone();
        let (header, ciphertext) = next.ratchet_encrypt(plaintext.as_bytes(), rng)?;

        let our_current = next
            .our_current_key
            .as_ref()
            .ok_or_else(|| invalid("missing current local key"))?;
        let current_secret = our_current.secret_key()?;
        let header_key = derive_conversation_key(&current_secret, &next.their_next_public_key)?;
        let encrypted_header = encrypt_conversation_key_with_rng(
            header_key.as_array(),
            serde_json::to_string(&header)?,
            rng,
        )?;
        let header_tag = Tag::parse(["header", encrypted_header.as_str()])?;
        let unsigned = UnsignedEvent::new(
            our_current.public_key,
            created_at,
            Kind::DoubleRatchetMessage,
            [header_tag],
            ciphertext,
        );
        let event = sign_event_with_rng(unsigned, &current_secret, rng)?;

        *self = next;
        Ok(event)
    }

    /// Decrypt and validate a signed kind `1060` event using caller-supplied randomness.
    ///
    /// A duplicate that still belongs to a current or cached receiving chain returns `Ok(None)`.
    /// Once an old chain's final skipped key has been consumed or evicted, that sender is no
    /// longer associated with the session and a replay from it is an error. Any failure, including
    /// an invalid outer event or inner rumor ID, leaves the session byte-for-byte unchanged.
    pub fn receive_message_with_rng<R>(
        &mut self,
        event: &Event,
        rng: &mut R,
    ) -> Result<Option<UnsignedEvent>, Error>
    where
        R: Rng + CryptoRng,
    {
        validate_outer_event(event)?;
        if !self.matches_sender(event.pubkey) {
            return Err(invalid("unexpected double-ratchet sender"));
        }
        let encrypted_header = encrypted_header(event)?;

        let mut next: Self = self.clone();
        let plaintext =
            match next.ratchet_decrypt(event.pubkey, encrypted_header, &event.content, rng)? {
                ReceiveResult::Plaintext(plaintext) => plaintext,
                ReceiveResult::Duplicate => return Ok(None),
            };

        let rumor: UnsignedEvent = serde_json::from_slice(&plaintext)?;
        validate_rumor(&rumor)?;
        *self = next;
        Ok(Some(rumor))
    }

    fn ratchet_encrypt<R>(
        &mut self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(Header, String), Error>
    where
        R: Rng + CryptoRng,
    {
        let chain_key = self
            .sending_chain_key
            .as_ref()
            .ok_or_else(|| invalid("missing sending chain key"))?;
        let (next_chain_key, message_key) = kdf(chain_key.as_ref(), &[1]);
        let number = self.sending_chain_message_number;
        let next_number = number
            .checked_add(1)
            .ok_or_else(|| invalid("sending message counter overflow"))?;
        let header = Header {
            number,
            previous_chain_length: self.previous_sending_chain_message_count,
            next_public_key: self.our_next_key.public_key,
        };
        let ciphertext = encrypt_conversation_key_with_rng(message_key.as_array(), plaintext, rng)?;

        self.sending_chain_key = Some(next_chain_key);
        self.sending_chain_message_number = next_number;
        Ok((header, ciphertext))
    }

    fn ratchet_decrypt<R>(
        &mut self,
        sender: PublicKey,
        encrypted_header: &str,
        ciphertext: &str,
        rng: &mut R,
    ) -> Result<ReceiveResult, Error>
    where
        R: Rng + CryptoRng,
    {
        let (header, target) = self.decrypt_header(sender, encrypted_header)?;

        if target == HeaderTarget::Skipped {
            return self.decrypt_skipped_message(sender, header.number, ciphertext);
        }

        if target == HeaderTarget::Next {
            if sender != self.their_next_public_key {
                return Err(invalid("unexpected DH ratchet sender"));
            }
            if header.next_public_key == sender {
                return Err(invalid(
                    "a ratchet key cannot advertise itself as its successor",
                ));
            }

            if self.receiving_chain_key.is_some() {
                let previous_sender = self
                    .their_current_public_key
                    .ok_or_else(|| invalid("missing current remote key"))?;
                self.skip_message_keys(header.previous_chain_length, previous_sender)?;
            } else if header.previous_chain_length != 0 {
                return Err(invalid(
                    "nonzero previous chain length on the first ratchet",
                ));
            }

            self.their_current_public_key = Some(sender);
            self.their_next_public_key = header.next_public_key;
            self.dh_ratchet(rng)?;
        }

        if let Some(plaintext) = self.take_skipped_message(sender, header.number, ciphertext)? {
            return Ok(ReceiveResult::Plaintext(plaintext));
        }

        if header.number < self.receiving_chain_message_number {
            return Ok(ReceiveResult::Duplicate);
        }
        self.skip_message_keys(header.number, sender)?;

        let chain_key = self
            .receiving_chain_key
            .as_ref()
            .ok_or_else(|| invalid("missing receiving chain key"))?;
        let (next_chain_key, message_key) = kdf(chain_key.as_ref(), &[1]);
        let next_number = self
            .receiving_chain_message_number
            .checked_add(1)
            .ok_or_else(|| invalid("receiving message counter overflow"))?;
        let plaintext = decrypt_conversation_key_bytes(message_key.as_array(), ciphertext)?;
        self.receiving_chain_key = Some(next_chain_key);
        self.receiving_chain_message_number = next_number;
        Ok(ReceiveResult::Plaintext(plaintext))
    }

    fn decrypt_header(
        &self,
        sender: PublicKey,
        encrypted_header: &str,
    ) -> Result<(Header, HeaderTarget), Error> {
        if self.their_current_public_key == Some(sender) {
            if let Some(current) = &self.our_current_key {
                let key = derive_conversation_key(&current.secret_key()?, &sender)?;
                if let Ok(header) = decrypt_header_with_key(key.as_array(), encrypted_header) {
                    return Ok((header, HeaderTarget::Current));
                }
            }
        }

        if self.their_next_public_key == sender {
            let key = derive_conversation_key(&self.our_next_key.secret_key()?, &sender)?;
            if let Ok(header) = decrypt_header_with_key(key.as_array(), encrypted_header) {
                return Ok((header, HeaderTarget::Next));
            }
        }

        if let Some(skipped) = self.skipped_keys.get(&sender) {
            if let Ok(header) =
                decrypt_header_with_key(skipped.header_key.as_array(), encrypted_header)
            {
                return Ok((header, HeaderTarget::Skipped));
            }
        }

        Err(invalid("failed to decrypt double-ratchet header"))
    }

    fn dh_ratchet<R>(&mut self, rng: &mut R) -> Result<(), Error>
    where
        R: Rng + CryptoRng,
    {
        self.previous_sending_chain_message_count = self.sending_chain_message_number;
        self.sending_chain_message_number = 0;
        self.receiving_chain_message_number = 0;

        let first_dh = derive_conversation_key(
            &self.our_next_key.secret_key()?,
            &self.their_next_public_key,
        )?;
        let (intermediate_root, receiving_chain_key) =
            kdf(self.root_key.as_ref(), first_dh.as_ref());
        self.receiving_chain_key = Some(receiving_chain_key);
        self.our_current_key = Some(self.our_next_key.clone());
        self.our_next_key = LocalKey::new(random_secret_key_with_rng(rng));

        let second_dh = derive_conversation_key(
            &self.our_next_key.secret_key()?,
            &self.their_next_public_key,
        )?;
        let (root_key, sending_chain_key) = kdf(intermediate_root.as_ref(), second_dh.as_ref());
        self.root_key = root_key;
        self.sending_chain_key = Some(sending_chain_key);
        Ok(())
    }

    fn skip_message_keys(&mut self, until: u32, sender: PublicKey) -> Result<(), Error> {
        if until <= self.receiving_chain_message_number {
            return Ok(());
        }
        let gap = until
            .checked_sub(self.receiving_chain_message_number)
            .ok_or_else(|| invalid("invalid receiving message counter"))?;
        if usize::try_from(gap).map_or(true, |gap| gap > MAX_SKIP) {
            return Err(invalid("too many skipped double-ratchet messages"));
        }

        let header_key = if self.skipped_keys.contains_key(&sender) {
            None
        } else {
            let current = self
                .our_current_key
                .as_ref()
                .ok_or_else(|| invalid("missing current local key"))?;
            Some(derive_conversation_key(&current.secret_key()?, &sender)?)
        };
        if let Some(header_key) = header_key {
            self.skipped_keys.insert(
                sender,
                SkippedKeys {
                    header_key,
                    message_keys: BTreeMap::new(),
                },
            );
        }

        while self.receiving_chain_message_number < until {
            let chain_key = self
                .receiving_chain_key
                .as_ref()
                .ok_or_else(|| invalid("missing receiving chain key"))?;
            let (next_chain_key, message_key) = kdf(chain_key.as_ref(), &[1]);
            let number = self.receiving_chain_message_number;
            let next_number = number
                .checked_add(1)
                .ok_or_else(|| invalid("receiving message counter overflow"))?;
            let sequence = self.next_cache_sequence;
            self.next_cache_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid("skipped-key sequence overflow"))?;
            self.skipped_keys
                .get_mut(&sender)
                .ok_or_else(|| invalid("missing skipped-key cache"))?
                .message_keys
                .insert(
                    number,
                    CachedMessageKey {
                        sequence,
                        key: message_key,
                    },
                );
            self.receiving_chain_key = Some(next_chain_key);
            self.receiving_chain_message_number = next_number;
        }
        self.prune_skipped_keys();
        Ok(())
    }

    fn decrypt_skipped_message(
        &mut self,
        sender: PublicKey,
        number: u32,
        ciphertext: &str,
    ) -> Result<ReceiveResult, Error> {
        match self.take_skipped_message(sender, number, ciphertext)? {
            Some(plaintext) => Ok(ReceiveResult::Plaintext(plaintext)),
            None => Ok(ReceiveResult::Duplicate),
        }
    }

    fn take_skipped_message(
        &mut self,
        sender: PublicKey,
        number: u32,
        ciphertext: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        let key = match self
            .skipped_keys
            .get(&sender)
            .and_then(|entry| entry.message_keys.get(&number))
        {
            Some(cached) => cached.key.clone(),
            None => return Ok(None),
        };
        let plaintext = decrypt_conversation_key_bytes(key.as_array(), ciphertext)?;

        if let Some(entry) = self.skipped_keys.get_mut(&sender) {
            entry.message_keys.remove(&number);
            if entry.message_keys.is_empty() {
                self.skipped_keys.remove(&sender);
            }
        }
        Ok(Some(plaintext))
    }

    fn prune_skipped_keys(&mut self) {
        while self.skipped_message_count() > MAX_SKIP {
            let oldest = self
                .skipped_keys
                .iter()
                .flat_map(|(sender, entry)| {
                    entry
                        .message_keys
                        .iter()
                        .map(move |(number, cached)| (*sender, *number, cached.sequence))
                })
                .min_by_key(|(_, _, sequence)| *sequence);
            let Some((sender, number, _)) = oldest else {
                break;
            };
            if let Some(entry) = self.skipped_keys.get_mut(&sender) {
                entry.message_keys.remove(&number);
                if entry.message_keys.is_empty() {
                    self.skipped_keys.remove(&sender);
                }
            }
        }
    }

    fn validate_persisted_state(&self) -> Result<(), Error> {
        self.their_next_public_key.xonly()?;
        if let Some(public_key) = self.their_current_public_key {
            public_key.xonly()?;
            if public_key == self.their_next_public_key {
                return Err(invalid("current and next remote ratchet keys must differ"));
            }
        }

        if self.our_current_key.is_some() != self.sending_chain_key.is_some() {
            return Err(invalid("inconsistent sending-chain state"));
        }
        if self.their_current_public_key.is_some() != self.receiving_chain_key.is_some() {
            return Err(invalid("inconsistent receiving-chain state"));
        }
        if self.sending_chain_key.is_none() && self.sending_chain_message_number != 0 {
            return Err(invalid("sending counter without a sending chain"));
        }
        if self.receiving_chain_key.is_none() && self.receiving_chain_message_number != 0 {
            return Err(invalid("receiving counter without a receiving chain"));
        }
        if self
            .our_current_key
            .as_ref()
            .is_some_and(|current| current.public_key == self.our_next_key.public_key)
        {
            return Err(invalid("current and next local ratchet keys must differ"));
        }
        if self.skipped_message_count() > MAX_SKIP {
            return Err(invalid("persisted skipped-key cache exceeds MAX_SKIP"));
        }

        let mut sequences = BTreeSet::new();
        for (sender, skipped) in &self.skipped_keys {
            sender.xonly()?;
            if skipped.message_keys.is_empty() {
                return Err(invalid("persisted skipped-key entry is empty"));
            }
            for cached in skipped.message_keys.values() {
                if cached.sequence >= self.next_cache_sequence {
                    return Err(invalid("invalid persisted skipped-key sequence"));
                }
                if !sequences.insert(cached.sequence) {
                    return Err(invalid("duplicate persisted skipped-key sequence"));
                }
            }
        }
        Ok(())
    }

    fn skipped_message_count(&self) -> usize {
        self.skipped_keys
            .values()
            .map(|entry| entry.message_keys.len())
            .sum()
    }
}

impl_json_methods!(Session);

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalKey {
    public_key: PublicKey,
    private_key: SecretBytes,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalKeyData {
    public_key: PublicKey,
    private_key: SecretBytes,
}

impl<'de> Deserialize<'de> for LocalKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = LocalKeyData::deserialize(deserializer)?;
        let secret_key =
            SecretKey::from_slice(data.private_key.as_ref()).map_err(serde::de::Error::custom)?;
        let secp = Secp256k1::signing_only();
        if PublicKey::from_secret_key(&secp, &secret_key) != data.public_key {
            return Err(serde::de::Error::custom(
                "local ratchet public and private keys do not match",
            ));
        }
        Ok(Self {
            public_key: data.public_key,
            private_key: data.private_key,
        })
    }
}

impl LocalKey {
    fn new(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::signing_only();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Self {
            public_key,
            private_key: SecretBytes(secret_key.to_secret_bytes()),
        }
    }

    fn secret_key(&self) -> Result<SecretKey, Error> {
        SecretKey::from_slice(self.private_key.as_ref())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SkippedKeys {
    header_key: SecretBytes,
    message_keys: BTreeMap<u32, CachedMessageKey>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedMessageKey {
    sequence: u64,
    key: SecretBytes,
}

#[derive(Clone, PartialEq, Eq)]
struct SecretBytes([u8; 32]);

impl SecretBytes {
    #[inline]
    fn as_array(&self) -> &[u8; 32] {
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
        serializer.serialize_str(&faster_hex::hex_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        let bytes = crate::util::hex_decode::<32>(&value).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderTarget {
    Current,
    Next,
    Skipped,
}

enum ReceiveResult {
    Plaintext(Vec<u8>),
    Duplicate,
}

struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[inline]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[inline]
fn invalid(message: &'static str) -> Error {
    Error::with_static_message(ErrorKind::Invalid, message)
}

fn validate_rumor(rumor: &UnsignedEvent) -> Result<(), Error> {
    let id = rumor
        .id
        .ok_or_else(|| invalid("double-ratchet rumor is missing its ID"))?;
    if rumor.compute_id() != id {
        return Err(invalid("invalid double-ratchet rumor ID"));
    }
    Ok(())
}

fn validate_outer_event(event: &Event) -> Result<(), Error> {
    if event.kind != Kind::DoubleRatchetMessage {
        return Err(invalid("invalid double-ratchet event kind"));
    }
    let secp = Secp256k1::verification_only();
    event.verify_with_ctx(&secp)
}

fn encrypted_header(event: &Event) -> Result<&str, Error> {
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

fn derive_conversation_key(
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

fn kdf(input1: &[u8], input2: &[u8]) -> (SecretBytes, SecretBytes) {
    // NIP-117 defines input2 as the HKDF salt and input1 as the input key material. Each output
    // is an independent one-block expansion with info [1] or [2], not a split 64-byte expansion.
    let prk = hkdf::extract(input2, input1);
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    hkdf::expand_into(prk.as_byte_array(), &[1], &mut first);
    hkdf::expand_into(prk.as_byte_array(), &[2], &mut second);
    (SecretBytes(first), SecretBytes(second))
}

fn decrypt_header_with_key(key: &[u8; 32], encrypted_header: &str) -> Result<Header, Error> {
    let plaintext = decrypt_conversation_key(key, encrypted_header)?;
    Ok(serde_json::from_str(&plaintext)?)
}

/// Generate a valid secp256k1 secret key with caller-supplied randomness.
pub(super) fn random_secret_key_with_rng<R>(rng: &mut R) -> SecretKey
where
    R: Rng + CryptoRng,
{
    SecretKey::generate_with_rng(rng)
}

/// Sign an unsigned event with caller-supplied randomness.
pub(super) fn sign_event_with_rng<R>(
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
pub(super) fn encrypt_conversation_key_with_rng<R, T>(
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
    let payload = super::nip44::v2::encrypt_to_bytes_with_nonce(&key, plaintext.as_ref(), nonce)?;
    Ok(general_purpose::STANDARD.encode(payload))
}

/// NIP-44 decrypt UTF-8 text with an already-derived raw conversation key.
pub(super) fn decrypt_conversation_key<T>(
    conversation_key: &[u8; 32],
    payload: T,
) -> Result<String, Error>
where
    T: AsRef<[u8]>,
{
    let plaintext = decrypt_conversation_key_bytes(conversation_key, payload)?;
    String::from_utf8(plaintext).map_err(Error::malformed)
}

fn decrypt_conversation_key_bytes<T>(
    conversation_key: &[u8; 32],
    payload: T,
) -> Result<Vec<u8>, Error>
where
    T: AsRef<[u8]>,
{
    let decoded = general_purpose::STANDARD
        .decode(payload.as_ref())
        .map_err(Error::malformed_display)?;
    if decoded.first() != Some(&2) {
        return Err(Error::with_static_message(
            ErrorKind::Unsupported,
            "unsupported NIP-44 payload version",
        ));
    }
    let key = ConversationKey::new(*conversation_key);
    super::nip44::v2::decrypt_to_bytes(&key, &decoded)
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec};
    use core::convert::Infallible;

    use rand::rngs::Xoshiro256PlusPlus;
    use rand::{SeedableRng, TryCryptoRng, TryRng};

    use super::*;

    struct TestRng(Xoshiro256PlusPlus);

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self(Xoshiro256PlusPlus::seed_from_u64(seed))
        }
    }

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0.try_next_u32()
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0.try_next_u64()
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0.try_fill_bytes(dst)
        }
    }

    impl TryCryptoRng for TestRng {}

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn public(secret_key: &SecretKey) -> PublicKey {
        let secp = Secp256k1::signing_only();
        PublicKey::from_secret_key(&secp, secret_key)
    }

    fn session_pair() -> (Session, Session, TestRng, TestRng) {
        let alice_secret = secret(1);
        let bob_secret = secret(2);
        let mut alice_rng = TestRng::new(11);
        let alice = Session::new_initiator_with_rng(
            public(&bob_secret),
            alice_secret.clone(),
            [3; 32],
            &mut alice_rng,
        )
        .unwrap();
        let bob = Session::new_responder(public(&alice_secret), bob_secret, [3; 32]).unwrap();
        (alice, bob, alice_rng, TestRng::new(22))
    }

    fn rumor(content: &str) -> UnsignedEvent {
        UnsignedEvent::new(
            public(&secret(9)),
            Timestamp::from_secs(1_700_000_000),
            Kind::TextNote,
            [],
            content,
        )
    }

    fn send(session: &mut Session, content: &str, rng: &mut TestRng) -> Event {
        session
            .send_message_with_rng(rumor(content), Timestamp::from_secs(1_700_000_100), rng)
            .unwrap()
    }

    fn send_raw_plaintext(session: &mut Session, plaintext: &[u8], rng: &mut TestRng) -> Event {
        let mut next = session.clone();
        let (header, ciphertext) = next.ratchet_encrypt(plaintext, rng).unwrap();
        let current = next.our_current_key.as_ref().unwrap();
        let secret = current.secret_key().unwrap();
        let header_key = derive_conversation_key(&secret, &next.their_next_public_key).unwrap();
        let encrypted_header = encrypt_conversation_key_with_rng(
            header_key.as_array(),
            serde_json::to_string(&header).unwrap(),
            rng,
        )
        .unwrap();
        let unsigned = UnsignedEvent::new(
            current.public_key,
            Timestamp::from_secs(1_700_000_100),
            Kind::DoubleRatchetMessage,
            [Tag::parse(["header", encrypted_header.as_str()]).unwrap()],
            ciphertext,
        );
        let event = sign_event_with_rng(unsigned, &secret, rng).unwrap();
        *session = next;
        event
    }

    fn receive(session: &mut Session, event: &Event, rng: &mut TestRng) -> UnsignedEvent {
        session
            .receive_message_with_rng(event, rng)
            .unwrap()
            .expect("message must not be a duplicate")
    }

    #[test]
    fn kdf_matches_independent_expand_vector() {
        let (first, second) = kdf(&[0x11; 32], &[0x22; 32]);
        assert_eq!(
            first.0,
            crate::util::hex_decode(
                "4db1ab29554117b78d86d7d9bd5fdd984d2be52b91aba9f52ce25c4ca3ce3a81"
            )
            .unwrap()
        );
        assert_eq!(
            second.0,
            crate::util::hex_decode(
                "a47584fb3ffdb3cb4dc6a54071050f9bca4a18b19b2789e7f8278679275239bc"
            )
            .unwrap()
        );
    }

    #[test]
    fn header_uses_camel_case_wire_names() {
        let header = Header {
            number: 4,
            previous_chain_length: 3,
            next_public_key: public(&secret(7)),
        };
        let json = serde_json::to_value(header).unwrap();
        assert_eq!(json["number"], 4);
        assert_eq!(json["previousChainLength"], 3);
        assert!(json.get("nextPublicKey").is_some());
        assert!(json.get("previous_chain_length").is_none());
    }

    #[test]
    fn bidirectional_ping_pong_and_rumor_id_completion() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        assert!(alice.can_send());
        assert!(!bob.can_send());

        let first = send(&mut alice, "one", &mut alice_rng);
        let first_rumor = receive(&mut bob, &first, &mut bob_rng);
        assert_eq!(first_rumor.content, "one");
        assert_eq!(first_rumor.id, Some(first_rumor.compute_id()));
        assert!(bob.can_send());

        let second = send(&mut bob, "two", &mut bob_rng);
        assert_eq!(receive(&mut alice, &second, &mut alice_rng).content, "two");
        let third = send(&mut alice, "three", &mut alice_rng);
        assert_eq!(receive(&mut bob, &third, &mut bob_rng).content, "three");
    }

    #[test]
    fn burst_messages_are_received_out_of_order() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        let events: Vec<Event> = (0..6)
            .map(|number| send(&mut alice, &format!("message {number}"), &mut alice_rng))
            .collect();

        for number in [5usize, 1, 3, 0, 4, 2] {
            let received = receive(&mut bob, &events[number], &mut bob_rng);
            assert_eq!(received.content, format!("message {number}"));
        }
        assert!(bob.skipped_keys.is_empty());
    }

    #[test]
    fn delayed_message_survives_more_than_two_dh_ratchets() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();

        let delayed = send(&mut alice, "delayed", &mut alice_rng);
        let first_tail = send(&mut alice, "first tail", &mut alice_rng);
        receive(&mut bob, &first_tail, &mut bob_rng); // Bob's first DH ratchet.

        let bob_one = send(&mut bob, "bob one", &mut bob_rng);
        receive(&mut alice, &bob_one, &mut alice_rng); // Alice's first DH ratchet.
        let alice_two = send(&mut alice, "alice two", &mut alice_rng);
        receive(&mut bob, &alice_two, &mut bob_rng); // Bob's second DH ratchet.
        let bob_two = send(&mut bob, "bob two", &mut bob_rng);
        receive(&mut alice, &bob_two, &mut alice_rng); // Alice's second DH ratchet.
        let alice_three = send(&mut alice, "alice three", &mut alice_rng);
        receive(&mut bob, &alice_three, &mut bob_rng); // Bob's third DH ratchet.

        assert_ne!(bob.their_current_public_key, Some(delayed.pubkey));
        assert_ne!(bob.their_next_public_key, delayed.pubkey);
        assert!(bob.skipped_keys.contains_key(&delayed.pubkey));
        assert_eq!(receive(&mut bob, &delayed, &mut bob_rng).content, "delayed");
        assert!(!bob.remote_public_keys().contains(&delayed.pubkey));
        assert!(!bob.matches_sender(delayed.pubkey));
    }

    #[test]
    fn duplicate_and_tamper_do_not_mutate_state() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        let event = send(&mut alice, "once", &mut alice_rng);
        receive(&mut bob, &event, &mut bob_rng);
        let after_receive = bob.as_json();

        assert!(
            bob.receive_message_with_rng(&event, &mut bob_rng)
                .unwrap()
                .is_none()
        );
        assert_eq!(bob.as_json(), after_receive);

        let mut tampered = send(&mut alice, "authentic", &mut alice_rng);
        tampered.content.push('x');
        let before_tamper = bob.as_json();
        assert!(
            bob.receive_message_with_rng(&tampered, &mut bob_rng)
                .is_err()
        );
        assert_eq!(bob.as_json(), before_tamper);
    }

    #[test]
    fn invalid_inner_rumor_id_is_rejected_atomically() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        let mut invalid_rumor = rumor("before mutation");
        invalid_rumor.ensure_id();
        invalid_rumor.content = String::from("after mutation");
        let invalid_event = send_raw_plaintext(
            &mut alice,
            serde_json::to_string(&invalid_rumor).unwrap().as_bytes(),
            &mut alice_rng,
        );

        let before = bob.as_json();
        assert!(
            bob.receive_message_with_rng(&invalid_event, &mut bob_rng)
                .is_err()
        );
        assert_eq!(bob.as_json(), before);

        // The failed message did not advance Bob; he can skip its key and receive the next one.
        let valid_event = send(&mut alice, "valid successor", &mut alice_rng);
        assert_eq!(
            receive(&mut bob, &valid_event, &mut bob_rng).content,
            "valid successor"
        );
    }

    #[test]
    fn serde_roundtrip_mid_session_preserves_cached_messages() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        let delayed = send(&mut alice, "zero", &mut alice_rng);
        let later = send(&mut alice, "one", &mut alice_rng);
        receive(&mut bob, &later, &mut bob_rng);

        let serialized = bob.as_json();
        assert!(!serialized.contains('[')); // Secret material uses compact hex, not byte arrays.
        let mut restored = Session::from_json(serialized).unwrap();
        assert_eq!(restored, bob);
        assert_eq!(
            receive(&mut restored, &delayed, &mut bob_rng).content,
            "zero"
        );

        let reply = send(&mut restored, "reply", &mut bob_rng);
        assert_eq!(receive(&mut alice, &reply, &mut alice_rng).content, "reply");
    }

    #[test]
    fn persisted_state_rejects_corrupt_keypairs_and_invariants() {
        let (alice, _, _, _) = session_pair();

        let mut mismatched_keypair = serde_json::to_value(&alice).unwrap();
        mismatched_keypair["ourNextKey"]["publicKey"] =
            serde_json::Value::String(public(&secret(8)).to_hex());
        assert!(serde_json::from_value::<Session>(mismatched_keypair).is_err());

        let mut invalid_remote_key = serde_json::to_value(&alice).unwrap();
        invalid_remote_key["theirNextPublicKey"] =
            serde_json::Value::String(faster_hex::hex_string(&[0xff; 32]));
        assert!(serde_json::from_value::<Session>(invalid_remote_key).is_err());

        let mut inconsistent_chain = serde_json::to_value(&alice).unwrap();
        inconsistent_chain["sendingChainKey"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<Session>(inconsistent_chain).is_err());
    }

    #[test]
    fn debug_redacts_every_key() {
        let (alice, _, _, _) = session_pair();
        let root = faster_hex::hex_string(alice.root_key.as_array());
        let local = faster_hex::hex_string(
            alice
                .our_current_key
                .as_ref()
                .unwrap()
                .private_key
                .as_array(),
        );
        let debug = format!("{alice:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&root));
        assert!(!debug.contains(&local));
        assert!(!debug.contains(&alice.their_next_public_key.to_hex()));
    }

    #[test]
    fn global_skip_limit_accepts_limit_and_rejects_limit_plus_one() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        let mut first = None;
        let mut at_limit = None;
        for number in 0..=MAX_SKIP {
            let event = send(&mut alice, "skip", &mut alice_rng);
            if number == 0 {
                first = Some(event.clone());
            }
            at_limit = Some(event);
        }
        receive(&mut bob, &at_limit.unwrap(), &mut bob_rng);
        assert_eq!(bob.skipped_message_count(), MAX_SKIP);
        assert_eq!(
            receive(&mut bob, &first.unwrap(), &mut bob_rng).content,
            "skip"
        );

        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        let mut too_far = None;
        for _ in 0..=MAX_SKIP + 1 {
            too_far = Some(send(&mut alice, "too far", &mut alice_rng));
        }
        let before = bob.as_json();
        assert!(
            bob.receive_message_with_rng(&too_far.unwrap(), &mut bob_rng)
                .is_err()
        );
        assert_eq!(bob.as_json(), before);
    }

    #[test]
    fn responder_rejects_invalid_xonly_remote_key() {
        let invalid_public_key = PublicKey::from_byte_array([0xff; 32]);
        assert!(Session::new_responder(invalid_public_key, secret(2), [3; 32]).is_err());
    }

    #[test]
    fn decrypts_first_typescript_reference_event() {
        // First event from nostr-double-ratchet/test-vectors/ts-generated.json. Later vector
        // messages depend on the generator's private random ratchet keys and are intentionally
        // not embedded here.
        const EVENT: &str = r#"{"id":"cbf5c325bb54055050f148d9ae1a7197918142c6df76968ace985f0028a08bc8","pubkey":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","created_at":1704067200,"kind":1060,"tags":[["header","Ai3RFOiEN/rJ+OO62lOm6Vbbzgl9vGVEhL0RSY7XHB2tj92twctf0ngH5fiRlu/sxNIvoggSrV0Oa1kMrJEw1rLrHhxtkEHAphpQOHgVUk0F9HSzRQAUmXuMEL85qgLtGQI9EuPz/lGSRi7sbocQWRxDe3j8VLFQkeyR6zPsNr2eG5EbPXyVD3+0rQMrHjf90dfbDPVr0Ts8uSf3XBd1Pba1FMyHt5KXtVS1XDDV1Q4qO5sijahDUquEQaNIqZSlc5AB"]],"content":"AvN/9kKCbZrDGZMFBke+mBoBCMcrS68GqusV895/yQPb9gcr4na152aO2ncVwe9MF0J+qMLZpidBg6JfzAw/mo2WlYLooZExNs6WAoLhEeNQ37BAhC9yepcnfCbum4XrckwkKUYDIhzpJjgCJbEFKp6sQr+cKKsUEBQM1aeLLAzzo4gB+FXbKZbYT7HwVX8hseutgDB5vsubHPCSA5lU4nf/mAEUapvEz2qJaS1ya0dZ2H1KZ/Ejcbo1oj3/WmjmgnDNXMCBHfo0p7G4+fGtaF5oyOsvciWiCOMY4aIzxAW3+5zPeRczVq6lbHo4tdhv3nAtetudSL1MRo8aoTvwTAm79zAcHNspdaHmVpix7JMjKvFv+XmkLn8d0OrQJ215uQSbF+9DnX1RiwiGdSBd7PsYCEqVlwVHfllor4PH4OTQsOQ=","sig":"9e75eb412702df314a9aa298e2841384493dc2cc76775c7879cc914faa4b279ca84b2d7ef436c00419c09981f9d7c6e7d33278bd91d0dd1b7e20cb706e706b93"}"#;

        let event = Event::from_json(EVENT).unwrap();
        let mut bob = Session::new_responder(event.pubkey, secret(0x22), [0x33; 32]).unwrap();
        let mut rng = TestRng::new(117);
        let rumor = receive(&mut bob, &event, &mut rng);
        assert_eq!(rumor.content, "Hello from TypeScript!");
    }

    #[test]
    fn outer_event_requires_one_nonempty_header_and_valid_signature() {
        let (mut alice, mut bob, mut alice_rng, mut bob_rng) = session_pair();
        let event = send(&mut alice, "valid", &mut alice_rng);

        let mut wrong_kind = event.clone();
        wrong_kind.kind = Kind::TextNote;
        assert!(
            bob.receive_message_with_rng(&wrong_kind, &mut bob_rng)
                .is_err()
        );

        let unsigned = UnsignedEvent::new(
            event.pubkey,
            event.created_at,
            Kind::DoubleRatchetMessage,
            vec![
                Tag::parse(["header", "one"]).unwrap(),
                Tag::parse(["header", "two"]).unwrap(),
            ],
            event.content,
        );
        let duplicate_header = sign_event_with_rng(
            unsigned,
            &alice
                .our_current_key
                .as_ref()
                .unwrap()
                .secret_key()
                .unwrap(),
            &mut alice_rng,
        )
        .unwrap();
        assert!(
            bob.receive_message_with_rng(&duplicate_header, &mut bob_rng)
                .is_err()
        );
    }
}
