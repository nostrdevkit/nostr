// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, Rng};
use secp256k1::Secp256k1;
use serde::{Deserialize, Deserializer, Serialize};

use super::crypto::{
    Redacted, SecretBytes, decrypt_conversation_key_bytes, decrypt_header_with_key,
    derive_conversation_key, encrypt_conversation_key_with_rng, encrypted_header, invalid, kdf,
    parse_rumor, random_secret_key_with_rng, sign_event_with_rng, validate_encoded_payload_size,
    validate_outer_event, validate_rumor,
};
use super::{Header, MAX_SKIP, Session};
use crate::error::Error;
use crate::event::{Event, Kind, Tag, UnsignedEvent};
use crate::key::{PublicKey, SecretKey};
use crate::types::Timestamp;
use crate::util::impl_json_methods;

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
    ///
    /// The returned rumor's `pubkey` is peer-supplied inner data, not an independent proof of that
    /// identity. Authenticate and persist the session-to-peer binding established by the invite or
    /// other authenticated key-exchange channel.
    pub fn receive_message_with_rng<R>(
        &mut self,
        event: &Event,
        rng: &mut R,
    ) -> Result<Option<UnsignedEvent>, Error>
    where
        R: Rng + CryptoRng,
    {
        if event.kind != Kind::DoubleRatchetMessage {
            return Err(invalid("invalid double-ratchet event kind"));
        }
        if !self.matches_sender(event.pubkey) {
            return Err(invalid("unexpected double-ratchet sender"));
        }
        let encrypted_header = encrypted_header(event)?;
        validate_encoded_payload_size(encrypted_header.as_bytes())?;
        validate_encoded_payload_size(event.content.as_bytes())?;
        validate_outer_event(event)?;

        let mut next: Self = self.clone();
        let plaintext =
            match next.ratchet_decrypt(event.pubkey, encrypted_header, &event.content, rng)? {
                ReceiveResult::Plaintext(plaintext) => plaintext,
                ReceiveResult::Duplicate => return Ok(None),
            };

        let rumor = parse_rumor(&plaintext)?;
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
        header.next_public_key.xonly()?;

        if target == HeaderTarget::Current && header.next_public_key != self.their_next_public_key {
            return Err(invalid(
                "current chain advertised an unexpected next ratchet key",
            ));
        }

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
pub(super) struct LocalKey {
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
pub(super) struct SkippedKeys {
    header_key: SecretBytes,
    message_keys: BTreeMap<u32, CachedMessageKey>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CachedMessageKey {
    sequence: u64,
    key: SecretBytes,
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

#[inline]
pub(super) fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
