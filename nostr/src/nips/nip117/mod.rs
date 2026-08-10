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
//! A [`Session`] encrypts arbitrary [`UnsignedEvent`](crate::event::UnsignedEvent) rumors into
//! signed kind `1060` events and decrypts them while advancing its ratchet state. Persist the newest
//! session after every successful operation; after sending, store it together with the returned
//! event and republish that same event on retry. Use [`Session::remote_public_keys`] and
//! [`Session::matches_sender`] to route fetched events. NIP-118 provides an optional invite
//! handshake; callers can instead create matching sessions after exchanging the ephemeral public
//! keys and shared secret through another authenticated channel. Bind each session to the peer
//! identity authenticated by that setup: an inner rumor's `pubkey` is peer-supplied data, not an
//! independent identity proof.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use self::crypto::SecretBytes;
use self::session::{LocalKey, SkippedKeys};
use crate::key::PublicKey;

mod crypto;
mod session;

#[cfg(feature = "nip118")]
pub(super) use self::crypto::{
    decrypt_conversation_key, encrypt_conversation_key_with_rng, parse_rumor,
    random_secret_key_with_rng, sign_event_with_rng, validate_encoded_payload_size,
};

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
/// must be treated as secret material and stored with authenticated encryption, access control,
/// and rollback protection. An attacker who can alter or restore state can inject keys, reuse
/// ratchet state, lose messages, or fork the conversation. Use a single current copy of a session:
/// concurrently using clones can cause the same failures.
///
/// A session authenticates its ephemeral ratchet authors. Applications must separately retain the
/// session-to-peer identity binding established by NIP-118 or another authenticated key exchange;
/// the `pubkey` inside a decrypted rumor is self-asserted by that peer.
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
    #[serde(default, skip_serializing_if = "session::is_zero")]
    next_cache_sequence: u64,
}
