// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-118: Nostr Double Ratchet Invites
//!
//! <https://github.com/nostr-protocol/nips/pull/1813>
//!
//! This module implements the protocol-level invite and response handshake. It returns initialized
//! [`Session`] and [`Event`] values that applications can connect to their relay, persistence,
//! contact, and device layers.
//!
//! NIP-118 is optional: applications that already exchange ephemeral public keys and a shared
//! secret through another authenticated channel can construct matching NIP-117 sessions directly.
//!
//! # Workflow
//!
//! The inviter creates and stores an owned [`Invite`], then shares a private URL through an
//! authenticated channel or signs and publishes its public invite event. The invitee parses it and
//! calls [`Invite::accept_with_rng`], stores the returned session with the response event, and
//! publishes that event. After applying replay and invite-use policy, the inviter calls
//! [`Invite::process_response`]. The invitee is the session initiator and sends the first kind
//! `1060` message.

mod invite;
mod wire;

use serde::Serialize;

use crate::event::Event;
use crate::key::{PublicKey, SecretKey};
use crate::nips::nip117::Session;

const INVITE_RESPONSE_TIMESTAMP_WINDOW: u64 = 2 * 24 * 60 * 60;

/// A NIP-118 invitation to establish a NIP-117 session.
///
/// Invitations created locally own the ephemeral secret key needed to process
/// responses. Invitations parsed from a URL or event retain the shared secret,
/// but not the inviter's ephemeral secret key; they can be accepted, but cannot
/// process a response. A private invite URL is sensitive capability material,
/// while a published invite event exposes its shared secret publicly.
///
/// The serialized representation of an owned invite contains both the ephemeral secret key and
/// the shared secret and must be stored securely. A later compromise of both a retained invite and
/// the inviter identity key can decrypt archived responses and reconstruct their initial responder
/// sessions. Deleting expired or consumed invite secrets limits that exposure.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Invite {
    inviter: PublicKey,
    inviter_ephemeral_public_key: PublicKey,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "wire::serde_optional_secret_key"
    )]
    inviter_ephemeral_secret_key: Option<SecretKey>,
    #[serde(with = "wire::serde_shared_secret")]
    shared_secret: [u8; 32],
}

/// The result of accepting an [`Invite`].
#[derive(Debug, Clone)]
pub struct InviteAcceptance {
    /// The invitee's initialized NIP-117 session.
    pub session: Session,
    /// The signed kind `1059` response to publish.
    pub response_event: Event,
}

/// A successfully processed invite response.
#[derive(Debug, Clone)]
pub struct InviteResponse {
    /// The inviter's initialized NIP-117 session.
    pub session: Session,
    /// The authenticated Nostr identity of the invitee, cryptographically bound to the session's
    /// initial key by the response proof.
    pub invitee_identity: PublicKey,
}

#[cfg(test)]
mod tests;
