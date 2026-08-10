// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, Rng, RngExt};
use secp256k1::Secp256k1;
use zeroize::Zeroize;

use super::wire::{
    InviteResponsePayload, invalid, missing, parse_response_payload, session_proof_digest,
    validate_public_key, validate_response_rumor, validate_response_tags, verify_session_proof,
};
use super::{INVITE_RESPONSE_TIMESTAMP_WINDOW, Invite, InviteAcceptance, InviteResponse};
use crate::error::Error;
use crate::event::{Event, Kind, Tag, UnsignedEvent};
use crate::key::{Keys, PublicKey, SecretKey};
use crate::nips::nip44::{self, Version};
use crate::nips::nip117::{
    Session, decrypt_conversation_key, encrypt_conversation_key_with_rng, parse_rumor,
    random_secret_key_with_rng, sign_event_with_rng, validate_encoded_payload_size,
};
use crate::types::Timestamp;

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("inviter", &self.inviter)
            .field(
                "inviter_ephemeral_public_key",
                &self.inviter_ephemeral_public_key,
            )
            .field(
                "inviter_ephemeral_secret_key",
                &self
                    .inviter_ephemeral_secret_key
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("shared_secret", &"<redacted>")
            .finish()
    }
}

impl Drop for Invite {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl Invite {
    /// Construct an invite which owns the ephemeral secret key.
    pub fn from_owned_parts(
        inviter: PublicKey,
        inviter_ephemeral_secret_key: SecretKey,
        shared_secret: [u8; 32],
    ) -> Result<Self, Error> {
        validate_public_key(inviter, "invalid inviter public key")?;
        let secp = Secp256k1::signing_only();
        let inviter_ephemeral_public_key =
            PublicKey::from_secret_key(&secp, &inviter_ephemeral_secret_key);

        Ok(Self {
            inviter,
            inviter_ephemeral_public_key,
            inviter_ephemeral_secret_key: Some(inviter_ephemeral_secret_key),
            shared_secret,
        })
    }

    /// Construct an acceptor-side invite from its shareable parts.
    pub fn from_public_parts(
        inviter: PublicKey,
        inviter_ephemeral_public_key: PublicKey,
        shared_secret: [u8; 32],
    ) -> Result<Self, Error> {
        validate_public_key(inviter, "invalid inviter public key")?;
        validate_public_key(
            inviter_ephemeral_public_key,
            "invalid invite ephemeral public key",
        )?;
        Ok(Self {
            inviter,
            inviter_ephemeral_public_key,
            inviter_ephemeral_secret_key: None,
            shared_secret,
        })
    }

    /// Generate a new owned invite using the supplied cryptographically secure RNG.
    pub fn new_with_rng<R>(inviter: PublicKey, rng: &mut R) -> Result<Self, Error>
    where
        R: Rng + CryptoRng,
    {
        let inviter_ephemeral_secret_key = random_secret_key_with_rng(rng);
        let shared_secret = random_secret_key_with_rng(rng).to_secret_bytes();
        Self::from_owned_parts(inviter, inviter_ephemeral_secret_key, shared_secret)
    }

    /// Get the inviter's Nostr identity public key.
    #[inline]
    pub fn inviter(&self) -> PublicKey {
        self.inviter
    }

    /// Get the inviter's ephemeral public key.
    #[inline]
    pub fn inviter_ephemeral_public_key(&self) -> PublicKey {
        self.inviter_ephemeral_public_key
    }

    /// Get the inviter's ephemeral secret key, if this invite owns it.
    #[inline]
    pub fn inviter_ephemeral_secret_key(&self) -> Option<&SecretKey> {
        self.inviter_ephemeral_secret_key.as_ref()
    }

    /// Get the invite shared secret.
    ///
    /// This value is sensitive in a private invite. A public invite event exposes it, so it must
    /// not be treated as access-control material in that case.
    #[inline]
    pub fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Accept this invite and create the response event to publish.
    ///
    /// Persist the returned session together with the response event before publishing it. This
    /// side is the session initiator and sends the first kind `1060` message.
    pub fn accept_with_rng<R>(
        &self,
        invitee_identity: &Keys,
        created_at: Timestamp,
        rng: &mut R,
    ) -> Result<InviteAcceptance, Error>
    where
        R: Rng + CryptoRng,
    {
        validate_public_key(self.inviter, "invalid inviter public key")?;
        validate_public_key(
            self.inviter_ephemeral_public_key,
            "invalid invite ephemeral public key",
        )?;

        let invitee_session_secret_key = random_secret_key_with_rng(rng);
        let secp = Secp256k1::signing_only();
        let invitee_session_public_key =
            PublicKey::from_secret_key(&secp, &invitee_session_secret_key);
        let proof_digest = session_proof_digest(
            self.inviter,
            self.inviter_ephemeral_public_key,
            invitee_identity.public_key(),
            invitee_session_public_key,
            &self.shared_secret,
        );
        let invitee_session_keys = Keys::new_with_ctx(&secp, invitee_session_secret_key.clone());
        let session_proof = invitee_session_keys.sign_schnorr_with_rng(&secp, proof_digest, rng);
        let session = Session::new_initiator_with_rng(
            self.inviter_ephemeral_public_key,
            invitee_session_secret_key,
            self.shared_secret,
            rng,
        )?;

        let payload = serde_json::to_string(&InviteResponsePayload {
            session_key: invitee_session_public_key,
            session_proof,
        })?;
        let identity_encrypted = nip44::encrypt_with_rng(
            invitee_identity.secret_key(),
            &self.inviter,
            payload,
            Version::V2,
            rng,
        )?;
        let shared_secret_encrypted =
            encrypt_conversation_key_with_rng(&self.shared_secret, identity_encrypted, rng)?;

        let mut rumor = UnsignedEvent::new(
            invitee_identity.public_key(),
            created_at,
            Kind::DoubleRatchetMessage,
            Vec::<Tag>::new(),
            shared_secret_encrypted,
        );
        rumor.ensure_id();

        let one_use_secret_key = random_secret_key_with_rng(rng);
        let one_use_public_key = PublicKey::from_secret_key(&secp, &one_use_secret_key);
        let content = nip44::encrypt_with_rng(
            &one_use_secret_key,
            &self.inviter_ephemeral_public_key,
            serde_json::to_string(&rumor)?,
            Version::V2,
            rng,
        )?;
        let timestamp_tweak = rng.random_range(0..INVITE_RESPONSE_TIMESTAMP_WINDOW);
        let response_created_at =
            Timestamp::from_secs(created_at.as_secs().saturating_sub(timestamp_tweak));
        let unsigned_response = UnsignedEvent::new(
            one_use_public_key,
            response_created_at,
            Kind::GiftWrap,
            [Tag::parse([
                "p",
                &self.inviter_ephemeral_public_key.to_hex(),
            ])?],
            content,
        );
        let response_event = sign_event_with_rng(unsigned_response, &one_use_secret_key, rng)?;

        Ok(InviteAcceptance {
            session,
            response_event,
        })
    }

    /// Authenticate an invite response and initialize the inviter's session.
    ///
    /// This verifies both the invitee identity encryption and a Schnorr proof that the invitee
    /// controls the advertised session key before any session is constructed.
    ///
    /// This protocol layer is intentionally stateless. Before installing the returned session,
    /// callers must deduplicate `event.id` and enforce their invite-use, expiration, and revocation
    /// policy so a replayed response cannot replace an established session.
    pub fn process_response(
        &self,
        event: &Event,
        inviter_identity_secret: &SecretKey,
    ) -> Result<InviteResponse, Error> {
        let inviter_ephemeral_secret_key = self
            .inviter_ephemeral_secret_key
            .as_ref()
            .ok_or_else(|| missing("invite ephemeral secret key unavailable"))?;
        let secp = Secp256k1::new();
        let supplied_inviter = PublicKey::from_secret_key(&secp, inviter_identity_secret);
        if supplied_inviter != self.inviter {
            return Err(invalid("inviter identity secret key does not match invite"));
        }
        if event.kind != Kind::GiftWrap {
            return Err(invalid("invalid invite response kind"));
        }
        validate_encoded_payload_size(event.content.as_bytes())?;
        event.verify_with_ctx(&secp)?;
        validate_response_tags(event, self.inviter_ephemeral_public_key)?;

        let rumor_json =
            nip44::decrypt(inviter_ephemeral_secret_key, &event.pubkey, &event.content)?;
        let rumor = parse_rumor(rumor_json.as_bytes())?;
        validate_response_rumor(&rumor)?;

        let identity_encrypted = decrypt_conversation_key(&self.shared_secret, &rumor.content)?;
        let payload = nip44::decrypt(inviter_identity_secret, &rumor.pubkey, identity_encrypted)?;
        let payload = parse_response_payload(&payload)?;
        verify_session_proof(
            &payload,
            self.inviter,
            self.inviter_ephemeral_public_key,
            rumor.pubkey,
            &self.shared_secret,
        )?;
        let session = Session::new_responder(
            payload.session_key,
            inviter_ephemeral_secret_key.clone(),
            self.shared_secret,
        )?;

        Ok(InviteResponse {
            session,
            invitee_identity: rumor.pubkey,
        })
    }
}
