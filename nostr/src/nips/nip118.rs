// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-118: Nostr Double Ratchet Invites
//!
//! <https://github.com/nostr-protocol/nips/pull/1813>
//!
//! This module implements the protocol-level invite and response handshake. It
//! intentionally does not implement invite-use policy, persistence management,
//! device rosters, or session management.
//!
//! # Workflow
//!
//! The inviter creates and stores an owned [`Invite`], then shares a private URL or signs and
//! publishes its public invite event. The invitee parses it and calls [`Invite::accept_with_rng`],
//! stores the returned session with the response event, and publishes that event. After applying
//! replay and invite-use policy, the inviter calls [`Invite::process_response`]. The invitee is
//! the session initiator and sends the first kind `1060` message.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use rand::{CryptoRng, Rng, RngExt};
use secp256k1::Secp256k1;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use super::nip117::{
    Session, decrypt_conversation_key, encrypt_conversation_key_with_rng,
    random_secret_key_with_rng, sign_event_with_rng,
};
use crate::error::{Error, ErrorKind};
use crate::event::{Event, Kind, Tag, UnsignedEvent};
use crate::key::{Keys, PublicKey, SecretKey};
use crate::nips::nip44::{self, Version};
use crate::types::Timestamp;
use crate::types::url::{Url, form_urlencoded};

const INVITE_TAG_PREFIX: &str = "double-ratchet/invites/";
const INVITE_LABEL: &str = "double-ratchet/invites";
const INVITE_RESPONSE_TIMESTAMP_WINDOW: u64 = 2 * 24 * 60 * 60;

/// A NIP-118 invitation to establish a NIP-117 session.
///
/// Invitations created locally own the ephemeral secret key needed to process
/// responses. Invitations parsed from a URL or event retain the shared secret,
/// but not the inviter's ephemeral secret key; they can be accepted, but cannot
/// process a response. A private invite URL is sensitive capability material,
/// while a published invite event exposes its shared secret publicly.
///
/// The serialized representation of an owned invite contains both the
/// ephemeral secret key and the shared secret and must be stored securely.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Invite {
    inviter: PublicKey,
    inviter_ephemeral_public_key: PublicKey,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_optional_secret_key"
    )]
    inviter_ephemeral_secret_key: Option<SecretKey>,
    #[serde(with = "serde_shared_secret")]
    shared_secret: [u8; 32],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InviteData {
    inviter: PublicKey,
    inviter_ephemeral_public_key: PublicKey,
    #[serde(default, with = "serde_optional_secret_key")]
    inviter_ephemeral_secret_key: Option<SecretKey>,
    #[serde(with = "serde_shared_secret")]
    shared_secret: [u8; 32],
}

impl Drop for InviteData {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl<'de> Deserialize<'de> for Invite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = InviteData::deserialize(deserializer)?;
        validate_public_key(data.inviter, "invalid inviter public key")
            .map_err(serde::de::Error::custom)?;
        validate_public_key(
            data.inviter_ephemeral_public_key,
            "invalid invite ephemeral public key",
        )
        .map_err(serde::de::Error::custom)?;

        if let Some(secret_key) = &data.inviter_ephemeral_secret_key {
            let secp = Secp256k1::signing_only();
            let derived = PublicKey::from_secret_key(&secp, secret_key);
            if derived != data.inviter_ephemeral_public_key {
                return Err(serde::de::Error::custom(
                    "invite ephemeral public and secret keys do not match",
                ));
            }
        }

        Ok(Self {
            inviter: data.inviter,
            inviter_ephemeral_public_key: data.inviter_ephemeral_public_key,
            inviter_ephemeral_secret_key: data.inviter_ephemeral_secret_key.clone(),
            shared_secret: data.shared_secret,
        })
    }
}

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
    /// The authenticated Nostr identity of the invitee.
    pub invitee_identity: PublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteUrlData {
    inviter: PublicKey,
    #[serde(alias = "inviterEphemeralPublicKey")]
    ephemeral_key: PublicKey,
    #[serde(with = "serde_shared_secret")]
    shared_secret: [u8; 32],
}

impl Drop for InviteUrlData {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteResponsePayload {
    session_key: PublicKey,
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

    /// Encode this invite in the fragment of an absolute URL.
    ///
    /// The fragment contains the shared secret. Although fragments are not
    /// normally sent to the web server, the complete URL is sensitive.
    pub fn to_url<S>(&self, root: S) -> Result<String, Error>
    where
        S: AsRef<str>,
    {
        let data = InviteUrlData {
            inviter: self.inviter,
            ephemeral_key: self.inviter_ephemeral_public_key,
            shared_secret: self.shared_secret,
        };
        let json = serde_json::to_string(&data)?;
        let encoded: String = form_urlencoded::byte_serialize(json.as_bytes()).collect();
        let mut url = Url::parse(root.as_ref()).map_err(Error::malformed)?;
        url.set_fragment(Some(&encoded));
        Ok(url.to_string())
    }

    /// Parse an acceptor-side invite from a URL fragment.
    pub fn from_url<S>(url: S) -> Result<Self, Error>
    where
        S: AsRef<str>,
    {
        let url = Url::parse(url.as_ref()).map_err(Error::malformed)?;
        let fragment = url
            .fragment()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                Error::with_static_message(ErrorKind::Missing, "invite URL fragment missing")
            })?;
        let prefixed = format!("invite={fragment}");
        let mut parts = form_urlencoded::parse(prefixed.as_bytes());
        let (key, decoded) = parts.next().ok_or_else(|| {
            Error::with_static_message(ErrorKind::Malformed, "invalid invite URL fragment")
        })?;
        if key != "invite" || parts.next().is_some() {
            return Err(Error::with_static_message(
                ErrorKind::Malformed,
                "invalid invite URL fragment",
            ));
        }

        let data: InviteUrlData = serde_json::from_str(decoded.as_ref())?;
        validate_public_key(data.inviter, "invalid inviter public key")?;
        validate_public_key(data.ephemeral_key, "invalid invite ephemeral public key")?;
        Self::from_public_parts(data.inviter, data.ephemeral_key, data.shared_secret)
    }

    /// Build an unsigned public invite event.
    ///
    /// The inviter must sign the returned event before publication.
    pub fn to_unsigned_event<S>(
        &self,
        identifier: S,
        created_at: Timestamp,
    ) -> Result<UnsignedEvent, Error>
    where
        S: AsRef<str>,
    {
        let identifier = identifier.as_ref();
        if identifier.is_empty() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "invite identifier must not be empty",
            ));
        }

        let tags = [
            Tag::parse(["d", &format!("{INVITE_TAG_PREFIX}{identifier}")])?,
            Tag::parse(["l", INVITE_LABEL])?,
            Tag::parse(["ephemeralKey", &self.inviter_ephemeral_public_key.to_hex()])?,
            Tag::parse(["sharedSecret", &faster_hex::hex_string(&self.shared_secret)])?,
        ];
        Ok(UnsignedEvent::new(
            self.inviter,
            created_at,
            Kind::ApplicationSpecificData,
            tags,
            "",
        ))
    }

    /// Parse and verify an acceptor-side invite from a signed event.
    pub fn from_event(event: &Event) -> Result<Self, Error> {
        if event.kind != Kind::ApplicationSpecificData {
            return Err(invalid("invalid invite event kind"));
        }
        if !event.content.is_empty() {
            return Err(invalid("invite event content must be empty"));
        }
        let secp = Secp256k1::verification_only();
        event.verify_with_ctx(&secp)?;
        validate_public_key(event.pubkey, "invalid inviter public key")?;

        let mut d_tag = None;
        let mut label_tag = None;
        let mut ephemeral_key = None;
        let mut shared_secret = None;
        for tag in event.tags.iter() {
            match tag.kind() {
                "d" | "l" | "ephemeralKey" | "sharedSecret" => {
                    if tag.len() != 2 {
                        return Err(invalid("invalid invite event tag"));
                    }
                    let value = tag
                        .content()
                        .ok_or_else(|| invalid("invalid invite event tag"))?;
                    let duplicate = match tag.kind() {
                        "d" => d_tag.replace(value).is_some(),
                        "l" => label_tag.replace(value).is_some(),
                        "ephemeralKey" => ephemeral_key.replace(value).is_some(),
                        "sharedSecret" => shared_secret.replace(value).is_some(),
                        _ => false,
                    };
                    if duplicate {
                        return Err(invalid("duplicate invite event tag"));
                    }
                }
                _ => {}
            }
        }

        let d_tag = d_tag.ok_or_else(|| missing("invite d tag missing"))?;
        if d_tag
            .strip_prefix(INVITE_TAG_PREFIX)
            .filter(|identifier| !identifier.is_empty())
            .is_none()
        {
            return Err(invalid("invalid invite d tag"));
        }
        if label_tag != Some(INVITE_LABEL) {
            return Err(invalid("invalid invite label tag"));
        }
        let inviter_ephemeral_public_key = PublicKey::from_hex(
            ephemeral_key.ok_or_else(|| missing("invite ephemeralKey tag missing"))?,
        )?;
        validate_public_key(
            inviter_ephemeral_public_key,
            "invalid invite ephemeral public key",
        )?;
        let shared_secret = crate::util::hex_decode(
            shared_secret.ok_or_else(|| missing("invite sharedSecret tag missing"))?,
        )?;

        Self::from_public_parts(event.pubkey, inviter_ephemeral_public_key, shared_secret)
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
        let session = Session::new_initiator_with_rng(
            self.inviter_ephemeral_public_key,
            invitee_session_secret_key,
            self.shared_secret,
            rng,
        )?;

        let payload = serde_json::to_string(&InviteResponsePayload {
            session_key: invitee_session_public_key,
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
        event.verify_with_ctx(&secp)?;
        validate_response_tags(event, self.inviter_ephemeral_public_key)?;

        let rumor_json =
            nip44::decrypt(inviter_ephemeral_secret_key, &event.pubkey, &event.content)?;
        let rumor: UnsignedEvent = serde_json::from_str(&rumor_json)?;
        validate_response_rumor(&rumor)?;

        let identity_encrypted = decrypt_conversation_key(&self.shared_secret, &rumor.content)?;
        let payload = nip44::decrypt(inviter_identity_secret, &rumor.pubkey, identity_encrypted)?;
        let invitee_session_public_key = parse_response_session_key(&payload)?;
        let session = Session::new_responder(
            invitee_session_public_key,
            inviter_ephemeral_secret_key.clone(),
            self.shared_secret,
        )?;

        Ok(InviteResponse {
            session,
            invitee_identity: rumor.pubkey,
        })
    }
}

fn validate_response_tags(event: &Event, expected_recipient: PublicKey) -> Result<(), Error> {
    let mut recipient_tags = event.tags.iter().filter(|tag| tag.kind() == "p");
    let tag = recipient_tags
        .next()
        .ok_or_else(|| missing("invite response p tag missing"))?;
    if recipient_tags.next().is_some() {
        return Err(invalid("invite response must contain exactly one p tag"));
    }
    if tag.len() != 2 || tag.kind() != "p" {
        return Err(invalid("invalid invite response p tag"));
    }
    let recipient = PublicKey::from_hex(
        tag.content()
            .ok_or_else(|| missing("invite response recipient missing"))?,
    )?;
    if recipient != expected_recipient {
        return Err(invalid("invite response recipient does not match invite"));
    }
    Ok(())
}

fn validate_response_rumor(rumor: &UnsignedEvent) -> Result<(), Error> {
    if rumor.id.is_none() {
        return Err(missing("invite response rumor ID missing"));
    }
    rumor.verify_id()?;
    if rumor.kind != Kind::DoubleRatchetMessage {
        return Err(invalid("invalid invite response rumor kind"));
    }
    if !rumor.tags.is_empty() {
        return Err(invalid("invite response rumor tags must be empty"));
    }
    if rumor.content.is_empty() {
        return Err(invalid("invite response rumor content must not be empty"));
    }
    validate_public_key(rumor.pubkey, "invalid invitee identity public key")
}

fn parse_response_session_key(payload: &str) -> Result<PublicKey, Error> {
    let session_key = match serde_json::from_str::<InviteResponsePayload>(payload) {
        Ok(payload) => payload.session_key,
        Err(_) => PublicKey::from_hex(payload)?,
    };
    validate_public_key(session_key, "invalid invitee session public key")?;
    Ok(session_key)
}

fn validate_public_key(public_key: PublicKey, message: &'static str) -> Result<(), Error> {
    public_key.xonly().map(|_| ()).map_err(|_| invalid(message))
}

#[inline]
fn invalid(message: &'static str) -> Error {
    Error::with_static_message(ErrorKind::Invalid, message)
}

#[inline]
fn missing(message: &'static str) -> Error {
    Error::with_static_message(ErrorKind::Missing, message)
}

mod serde_shared_secret {
    use super::*;

    pub(super) fn serialize<S>(secret: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&faster_hex::hex_string(secret))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        crate::util::hex_decode(&encoded).map_err(serde::de::Error::custom)
    }
}

mod serde_optional_secret_key {
    use super::*;

    pub(super) fn serialize<S>(secret: &Option<SecretKey>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match secret {
            Some(secret) => serializer.serialize_some(&secret.to_secret_hex()),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<SecretKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|secret| SecretKey::from_hex(&secret).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
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

    fn keys(byte: u8) -> Keys {
        Keys::new_with_ctx(
            &Secp256k1::signing_only(),
            SecretKey::from_slice(&[byte; 32]).unwrap(),
        )
    }

    fn owned_invite(inviter: &Keys) -> Invite {
        Invite::from_owned_parts(
            inviter.public_key(),
            SecretKey::from_slice(&[2; 32]).unwrap(),
            [5; 32],
        )
        .unwrap()
    }

    #[test]
    fn persistence_roundtrip_and_debug_redact_secrets() {
        let inviter = keys(1);
        let invite = owned_invite(&inviter);
        let serialized = serde_json::to_string(&invite).unwrap();
        let restored: Invite = serde_json::from_str(&serialized).unwrap();
        assert_eq!(restored, invite);

        let debug = format!("{invite:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&SecretKey::from_slice(&[2; 32]).unwrap().to_secret_hex()));
        assert!(!debug.contains(&faster_hex::hex_string(&[5; 32])));

        let mut mismatched = serde_json::to_value(&invite).unwrap();
        mismatched["inviterEphemeralPublicKey"] =
            serde_json::Value::String(keys(7).public_key().to_hex());
        assert!(serde_json::from_value::<Invite>(mismatched).is_err());

        let invalid_public_key = PublicKey::from_byte_array([0xff; 32]);
        assert!(
            Invite::from_public_parts(inviter.public_key(), invalid_public_key, [5; 32]).is_err()
        );
    }

    #[test]
    fn url_and_event_roundtrip() {
        let inviter = keys(1);
        let invite = owned_invite(&inviter);

        let url = invite.to_url("https://example.com/chat").unwrap();
        assert!(url.contains("#%7B%22inviter%22"));
        assert!(!url.contains("%257B"));
        let from_url = Invite::from_url(&url).unwrap();
        assert_eq!(from_url.inviter(), invite.inviter());
        assert_eq!(
            from_url.inviter_ephemeral_public_key(),
            invite.inviter_ephemeral_public_key()
        );
        assert_eq!(from_url.shared_secret(), invite.shared_secret());
        assert!(from_url.inviter_ephemeral_secret_key().is_none());

        let mut rng = TestRng::new(1);
        let event = sign_event_with_rng(
            invite
                .to_unsigned_event("primary", Timestamp::from_secs(1_700_000_000))
                .unwrap(),
            inviter.secret_key(),
            &mut rng,
        )
        .unwrap();
        let from_event = Invite::from_event(&event).unwrap();
        assert_eq!(from_event, from_url);

        assert_eq!(event.tags.len(), 4);
        assert_eq!(event.tags[0].kind(), "d");
        assert_eq!(
            event.tags[0].content(),
            Some("double-ratchet/invites/primary")
        );
        assert_eq!(event.tags[1].kind(), "l");
        assert_eq!(event.tags[1].content(), Some("double-ratchet/invites"));
        assert_eq!(event.tags[2].kind(), "ephemeralKey");
        assert_eq!(
            event.tags[2].content(),
            Some(invite.inviter_ephemeral_public_key().to_hex().as_str())
        );
        assert_eq!(event.tags[3].kind(), "sharedSecret");
        assert_eq!(
            event.tags[3].content(),
            Some(faster_hex::hex_string(&[5; 32]).as_str())
        );
    }

    #[test]
    fn event_parser_rejects_tampering_and_duplicate_protocol_tags() {
        let inviter = keys(1);
        let invite = owned_invite(&inviter);
        let mut rng = TestRng::new(2);

        let mut event = sign_event_with_rng(
            invite
                .to_unsigned_event("primary", Timestamp::from_secs(1))
                .unwrap(),
            inviter.secret_key(),
            &mut rng,
        )
        .unwrap();
        event.content.push('x');
        assert!(Invite::from_event(&event).is_err());

        let mut unsigned = invite
            .to_unsigned_event("primary", Timestamp::from_secs(1))
            .unwrap();
        unsigned.tags.push(Tag::parse(["extra", "value"]).unwrap());
        let event = sign_event_with_rng(unsigned, inviter.secret_key(), &mut rng).unwrap();
        assert!(Invite::from_event(&event).is_ok());

        let mut unsigned = invite
            .to_unsigned_event("primary", Timestamp::from_secs(1))
            .unwrap();
        unsigned
            .tags
            .push(Tag::parse(["d", "double-ratchet/invites/duplicate"]).unwrap());
        let event = sign_event_with_rng(unsigned, inviter.secret_key(), &mut rng).unwrap();
        assert!(Invite::from_event(&event).is_err());
    }

    #[test]
    fn response_bootstraps_first_session_message() {
        let inviter = keys(1);
        let invitee = keys(3);
        let invite = owned_invite(&inviter);
        let timestamp = Timestamp::from_secs(1_700_000_000);
        let mut rng = TestRng::new(3);

        let acceptance = invite
            .accept_with_rng(&invitee, timestamp, &mut rng)
            .unwrap();
        acceptance
            .response_event
            .verify_with_ctx(&Secp256k1::verification_only())
            .unwrap();
        assert_eq!(acceptance.response_event.kind, Kind::GiftWrap);
        assert!(acceptance.response_event.created_at <= timestamp);
        assert!(
            acceptance.response_event.created_at.as_secs()
                >= timestamp
                    .as_secs()
                    .saturating_sub(INVITE_RESPONSE_TIMESTAMP_WINDOW)
        );

        let response = invite
            .process_response(&acceptance.response_event, inviter.secret_key())
            .unwrap();
        assert_eq!(response.invitee_identity, invitee.public_key());

        let mut response_with_pow = acceptance.response_event.clone();
        response_with_pow
            .tags
            .push(Tag::parse(["nonce", "1", "1"]).unwrap());
        assert!(
            validate_response_tags(&response_with_pow, invite.inviter_ephemeral_public_key())
                .is_ok()
        );
        response_with_pow
            .tags
            .push(Tag::parse(["p", &invite.inviter_ephemeral_public_key().to_hex()]).unwrap());
        assert!(
            validate_response_tags(&response_with_pow, invite.inviter_ephemeral_public_key())
                .is_err()
        );

        let mut rumor = UnsignedEvent::new(
            invitee.public_key(),
            Timestamp::from_secs(1_700_000_001),
            Kind::TextNote,
            Vec::<Tag>::new(),
            "hello after invite",
        );
        rumor.ensure_id();
        let mut invitee_session = acceptance.session;
        let mut inviter_session = response.session;
        let message = invitee_session
            .send_message_with_rng(rumor, Timestamp::from_secs(1_700_000_002), &mut rng)
            .unwrap();
        let received = inviter_session
            .receive_message_with_rng(&message, &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(received.pubkey, invitee.public_key());
        assert_eq!(received.kind, Kind::TextNote);
        assert_eq!(received.content, "hello after invite");
    }

    #[test]
    fn response_rejects_wrong_keys_tampering_and_public_only_invite() {
        let inviter = keys(1);
        let invitee = keys(3);
        let wrong_identity = keys(4);
        let invite = owned_invite(&inviter);
        let mut rng = TestRng::new(4);
        let acceptance = invite
            .accept_with_rng(&invitee, Timestamp::from_secs(100), &mut rng)
            .unwrap();

        assert!(
            invite
                .process_response(&acceptance.response_event, wrong_identity.secret_key())
                .is_err()
        );

        let mut tampered = acceptance.response_event.clone();
        tampered.content.push('x');
        assert!(
            invite
                .process_response(&tampered, inviter.secret_key())
                .is_err()
        );

        let wrong_shared_secret = Invite::from_owned_parts(
            inviter.public_key(),
            SecretKey::from_slice(&[2; 32]).unwrap(),
            [9; 32],
        )
        .unwrap();
        assert!(
            wrong_shared_secret
                .process_response(&acceptance.response_event, inviter.secret_key())
                .is_err()
        );

        let public_only = Invite::from_public_parts(
            invite.inviter(),
            invite.inviter_ephemeral_public_key(),
            *invite.shared_secret(),
        )
        .unwrap();
        let error = public_only
            .process_response(&acceptance.response_event, inviter.secret_key())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Missing);

        let other_invite = Invite::from_owned_parts(
            inviter.public_key(),
            SecretKey::from_slice(&[7; 32]).unwrap(),
            [5; 32],
        )
        .unwrap();
        let other_response = other_invite
            .accept_with_rng(&invitee, Timestamp::from_secs(100), &mut rng)
            .unwrap()
            .response_event;
        assert!(
            invite
                .process_response(&other_response, inviter.secret_key())
                .is_err()
        );
    }

    #[test]
    fn response_payload_accepts_deployed_extension_and_legacy_plaintext() {
        let session_key = keys(6).public_key();
        let extended = format!(
            r#"{{"sessionKey":"{}","ownerPublicKey":"{}"}}"#,
            session_key,
            keys(8).public_key()
        );
        assert_eq!(parse_response_session_key(&extended).unwrap(), session_key);
        assert_eq!(
            parse_response_session_key(&session_key.to_hex()).unwrap(),
            session_key
        );
    }

    #[test]
    fn processes_typescript_invite_response_vector() {
        const RESPONSE_EVENT: &str = r#"{
          "kind": 1059,
          "pubkey": "d1d530e406de1b7cba221208598c8812c8b3e660615ceee1778fefbecf792e28",
          "content": "Am9r/nq63KpvIw/YlsF3yMDA+9WIL9K6bvgE18xs9r4UFrJFgAMqY4DcDum9pzxMvj2hQ0zqiOlzu5c9/6udHfC/i+PCPsNdg6hQihqYRE0nQAXaLvxZAOWAeV+Gyc4dlrPLgzK4S8PJOOeC0yrTtTYAO/t5+HvOWQTqPUz+0GsEWXaUDKZ8dA9k5vX470QHvtOncWdkAyBRGdAptkyp8Q1KOjfh9yqMMRZRqXjenV5Kyj3uZOrGLndpsxtQZZoxCf3ofCIwPOR6nM0L4bopAHG/jlYcF6reXthTeS5B3usjE0oDooLu4/RY+xwBFiDSXC3AffbJMF+uaiFjSuERDIILe74XHUIDy7GcvhbFwLmYRCXcc7ocx7pLIZaP19suaBo2m7fxewQSJDStyhY2p3DS0ItrbRizMwwry0W/pUSOq65/l05I6+XKT2ZzJYIz1T67Dy74okTVqvyK3ITuNdFcqhRvcUsueqzia89Yfb5gUvcqUd16qhuPin+cA/yV5JApqT+eRqpPwpuAnc1SdeaedtsSsWNcxqtgwH0po6ydz3joZ+A2trWS4ubesK+p8BPFuCbAqcDBhcU/A1VVC8u6CUSwxfrklJAUIM8Xcb5R66zJl/TEvw+2MTwZS/f62dFGjv+502W/q9LogvNsBlAmsvG2/HD4FN/5SAIngD/ewg5DkI/TfReblveMmIVdG7ARmrI6HvvIpZyT944WfdChv2fY+B2vRUDCBNWSgCU3yajZxow9A1cDo0OOhYgnBtVlett0TjwYTpnfWR6vvUIt4zqwZ6JF2P/eMFo3C6qffqY0V88PjA5vfkg5GZsumI4Kv0Xio7RNXH8cj3y5KxLqzMQH//tej8rW5KLBLCtGV7Yu4rgKgYvdpngxHpXJkd5Gj0yfzG8C4tlblOmY9/jkeaeWw8sG37yQjosW/cDyVtxCjrdnjaWg1ehlcrYeG4w+8RYXZTdiHsQL75fIQ6xR4IedQqbk3MN7bl89EcsbL7CbbiaMAAbJG5jwtRQAzs7GW4FjjYlxH+7xDy/dFGc+mO4OLtX9ADBM4gSEialH2IomiM5EPXRug5I2ojwUsbpc+30yp3vO0jijrl73mcsAbJSB5yvD/zDrAI4gT2vVcwofQbi7pdTfhGe1Qe+yH7iPx7i8/FdP9GFlOsx9tMlKcKxrlRBKLUBmc1WPVBjwMdCjSSh9ib1cm0IZSlckdPaJA8zA1IW6/OwOog/oUjKMVIkjRlaEB/VMIA2VBnOVUyqPKXG4DG8oNyf8eJyaICaj",
          "created_at": 1782876705,
          "tags": [["p", "466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"]],
          "id": "195a235d91ab72ebb7f82fad9a11f5439c5b920f83e3629e3733a7528e14e7a8",
          "sig": "7b7a3fa68cc648deedfa178f5bb576e5de3ea8491717c2d42558caad45ad95e726434b96fe9e801272a68ec2ff55db0d68a3afd7430727099d35bdf2ff6b2054"
        }"#;

        let inviter = Keys::new_with_ctx(
            &Secp256k1::signing_only(),
            SecretKey::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
        );
        let invite = Invite::from_owned_parts(
            inviter.public_key(),
            SecretKey::from_hex("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap(),
            [0x55; 32],
        )
        .unwrap();
        let event: Event = serde_json::from_str(RESPONSE_EVENT).unwrap();
        let response = invite
            .process_response(&event, inviter.secret_key())
            .unwrap();

        assert_eq!(
            response.invitee_identity,
            PublicKey::from_hex("3c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1")
                .unwrap()
        );
        assert!(
            response.session.remote_public_keys().contains(
                &PublicKey::from_hex(
                    "41e59453e9f97f8495c9e32ddee73f52ed8dd6f5c00f83d88737762b251469ac"
                )
                .unwrap()
            )
        );
    }
}
