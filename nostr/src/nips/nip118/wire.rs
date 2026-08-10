// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use alloc::string::{String, ToString};

use bitcoin_hashes::{HashEngine, sha256};
use secp256k1::Secp256k1;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use super::Invite;
use crate::error::{Error, ErrorKind};
use crate::event::{Event, Kind, Signature, Tag, UnsignedEvent};
use crate::key::{PublicKey, SecretKey};
use crate::types::Timestamp;
use crate::types::url::{Url, form_urlencoded};

const INVITE_TAG_PREFIX: &str = "double-ratchet/invites/";
const INVITE_LABEL: &str = "double-ratchet/invites";
const SESSION_PROOF_DOMAIN: &[u8] = b"NIP-118/session-proof/v1";
pub(super) const MAX_INVITE_URL_LENGTH: usize = 4096;

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
pub(super) struct InviteResponsePayload {
    pub(super) session_key: PublicKey,
    pub(super) session_proof: Signature,
}

impl Invite {
    /// Encode this invite in the fragment of an absolute URL.
    ///
    /// The fragment contains the shared secret. Although fragments are not normally sent to the
    /// web server, the complete URL is sensitive. Deliver private invite URLs through a channel
    /// that authenticates the inviter; the URL itself is unsigned and accepting it reveals the
    /// invitee's identity to whoever controls the invite.
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
        let url = url.to_string();
        if url.len() > MAX_INVITE_URL_LENGTH {
            return Err(invalid("invite URL is too large"));
        }
        Ok(url)
    }

    /// Parse an acceptor-side invite from a URL fragment.
    ///
    /// This rejects URLs larger than 4096 bytes before parsing to bound work on untrusted input.
    pub fn from_url<S>(url: S) -> Result<Self, Error>
    where
        S: AsRef<str>,
    {
        let input = url.as_ref();
        if input.len() > MAX_INVITE_URL_LENGTH {
            return Err(invalid("invite URL is too large"));
        }
        let url = Url::parse(input).map_err(Error::malformed)?;
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
}

pub(super) fn validate_response_tags(
    event: &Event,
    expected_recipient: PublicKey,
) -> Result<(), Error> {
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

pub(super) fn validate_response_rumor(rumor: &UnsignedEvent) -> Result<(), Error> {
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

pub(super) fn parse_response_payload(payload: &str) -> Result<InviteResponsePayload, Error> {
    let payload: InviteResponsePayload = serde_json::from_str(payload)?;
    validate_public_key(payload.session_key, "invalid invitee session public key")?;
    Ok(payload)
}

/// Hash the canonical NIP-118 session-key proof transcript.
///
/// The preimage is the ASCII domain `NIP-118/session-proof/v1`, followed by five fixed-width
/// 32-byte values in this order: inviter identity x-only public key, inviter ephemeral x-only
/// public key, invitee identity x-only public key, invitee session x-only public key, and shared
/// secret. No separators or text encodings are present.
pub(super) fn session_proof_digest(
    inviter_identity: PublicKey,
    inviter_ephemeral: PublicKey,
    invitee_identity: PublicKey,
    session_key: PublicKey,
    shared_secret: &[u8; 32],
) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(SESSION_PROOF_DOMAIN);
    engine.input(inviter_identity.as_bytes());
    engine.input(inviter_ephemeral.as_bytes());
    engine.input(invitee_identity.as_bytes());
    engine.input(session_key.as_bytes());
    engine.input(shared_secret);
    engine.finalize().to_byte_array()
}

pub(super) fn verify_session_proof(
    payload: &InviteResponsePayload,
    inviter_identity: PublicKey,
    inviter_ephemeral: PublicKey,
    invitee_identity: PublicKey,
    shared_secret: &[u8; 32],
) -> Result<(), Error> {
    let session_key = payload
        .session_key
        .xonly()
        .map_err(|_| invalid("invalid invitee session public key"))?;
    let digest = session_proof_digest(
        inviter_identity,
        inviter_ephemeral,
        invitee_identity,
        payload.session_key,
        shared_secret,
    );
    Secp256k1::verification_only()
        .verify_schnorr(payload.session_proof.as_secp256k1(), &digest, &session_key)
        .map_err(|_| invalid("invalid invite session proof"))
}

pub(super) fn validate_public_key(
    public_key: PublicKey,
    message: &'static str,
) -> Result<(), Error> {
    public_key.xonly().map(|_| ()).map_err(|_| invalid(message))
}

#[inline]
pub(super) fn invalid(message: &'static str) -> Error {
    Error::with_static_message(ErrorKind::Invalid, message)
}

#[inline]
pub(super) fn missing(message: &'static str) -> Error {
    Error::with_static_message(ErrorKind::Missing, message)
}

pub(super) mod serde_shared_secret {
    use super::*;

    pub(in crate::nips::nip118) fn serialize<S>(
        secret: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Zeroizing::new(faster_hex::hex_string(secret));
        serializer.serialize_str(&encoded)
    }

    pub(in crate::nips::nip118) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut encoded = String::deserialize(deserializer)?;
        let decoded = crate::util::hex_decode(&encoded).map_err(serde::de::Error::custom);
        encoded.zeroize();
        decoded
    }
}

pub(super) mod serde_optional_secret_key {
    use super::*;

    pub(in crate::nips::nip118) fn serialize<S>(
        secret: &Option<SecretKey>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match secret {
            Some(secret) => {
                let encoded = Zeroizing::new(secret.to_secret_hex());
                serializer.serialize_some(encoded.as_str())
            }
            None => serializer.serialize_none(),
        }
    }

    pub(in crate::nips::nip118) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<SecretKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|mut secret| {
                let decoded = SecretKey::from_hex(&secret).map_err(serde::de::Error::custom);
                secret.zeroize();
                decoded
            })
            .transpose()
    }
}
