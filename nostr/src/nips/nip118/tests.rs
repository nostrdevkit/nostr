// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use alloc::vec::Vec;
use core::convert::Infallible;

use rand::rngs::Xoshiro256PlusPlus;
use rand::{SeedableRng, TryCryptoRng, TryRng};
use secp256k1::Secp256k1;

use super::wire::{parse_response_session_key, validate_response_tags};
use super::{INVITE_RESPONSE_TIMESTAMP_WINDOW, Invite};
use crate::error::ErrorKind;
use crate::event::{Event, Kind, Tag, UnsignedEvent};
use crate::key::{Keys, PublicKey, SecretKey};
use crate::nips::nip117::sign_event_with_rng;
use crate::types::Timestamp;

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
    assert!(Invite::from_public_parts(inviter.public_key(), invalid_public_key, [5; 32]).is_err());
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
        validate_response_tags(&response_with_pow, invite.inviter_ephemeral_public_key()).is_ok()
    );
    response_with_pow
        .tags
        .push(Tag::parse(["p", &invite.inviter_ephemeral_public_key().to_hex()]).unwrap());
    assert!(
        validate_response_tags(&response_with_pow, invite.inviter_ephemeral_public_key()).is_err()
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
    let event: Event =
        serde_json::from_str(include_str!("fixtures/typescript_invite_response.json")).unwrap();
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
