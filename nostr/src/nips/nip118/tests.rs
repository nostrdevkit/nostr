// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use alloc::string::ToString;
use alloc::vec::Vec;
use core::convert::Infallible;

use rand::rngs::Xoshiro256PlusPlus;
use rand::{SeedableRng, TryCryptoRng, TryRng};
use secp256k1::Secp256k1;

use super::wire::{
    InviteResponsePayload, MAX_INVITE_URL_LENGTH, parse_response_payload, session_proof_digest,
    validate_response_tags, verify_session_proof,
};
use super::{INVITE_RESPONSE_TIMESTAMP_WINDOW, Invite};
use crate::error::ErrorKind;
use crate::event::{Event, Kind, Signature, Tag, UnsignedEvent};
use crate::key::{Keys, PublicKey, SecretKey};
use crate::nips::nip44::{self, Version};
use crate::nips::nip117::{encrypt_conversation_key_with_rng, sign_event_with_rng};
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

fn wrap_response_rumor(invite: &Invite, rumor_json: &str, rng: &mut TestRng) -> Event {
    let one_use_keys = keys(9);
    let content = nip44::encrypt_with_rng(
        one_use_keys.secret_key(),
        &invite.inviter_ephemeral_public_key(),
        rumor_json,
        Version::V2,
        rng,
    )
    .unwrap();
    let unsigned = UnsignedEvent::new(
        one_use_keys.public_key(),
        Timestamp::from_secs(100),
        Kind::GiftWrap,
        [Tag::parse(["p", &invite.inviter_ephemeral_public_key().to_hex()]).unwrap()],
        content,
    );
    sign_event_with_rng(unsigned, one_use_keys.secret_key(), rng).unwrap()
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
fn url_parser_bounds_untrusted_input() {
    let invite = owned_invite(&keys(1));
    let url = invite.to_url("https://example.com/").unwrap();
    let fragment = url.split_once('#').unwrap().1;
    let fixed_len = "https://example.com/".len() + 1 + fragment.len();
    let padding = "a".repeat(MAX_INVITE_URL_LENGTH - fixed_len);
    let boundary = format!("https://example.com/{padding}#{fragment}");
    assert_eq!(boundary.len(), MAX_INVITE_URL_LENGTH);
    assert!(Invite::from_url(&boundary).is_ok());

    let oversized = format!("https://example.com/{padding}a#{fragment}");
    assert_eq!(oversized.len(), MAX_INVITE_URL_LENGTH + 1);
    assert!(Invite::from_url(&oversized).is_err());

    let oversized_root = format!("https://example.com/{}", "a".repeat(MAX_INVITE_URL_LENGTH));
    assert!(invite.to_url(oversized_root).is_err());
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
fn response_rejects_oversized_content_before_decryption() {
    let inviter = keys(1);
    let invite = owned_invite(&inviter);
    let one_use_keys = keys(9);
    let oversized = "A".repeat(crate::nips::nip44::v2::MAX_ENCODED_PAYLOAD_SIZE + 4);
    let unsigned = UnsignedEvent::new(
        one_use_keys.public_key(),
        Timestamp::from_secs(100),
        Kind::GiftWrap,
        [Tag::parse(["p", &invite.inviter_ephemeral_public_key().to_hex()]).unwrap()],
        oversized,
    );
    let mut rng = TestRng::new(43);
    let response = sign_event_with_rng(unsigned, one_use_keys.secret_key(), &mut rng).unwrap();

    assert!(
        invite
            .process_response(&response, inviter.secret_key())
            .is_err()
    );
}

#[test]
fn response_rumor_rejects_signed_and_unknown_fields() {
    let inviter = keys(1);
    let invitee = keys(3);
    let invite = owned_invite(&inviter);
    let mut rng = TestRng::new(40);
    let acceptance = invite
        .accept_with_rng(&invitee, Timestamp::from_secs(100), &mut rng)
        .unwrap();
    let rumor_json = nip44::decrypt(
        invite.inviter_ephemeral_secret_key().unwrap(),
        &acceptance.response_event.pubkey,
        &acceptance.response_event.content,
    )
    .unwrap();

    for (field, value) in [
        (
            "sig",
            serde_json::Value::String(acceptance.response_event.sig.to_hex()),
        ),
        ("unexpected", serde_json::Value::Bool(true)),
    ] {
        let mut rumor: serde_json::Value = serde_json::from_str(&rumor_json).unwrap();
        rumor[field] = value;
        let response = wrap_response_rumor(&invite, &rumor.to_string(), &mut rng);
        assert!(
            invite
                .process_response(&response, inviter.secret_key())
                .is_err()
        );
    }
}

#[test]
fn session_proof_binds_all_context_and_requires_session_secret() {
    let inviter_identity = keys(1);
    let inviter_ephemeral = keys(2);
    let invitee_identity = keys(3);
    let session_keys = keys(4);
    let shared_secret = [5; 32];
    let mut rng = TestRng::new(41);
    let digest = session_proof_digest(
        inviter_identity.public_key(),
        inviter_ephemeral.public_key(),
        invitee_identity.public_key(),
        session_keys.public_key(),
        &shared_secret,
    );
    assert_eq!(
        faster_hex::hex_string(&digest),
        "e7d5fbafa8806383fd0f4a6db7f29eb87876560575659e8b30e3794706e8465a"
    );
    let proof = session_keys.sign_schnorr_with_rng(&Secp256k1::signing_only(), digest, &mut rng);
    let payload = InviteResponsePayload {
        session_key: session_keys.public_key(),
        session_proof: proof,
    };
    assert!(
        verify_session_proof(
            &payload,
            inviter_identity.public_key(),
            inviter_ephemeral.public_key(),
            invitee_identity.public_key(),
            &shared_secret,
        )
        .is_ok()
    );

    assert!(
        verify_session_proof(
            &payload,
            keys(6).public_key(),
            inviter_ephemeral.public_key(),
            invitee_identity.public_key(),
            &shared_secret,
        )
        .is_err()
    );
    assert!(
        verify_session_proof(
            &payload,
            inviter_identity.public_key(),
            keys(6).public_key(),
            invitee_identity.public_key(),
            &shared_secret,
        )
        .is_err()
    );
    assert!(
        verify_session_proof(
            &payload,
            inviter_identity.public_key(),
            inviter_ephemeral.public_key(),
            keys(6).public_key(),
            &shared_secret,
        )
        .is_err()
    );
    let changed_session_payload = InviteResponsePayload {
        session_key: keys(6).public_key(),
        session_proof: proof,
    };
    assert!(
        verify_session_proof(
            &changed_session_payload,
            inviter_identity.public_key(),
            inviter_ephemeral.public_key(),
            invitee_identity.public_key(),
            &shared_secret,
        )
        .is_err()
    );
    assert!(
        verify_session_proof(
            &payload,
            inviter_identity.public_key(),
            inviter_ephemeral.public_key(),
            invitee_identity.public_key(),
            &[6; 32],
        )
        .is_err()
    );
    let mut changed_proof = proof.to_bytes();
    changed_proof[0] ^= 1;
    let changed_proof_payload = InviteResponsePayload {
        session_key: session_keys.public_key(),
        session_proof: Signature::from_byte_array(changed_proof),
    };
    assert!(
        verify_session_proof(
            &changed_proof_payload,
            inviter_identity.public_key(),
            inviter_ephemeral.public_key(),
            invitee_identity.public_key(),
            &shared_secret,
        )
        .is_err()
    );

    // An attacker can observe the session public key and sign a transcript for their own identity,
    // but a signature made with any other secret cannot prove ownership of that observed key.
    let attacker_identity = keys(7);
    let attacker_signer = keys(8);
    let forged_digest = session_proof_digest(
        inviter_identity.public_key(),
        inviter_ephemeral.public_key(),
        attacker_identity.public_key(),
        session_keys.public_key(),
        &shared_secret,
    );
    let forged_payload = InviteResponsePayload {
        session_key: session_keys.public_key(),
        session_proof: attacker_signer.sign_schnorr_with_rng(
            &Secp256k1::signing_only(),
            forged_digest,
            &mut rng,
        ),
    };
    assert!(
        verify_session_proof(
            &forged_payload,
            inviter_identity.public_key(),
            inviter_ephemeral.public_key(),
            attacker_identity.public_key(),
            &shared_secret,
        )
        .is_err()
    );
}

#[test]
fn response_rejects_identity_claiming_observed_session_key_without_secret() {
    let inviter_identity = keys(1);
    let honest_invitee = keys(3);
    let attacker_identity = keys(7);
    let wrong_session_signer = keys(8);
    let invite = owned_invite(&inviter_identity);
    let mut rng = TestRng::new(42);
    let acceptance = invite
        .accept_with_rng(&honest_invitee, Timestamp::from_secs(100), &mut rng)
        .unwrap();
    let observed_session_key = acceptance.session.current_public_key().unwrap();

    let digest = session_proof_digest(
        inviter_identity.public_key(),
        invite.inviter_ephemeral_public_key(),
        attacker_identity.public_key(),
        observed_session_key,
        invite.shared_secret(),
    );
    let forged_payload = InviteResponsePayload {
        session_key: observed_session_key,
        session_proof: wrong_session_signer.sign_schnorr_with_rng(
            &Secp256k1::signing_only(),
            digest,
            &mut rng,
        ),
    };
    let identity_encrypted = nip44::encrypt_with_rng(
        attacker_identity.secret_key(),
        &inviter_identity.public_key(),
        serde_json::to_string(&forged_payload).unwrap(),
        Version::V2,
        &mut rng,
    )
    .unwrap();
    let content =
        encrypt_conversation_key_with_rng(invite.shared_secret(), identity_encrypted, &mut rng)
            .unwrap();
    let mut rumor = UnsignedEvent::new(
        attacker_identity.public_key(),
        Timestamp::from_secs(100),
        Kind::DoubleRatchetMessage,
        Vec::<Tag>::new(),
        content,
    );
    rumor.ensure_id();
    let response = wrap_response_rumor(&invite, &serde_json::to_string(&rumor).unwrap(), &mut rng);

    assert!(
        invite
            .process_response(&response, inviter_identity.secret_key())
            .is_err()
    );
}

#[test]
fn response_payload_requires_proof_but_allows_extensions() {
    let session_key = keys(6).public_key();
    let proof = Signature::from_byte_array([7; 64]);
    let payload = format!(r#"{{"sessionKey":"{session_key}","sessionProof":"{proof}"}}"#);
    assert_eq!(
        parse_response_payload(&payload).unwrap().session_key,
        session_key
    );

    let proofless = format!(r#"{{"sessionKey":"{session_key}"}}"#);
    assert!(parse_response_payload(&proofless).is_err());
    assert!(parse_response_payload(&session_key.to_hex()).is_err());
    let extended = format!(
        r#"{{"sessionKey":"{session_key}","sessionProof":"{proof}","ownerPublicKey":"{}"}}"#,
        keys(8).public_key()
    );
    assert_eq!(
        parse_response_payload(&extended).unwrap().session_key,
        session_key
    );
}

#[test]
fn processes_proof_bearing_typescript_invite_response_vector() {
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
                "0e47314393a07008e3a800d98122d516cc1213e990534dbe88ca81f078d911f1"
            )
            .unwrap()
        )
    );
}
