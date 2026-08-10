// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

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
        crate::util::hex_decode("4db1ab29554117b78d86d7d9bd5fdd984d2be52b91aba9f52ce25c4ca3ce3a81")
            .unwrap()
    );
    assert_eq!(
        second.0,
        crate::util::hex_decode("a47584fb3ffdb3cb4dc6a54071050f9bca4a18b19b2789e7f8278679275239bc")
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
    const EVENT: &str = include_str!("fixtures/typescript-first-event.json");

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
