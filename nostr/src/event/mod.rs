// Copyright (c) 2021 Paul Miller
// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Event

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::String;
use core::any::Any;
use core::cmp::Ordering;
use core::fmt;
use core::fmt::Debug;
use core::future::Future;
use core::hash::{Hash, Hasher};
use core::pin::Pin;

use secp256k1::{Secp256k1, Verification};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod builder;
mod id;
mod kind;
mod signature;
mod tag;
mod unsigned;

pub use self::builder::*;
pub use self::id::*;
pub use self::kind::*;
pub use self::signature::*;
pub use self::tag::*;
pub use self::unsigned::*;
use crate::error::{Error, ErrorKind};
use crate::key::PublicKey;
use crate::nips::nip01::{Coordinate, Metadata};
use crate::nips::nip19::{Nip19Event, ToBech32};
use crate::nips::nip21::ToNostrUri;
use crate::types::Timestamp;
#[cfg(feature = "std")]
use crate::util::SECP256K1;
use crate::util::impl_json_methods;

const ID: &str = "id";
const PUBKEY: &str = "pubkey";
const CREATED_AT: &str = "created_at";
const KIND: &str = "kind";
const TAGS: &str = "tags";
const CONTENT: &str = "content";
const SIG: &str = "sig";

/// Nostr event
#[derive(Clone)]
#[non_exhaustive] // In the future private fields may be added, so force event construction with `Event::new`.
pub struct Event {
    /// ID
    pub id: EventId,
    /// Author
    pub pubkey: PublicKey,
    /// UNIX timestamp (seconds)
    pub created_at: Timestamp,
    /// Kind
    pub kind: Kind,
    /// Tag list
    pub tags: Tags,
    /// Content
    pub content: String,
    /// Signature
    pub sig: Signature,
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Event")
            .field(ID, &self.id)
            .field(PUBKEY, &self.pubkey)
            .field(CREATED_AT, &self.created_at)
            .field(KIND, &self.kind)
            .field(TAGS, &self.tags)
            .field(CONTENT, &self.content)
            .field(SIG, &self.sig)
            .finish()
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.pubkey == other.pubkey
            && self.created_at == other.created_at
            && self.kind == other.kind
            && self.tags == other.tags
            && self.content == other.content
            && self.sig == other.sig
    }
}

impl Eq for Event {}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.created_at != other.created_at {
            // Descending order
            // NOT EDIT, will break many things!!
            // If the change is required, search for EVENT_ORD_IMPL comment
            // in the code and adj things.
            self.created_at.cmp(&other.created_at).reverse()
        } else {
            self.id.cmp(&other.id)
        }
    }
}

impl Hash for Event {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.pubkey.hash(state);
        self.created_at.hash(state);
        self.kind.hash(state);
        self.tags.hash(state);
        self.content.hash(state);
        self.sig.hash(state);
    }
}

impl Event {
    /// Compose event
    pub fn new<I, S>(
        id: EventId,
        public_key: PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: I,
        content: S,
        sig: Signature,
    ) -> Self
    where
        I: IntoIterator<Item = Tag>,
        S: Into<String>,
    {
        Self {
            id,
            pubkey: public_key,
            created_at,
            kind,
            tags: Tags::from_list(tags.into_iter().collect()),
            content: content.into(),
            sig,
        }
    }

    /// Verify both [`EventId`] and [`Signature`]
    #[inline]
    #[cfg(feature = "std")]
    pub fn verify(&self) -> Result<(), Error> {
        self.verify_with_ctx(&SECP256K1)
    }

    /// Verify both [`EventId`] and [`Signature`]
    pub fn verify_with_ctx<C>(&self, secp: &Secp256k1<C>) -> Result<(), Error>
    where
        C: Verification,
    {
        // Verify ID
        if !self.verify_id() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Invalid event ID",
            ));
        }

        // Verify signature
        if !self.verify_signature_with_ctx(secp) {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Invalid signature",
            ));
        }

        Ok(())
    }

    /// Verify if the [`EventId`] it's composed correctly
    pub fn verify_id(&self) -> bool {
        let id: EventId = EventId::compute(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags,
            &self.content,
        );
        id == self.id
    }

    /// Verify only event [`Signature`]
    #[inline]
    #[cfg(feature = "std")]
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_with_ctx(&SECP256K1)
    }

    /// Verify event signature
    #[inline]
    pub fn verify_signature_with_ctx<C>(&self, secp: &Secp256k1<C>) -> bool
    where
        C: Verification,
    {
        match self.pubkey.xonly() {
            Ok(public_key) => secp
                .verify_schnorr(self.sig.as_secp256k1(), self.id.as_bytes(), &public_key)
                .is_ok(),
            Err(..) => false, // TODO: return error?
        }
    }

    /// Check POW
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    #[inline]
    pub fn check_pow(&self, difficulty: u8) -> bool {
        self.id.check_pow(difficulty)
    }

    /// Returns `true` if the event has an expiration tag that is expired.
    /// If an event has no expiration tag, then it will return `false`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/40.md>
    #[inline]
    #[cfg(feature = "std")]
    pub fn is_expired(&self) -> bool {
        let now: Timestamp = Timestamp::now();
        self.is_expired_at(now)
    }

    /// Returns `true` if the event has an expiration tag that is expired.
    /// If an event has no expiration tag, then it will return `false`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/40.md>
    #[inline]
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        if let Some(timestamp) = self.tags.expiration() {
            return timestamp < now;
        }
        false
    }

    /// Get the coordinate of this event
    ///
    /// Return a coordinate only if the event kind is `replaceable` or `addressable`.
    pub fn coordinate(&self) -> Option<Coordinate> {
        if self.kind.is_replaceable() || self.kind.is_addressable() {
            return Some(Coordinate {
                kind: self.kind,
                public_key: self.pubkey,
                identifier: self.tags.identifier().unwrap_or_default(),
            });
        }

        None
    }

    /// Check if it's a protected event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/70.md>
    #[inline]
    pub fn is_protected(&self) -> bool {
        self.tags.iter().any(|t| t.is_protected())
    }
}

impl_json_methods!(Event);

impl ToBech32 for Event {
    type Err = Error;

    fn to_bech32(&self) -> Result<String, Self::Err> {
        match self.coordinate() {
            Some(coordinate) => coordinate.to_bech32(),
            None => Nip19Event::from(self).to_bech32(),
        }
    }
}

impl ToNostrUri for Event {}

impl TryFrom<&Event> for Metadata {
    type Error = Error;

    fn try_from(event: &Event) -> Result<Self, Self::Error> {
        Metadata::from_json(&event.content)
    }
}

/// Struct used for de/serialization of [`Event`]
#[derive(Serialize, Deserialize)]
struct EventIntermediate<'a> {
    pub id: EventId,
    pub pubkey: PublicKey,
    pub created_at: Cow<'a, Timestamp>,
    pub kind: Kind,
    pub tags: Cow<'a, Tags>,
    pub content: Cow<'a, str>,
    pub sig: Signature,
}

impl<'a> From<&'a Event> for EventIntermediate<'a> {
    fn from(e: &'a Event) -> Self {
        Self {
            id: e.id,
            pubkey: e.pubkey,
            created_at: Cow::Borrowed(&e.created_at),
            kind: e.kind,
            tags: Cow::Borrowed(&e.tags),
            content: Cow::Borrowed(&e.content),
            sig: e.sig,
        }
    }
}

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let e: EventIntermediate<'_> = self.into();
        e.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inter: EventIntermediate<'_> = EventIntermediate::deserialize(deserializer)?;

        Ok(Self {
            id: inter.id,
            pubkey: inter.pubkey,
            created_at: inter.created_at.into_owned(),
            kind: inter.kind,
            tags: inter.tags.into_owned(),
            content: inter.content.into_owned(),
            sig: inter.sig,
        })
    }
}

/// Sign event
pub trait SignEvent: Any + Debug + Send + Sync {
    /// Error type
    type Error: core::error::Error + Send + Sync;

    /// Sign an unsigned event
    fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, Self::Error>;
}

/// Sign event
pub trait AsyncSignEvent: Any + Debug + Send + Sync {
    /// Error type
    type Error: core::error::Error + Send + Sync;

    /// Sign an unsigned event
    fn sign_event_async(
        &self,
        unsigned: UnsignedEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + '_>>;
}

/// Finalize a builder into a signed event.
pub trait FinalizeEvent<S>: Sized
where
    S: ?Sized,
{
    /// Error type
    type Error: core::error::Error + Send + Sync;

    /// Build and sign the event.
    fn finalize(self, signer: &S) -> Result<Event, Self::Error>;
}

/// Finalize a builder into a signed event with an asynchronous signer.
pub trait FinalizeEventAsync<S>: Sized
where
    S: ?Sized,
{
    /// Error type
    type Error: core::error::Error + Send + Sync;

    /// Build and sign the event.
    fn finalize_async<'a>(
        self,
        signer: &'a S,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + 'a>>
    where
        Self: 'a,
        S: 'a;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::key::Keys;
    #[cfg(feature = "std")]
    use crate::test_utils::allocation_delta;

    #[test]
    fn test_tags_deser_without_recommended_relay() {
        let sample_event = r#"{"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","created_at":1640839235,"kind":4,"tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]],"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd"}"#;
        let ev_ser = Event::from_json(sample_event).unwrap();
        assert_eq!(ev_ser.as_json(), sample_event);
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn test_custom_kind() {
        let keys = Keys::generate();
        let e: Event = EventBuilder::new(Kind::Custom(123))
            .finalize(&keys)
            .unwrap();

        let serialized = e.as_json();
        let deserialized = Event::from_json(serialized).unwrap();

        assert_eq!(e, deserialized);
        assert_eq!(Kind::Custom(123), e.kind);
        assert_eq!(Kind::Custom(123), deserialized.kind);
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn test_event_expired() {
        let my_keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote)
            .content("my content")
            .tags([Tag::expiration(Timestamp::from(1600000000))])
            .finalize(&my_keys)
            .unwrap();

        assert!(&event.is_expired());
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn test_event_not_expired() {
        let now = Timestamp::now();
        let expiry_date: u64 = now.as_secs() * 2;

        let my_keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote)
            .content("my content")
            .tags([Tag::expiration(Timestamp::from(expiry_date))])
            .finalize(&my_keys)
            .unwrap();

        assert!(!&event.is_expired());
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn test_event_without_expiration_tag() {
        let my_keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote)
            .content("my content")
            .finalize(&my_keys)
            .unwrap();
        assert!(!&event.is_expired());
    }

    #[test]
    fn test_verify_event_id() {
        let event = Event::from_json(r#"{"content":"","created_at":1698412975,"id":"f55c30722f056e330d8a7a6a9ba1522f7522c0f1ced1c93d78ea833c78a3d6ec","kind":3,"pubkey":"f831caf722214748c72db4829986bd0cbb2bb8b3aeade1c959624a52a9629046","sig":"5092a9ffaecdae7d7794706f085ff5852befdf79df424cc3419bb797bf515ae05d4f19404cb8324b8b4380a4bd497763ac7b0f3b1b63ef4d3baa17e5f5901808","tags":[["p","4ddeb9109a8cd29ba279a637f5ec344f2479ee07df1f4043f3fe26d8948cfef9","",""],["p","bb6fd06e156929649a73e6b278af5e648214a69d88943702f1fb627c02179b95","",""],["p","b8b8210f33888fdbf5cedee9edf13c3e9638612698fe6408aff8609059053420","",""],["p","9dcee4fabcd690dc1da9abdba94afebf82e1e7614f4ea92d61d52ef9cd74e083","",""],["p","3eea9e831fefdaa8df35187a204d82edb589a36b170955ac5ca6b88340befaa0","",""],["p","885238ab4568f271b572bf48b9d6f99fa07644731f288259bd395998ee24754e","",""],["p","568a25c71fba591e39bebe309794d5c15d27dbfa7114cacb9f3586ea1314d126","",""]]}"#).unwrap();
        assert!(event.verify_id());

        let event = Event::from_json(r#"{"content":"Think about this.\n\nThe most powerful centralized institutions in the world have been replaced by a protocol that protects the individual. #bitcoin\n\nDo you doubt that we can replace everything else?\n\nBullish on the future of humanity\nnostr:nevent1qqs9ljegkuk2m2ewfjlhxy054n6ld5dfngwzuep0ddhs64gc49q0nmqpzdmhxue69uhhyetvv9ukzcnvv5hx7un8qgsw3mfhnrr0l6ll5zzsrtpeufckv2lazc8k3ru5c3wkjtv8vlwngksrqsqqqqqpttgr27","created_at":1703184271,"id":"38acf9b08d06859e49237688a9fd6558c448766f47457236c2331f93538992c6","kind":1,"pubkey":"e8ed3798c6ffebffa08501ac39e271662bfd160f688f94c45d692d8767dd345a","sig":"f76d5ecc8e7de688ac12b9d19edaacdcffb8f0c8fa2a44c00767363af3f04dbc069542ddc5d2f63c94cb5e6ce701589d538cf2db3b1f1211a96596fabb6ecafe","tags":[["e","5fcb28b72cadab2e4cbf7311f4acf5f6d1a99a1c2e642f6b6f0d5518a940f9ec","","mention"],["p","e8ed3798c6ffebffa08501ac39e271662bfd160f688f94c45d692d8767dd345a","","mention"],["t","bitcoin"],["t","bitcoin"]]}"#).unwrap();
        assert!(event.verify_id());
    }

    #[test]
    fn test_iter_event_ids() {
        let json = r#"{
              "content": "+",
              "created_at": 1716508454,
              "id": "3e9e9c2fbf263590860a9c60a7de6b0d166230a5a15aa8dcdb70f537cec9807a",
              "kind": 7,
              "pubkey": "3bbddb5c7233ad993b41cb639e63122120f391b8580a9b83aae33c648230e0a3",
              "sig": "3f2ba6d713e4851500b81de2d2ef44b72f1eff061898bf8488e74f7e4ed141b0dadab4c3a9c6b237f3a6db83171bd41eafd7ab973f6fb067a4305e95abeadeee",
              "tags": [
                [
                  "e",
                  "e1e786c60ed884b6e784712aaf70e63b848b7403ef651b52b701d87739ea1808",
                  "",
                  "",
                  "04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"
                ],
                [
                  "p",
                  "04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"
                ]
              ]
            }"#;
        let event = Event::from_json(json).unwrap();
        assert_eq!(event.tags.event_ids().count(), 1);
    }

    #[test]
    fn test_event_with_unknown_fields() {
        let json: &str = r##"{
               "citedNotesCache": [],
               "citedUsersCache": [
                 "aac07d95089ce6adf08b9156d43c1a4ab594c6130b7dcb12ec199008c5819a2f"
               ],
               "content": "#JoininBox is a minimalistic, security focused Linux environment for #JoinMarket with a terminal based graphical menu.\n\nnostr:npub14tq8m9ggnnn2muytj9tdg0q6f26ef3snpd7ukyhvrxgq33vpnghs8shy62 👍🧡\n\nhttps://www.nobsbitcoin.com/joininbox-v0-8-0/",
               "created_at": 1687070234,
               "id": "c8acc12a232ea6caedfaaf0c52148635de6ffd312c3f432c6eca11720c102e54",
               "kind": 1,
               "pubkey": "27154fb873badf69c3ea83a0da6e65d6a150d2bf8f7320fc3314248d74645c64",
               "sig": "e27062b1b7187ffa0b521dab23fff6c6b62c00fd1b029e28368d7d070dfb225f7e598e3b1c6b1e2335b286ec3702492bce152035105b934f594cd7323d84f0ee",
               "tags": [["t","joininbox"],["t","joinmarket"],["p","aac07d95089ce6adf08b9156d43c1a4ab594c6130b7dcb12ec199008c5819a2f"]]
        }"##;

        // Deserialize
        let event = Event::from_json(json).unwrap();

        // Re-serialize
        let re_serialized_json = event.as_json();

        let expected_json: &str = r##"{"id":"c8acc12a232ea6caedfaaf0c52148635de6ffd312c3f432c6eca11720c102e54","pubkey":"27154fb873badf69c3ea83a0da6e65d6a150d2bf8f7320fc3314248d74645c64","created_at":1687070234,"kind":1,"tags":[["t","joininbox"],["t","joinmarket"],["p","aac07d95089ce6adf08b9156d43c1a4ab594c6130b7dcb12ec199008c5819a2f"]],"content":"#JoininBox is a minimalistic, security focused Linux environment for #JoinMarket with a terminal based graphical menu.\n\nnostr:npub14tq8m9ggnnn2muytj9tdg0q6f26ef3snpd7ukyhvrxgq33vpnghs8shy62 👍🧡\n\nhttps://www.nobsbitcoin.com/joininbox-v0-8-0/","sig":"e27062b1b7187ffa0b521dab23fff6c6b62c00fd1b029e28368d7d070dfb225f7e598e3b1c6b1e2335b286ec3702492bce152035105b934f594cd7323d84f0ee"}"##;
        assert_eq!(re_serialized_json, expected_json.trim());
    }

    #[test]
    fn test_get_event_coordinate() {
        // Text note
        let json: &str = r#"{"id":"cb8feca582979d91fe90455867b34dbf4d65e4b86e86b3c68c368ca9f9eef6f2","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1707409439,"kind":1,"tags":[["-"]],"content":"hello members of the secret group","sig":"fa163f5cfb75d77d9b6269011872ee22b34fb48d23251e9879bb1e4ccbdd8aaaf4b6dc5f5084a65ef42c52fbcde8f3178bac3ba207de827ec513a6aa39fa684c"}"#;
        let event = Event::from_json(json).unwrap();
        assert!(event.coordinate().is_none());

        // Replaceable
        let json: &str = r#"{"id":"8b19ce08cc0b20fd6c30e73b102fd3092c4f95f1c2a23d44064f9634b4593da5","pubkey":"2f35aaff0c870f0510a8bed198e1f8c35e95c996148f2d0c0fb1825b05b8dd35","created_at":1731251995,"kind":0,"tags":[],"content":"{\"name\":\"username\",\"display_name\":\"My Username\",\"about\":\"Description\",\"picture\":\"https://example.com/avatar.png\",\"banner\":\"https://example.com/banner.png\",\"nip05\":\"username@example.com\",\"lud16\":\"pay@yukikishimoto.com\"}","sig":"b26e4dfea18d4ecb072c665f9ed34b66d8dd9a45093790ea17cb618d85319587aa094f5c091efa3e237cd50976884e02c64c2f2b187c3ebdc4f773b2d74a61a4"}"#;
        let event = Event::from_json(json).unwrap();
        assert_eq!(
            event.coordinate(),
            Some(Coordinate {
                kind: Kind::Metadata,
                public_key: PublicKey::from_hex(
                    "2f35aaff0c870f0510a8bed198e1f8c35e95c996148f2d0c0fb1825b05b8dd35"
                )
                .unwrap(),
                identifier: String::new(),
            })
        );
    }

    #[test]
    fn test_protected_event() {
        let json: &str = r#"{"id":"cb8feca582979d91fe90455867b34dbf4d65e4b86e86b3c68c368ca9f9eef6f2","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1707409439,"kind":1,"tags":[["-"]],"content":"hello members of the secret group","sig":"fa163f5cfb75d77d9b6269011872ee22b34fb48d23251e9879bb1e4ccbdd8aaaf4b6dc5f5084a65ef42c52fbcde8f3178bac3ba207de827ec513a6aa39fa684c"}"#;
        let event = Event::from_json(json).unwrap();
        assert!(event.is_protected());

        // NOT protected
        let json: &str = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let event = Event::from_json(json).unwrap();
        assert!(!event.is_protected());
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_event_allocations_with_content_and_tags() {
        let json: &str = r#"{"id":"3e9e9c2fbf263590860a9c60a7de6b0d166230a5a15aa8dcdb70f537cec9807a","pubkey":"3bbddb5c7233ad993b41cb639e63122120f391b8580a9b83aae33c648230e0a3","created_at":1716508454,"kind":7,"sig":"3f2ba6d713e4851500b81de2d2ef44b72f1eff061898bf8488e74f7e4ed141b0dadab4c3a9c6b237f3a6db83171bd41eafd7ab973f6fb067a4305e95abeadeee","tags":[["e","e1e786c60ed884b6e784712aaf70e63b848b7403ef651b52b701d87739ea1808","","","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"]],"content":"+"}"#;

        let (_event, delta) = allocation_delta(|| Event::from_json(json).unwrap());
        assert_eq!(delta, 9);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_event_allocations_with_content_and_without_tags() {
        let json: &str = r#"{"id":"cb8feca582979d91fe90455867b34dbf4d65e4b86e86b3c68c368ca9f9eef6f2","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1707409439,"kind":1,"tags":[],"content":"hello members of the secret group","sig":"fa163f5cfb75d77d9b6269011872ee22b34fb48d23251e9879bb1e4ccbdd8aaaf4b6dc5f5084a65ef42c52fbcde8f3178bac3ba207de827ec513a6aa39fa684c"}"#;

        let (_event, delta) = allocation_delta(|| Event::from_json(json).unwrap());
        assert_eq!(delta, 1);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_event_allocations_without_content_and_tags() {
        let json: &str = r#"{"id":"cb8feca582979d91fe90455867b34dbf4d65e4b86e86b3c68c368ca9f9eef6f2","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1707409439,"kind":1,"tags":[],"content":"","sig":"fa163f5cfb75d77d9b6269011872ee22b34fb48d23251e9879bb1e4ccbdd8aaaf4b6dc5f5084a65ef42c52fbcde8f3178bac3ba207de827ec513a6aa39fa684c"}"#;

        let (_event, delta) = allocation_delta(|| Event::from_json(json).unwrap());
        assert_eq!(delta, 0);
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    #[bench]
    pub fn deserialize_event(bh: &mut Bencher) {
        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        bh.iter(|| {
            black_box(Event::from_json(json)).unwrap();
        });
    }

    #[bench]
    pub fn serialize_event(bh: &mut Bencher) {
        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let event = Event::from_json(json).unwrap();
        bh.iter(|| {
            black_box(event.as_json());
        });
    }

    #[bench]
    pub fn event_check_pow(bh: &mut Bencher) {
        let json = r#"{"id":"000006d11924b38e55275637c6401965c54f9ae05ffed89bce0edc1720984656","pubkey":"385c3a6ec0b9d57a4330dbd6284989be5bd00e41c535f9ca39b6ae7c521b81cd","created_at":1759497131,"kind":1,"tags":[["nonce","1180727","20"]],"content":"This is a Nostr message with embedded proof-of-work","sig":"0b216dfa714db2f146f9fa7cf20954c3fd5a2dabf69cd30ab58cf142a7ebe0fd3f4bc8e9c261245dabc0be8f942ec15d3fe3ce4dcbe81df01ceb4ced91739f52"}"#;
        let event = Event::from_json(json).unwrap();
        bh.iter(|| {
            black_box(event.check_pow(16));
        });
    }

    #[bench]
    pub fn verify_event_id(bh: &mut Bencher) {
        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let event = Event::from_json(json).unwrap();
        bh.iter(|| {
            black_box(event.verify_id());
        });
    }

    #[bench]
    pub fn verify_event_sig(bh: &mut Bencher) {
        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let event = Event::from_json(json).unwrap();
        bh.iter(|| {
            black_box(event.verify_signature());
        });
    }
}
