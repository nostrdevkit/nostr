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
mod tags;
mod unsigned;

pub use self::builder::*;
pub use self::id::*;
pub use self::kind::*;
pub use self::signature::*;
pub use self::tags::*;
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
    pub fn new<T, S>(
        id: EventId,
        public_key: PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: T,
        content: S,
        sig: Signature,
    ) -> Self
    where
        T: Into<Tags>,
        S: Into<String>,
    {
        Self {
            id,
            pubkey: public_key,
            created_at,
            kind,
            tags: tags.into(),
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
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::nips::nip40::Nip40Tag;
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
            .tag(Nip40Tag::Expiration(Timestamp::from(1600000000)))
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
            .tag(Nip40Tag::Expiration(Timestamp::from(expiry_date)))
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
        assert_eq!(delta, 2);
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

    #[test]
    #[cfg(feature = "std")]
    fn test_event_allocation_with_hundreds_of_tags() {
        let json: &str = r#"{"id":"4e14d76e98d6877be193ea92c5605026aeb97ed9b90b769438c52e7ec4785a1f","pubkey":"68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","created_at":1794575666,"kind":3,"tags":[["p","84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240"],["p","04918dfc36c93e7db6cc0d60f37e1522f1c36b64d3f4b424c532d7c595febbc5"],["p","20d88bae0c38e6407279e6a83350a931e714f0135e013ea4a1b14f936b7fead5"],["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"],["p","3b6a3d3bb3358836a64d1c80292b96e7698ec35a2e5ca451defa6bd3af3eeb84"],["p","3d2e51508699f98f0f2bdbe7a45b673c687fe6420f466dc296d90b908d51d594"],["p","6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93"],["p","82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2"],["p","b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a"],["p","b93049a6e2547a36a7692d90e4baa809012526175546a17337454def9ab69d30"],["p","ef151c7a380f40a75d7d1493ac347b6777a9d9b5fa0aa3cddb47fc78fab69a8b"],["p","04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9"],["p","b190175cef407c593f17c155480eda1a2ee7f6c84378eef0e97353f87ee59300"],["p","b66be78da89991544a05c3a2b63da1d15eefe8e9a1bb6a4369f8616865bd6b7c"],["p","e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af"],["p","875705d034963b8487a8246468612a854ed2b5af66be936e1e48c25ce96a750d"],["p","4df7b43b3a4db4b99e3dbad6bd0f84226726efd63ae7e027f91acbd91b4dba48"],["p","50d94fc2d8580c682b071a542f8b1e31a200b0508bab95a33bef0855df281d63"],["p","c998a5739f04f7fff202c54962aa5782b34ecb10d6f915bdfdd7582963bf9171"],["p","b9a537523bba2fcdae857d90d8a760de4f2139c9f90d986f747ce7d0ec0d173d"],["p","175f568d77fb0cb7400f0ddd8aed1738cd797532b314ef053a1669d4dba7433a"],["p","99bb5591c9116600f845107d31f9b59e2f7c7e09a1ff802e84f1d43da557ca64"],["p","e4336cd525df79fa4d3af364fd9600d4b10dce4215aa4c33ed77ea0842344b10"],["p","f0293508f3eb9e6fe99c2fd8ba69ff446216872a2d9f67979bfa4db8b3155806"],["p","60d53675f07dee9e7d77910efa44682d87cb532313ba66b8f4449d649172296b"],["p","218238431393959d6c8617a3bd899303a96609b44a644e973891038a7de8622d"],["p","68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272"],["p","0c371f5ed95076613443e8331c4b60828ed67bcdefaa1698fb5ce9d7b3285ffb"],["p","4260bdcbabf20b8d506ceb63d320bf1c2eb2946a83959cc525570d26387a2b02"],["p","be7a5291b532e8b918f2dc98148948a33d3e0da07788d7416f73b4c7514f08e6"],["p","d1f3c71639ae3bba17ffc6c8deb1fdb3a56506b3492213d033528cc291523704"],["p","aac07d95089ce6adf08b9156d43c1a4ab594c6130b7dcb12ec199008c5819a2f"],["p","000000000652e452ee68a01187fb08c899496cb46cb51d1aa0803d063acedba7"],["p","b120d3eeb56dd9e23bbea7282f394e7a2155e802ba1920d294426d3ec091b0fe"],["p","126103bfddc8df256b6e0abfd7f3797c80dcc4ea88f7c2f87dd4104220b4d65f"],["p","4657dfe8965be8980a93072bcfb5e59a65124406db0f819215ee78ba47934b3e"],["p","2dd140ca80db62bcf377d7dbe68d22a95baa41d19c5b4971a78204af7596051a"],["p","58c741aa630c2da35a56a77c1d05381908bd10504fdd2d8b43f725efa6d23196"],["p","eab0e756d32b80bcd464f3d844b8040303075a13eabc3599a762c9ac7ab91f4f"],["p","58ead82fa15b550094f7f5fe4804e0fe75b779dbef2e9b20511eccd69e6d08f9"],["p","7b3f7803750746f455413a221f80965eecb69ef308f2ead1da89cc2c8912e968"],["p","a536ab1f7f3c0133baadbdf472b1ac7ad4b774ed432c1989284193572788bca0"],["p","4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"],["p","93518f91dfa51d8acf39217cdcd3d2ccd178433cb9e72368544aacd7412cb50c"],["p","8b6d16db3516cac6db98df93a633ccb8116cb1088a25c2d86a70b9b17a63259a"],["p","dbe0b1bdbe129ce38db753d6a997e6a29e693afd02aa1d1f9b005fa7386e5c26"],["p","a008def15796fba9a0d6fab04e8fd57089285d9fd505da5a83fe8aad57a3564d"],["p","ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49"],["p","15b5cf6cdf4fd1c02f28bcce0f197cafae4c8c7c66a3e2e23af9fe610875315e"],["p","00033a937a5e29cfe9aab48d311a3061563cd8348ebc7e2ca9cc5c33774465e5"],["p","3691939e3458d1acf9af4ad0d5a80f2e1c4b4f167cffb9cbb66e1b4343dc5dc0"],["p","645681b9d067b1a362c4bee8ddff987d2466d49905c26cb8fec5e6fb73af5c84"],["p","3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"],["p","aa55a479ad6934d0fd78f3dbd88515cd1ca0d7a110812e711380d59df7598935"],["p","b16817e63a31b4adba5f5b7f018e5c9cc06aeaaefa4ba2a4bc8c16c1828dedea"],["p","11674b2d321fc24239b02afdf966c32e36594a6282bd7f3d4bcd12438558ab51"],["p","da18e9860040f3bf493876fc16b1a912ae5a6f6fa8d5159c3de2b8233a0d9851"],["p","3829e00e2b7f81f94fa1103ede83be1f140724299c9a3732f68abd38c307525e"],["p","f1725586a402c06aec818d1478a45aaa0dc16c7a9c4869d97c350336d16f8e43"],["p","a9e42a0ca6e4b1208088b68a4fd6407481b12060f915a0fecb4c8874557e3749"],["p","3878d95db7b854c3a0d3b2d6b7bf9bf28b36162be64326f5521ba71cf3b45a69"],["p","7579076d9aff0a4cfdefa7e2045f2486c7e5d8bc63bfc6b45397233e1bbfcb19"],["p","6b4ec98f02e647e01440b473bbd92a7fae21e01b6aa6c65e32db94a36092272e"],["p","b12deee231e85bec19f3e4e3fee5893d449b8ce159ed2adcecf60262afca6d50"],["p","800e0fe3d8638ce3f75a56ed865df9d96fc9d9cd2f75550df0d7f5c1d8468b0b"],["p","93bd0c6f3ccbae47388b01ac6ce0b2c013114dca4c08d6e2712d4ff71405a3c3"],["p","efe5d120df0cc290fa748727fb45ac487caad346d4f2293ab069e8f01fc51981"],["p","ea57b25f7a57c61d7dd0bf62411244a580d6709e42a20428fd381f89ef8d63db"],["p","b98ded4ceaea20790dbcb3c31400692009d34c7f9927c286835a99b7481a5c22"],["p","83d999a148625c3d2bb819af3064c0f6a12d7da88f68b2c69221f3a746171d19"],["p","0596b8167de4d926ba1658286936eebd22532ea67ec12a90c0780ad66df1fc99"],["p","6fd3915a55ad0c2eae64e2b818acbbae9c6b3d9b5ee44e19aa040fb09f0d3cdd"],["p","66c292bee0a69c221aebd2f288ffe1efaa3163217161c9539337e2b0dd55136a"],["p","1739d937dc8c0c7370aa27585938c119e25c41f6c441a5d34c6d38503e3136ef"],["p","a60e79e0edad5100d7543b669e513dbc1c2170e8e9b74fdb8e971afd1e0e6813"],["p","b33bf9e97b78f35694a02e6bbef8e77059373e42b0a85a63f25a50ebfdadf50d"],["p","d26f78e5954117b5c6538a2d6c88a2296c65c038770399d7069a97826eb06a95"],["p","ba690466f23faa3891570c0a38e81d0a9f84a7bcc79672d19d1abb2fc11156f0"],["p","03ed4fd0958f8353b3e8a8493bae80b35a868a19ec46a6ccd60cd52e52d32962"],["p","a789a409ff78d377294f1a5d3e4b294e80ade7118cc5670951e6ec35eaa7564c"],["p","63fe6318dc58583cfe16810f86dd09e18bfd76aabc24a0081ce2856f330504ed"],["p","1989034e56b8f606c724f45a12ce84a11841621aaf7182a1f6564380b9c4276b"],["p","cc3790930722bfa73e28f9a2aa0832706884305cb80687e20927c7960db99185"],["p","d04ecf33a303a59852fdb681ed8b412201ba85d8d2199aec73cb62681d62aa90"],["p","2658362c3137eaa801fae404be36ffc80e16a61c43a891a3a046bec4b72e498a"],["p","5468bceeb74ce35cb4173dcc9974bddac9e894a74bf3d44f9ca8b7554605c9ed"],["p","cc8d072efdcc676fcbac14f6cd6825edc3576e55eb786a2a975ee034a6a026cb"],["p","5df936e47d5d114a2b1c27b9bb6955c2e86cd5614386a96252029187d35e7206"],["p","850605096dbfb50b929e38a6c26c3d56c425325c85e05de29b759bc0e5d6cebc"],["p","6b4a29bbd43d1d0eeead384f512dbb591ce9407d27dba48ad54b00d9d2e1972b"],["p","c301f13372c8f0d9bc8186d874fa45fa33aede13e66f4187a3bd22ee41c95b2a"],["p","dbb19ae0e0ea853289c54c7ca810782b61306c848cad8d8416174597c3f22d5a"],["p","00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9"],["p","23c6f685c776d1c4ced6a5571616fcdf9f5e3c82be547477d4c4845ceb7ff403"],["p","756098de196f2d78c7b66ce8de7daa26292fdb507aa17e0cf4a464fed0b0dc65"],["p","ccac436aec1c1ec2ae514ade0b864e337b04cd30cc21c50d73e0aeb0d4fad715"],["p","3ddeea527009e25c88d34212f7c9aa36344fbeebd2b69a04ee77ffc3c0ef7371"],["p","5e70f2977a61214de215585a409f9592e65bd1b8177190700ae61937b1014737"],["p","2183e94758481d0f124fbd93c56ccaa45e7e545ceeb8d52848f98253f497b975"],["p","5a3de28ffd09d7506cff0a2672dbdb1f836307bcff0217cc144f48e19eea3fff"],["p","fbdf630c45bd357842b61b21450bde1447f91c234bc2d4bf7031824a7e47193e"],["p","af2f682f512899852c6654ff065aa405a41d15e2b1cb6c9173123605744f06e6"],["p","17538dc2a62769d09443f18c37cbe358fab5bbf981173542aa7c5ff171ed77c4"],["p","9be21611a341426e9146257c54179e22d178bb7d4106e247ddf3e507b7985a6b"],["p","d7df8b3e14166796a8ad8740b06f427aea9dd95b72e0276aa9179210e27f81f7"],["p","9711d1aba806a3a285ff3e87d175902c2f250741860d9c65903c8b5e863ebd81"],["p","5db24d2f09b3e4957519967c6602730deb5ac6f50e2bd0661c04b24712d97fa2"],["p","b7ed68b062de6b4a12e51fd5285c1e1e0ed0e5128cda93ab11b4150b55ed32fc"],["p","2774d83c8f9789c583414292b1192c4345db7ff0d551ea32efa2958f4192f6e5"],["p","3af187bfe00920d87068a6bcdffc48f4b241d1d82594cd395119a30891041654"],["p","c7dccba4fe4426a7b1ea239a5637ba40fab9862c8c86b3330fe65e9f667435f6"],["p","7fa56f5d6962ab1e3cd424e758c3002b8665f7b0d8dcee9fe9e288d7751ac194"],["p","c2622c916d9b90e10a81b2ba67b19bdfc5d6be26c25756d1f990d3785ce1361b"],["p","338ef72e3deebda385aedea5e89b87ec35a7d296d4a9b642bb2c1ad926007db7"],["p","096c0beaac04ac872a68b32106bfec6218ee39386f9e750daefbfbd1189305aa"],["p","4379e76bfa76a80b8db9ea759211d90bb3e67b2202f8880cc4f5ffe2065061ad"],["p","72bdbc57bdd6dfc4e62685051de8041d148c3c68fe42bf301f71aa6cf53e52fb"],["p","c582af78dff442700ec59e21786532a7074c00be8b7b1eac989bbf62698069cc"],["p","75d737c3472471029c44876b330d2284288a42779b591a2ed4daa1c6c07efaf7"],["p","dadbe86a2669e84b31e50f8877311ea564182421f9ad3bd0c37878589c493e92"],["p","71ecabd8b6b33548e075ff01b31568ffda19d0ac2788067d99328c6de4885975"],["p","eee391eec3551ed23b961027de2355c0f2d89a92baf498d9b74863778d0b97c2"],["p","7b991f776d04d87cb5d4259688187a520f6afc16b2b9ad26dac6b8ee76c2840d"],["p","1027fd5bc3b5e50c9800d48bc8acfbc290d89b857c7ce15572a57048c4c0558e"],["p","50f128b35eb247c92bc309a95419076b94bb66062481ed0535a323e4e9abf894"],["p","791b7f817d3223f2832c24693a9c0e8b9922631ab36ab9a3c0b47bfcbb1d32d1"],["p","fbd06344002e4d4f87839a760ba5a332bc64a24aac0dab037688cfda6279d445"],["p","f5f98ba54045a2fa8df2a97c35fc30299b9e0d51a701795c040ca80cedaf39b4"],["p","7754a7761505cdb1028e8a49d9beb62e4096cd66a6a1d45b6ba86287c33d10d9"],["p","7215b2db8754494fd3452b7f2d28b56e23863b95446bf68d79f980a7ad5ec7cd"],["p","8f474abb70c3987ff7e93fdd9e01cbade2dad5a8b3469fa1aba299823a1cee89"],["p","8bf629b3d519a0f8a8390137a445c0eb2f5f2b4a8ed71151de898051e8006f13"],["p","d22bcdb1d2505bc060f65a86cd5f20532ec5f3e41c06aea9edac39f6ba76fd6e"],["p","be7d2a917eeb7566bfc4982c506ee9027eed5540b4ba80326ace6cb00fe57a71"],["p","e01819d64d9744343d0e81eac6cdbc37d63385cea56cf0ee470881be20504efd"],["p","52b4a076bcbbbdc3a1aefa3735816cf74993b1b8db202b01c883c58be7fad8bd"],["p","e740f5878098eba1a0a81d2504ee0171c4e79b75f92534da33f7f620f3ea0b0d"],["p","1afe0c74e3d7784eba93a5e3fa554a6eeb01928d12739ae8ba4832786808e36d"],["p","c756327758f0db3991fc865bd2512b300a4c7e8c5fb073bc42da5d30ce87e0d0"],["p","4d7842051782e0d3feb034d150adc2b6bae4ee3b49786793bffa468b6f5b96b3"],["client","Primal Android"],["p","83c6e985c28d7dfb9b51eb209f82af91c8a8f6f322d84ca75453479916446f86"],["p","6398e15e3416de093b963ca38783d2a66a9657cb08cbba4f02546cdd55b6f1a4"]],"content":"{\"wss://relay.damus.io/\":{\"read\":true,\"write\":true},\"wss://nostr.oxtr.dev/\":{\"read\":true,\"write\":true},\"wss://nos.lol/\":{\"read\":true,\"write\":true},\"wss://relay.primal.net/\":{\"read\":true,\"write\":true},\"wss://nostr.wine/\":{\"read\":true,\"write\":false},\"wss://purplepag.es/\":{\"read\":true,\"write\":true},\"wss://relay.mostr.pub/\":{\"read\":true,\"write\":false},\"wss://algo.utxo.one/\":{\"read\":true,\"write\":true}}","sig":"bb210480001e3eef21ec797f6839ad4943f67dc5885830f6fca42190be40eae9b311d323b338744ae8f83950c8a438416371322681e10ebb9165640553e1b081"}"#;

        let (_event, delta) = allocation_delta(|| Event::from_json(json).unwrap());
        assert_eq!(delta, 2); // content + tags
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
