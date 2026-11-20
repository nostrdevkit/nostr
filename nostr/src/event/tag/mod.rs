// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Tag

use alloc::string::String;
use alloc::vec;
use alloc::vec::{IntoIter, Vec};
use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Index, IndexMut};
use core::str::FromStr;

use serde::de::Error as DeserializerError;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod codec;
mod list;

pub(crate) use self::codec::impl_tag_codec_conversions;
pub use self::list::*;
use super::id::EventId;
use crate::error::{Error, ErrorKind};
use crate::filter::SingleLetterTag;
use crate::key::PublicKey;
use crate::nips::nip01::{Coordinate, Nip01Tag};
use crate::nips::nip13::Nip13Tag;
use crate::nips::nip40::Nip40Tag;
use crate::nips::nip70::Nip70Tag;
use crate::types::{RelayUrl, Timestamp};

/// Tag
#[derive(Clone)]
pub struct Tag {
    buf: Vec<String>,
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Tag").field(&self.buf).finish()
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.buf == other.buf
    }
}

impl Eq for Tag {}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        self.buf.cmp(&other.buf)
    }
}

impl Hash for Tag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.buf.hash(state);
    }
}

impl Index<usize> for Tag {
    type Output = String;

    fn index(&self, index: usize) -> &Self::Output {
        self.buf.index(index)
    }
}

impl IndexMut<usize> for Tag {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.buf.index_mut(index)
    }
}

impl Tag {
    #[inline]
    pub(crate) fn new(buf: Vec<String>) -> Self {
        // The tag must not be empty!
        assert!(!buf.is_empty());

        // Construct
        Self { buf }
    }

    /// Constructs a tag from its raw string representation without validation.
    ///
    /// The first element is treated as the tag kind and every subsequent
    /// element as a tag value. Unlike [`Tag::parse`], this constructor does not
    /// check that the input contains at least one element.
    ///
    /// This constructor is intended for inputs that were already validated,
    /// such as data produced by a trusted decoder. Use [`Tag::parse`] for
    /// untrusted or otherwise unvalidated input.
    ///
    /// This function does not validate the tag against any NIP-specific
    /// structure or content requirements.
    ///
    /// # Safety
    ///
    /// `tag` must contain at least one element. Passing an empty vector violates
    /// the invariant relied upon by methods such as [`Tag::kind`] and may cause
    /// them to panic.
    #[inline]
    pub unsafe fn new_unchecked(tag: Vec<String>) -> Self {
        Self { buf: tag }
    }

    /// Parse tag
    ///
    /// Return error if the tag is empty!
    pub fn parse<I, S>(tag: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        // Collect
        let tag: Vec<String> = tag.into_iter().map(|v| v.into()).collect();

        // Check if it's empty
        if tag.is_empty() {
            return Err(Error::with_static_message(ErrorKind::Invalid, "empty tag"));
        }

        // Construct without an empty cell
        Ok(Self::new(tag))
    }

    /// Get tag kind
    #[inline]
    pub fn kind(&self) -> &str {
        // SAFETY: `buf` must not be empty, checked during parsing.
        &self.buf[0]
    }

    /// Return the **first** tag value (index `1`), if exists.
    #[inline]
    pub fn content(&self) -> Option<&str> {
        self.buf.get(1).map(|s| s.as_str())
    }

    /// Get [`SingleLetterTag`]
    #[inline]
    pub fn single_letter_tag(&self) -> Option<SingleLetterTag> {
        SingleLetterTag::from_str(self.kind()).ok()
    }

    /// Get tag len
    ///
    /// This will never return zero.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Appends a value to the back of the [`Tag`].
    ///
    /// Check [`Vec::push`] doc to learn more.
    #[inline]
    pub fn push<S>(&mut self, value: S)
    where
        S: Into<String>,
    {
        self.buf.push(value.into());
    }

    /// Removes the last value and returns it.
    /// If the [`Tag`] has only **one** value, returns `None`, since it can't be empty.
    ///
    /// Check [`Vec::pop`] doc to learn more.
    #[inline]
    pub fn pop(&mut self) -> Option<String> {
        // The tag must have at least one value!
        if self.buf.len() <= 1 {
            return None;
        }

        // Pop last item
        self.buf.pop()
    }

    /// Inserts a value at position `index` within the vector,
    /// shifting all other values after it to the right.
    ///
    /// The value at index `0` and `1` can't be empty.
    /// If an empty string is passed for those indexes, `false` is returned.
    ///
    /// Returns `true` if the value has been inserted or updated successfully.
    /// Returns `false` if `index > len`.
    ///
    /// Check [`Vec::insert`] doc to learn more.
    pub fn insert<S>(&mut self, index: usize, value: S) -> bool
    where
        S: Into<String>,
    {
        // Check if `index` is bigger than collection len
        if index > self.buf.len() {
            return false;
        }

        let value: String = value.into();

        // Return false if the value is empty at position 0 or 1
        if (index == 0 || index == 1) && value.is_empty() {
            return false;
        }

        // Insert at position
        self.buf.insert(index, value);

        // Inserted successfully
        true
    }

    /// Extends the collection.
    ///
    /// Check [`Vec::extend`] doc to learn more.
    #[inline]
    pub fn extend<I, S>(&mut self, iter: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.buf.extend(iter.into_iter().map(|v| v.into()));
    }

    /// Get as slice of strings
    #[inline]
    pub fn as_slice(&self) -> &[String] {
        &self.buf
    }

    /// Consume tag and return array of strings
    #[inline]
    pub fn to_vec(self) -> Vec<String> {
        self.buf
    }

    /// Compose `["e", "<event-id">]`
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn event(id: EventId) -> Self {
        Nip01Tag::Event {
            id,
            relay_hint: None,
            public_key: None,
        }
        .to_tag()
    }

    /// Compose `["p", "<public-key>"]` tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn public_key(public_key: PublicKey) -> Self {
        Nip01Tag::PublicKey {
            public_key,
            relay_hint: None,
        }
        .to_tag()
    }

    /// Compose `["d", "<identifier>"]` tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn identifier<T>(identifier: T) -> Self
    where
        T: Into<String>,
    {
        Nip01Tag::Identifier(identifier.into()).to_tag()
    }

    /// Compose `["a", "<coordinate>", "<optional-relay-url>"]` tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn coordinate(coordinate: Coordinate, relay_url: Option<RelayUrl>) -> Self {
        Nip01Tag::Coordinate {
            coordinate,
            relay_hint: relay_url,
        }
        .to_tag()
    }

    /// Compose `["nonce", "<nonce>", "<difficulty>"]` tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    #[inline]
    pub fn pow(nonce: u128, difficulty: u8) -> Self {
        Nip13Tag::Nonce { nonce, difficulty }.to_tag()
    }

    /// Compose `["expiration", "<timestamp>"]` tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/40.md>
    #[inline]
    pub fn expiration(timestamp: Timestamp) -> Self {
        Nip40Tag::Expiration(timestamp).to_tag()
    }

    /// Compose `["t", "<hashtag>"]` tag
    ///
    /// This will convert the hashtag to lowercase.
    #[inline]
    pub fn hashtag<T>(hashtag: T) -> Self
    where
        T: AsRef<str>,
    {
        Self::new(vec![String::from("t"), hashtag.as_ref().to_lowercase()])
    }

    /// Protected event
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/70.md>
    #[inline]
    pub fn protected() -> Self {
        Nip70Tag::Protected.to_tag()
    }

    /// Compose custom tag
    ///
    /// JSON: `["<kind>", "<value-1>", "<value-2>", ...]`
    pub fn custom<K, I, S>(kind: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        // Compose tag
        let mut buf: Vec<String> = Vec::with_capacity(1);
        buf.push(kind.into());
        buf.extend(values.into_iter().map(|v| v.into()));

        Self::new(buf)
    }

    /// Check if it's a protected event tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/70.md>
    #[inline]
    pub fn is_protected(&self) -> bool {
        self.buf == ["-"]
    }
}

impl IntoIterator for Tag {
    type Item = String;
    type IntoIter = IntoIter<Self::Item>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.buf.into_iter()
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.buf.len()))?;
        for element in self.buf.iter() {
            seq.serialize_element(&element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        type Data = Vec<String>;
        let tag: Data = Data::deserialize(deserializer)?;
        Self::parse(tag).map_err(DeserializerError::custom)
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::event::{Event, Kind, Signature};
    use crate::types::Timestamp;

    #[test]
    fn test_parse_empty_tag() {
        assert_eq!(
            Tag::parse::<Vec<_>, String>(vec![]).unwrap_err().kind(),
            ErrorKind::Invalid
        );
    }

    #[test]
    fn test_extract_tag_content() {
        let t: Tag = Tag::parse(["aaaaaa", "bbbbbb"]).unwrap();
        assert_eq!(t.content(), Some("bbbbbb"));

        // Test extract public key
        let t: Tag = Tag::parse([
            "custom-p",
            "f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785",
        ])
        .unwrap();
        assert_eq!(
            t.content(),
            Some("f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785")
        );

        // Test extract event ID
        let t: Tag = Tag::parse([
            "custom-e",
            "2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45",
        ])
        .unwrap();
        assert_eq!(
            t.content(),
            Some("2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45")
        );
    }

    #[test]
    fn test_tag_push() {
        let mut tag = Tag::parse(["d", "test"]).unwrap();
        tag.push("test2");
        assert_eq!(tag.len(), 3);
        assert_eq!(tag.to_vec(), ["d", "test", "test2"]);
    }

    #[test]
    fn test_tag_pop() {
        let mut tag = Tag::parse(["d", "test"]).unwrap();
        assert_eq!(tag.pop().unwrap(), "test");
        assert_eq!(tag.len(), 1);

        // Can't pop if the tag has only one value
        assert!(tag.pop().is_none());
        assert_eq!(tag.len(), 1);

        assert_eq!(tag.to_vec(), ["d"]);
    }

    #[test]
    fn test_tag_extend() {
        let mut tag = Tag::parse(["p", "pk"]).unwrap();
        tag.extend(["test", "test1"]);
        assert_eq!(tag.len(), 4);
        assert_eq!(tag.to_vec(), ["p", "pk", "test", "test1"]);
    }

    #[test]
    fn test_tag_insert() {
        let mut tag = Tag::parse(["p", "val", "relay", "other"]).unwrap();

        // Can't insert an empty value at index 0
        assert!(!tag.insert(0, ""));
        assert_eq!(tag.len(), 4);

        // Can't insert an empty value at index 1
        assert!(!tag.insert(1, ""));
        assert_eq!(tag.len(), 4);

        // Insert a value at index 1
        assert!(tag.insert(1, "pk"));
        assert_eq!(tag.len(), 5);

        assert_eq!(tag.to_vec(), ["p", "pk", "val", "relay", "other"]);
    }

    #[test]
    fn test_deserialize_tag_from_event() {
        // Got this fresh off the wire
        let event: &str = r#"{"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","created_at":1640839235,"kind":4,"tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]],"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd"}"#;
        let event = Event::from_json(event).unwrap();
        let tag = event.tags.first().unwrap();

        assert_eq!(
            tag,
            &Tag::public_key(
                PublicKey::from_hex(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn test_serialize_tag_to_event() {
        let public_key =
            PublicKey::from_hex("68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272")
                .unwrap();
        let event = Event::new(
            EventId::from_hex("378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7")
                .unwrap(),
            PublicKey::from_hex("79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3").unwrap(),
            Timestamp::from(1671739153),
            Kind::EncryptedDirectMessage,
            [Tag::public_key(public_key)],
            "8y4MRYrb4ztvXO2NmsHvUA==?iv=MplZo7oSdPfH/vdMC8Hmwg==",
            Signature::from_str("fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8").unwrap()
        );

        let event_json: &str = r#"{"id":"378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7","pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","created_at":1671739153,"kind":4,"tags":[["p","68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272"]],"content":"8y4MRYrb4ztvXO2NmsHvUA==?iv=MplZo7oSdPfH/vdMC8Hmwg==","sig":"fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8"}"#;

        assert_eq!(&event.as_json(), event_json);
    }

    #[test]
    fn test_tag_custom() {
        assert_eq!(
            vec!["r", "wss://atlas.nostr.land", ""],
            Tag::custom("r", ["wss://atlas.nostr.land", ""]).to_vec()
        );

        assert_eq!(
            Tag::parse(["r", "wss://atlas.nostr.land", ""]).unwrap(),
            Tag::custom("r", ["wss://atlas.nostr.land", ""])
        );

        assert_eq!(
            vec![
                "r",
                "3dbee968d1ddcdf07521e246e405e1fbb549080f1f4ef4e42526c4528f124220",
                ""
            ],
            Tag::custom(
                "r",
                [
                    "3dbee968d1ddcdf07521e246e405e1fbb549080f1f4ef4e42526c4528f124220",
                    ""
                ]
            )
            .to_vec()
        );

        assert_eq!(
            Tag::parse([
                "r",
                "3dbee968d1ddcdf07521e246e405e1fbb549080f1f4ef4e42526c4528f124220",
                ""
            ])
            .unwrap(),
            Tag::custom(
                "r",
                [
                    "3dbee968d1ddcdf07521e246e405e1fbb549080f1f4ef4e42526c4528f124220",
                    ""
                ]
            )
        );
    }

    #[test]
    fn test_hashtag() {
        assert_eq!(
            Tag::parse(["t", "Nostr"]).unwrap(),
            Tag::custom("t", ["Nostr"])
        );
        assert_eq!(Tag::hashtag("Nostr"), Tag::custom("t", ["nostr"]));
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    #[bench]
    pub fn get_tag_kind(bh: &mut Bencher) {
        let tag = Tag::identifier("id");
        bh.iter(|| {
            black_box(tag.kind());
        });
    }

    #[bench]
    pub fn parse_p_tag(bh: &mut Bencher) {
        let tag = [
            "p",
            "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
        ];
        bh.iter(|| {
            black_box(Tag::parse(tag)).unwrap();
        });
    }

    #[bench]
    pub fn parse_e_tag(bh: &mut Bencher) {
        let tag = [
            "e",
            "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
            "wss://relay.damus.io",
        ];
        bh.iter(|| {
            black_box(Tag::parse(tag)).unwrap();
        });
    }

    #[bench]
    pub fn parse_a_tag(bh: &mut Bencher) {
        let tag = [
            "a",
            "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
            "wss://relay.nostr.org",
        ];
        bh.iter(|| {
            black_box(Tag::parse(tag)).unwrap();
        });
    }

    #[bench]
    pub fn parse_t_tag(bh: &mut Bencher) {
        let tag = ["t", "test"];
        bh.iter(|| {
            black_box(Tag::parse(tag)).unwrap();
        });
    }
}
