// Copyright (c) 2021 Paul Miller
// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Filters

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::hash::Hash;

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

mod single_letter;

pub use self::single_letter::SingleLetterTag;
use crate::event::{Event, EventId, Kind, Tag};
use crate::key::PublicKey;
use crate::nips::nip01::Coordinate;
use crate::types::Timestamp;
use crate::util::impl_json_methods;

type GenericTags = BTreeMap<SingleLetterTag, BTreeSet<String>>;

/// Specifies which event fields to compare with a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MatchEventOptions {
    /// Compare the event id with the filter.
    pub id: bool,
    /// Compare the event author with the filter.
    pub author: bool,
    /// Compare the event kind with the filter.
    pub kind: bool,
    /// Compare the event tags with the filter.
    pub tags: bool,
    /// Check if event timestamp is after filter's `since`.
    pub since: bool,
    /// Check if event timestamp is before filter's `until`.
    pub until: bool,
    /// Check if event content contains filter's search terms
    /// (basic NIP-50 implementation without extensions).
    pub nip50: bool,
}

impl Default for MatchEventOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchEventOptions {
    /// Creates a new [`MatchEventOptions`] that **matches all event** fields by default.
    #[inline]
    pub const fn new() -> Self {
        Self {
            id: true,
            author: true,
            kind: true,
            tags: true,
            since: true,
            until: true,
            nip50: true,
        }
    }

    /// Returns a new [`MatchEventOptions`] that **won't match any event**.
    #[inline]
    pub const fn unmatch() -> Self {
        Self {
            id: false,
            author: false,
            kind: false,
            tags: false,
            since: false,
            until: false,
            nip50: false,
        }
    }

    /// Compare the event id with the filter.
    #[inline]
    pub const fn id(mut self, enable: bool) -> Self {
        self.id = enable;
        self
    }

    /// Compare the event author with the filter.
    #[inline]
    pub const fn author(mut self, enable: bool) -> Self {
        self.author = enable;
        self
    }

    /// Compare the event kind with the filter.
    #[inline]
    pub const fn kind(mut self, enable: bool) -> Self {
        self.kind = enable;
        self
    }

    /// Compare the event tags with the filter.
    #[inline]
    pub const fn tags(mut self, enable: bool) -> Self {
        self.tags = enable;
        self
    }

    /// Check if event timestamp is after filter's `since`.
    #[inline]
    pub const fn since(mut self, enable: bool) -> Self {
        self.since = enable;
        self
    }

    /// Check if event timestamp is before filter's `until`.
    #[inline]
    pub const fn until(mut self, enable: bool) -> Self {
        self.until = enable;
        self
    }

    /// Check if event content contains filter's search terms
    /// (basic NIP-50 implementation without extensions).
    #[inline]
    pub const fn nip50(mut self, enable: bool) -> Self {
        self.nip50 = enable;
        self
    }
}

/// Subscription filters
///
/// <https://github.com/nostr-protocol/nips/blob/master/01.md>
//
// NOTE: the various fields are `Option` for the reason described at https://github.com/nostrdevkit/nostr/issues/302
//
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Filter {
    /// List of [`EventId`]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ids: Option<BTreeSet<EventId>>,
    /// List of [`PublicKey`]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub authors: Option<BTreeSet<PublicKey>>,
    /// List of a kind numbers
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub kinds: Option<BTreeSet<Kind>>,
    /// It's a string describing a query in a human-readable form, i.e. "best nostr apps"
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/50.md>
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub search: Option<String>,
    /// An integer unix timestamp, events must be newer than this to pass
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub since: Option<Timestamp>,
    /// An integer unix timestamp, events must be older than this to pass
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub until: Option<Timestamp>,
    /// Maximum number of events to be returned in the initial query
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub limit: Option<usize>,
    /// Generic tag queries
    #[serde(
        flatten,
        serialize_with = "serialize_generic_tags",
        deserialize_with = "deserialize_generic_tags"
    )]
    #[serde(default)]
    pub generic_tags: GenericTags,
}

impl Filter {
    /// Create new empty [`Filter`]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add [`EventId`]
    #[inline]
    pub fn id(self, id: EventId) -> Self {
        self.ids([id])
    }

    /// Add event ids or prefixes
    #[inline]
    pub fn ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.ids = extend_or_collect(self.ids, ids);
        self
    }

    /// Remove event ids
    #[inline]
    pub fn remove_ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.ids = remove_or_none(self.ids, ids);
        self
    }

    /// Add author
    #[inline]
    pub fn author(self, author: PublicKey) -> Self {
        self.authors([author])
    }

    /// Add authors
    #[inline]
    pub fn authors<I>(mut self, authors: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.authors = extend_or_collect(self.authors, authors);
        self
    }

    /// Remove authors
    #[inline]
    pub fn remove_authors<I>(mut self, authors: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.authors = remove_or_none(self.authors, authors);
        self
    }

    /// Add kind
    #[inline]
    pub fn kind(self, kind: Kind) -> Self {
        self.kinds([kind])
    }

    /// Add kinds
    #[inline]
    pub fn kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = Kind>,
    {
        self.kinds = extend_or_collect(self.kinds, kinds);
        self
    }

    /// Remove kinds
    #[inline]
    pub fn remove_kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = Kind>,
    {
        self.kinds = remove_or_none(self.kinds, kinds);
        self
    }

    /// Add event
    #[inline]
    pub fn event(self, id: EventId) -> Self {
        self.custom_tag(SingleLetterTag::LOWERCASE_E, id)
    }

    /// Add events
    #[inline]
    pub fn events<I>(self, events: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.custom_tags(SingleLetterTag::LOWERCASE_E, events)
    }

    /// Remove events
    #[inline]
    pub fn remove_events<I>(self, events: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.remove_custom_tags(SingleLetterTag::LOWERCASE_E, events)
    }

    /// Add pubkey
    #[inline]
    pub fn pubkey(self, pubkey: PublicKey) -> Self {
        self.custom_tag(SingleLetterTag::LOWERCASE_P, pubkey)
    }

    /// Add pubkeys
    #[inline]
    pub fn pubkeys<I>(self, pubkeys: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.custom_tags(SingleLetterTag::LOWERCASE_P, pubkeys)
    }

    /// Remove pubkeys
    #[inline]
    pub fn remove_pubkeys<I>(self, pubkeys: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.remove_custom_tags(SingleLetterTag::LOWERCASE_P, pubkeys)
    }

    /// Add hashtag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/12.md>
    #[inline]
    pub fn hashtag<S>(self, hashtag: S) -> Self
    where
        S: Into<String>,
    {
        self.custom_tag(SingleLetterTag::LOWERCASE_T, hashtag)
    }

    /// Add hashtags
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/12.md>
    #[inline]
    pub fn hashtags<I, S>(self, hashtags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.custom_tags(SingleLetterTag::LOWERCASE_T, hashtags)
    }

    /// Remove hashtags
    #[inline]
    pub fn remove_hashtags<I, S>(self, hashtags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.remove_custom_tags(SingleLetterTag::LOWERCASE_T, hashtags)
    }

    /// Add reference
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/12.md>
    #[inline]
    pub fn reference<S>(self, reference: S) -> Self
    where
        S: Into<String>,
    {
        self.custom_tag(SingleLetterTag::LOWERCASE_R, reference)
    }

    /// Add references
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/12.md>
    #[inline]
    pub fn references<I, S>(self, references: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.custom_tags(SingleLetterTag::LOWERCASE_R, references)
    }

    /// Remove references
    #[inline]
    pub fn remove_references<I, S>(self, references: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.remove_custom_tags(SingleLetterTag::LOWERCASE_R, references)
    }

    /// Add identifier
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn identifier<S>(self, identifier: S) -> Self
    where
        S: Into<String>,
    {
        self.custom_tag(SingleLetterTag::LOWERCASE_D, identifier)
    }

    /// Add identifiers
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn identifiers<I, S>(self, identifiers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.custom_tags(SingleLetterTag::LOWERCASE_D, identifiers)
    }

    /// Remove identifiers
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn remove_identifiers<I, S>(self, identifiers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.remove_custom_tags(SingleLetterTag::LOWERCASE_D, identifiers)
    }

    /// Add coordinate
    ///
    /// Query for `a` tag.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn coordinate(self, coordinate: &Coordinate) -> Self {
        self.custom_tag(SingleLetterTag::LOWERCASE_A, coordinate.to_string())
    }

    /// Add coordinates
    ///
    /// Query for `a` tags.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn coordinates<'a, I>(self, coordinates: I) -> Self
    where
        I: IntoIterator<Item = &'a Coordinate>,
    {
        self.custom_tags(
            SingleLetterTag::LOWERCASE_A,
            coordinates.into_iter().map(|c| c.to_string()),
        )
    }

    /// Remove coordinates
    ///
    /// Remove `a` tags.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn remove_coordinates<'a, I>(self, coordinates: I) -> Self
    where
        I: IntoIterator<Item = &'a Coordinate>,
    {
        self.remove_custom_tags(
            SingleLetterTag::LOWERCASE_A,
            coordinates.into_iter().map(|c| c.to_string()),
        )
    }

    /// Add search field
    #[inline]
    pub fn search<S>(mut self, value: S) -> Self
    where
        S: Into<String>,
    {
        self.search = Some(value.into());
        self
    }

    /// Remove search
    #[inline]
    pub fn remove_search(mut self) -> Self {
        self.search = None;
        self
    }

    /// Add since unix timestamp
    #[inline]
    pub fn since(mut self, since: Timestamp) -> Self {
        self.since = Some(since);
        self
    }

    /// Remove since
    #[inline]
    pub fn remove_since(mut self) -> Self {
        self.since = None;
        self
    }

    /// Add until unix timestamp
    #[inline]
    pub fn until(mut self, until: Timestamp) -> Self {
        self.until = Some(until);
        self
    }

    /// Remove until
    #[inline]
    pub fn remove_until(mut self) -> Self {
        self.until = None;
        self
    }

    /// Add limit
    ///
    /// Maximum number of events to be returned in the initial query
    #[inline]
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Remove limit
    #[inline]
    pub fn remove_limit(mut self) -> Self {
        self.limit = None;
        self
    }

    /// Add custom tag
    pub fn custom_tag<S>(self, tag: SingleLetterTag, value: S) -> Self
    where
        S: Into<String>,
    {
        self.custom_tags(tag, [value])
    }

    /// Add a generic tag from an already-constructed [`Tag`]
    ///
    /// Only single-letter tags can be indexed in a [`Filter`]. The value is
    /// derived from the tag's serialized form (the element after the tag name).
    /// If the `tag` has no single-letter representation or no value, the filter
    /// is returned unchanged.
    pub fn tag(self, tag: Tag) -> Self {
        // Only single-letter tags can be indexed in a filter
        let single_letter_tag: SingleLetterTag = match tag.single_letter_tag() {
            Some(t) => t,
            None => return self,
        };

        // Derive the value from the serialized form (the element after the tag name)
        match tag.content() {
            Some(value) => self.custom_tag(single_letter_tag, value),
            // No value to index: leave the filter unchanged
            None => self,
        }
    }

    /// Add custom tags
    pub fn custom_tags<I, S>(mut self, tag: SingleLetterTag, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let values: BTreeSet<String> = values.into_iter().map(|v| v.into()).collect();
        self.generic_tags.entry(tag).or_default().extend(values);
        self
    }

    /// Remove custom tag
    pub fn remove_custom_tags<I, T>(mut self, tag: SingleLetterTag, values: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let values = values.into_iter().map(|v| v.into());
        self.generic_tags.entry(tag).and_modify(|set| {
            for item in values {
                set.remove(&item);
            }
        });

        // Remove tag if empty
        if let Some(set) = self.generic_tags.get(&tag) {
            if set.is_empty() {
                self.generic_tags.remove(&tag);
            }
        }

        self
    }

    /// Check if [`Filter`] is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self == &Filter::default()
    }

    /// Extract **all** public keys (both from `authors` and `#p`)
    pub fn extract_public_keys(&self) -> BTreeSet<PublicKey> {
        let mut public_keys: BTreeSet<PublicKey> = BTreeSet::new();

        if let Some(authors) = &self.authors {
            public_keys.extend(authors);
        }

        if let Some(p_tag) = self.generic_tags.get(&SingleLetterTag::LOWERCASE_P) {
            public_keys.extend(p_tag.iter().filter_map(|p| PublicKey::from_hex(p).ok()));
        }

        public_keys
    }

    #[inline]
    fn ids_match(&self, event: &Event) -> bool {
        self.ids
            .as_ref()
            .is_none_or(|ids| ids.is_empty() || ids.contains(&event.id))
    }

    #[inline]
    fn authors_match(&self, event: &Event) -> bool {
        self.authors
            .as_ref()
            .is_none_or(|authors| authors.is_empty() || authors.contains(&event.pubkey))
    }

    fn tag_match(&self, event: &Event) -> bool {
        if self.generic_tags.is_empty() {
            return true;
        }

        if event.tags.is_empty() {
            return false;
        }

        let mut missing: usize = self.generic_tags.len();
        let mut done: u64 = 0;

        for t in event.tags.iter() {
            let (Some(letter), Some(val)) = (t.single_letter_tag(), t.content()) else {
                continue;
            };

            let bit: u32 = letter_bit(letter);

            // If already done, immediately skip, avoiding the BTreeSet lookup
            if done & (1u64 << bit) != 0 {
                continue;
            }

            let Some(set) = self.generic_tags.get(&letter) else {
                continue;
            };

            if set.contains(val) {
                done |= 1u64 << bit;

                missing -= 1;

                if missing == 0 {
                    return true;
                }
            }
        }

        missing == 0
    }

    #[inline]
    fn kind_match(&self, event: &Event) -> bool {
        self.kinds
            .as_ref()
            .is_none_or(|kinds| kinds.is_empty() || kinds.contains(&event.kind))
    }

    #[inline]
    fn search_match(&self, event: &Event) -> bool {
        match &self.search {
            // `windows(0)` panics, while an empty substring is defined to match.
            Some(query) if query.is_empty() => true,
            Some(query) => event
                .content
                .as_bytes()
                .windows(query.len())
                .any(|window| window.eq_ignore_ascii_case(query.as_bytes())),
            None => true,
        }
    }

    /// Determine if [Filter] match given [Event].
    #[inline]
    pub fn match_event(&self, event: &Event, opts: MatchEventOptions) -> bool {
        (!opts.id || self.ids_match(event))
            && (!opts.author || self.authors_match(event))
            && (!opts.kind || self.kind_match(event))
            && (!opts.since || self.since.is_none_or(|t| event.created_at >= t))
            && (!opts.until || self.until.is_none_or(|t| event.created_at <= t))
            && (!opts.tags || self.tag_match(event))
            && (!opts.nip50 || self.search_match(event))
    }
}

/// 'a'..'z' -> 0..25, 'A'..'Z' -> 26..51
#[inline]
fn letter_bit(letter: SingleLetterTag) -> u32 {
    let c: char = letter.as_char();
    let base: u32 = (c.to_ascii_lowercase() as u32) - ('a' as u32);
    if c.is_ascii_lowercase() {
        base
    } else {
        base + 26
    }
}

impl_json_methods!(Filter);

impl From<Filter> for Vec<Filter> {
    fn from(filter: Filter) -> Self {
        vec![filter]
    }
}

fn serialize_generic_tags<S>(generic_tags: &GenericTags, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(generic_tags.len()))?;

    // The key is always `#` followed by a single ASCII letter, so it fits in a
    // fixed buffer. `format!` would allocate a `String` for every entry.
    let mut key: [u8; 2] = [b'#', 0];

    for (tag, values) in generic_tags.iter() {
        key[1] = tag.as_byte();
        let key: &str = core::str::from_utf8(&key).map_err(serde::ser::Error::custom)?;
        map.serialize_entry(key, values)?;
    }

    map.end()
}

/// A generic tag query key.
///
/// `Some` when the key is `#` followed by a single letter, `None` for any other
/// key, which is ignored. Deserializing through this avoids allocating a
/// `String` for every key in the map.
struct TagKey(Option<SingleLetterTag>);

impl<'de> Deserialize<'de> for TagKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagKeyVisitor;

        impl Visitor<'_> for TagKeyVisitor {
            type Value = TagKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut chars = v.chars();
                if let (Some('#'), Some(ch), None) = (chars.next(), chars.next(), chars.next()) {
                    let tag: SingleLetterTag =
                        SingleLetterTag::from_char(ch).map_err(serde::de::Error::custom)?;
                    Ok(TagKey(Some(tag)))
                } else {
                    Ok(TagKey(None))
                }
            }
        }

        deserializer.deserialize_str(TagKeyVisitor)
    }
}

fn deserialize_generic_tags<'de, D>(deserializer: D) -> Result<GenericTags, D::Error>
where
    D: Deserializer<'de>,
{
    struct GenericTagsVisitor;

    impl<'de> Visitor<'de> for GenericTagsVisitor {
        type Value = GenericTags;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("map in which the keys are \"#X\" for some character X")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut generic_tags = BTreeMap::new();
            while let Some(TagKey(tag)) = map.next_key::<TagKey>()? {
                match tag {
                    Some(tag) => {
                        let values: BTreeSet<String> = map.next_value()?;
                        generic_tags.insert(tag, values);
                    }
                    // Not a `#X` key, so it isn't a generic tag query.
                    None => {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
            }
            Ok(generic_tags)
        }
    }

    deserializer.deserialize_map(GenericTagsVisitor)
}

fn extend_or_collect<T, I>(mut set: Option<BTreeSet<T>>, iter: I) -> Option<BTreeSet<T>>
where
    I: IntoIterator<Item = T>,
    T: Eq + Ord + Hash,
{
    match set.as_mut() {
        Some(s) => {
            s.extend(iter);
        }
        None => set = Some(iter.into_iter().collect()),
    };
    set
}

/// Remove values from set
/// If after remove the set is empty, will be returned `None`
fn remove_or_none<T, I>(mut set: Option<BTreeSet<T>>, iter: I) -> Option<BTreeSet<T>>
where
    I: IntoIterator<Item = T>,
    T: Eq + Ord + Hash,
{
    if let Some(s) = set.as_mut() {
        for item in iter.into_iter() {
            s.remove(&item);
        }

        if s.is_empty() {
            set = None;
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::event::{Signature, Tags};
    use crate::nips::nip01::Nip01Tag;

    #[test]
    fn test_kind_concatenation() {
        let filter = Filter::new()
            .kind(Kind::Metadata)
            .kind(Kind::TextNote)
            .kind(Kind::ContactList)
            .kinds([
                Kind::EncryptedDirectMessage,
                Kind::Metadata,
                Kind::LongFormTextNote,
            ]);
        assert_eq!(
            filter,
            Filter::new().kinds([
                Kind::Metadata,
                Kind::TextNote,
                Kind::ContactList,
                Kind::EncryptedDirectMessage,
                Kind::LongFormTextNote
            ])
        );
    }

    #[test]
    fn test_empty_filter_serialization() {
        let filter = Filter::new().authors([]);
        assert_eq!(filter.as_json(), r#"{"authors":[]}"#);

        let filter = Filter::new().pubkeys([]);
        assert_eq!(filter.as_json(), r##"{"#p":[]}"##);
    }

    #[test]
    fn test_remove() {
        let event_id =
            EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                .unwrap();

        // Test remove ids
        let filter = Filter::new().id(EventId::all_zeros()).id(event_id);
        let filter = filter.remove_ids([EventId::all_zeros()]);
        assert_eq!(filter, Filter::new().id(event_id));

        // Test remove #e tag
        let filter = Filter::new().events([EventId::all_zeros(), event_id]);
        let filter = filter.remove_events([EventId::all_zeros()]);
        assert_eq!(filter, Filter::new().event(event_id));
        let filter = filter.remove_events([event_id]);
        assert!(filter.is_empty());

        // Test remove #d tag
        let mut filter = Filter::new().identifier("myidentifier");
        filter = filter.custom_tag(SingleLetterTag::LOWERCASE_D, "mysecondid");
        filter = filter.identifiers(["test", "test2"]);
        filter = filter.remove_custom_tags(SingleLetterTag::LOWERCASE_D, ["test2"]);
        filter = filter.remove_identifiers(["mysecondid"]);
        assert_eq!(filter, Filter::new().identifiers(["myidentifier", "test"]));

        // Test remove custom tag
        let filter = Filter::new().custom_tags(SingleLetterTag::LOWERCASE_C, ["test", "test2"]);
        let filter = filter.remove_custom_tags(SingleLetterTag::LOWERCASE_C, ["test2"]);
        assert_eq!(
            filter,
            Filter::new().custom_tag(SingleLetterTag::LOWERCASE_C, "test")
        );
    }

    #[test]
    #[cfg(not(feature = "std"))]
    fn test_filter_serialization() {
        let filter = Filter::new()
            .identifier("identifier")
            .search("test")
            .custom_tag(SingleLetterTag::LOWERCASE_J, "test1")
            .custom_tag(
                SingleLetterTag::LOWERCASE_P,
                "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe",
            )
            .custom_tag(SingleLetterTag::LOWERCASE_Z, "rating");
        let json = r##"{"search":"test","#d":["identifier"],"#j":["test1"],"#p":["379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe"],"#z":["rating"]}"##;
        assert_eq!(filter.as_json(), json);
    }

    #[test]
    fn test_filter_serialization_with_uppercase_tag() {
        let filter = Filter::new().custom_tag(
            SingleLetterTag::UPPERCASE_P,
            "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe",
        );
        let json =
            r##"{"#P":["379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe"]}"##;
        assert_eq!(filter.as_json(), json);
    }

    #[test]
    fn test_filter_deserialization() {
        let json = r##"{"#a":["...", "test"],"#e":["70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5"],"#p":["379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe"],"search":"test","ids":["70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5"]}"##;
        let filter = Filter::from_json(json).unwrap();
        let event_id =
            EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                .unwrap();
        let pubkey =
            PublicKey::from_hex("379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe")
                .unwrap();

        // Check IDs
        assert!(filter.ids.unwrap().contains(&event_id));
        assert_eq!(filter.search, Some(String::from("test")));

        // Check #e tag
        let set = filter
            .generic_tags
            .get(&SingleLetterTag::LOWERCASE_E)
            .unwrap();
        assert!(set.contains(&event_id.to_hex()));

        // Check #p tag
        let set = filter
            .generic_tags
            .get(&SingleLetterTag::LOWERCASE_P)
            .unwrap();
        assert!(set.contains(&pubkey.to_hex()));

        // Check #a tag
        let set = filter
            .generic_tags
            .get(&SingleLetterTag::LOWERCASE_A)
            .unwrap();
        assert!(set.contains("..."));
        assert!(set.contains("test"));

        let json = r##"{"#":["..."],"search":"test"}"##;
        let filter = Filter::from_json(json).unwrap();
        assert_eq!(filter, Filter::new().search("test"));

        let json = r##"{"aa":["..."],"search":"test"}"##;
        let filter = Filter::from_json(json).unwrap();
        assert_eq!(filter, Filter::new().search("test"));
    }

    /// A key is a generic tag query only when it is `#` followed by exactly one
    /// letter. Anything else is ignored, except a single non-letter character,
    /// which is rejected.
    #[test]
    fn test_generic_tag_key_shapes() {
        // Ignored: not `#` + exactly one character.
        for json in [
            r##"{"#ab":["x"],"search":"test"}"##,
            r##"{"#":["x"],"search":"test"}"##,
            r##"{"t":["x"],"search":"test"}"##,
            r##"{"":["x"],"search":"test"}"##,
        ] {
            let filter = Filter::from_json(json).unwrap();
            assert_eq!(filter, Filter::new().search("test"), "{json}");
        }

        // Rejected: `#` followed by a single non-letter.
        for json in [
            r##"{"#1":["x"]}"##,
            r##"{"#_":["x"]}"##,
            r##"{"# ":["x"]}"##,
            r###"{"##":["x"]}"###,
        ] {
            assert!(Filter::from_json(json).is_err(), "{json}");
        }

        // Accepted, both cases.
        let filter = Filter::from_json(r##"{"#t":["x"],"#T":["y"]}"##).unwrap();
        assert_eq!(filter.generic_tags.len(), 2);
        assert_eq!(filter.as_json(), r##"{"#t":["x"],"#T":["y"]}"##);
    }

    #[test]
    fn test_filter_is_empty() {
        let filter = Filter::new().identifier("test");
        assert!(!filter.is_empty());

        let filter = Filter::new();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_match_event() {
        let event_id =
            EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                .unwrap();
        let pubkey =
            PublicKey::from_str("379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe")
                .unwrap();
        let event =
            Event::new(
                event_id,
                pubkey,
                Timestamp::from(1612809991),
                Kind::TextNote,
                [
                    Nip01Tag::public_key(PublicKey::from_str("b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a").unwrap()),
                    Nip01Tag::event(EventId::from_hex("7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96").unwrap()),
                ],
                "test",
                Signature::from_str("273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502").unwrap(),
            );
        let event_with_empty_tags: Event = Event::new(
            event_id,
            pubkey,
            Timestamp::from(1612809992),
            Kind::TextNote,
            Tags::new(),
            "test",
            Signature::from_str("273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502").unwrap(),
        );

        // ID match
        let filter: Filter = Filter::new().id(event_id);
        assert!(filter.match_event(&event, MatchEventOptions::new()));

        // Not match (kind)
        let filter: Filter = Filter::new().id(event_id).kind(Kind::Metadata);
        assert!(!filter.match_event(&event, MatchEventOptions::new()));

        // Match (author, kind and since)
        let filter: Filter = Filter::new()
            .author(pubkey)
            .kind(Kind::TextNote)
            .since(Timestamp::from(1612808000));
        assert!(filter.match_event(&event, MatchEventOptions::new()));

        // Not match (since)
        let filter: Filter = Filter::new()
            .author(pubkey)
            .kind(Kind::TextNote)
            .since(Timestamp::from(1700000000));
        assert!(!filter.match_event(&event, MatchEventOptions::new()));

        // Match (#p tag and kind)
        let filter: Filter = Filter::new()
            .pubkey(
                PublicKey::from_str(
                    "b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a",
                )
                .unwrap(),
            )
            .kind(Kind::TextNote);
        assert!(filter.match_event(&event, MatchEventOptions::new()));

        // Match (tags)
        let filter: Filter = Filter::new()
            .pubkey(
                PublicKey::from_str(
                    "b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a",
                )
                .unwrap(),
            )
            .event(
                EventId::from_hex(
                    "7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96",
                )
                .unwrap(),
            );
        assert!(filter.match_event(&event, MatchEventOptions::new()));

        // Match (tags)
        let filter: Filter = Filter::new().events(vec![
            EventId::from_hex("7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96")
                .unwrap(),
            EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                .unwrap(),
        ]);
        assert!(filter.match_event(&event, MatchEventOptions::new()));

        // Not match (tags)
        let filter: Filter = Filter::new().events(vec![
            EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                .unwrap(),
        ]);
        assert!(!filter.match_event(&event, MatchEventOptions::new()));

        // Not match (tags filter for events with empty tags)
        let filter: Filter = Filter::new().hashtag("this-should-not-match");
        assert!(!filter.match_event(&event, MatchEventOptions::new()));
        assert!(!filter.match_event(&event_with_empty_tags, MatchEventOptions::new()));

        // Test match search
        let filter: Filter = Filter::new().search("test");
        assert!(filter.match_event(&event, MatchEventOptions::new()));
    }

    #[test]
    fn test_filter_search_match_event() {
        let json: &str = r#"{
              "id": "3d1e30c357eba92568ba67138f9a508d29b306e5254952ee4d7c8039bd4a48fa",
              "pubkey": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
              "created_at": 1711027680,
              "kind": 0,
              "tags": [
                [
                  "alt",
                  "User profile for Yuki Kishimoto"
                ],
                [
                  "i",
                  "github:yukibtc",
                  "69d9980b6e6b5d77a3e1e369ccaca9ba"
                ]
              ],
              "content": "{\"banner\":\"https://i.imgur.com/f1h1GgJ.jpg\",\"website\":\"https://yukikishimoto.com\",\"nip05\":\"_@yukikishimoto.com\",\"picture\":\"https://yukikishimoto.com/images/avatar.jpg\",\"lud16\":\"pay@yukikishimoto.com\",\"display_name\":\"Yuki Kishimoto\",\"about\":\"GitHub: https://github.com/yukibtc\\nPGP: 86F3 105A DFA8 AB58 7268  DCD7 8D3D CD04 2496 19D1\",\"name\":\"Yuki Kishimoto\",\"displayName\":\"Yuki Kishimoto\"}",
              "sig": "27dddf90036cb7ea893eb13827342c49cbb72c442b3ac7b1f09081868b752d4c6e85882a881599e02a1374d4825e492e81703d44bce9728adccf66bb49f14220"
            }
        "#;
        let event = Event::from_json(json).unwrap();

        let filter = Filter::new().search("Yuki kishi");
        assert!(filter.match_event(&event, MatchEventOptions::new()));

        let filter = Filter::new().search("yuki kishimoto");
        assert!(filter.match_event(&event, MatchEventOptions::new()));

        let filter = Filter::new().search("");
        assert!(filter.match_event(&event, MatchEventOptions::new()));
    }
}

#[cfg(bench)]
mod benches {
    use core::str::FromStr;

    use test::{Bencher, black_box};

    use super::*;
    use crate::event::Signature;

    #[bench]
    pub fn filter_match_event(bh: &mut Bencher) {
        // Event
        let event =
            Event::new(
                EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                    .unwrap(),
                PublicKey::from_hex("379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe")
                    .unwrap(),
                Timestamp::from(1612809991),
                Kind::TextNote,
                [
                    ["p", "b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a"],
                    ["p", "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe"],
                    ["e", "7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96"],
                    ["k", "1"],
                ],
                "#JoininBox is a minimalistic, security focused Linux environment for #JoinMarket with a terminal based graphical menu.\n\nnostr:npub14tq8m9ggnnn2muytj9tdg0q6f26ef3snpd7ukyhvrxgq33vpnghs8shy62 👍🧡\n\nhttps://www.nobsbitcoin.com/joininbox-v0-8-0/",
                Signature::from_str("273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502").unwrap(),
            );

        // Filter
        let id =
            EventId::from_hex("7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96")
                .unwrap();
        let filter = Filter::new().event(id).search("linux").kind(Kind::TextNote);

        bh.iter(|| {
            black_box(filter.match_event(&event, MatchEventOptions::new()));
        });
    }
}
