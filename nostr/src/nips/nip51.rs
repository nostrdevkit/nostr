// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-51: Lists
//!
//! <https://github.com/nostr-protocol/nips/blob/master/51.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::nip01::Coordinate;
use super::nip30::Nip30Tag;
use super::util::{
    missing_tag_kind, take_event_id, take_public_key, take_relay_url, take_string, unknown_tag,
};
use crate::event::{
    EventBuilder, EventId, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::url::{RelayUrl, Url};

const WORD: &str = "word";
const PUBLIC_KEY: &str = "p";
const HASHTAG: &str = "t";
const EVENT: &str = "e";
const RELAY: &str = "relay";

/// Standardized NIP-51 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/51.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip51Tag {
    /// `p` tag
    PublicKey(PublicKey),
    /// `t` tag
    Hashtag(String),
    /// `e` tag
    Event(EventId),
    /// `relay` tag
    Relay(RelayUrl),
    /// `word` tag
    Word(String),
}

impl_tag_codec_conversions! {
    Nip51Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            PUBLIC_KEY => {
                let public_key: PublicKey = take_public_key(&mut iter)?;
                Ok(Self::PublicKey(public_key))
            }
            HASHTAG => {
                let hashtag: String = take_string(&mut iter, "hashtag")?;
                Ok(Self::Hashtag(hashtag.to_lowercase()))
            }
            EVENT => {
                let event_id: EventId = take_event_id(&mut iter)?;
                Ok(Self::Event(event_id))
            }
            RELAY => {
                let relay_url: RelayUrl = take_relay_url(&mut iter)?;
                Ok(Self::Relay(relay_url))
            }
            WORD => Ok(Self::Word(take_string(&mut iter, "word")?)),
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::PublicKey(public_key) => {
                Tag::new(vec![String::from(PUBLIC_KEY), public_key.to_hex()])
            }
            Self::Hashtag(hashtag) => Tag::new(vec![String::from(HASHTAG), hashtag.to_lowercase()]),
            Self::Event(event_id) => Tag::new(vec![String::from(EVENT), event_id.to_hex()]),
            Self::Relay(relay_url) => Tag::new(vec![String::from(RELAY), relay_url.to_string()]),
            Self::Word(word) => Tag::new(vec![String::from(WORD), word.clone()]),
        }
    }
}

/// Things the user doesn't want to see in their feeds
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MuteList {
    /// Public Keys
    pub public_keys: Vec<PublicKey>,
    /// Hashtags
    pub hashtags: Vec<String>,
    /// Event IDs
    pub event_ids: Vec<EventId>,
    /// Words
    pub words: Vec<String>,
}

impl From<MuteList> for Vec<Tag> {
    fn from(
        MuteList {
            public_keys,
            hashtags,
            event_ids,
            words,
        }: MuteList,
    ) -> Self {
        let mut tags =
            Vec::with_capacity(public_keys.len() + hashtags.len() + event_ids.len() + words.len());

        tags.extend(
            public_keys
                .into_iter()
                .map(Nip51Tag::PublicKey)
                .map(Into::into),
        );
        tags.extend(hashtags.into_iter().map(Nip51Tag::Hashtag).map(Into::into));
        tags.extend(event_ids.into_iter().map(Nip51Tag::Event).map(Into::into));
        tags.extend(words.into_iter().map(Nip51Tag::Word).map(Into::into));

        tags
    }
}

impl IntoEventBuilder for MuteList {
    fn into_event_builder(self) -> EventBuilder {
        let tags: Vec<Tag> = self.into();
        EventBuilder::new(Kind::MuteList).tags(tags)
    }
}

/// Uncategorized, "global" list of things a user wants to save
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bookmarks {
    /// Event IDs
    pub event_ids: Vec<EventId>,
    /// Coordinates
    pub coordinate: Vec<Coordinate>,
}

impl From<Bookmarks> for Vec<Tag> {
    fn from(
        Bookmarks {
            event_ids,
            coordinate,
        }: Bookmarks,
    ) -> Self {
        let mut tags = Vec::with_capacity(event_ids.len() + coordinate.len());

        tags.extend(event_ids.into_iter().map(Tag::event));
        tags.extend(coordinate.into_iter().map(Tag::from));

        tags
    }
}

impl IntoEventBuilder for Bookmarks {
    fn into_event_builder(self) -> EventBuilder {
        let tags: Vec<Tag> = self.into();
        EventBuilder::new(Kind::Bookmarks).tags(tags)
    }
}

/// Topics a user may be interested in and pointers
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interests {
    /// Hashtags
    pub hashtags: Vec<String>,
    /// Coordinates
    pub coordinate: Vec<Coordinate>,
}

impl From<Interests> for Vec<Tag> {
    fn from(
        Interests {
            hashtags,
            coordinate,
        }: Interests,
    ) -> Self {
        let mut tags = Vec::with_capacity(hashtags.len() + coordinate.len());

        tags.extend(hashtags.into_iter().map(Tag::hashtag));
        tags.extend(coordinate.into_iter().map(Tag::from));

        tags
    }
}

impl IntoEventBuilder for Interests {
    fn into_event_builder(self) -> EventBuilder {
        let tags: Vec<Tag> = self.into();
        EventBuilder::new(Kind::Interests).tags(tags)
    }
}

/// User preferred emojis and pointers to emoji sets
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Emojis {
    /// Emojis
    pub emojis: Vec<(String, Url)>,
    /// Coordinates
    pub coordinate: Vec<Coordinate>,
}

impl From<Emojis> for Vec<Tag> {
    fn from(Emojis { emojis, coordinate }: Emojis) -> Self {
        let mut tags = Vec::with_capacity(emojis.len() + coordinate.len());

        tags.extend(emojis.into_iter().map(|(shortcode, image_url)| {
            Nip30Tag::Emoji {
                shortcode,
                image_url,
                emoji_set: None,
            }
            .to_tag()
        }));
        tags.extend(coordinate.into_iter().map(Tag::from));

        tags
    }
}

impl IntoEventBuilder for Emojis {
    fn into_event_builder(self) -> EventBuilder {
        let tags: Vec<Tag> = self.into();
        EventBuilder::new(Kind::Emojis).tags(tags)
    }
}

/// Groups of articles picked by users as interesting and/or belonging to the same category
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArticlesCuration {
    /// Coordinates
    pub coordinate: Vec<Coordinate>,
    /// Event IDs
    pub event_ids: Vec<EventId>,
}

impl From<ArticlesCuration> for Vec<Tag> {
    fn from(
        ArticlesCuration {
            coordinate,
            event_ids,
        }: ArticlesCuration,
    ) -> Self {
        let mut tags = Vec::with_capacity(coordinate.len() + event_ids.len());

        tags.extend(coordinate.into_iter().map(Tag::from));
        tags.extend(event_ids.into_iter().map(Tag::event));

        tags
    }
}

/// Pinned notes list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinnedNotes {
    event_ids: Vec<EventId>,
}

impl PinnedNotes {
    /// Create a pinned notes list.
    pub fn new<I>(event_ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        Self {
            event_ids: event_ids.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for PinnedNotes {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::PinList).tags(self.event_ids.into_iter().map(Tag::event))
    }
}

/// Communities list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Communities {
    coordinates: Vec<Coordinate>,
}

impl Communities {
    /// Create a communities list.
    pub fn new<I>(coordinates: I) -> Self
    where
        I: IntoIterator<Item = Coordinate>,
    {
        Self {
            coordinates: coordinates.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for Communities {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Communities).tags(self.coordinates.into_iter().map(Tag::from))
    }
}

/// Public chats list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicChats {
    event_ids: Vec<EventId>,
}

impl PublicChats {
    /// Create a public chats list.
    pub fn new<I>(event_ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        Self {
            event_ids: event_ids.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for PublicChats {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::PublicChats).tags(self.event_ids.into_iter().map(Tag::event))
    }
}

/// Blocked relays list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockedRelays {
    relays: Vec<RelayUrl>,
}

impl BlockedRelays {
    /// Create a blocked relays list.
    pub fn new<I>(relays: I) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        Self {
            relays: relays.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for BlockedRelays {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::BlockedRelays).tags(self.relays.into_iter().map(Nip51Tag::Relay))
    }
}

/// Search relays list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SearchRelays {
    relays: Vec<RelayUrl>,
}

impl SearchRelays {
    /// Create a search relays list.
    pub fn new<I>(relays: I) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        Self {
            relays: relays.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for SearchRelays {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::SearchRelays).tags(self.relays.into_iter().map(Nip51Tag::Relay))
    }
}

/// Follow set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FollowSet {
    identifier: String,
    public_keys: Vec<PublicKey>,
}

impl FollowSet {
    /// Create a follow set.
    pub fn new<ID, I>(identifier: ID, public_keys: I) -> Self
    where
        ID: Into<String>,
        I: IntoIterator<Item = PublicKey>,
    {
        Self {
            identifier: identifier.into(),
            public_keys: public_keys.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for FollowSet {
    fn into_event_builder(self) -> EventBuilder {
        let tags = core::iter::once(Tag::identifier(self.identifier))
            .chain(self.public_keys.into_iter().map(Tag::public_key));
        EventBuilder::new(Kind::FollowSet).tags(tags)
    }
}

/// Relay set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelaySet {
    identifier: String,
    relays: Vec<RelayUrl>,
}

impl RelaySet {
    /// Create a relay set.
    pub fn new<ID, I>(identifier: ID, relays: I) -> Self
    where
        ID: Into<String>,
        I: IntoIterator<Item = RelayUrl>,
    {
        Self {
            identifier: identifier.into(),
            relays: relays.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for RelaySet {
    fn into_event_builder(self) -> EventBuilder {
        let tags = core::iter::once(Tag::identifier(self.identifier))
            .chain(self.relays.into_iter().map(Nip51Tag::Relay).map(Into::into));
        EventBuilder::new(Kind::RelaySet).tags(tags)
    }
}

/// Bookmark set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BookmarkSet {
    identifier: String,
    bookmarks: Bookmarks,
}

impl BookmarkSet {
    /// Create a bookmark set.
    pub fn new<S>(identifier: S, bookmarks: Bookmarks) -> Self
    where
        S: Into<String>,
    {
        Self {
            identifier: identifier.into(),
            bookmarks,
        }
    }
}

impl IntoEventBuilder for BookmarkSet {
    fn into_event_builder(self) -> EventBuilder {
        let mut tags: Vec<Tag> = self.bookmarks.into();
        tags.push(Tag::identifier(self.identifier));
        EventBuilder::new(Kind::BookmarkSet).tags(tags)
    }
}

/// Articles curation set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArticlesCurationSet {
    identifier: String,
    articles: ArticlesCuration,
}

impl ArticlesCurationSet {
    /// Create an articles curation set.
    pub fn new<S>(identifier: S, articles: ArticlesCuration) -> Self
    where
        S: Into<String>,
    {
        Self {
            identifier: identifier.into(),
            articles,
        }
    }
}

impl IntoEventBuilder for ArticlesCurationSet {
    fn into_event_builder(self) -> EventBuilder {
        let mut tags: Vec<Tag> = self.articles.into();
        tags.push(Tag::identifier(self.identifier));
        EventBuilder::new(Kind::ArticlesCurationSet).tags(tags)
    }
}

/// Videos curation set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VideosCurationSet {
    identifier: String,
    videos: Vec<Coordinate>,
}

impl VideosCurationSet {
    /// Create a videos curation set.
    pub fn new<S, I>(identifier: S, videos: I) -> Self
    where
        S: Into<String>,
        I: IntoIterator<Item = Coordinate>,
    {
        Self {
            identifier: identifier.into(),
            videos: videos.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for VideosCurationSet {
    fn into_event_builder(self) -> EventBuilder {
        let tags = core::iter::once(Tag::identifier(self.identifier)).chain(
            self.videos
                .into_iter()
                .map(|video| Tag::coordinate(video, None)),
        );
        EventBuilder::new(Kind::VideosCurationSet).tags(tags)
    }
}

/// Interest set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterestSet {
    identifier: String,
    hashtags: Vec<String>,
}

impl InterestSet {
    /// Create an interest set.
    pub fn new<ID, I, S>(identifier: ID, hashtags: I) -> Self
    where
        ID: Into<String>,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            identifier: identifier.into(),
            hashtags: hashtags.into_iter().map(Into::into).collect(),
        }
    }
}

impl IntoEventBuilder for InterestSet {
    fn into_event_builder(self) -> EventBuilder {
        let tags = core::iter::once(Tag::identifier(self.identifier))
            .chain(self.hashtags.into_iter().map(Tag::hashtag));
        EventBuilder::new(Kind::InterestSet).tags(tags)
    }
}

/// Emoji set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmojiSet {
    identifier: String,
    emojis: Vec<(String, Url)>,
}

impl EmojiSet {
    /// Create an emoji set.
    pub fn new<S, I>(identifier: S, emojis: I) -> Self
    where
        S: Into<String>,
        I: IntoIterator<Item = (String, Url)>,
    {
        Self {
            identifier: identifier.into(),
            emojis: emojis.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for EmojiSet {
    fn into_event_builder(self) -> EventBuilder {
        let tags = core::iter::once(Tag::identifier(self.identifier)).chain(
            self.emojis.into_iter().map(|(shortcode, image_url)| {
                Nip30Tag::Emoji {
                    shortcode,
                    image_url,
                    emoji_set: None,
                }
                .to_tag()
            }),
        );
        EventBuilder::new(Kind::EmojiSet).tags(tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_tag() {
        let public_key =
            PublicKey::from_hex("04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9")
                .unwrap();
        let tag = vec![
            "p",
            "04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9",
        ];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip51Tag::PublicKey(public_key));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_hashtag_tag() {
        let tag = vec!["t", "Nostr"];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip51Tag::Hashtag(String::from("nostr")));
        assert_eq!(parsed.to_tag(), Tag::parse(["t", "nostr"]).unwrap());
    }

    #[test]
    fn test_event_tag() {
        let event_id =
            EventId::from_hex("9ae37aa68f48645127299e9453eb5d908a0cbb6058ff340d528ed4d37c8994fb")
                .unwrap();
        let tag = vec![
            "e",
            "9ae37aa68f48645127299e9453eb5d908a0cbb6058ff340d528ed4d37c8994fb",
        ];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip51Tag::Event(event_id));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_word_tag() {
        let tag = vec!["word", "spam"];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip51Tag::Word(String::from("spam")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_relay_tag() {
        let tag = vec!["relay", "wss://relay.damus.io"];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip51Tag::Relay(RelayUrl::parse("wss://relay.damus.io").unwrap())
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn list_events() {
        let pinned = PinnedNotes::new([EventId::all_zeros()]).into_event_builder();
        assert_eq!(pinned.kind, Kind::PinList);
        assert_eq!(pinned.tags.len(), 1);

        let public_key =
            PublicKey::from_hex("04c915daefee38317fa734444acee390a8269fe5810b2241e5e6dd343dfbecc9")
                .unwrap();
        let follow_set = FollowSet::new("friends", [public_key]).into_event_builder();
        assert_eq!(follow_set.kind, Kind::FollowSet);
        assert_eq!(follow_set.tags.identifier(), Some(String::from("friends")));
        assert_eq!(
            follow_set.tags.public_keys().collect::<Vec<_>>(),
            [public_key]
        );
    }
}
