// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-51: Lists
//!
//! <https://github.com/nostr-protocol/nips/blob/master/51.md>

use alloc::string::String;
use alloc::vec::Vec;

use super::nip01::{Coordinate, Nip01Tag};
use super::nip30::Nip30Tag;
use super::util::{
    missing_tag_kind, take_event_id, take_public_key, take_relay_url, take_string, unknown_tag,
};
use crate::event::{EventBuilder, EventId, IntoEventBuilder, Kind, impl_tag_codec_conversions};
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

    fn write(self, tx) {
        match self {
            Self::PublicKey(public_key) => {
                tx.push_str(PUBLIC_KEY);
                tx.push_hex(public_key.as_bytes());
            }
            Self::Hashtag(hashtag) => {
                tx.push_str(HASHTAG);
                tx.push_str(&hashtag.to_lowercase());
            }
            Self::Event(event_id) => {
                tx.push_str(EVENT);
                tx.push_hex(event_id.as_bytes());
            }
            Self::Relay(relay_url) => {
                tx.push_str(RELAY);
                tx.push_str(relay_url.as_str());
            }
            Self::Word(word) => {
                tx.push_str(WORD);
                tx.push_str(&word);
            }
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

impl IntoEventBuilder for MuteList {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::MuteList)
            .tags(self.public_keys.into_iter().map(Nip51Tag::PublicKey))
            .tags(self.hashtags.into_iter().map(Nip51Tag::Hashtag))
            .tags(self.event_ids.into_iter().map(Nip51Tag::Event))
            .tags(self.words.into_iter().map(Nip51Tag::Word))
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

impl IntoEventBuilder for Bookmarks {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Bookmarks)
            .tags(self.event_ids.into_iter().map(Nip01Tag::event))
            .tags(self.coordinate.into_iter().map(Nip01Tag::from))
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

impl IntoEventBuilder for Interests {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Interests)
            .tags(self.hashtags.into_iter().map(Nip51Tag::Hashtag))
            .tags(self.coordinate.into_iter().map(Nip01Tag::from))
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

impl IntoEventBuilder for Emojis {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Emojis)
            .tags(
                self.emojis
                    .into_iter()
                    .map(|(shortcode, image_url)| Nip30Tag::Emoji {
                        shortcode,
                        image_url,
                        emoji_set: None,
                    }),
            )
            .tags(self.coordinate.into_iter().map(Nip01Tag::from))
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
        EventBuilder::new(Kind::PinList).tags(self.event_ids.into_iter().map(Nip01Tag::event))
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
        EventBuilder::new(Kind::Communities).tags(self.coordinates.into_iter().map(Nip01Tag::from))
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
        EventBuilder::new(Kind::PublicChats).tags(self.event_ids.into_iter().map(Nip01Tag::event))
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
        EventBuilder::new(Kind::FollowSet)
            .tag(Nip01Tag::identifier(self.identifier))
            .tags(self.public_keys.into_iter().map(Nip01Tag::public_key))
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
        EventBuilder::new(Kind::RelaySet)
            .tag(Nip01Tag::identifier(self.identifier))
            .tags(self.relays.into_iter().map(Nip51Tag::Relay))
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
        let mut builder: EventBuilder = self.bookmarks.into_event_builder();
        builder.kind = Kind::BookmarkSet;
        builder.tag(Nip01Tag::identifier(self.identifier))
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
        EventBuilder::new(Kind::ArticlesCurationSet)
            .tag(Nip01Tag::identifier(self.identifier))
            .tags(self.articles.coordinate.into_iter().map(Nip01Tag::from))
            .tags(self.articles.event_ids.into_iter().map(Nip01Tag::event))
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
        EventBuilder::new(Kind::VideosCurationSet)
            .tag(Nip01Tag::identifier(self.identifier))
            .tags(self.videos.into_iter().map(Nip01Tag::from))
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
        EventBuilder::new(Kind::InterestSet)
            .tag(Nip01Tag::identifier(self.identifier))
            .tags(self.hashtags.into_iter().map(Nip51Tag::Hashtag))
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
        EventBuilder::new(Kind::EmojiSet)
            .tag(Nip01Tag::identifier(self.identifier))
            .tags(
                self.emojis
                    .into_iter()
                    .map(|(shortcode, image_url)| Nip30Tag::Emoji {
                        shortcode,
                        image_url,
                        emoji_set: None,
                    }),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_hashtag_tag() {
        let tag = vec!["t", "Nostr"];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip51Tag::Hashtag(String::from("nostr")));
        assert_eq!(
            Tags::from_iter([parsed]),
            Tags::parse([["t", "nostr"]]).unwrap()
        );
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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_word_tag() {
        let tag = vec!["word", "spam"];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip51Tag::Word(String::from("spam")));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_relay_tag() {
        let tag = vec!["relay", "wss://relay.damus.io"];
        let parsed = Nip51Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip51Tag::Relay(RelayUrl::parse("wss://relay.damus.io").unwrap())
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
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
        let follow_set_tags: Tags = follow_set.tags.into();
        assert_eq!(follow_set_tags.identifier().as_deref(), Some("friends"));
        assert_eq!(
            follow_set_tags.public_keys().collect::<Vec<_>>(),
            [public_key]
        );
    }
}
