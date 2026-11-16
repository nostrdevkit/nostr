// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-B0: Web Bookmarks
//!
//! <https://github.com/nostr-protocol/nips/blob/master/B0.md>

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::util::{missing_tag_kind, take_string, take_timestamp, unknown_tag};
use crate::event::{EventBuilder, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions};
use crate::types::Timestamp;

const URL: &str = "d";
const PUBLISHED_AT: &str = "published_at";
const TITLE: &str = "title";
const HASHTAG: &str = "t";

/// Standardized NIP-B0 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/B0.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NipB0Tag {
    /// `d` tag containing the bookmarked URL without scheme
    Url(String),
    /// `published_at` tag
    PublishedAt(Timestamp),
    /// `title` tag
    Title(String),
    /// `t` tag
    Hashtag(String),
}

impl_tag_codec_conversions! {
    NipB0Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();

        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            URL => Ok(Self::Url(take_string(&mut iter, "URL")?)),
            PUBLISHED_AT => {
                let timestamp: Timestamp = take_timestamp(&mut iter)?;
                Ok(Self::PublishedAt(timestamp))
            }
            TITLE => Ok(Self::Title(take_string(&mut iter, "title")?)),
            HASHTAG => Ok(Self::Hashtag(
                take_string(&mut iter, "hashtag")?.to_lowercase(),
            )),
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::Url(url) => Tag::new(vec![String::from(URL), url.clone()]),
            Self::PublishedAt(timestamp) => {
                Tag::new(vec![String::from(PUBLISHED_AT), timestamp.to_string()])
            }
            Self::Title(title) => Tag::new(vec![String::from(TITLE), title.clone()]),
            Self::Hashtag(hashtag) => Tag::new(vec![String::from(HASHTAG), hashtag.to_lowercase()]),
        }
    }
}

/// Web Bookmark
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WebBookmark {
    /// Description of the web bookmark.
    pub description: String,
    /// URL of the web bookmark.
    pub url: String,
    /// Timestamp when the web bookmark was first published.
    pub published_at: Option<Timestamp>,
    /// Title of the web bookmark.
    pub title: Option<String>,
    /// Hashtags for the web bookmark.
    pub hashtags: Vec<String>,
}

impl WebBookmark {
    /// Create a new web bookmark
    #[inline]
    pub fn new<T>(description: T, url: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            description: description.into(),
            url: url.into(),
            published_at: None,
            title: None,
            hashtags: Vec::new(),
        }
    }

    /// Set the title.
    #[inline]
    pub fn title<T>(mut self, title: T) -> Self
    where
        T: Into<String>,
    {
        self.title = Some(title.into());
        self
    }

    /// Set the timestamp at which the web bookmark was published.
    #[inline]
    pub fn published_at(mut self, timestamp: Timestamp) -> Self {
        self.published_at = Some(timestamp);
        self
    }

    /// Add a hashtag/tag.
    pub fn hashtags<T>(mut self, hashtag: T) -> Self
    where
        T: Into<String>,
    {
        let hashtag = hashtag.into().to_lowercase();
        if !self.hashtags.contains(&hashtag) {
            self.hashtags.push(hashtag);
        }
        self
    }
}

impl IntoEventBuilder for WebBookmark {
    fn into_event_builder(self) -> EventBuilder {
        let mut tags: Vec<Tag> = vec![NipB0Tag::Url(self.url).into()];

        let mut add_if_some = |tag: Option<NipB0Tag>| {
            if let Some(tag) = tag {
                tags.push(tag.into());
            }
        };

        add_if_some(self.published_at.map(NipB0Tag::PublishedAt));
        add_if_some(self.title.map(NipB0Tag::Title));

        for hashtag in self.hashtags.into_iter() {
            tags.push(NipB0Tag::Hashtag(hashtag).into());
        }

        EventBuilder::new(Kind::WebBookmark)
            .content(self.description)
            .tags(tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_tag() {
        let tag = vec!["d", "alice.blog/post"];
        let parsed = NipB0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipB0Tag::Url(String::from("alice.blog/post")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_published_at_tag() {
        let tag = vec!["published_at", "1738863000"];
        let parsed = NipB0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipB0Tag::PublishedAt(Timestamp::from(1738863000)));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_title_tag() {
        let tag = vec!["title", "Blog insights by Alice"];
        let parsed = NipB0Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            NipB0Tag::Title(String::from("Blog insights by Alice"))
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_hashtag_tag() {
        let tag = vec!["t", "Insight"];
        let parsed = NipB0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipB0Tag::Hashtag(String::from("insight")));
        assert_eq!(parsed.to_tag(), Tag::parse(vec!["t", "insight"]).unwrap());
    }
}
