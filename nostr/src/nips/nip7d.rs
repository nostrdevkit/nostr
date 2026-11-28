// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-7D: Threads
//!
//! <https://github.com/nostr-protocol/nips/blob/master/7D.md>

use alloc::string::String;

use super::util::{missing_tag_kind, take_string, unknown_tag};
use crate::event::{Event, EventBuilder, IntoEventBuilder, Kind, impl_tag_codec_conversions};
use crate::nips::nip22::Nip22Tag;
use crate::types::RelayUrl;

const TITLE: &str = "title";

/// Thread event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Thread {
    content: String,
    title: Option<String>,
}

impl Thread {
    /// Create a thread.
    pub fn new<S>(content: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            content: content.into(),
            title: None,
        }
    }

    /// Set the thread title.
    pub fn title<S>(mut self, title: S) -> Self
    where
        S: Into<String>,
    {
        self.title = Some(title.into());
        self
    }
}

impl IntoEventBuilder for Thread {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Thread)
            .content(self.content)
            .tag_maybe(self.title.map(Nip7DTag::Title))
    }
}

/// Thread reply.
#[derive(Debug, Clone)]
pub struct ThreadReply<'a> {
    content: String,
    reply_to: &'a Event,
    relay_hint: Option<RelayUrl>,
}

impl<'a> ThreadReply<'a> {
    /// Create a thread reply.
    pub fn new<S>(content: S, reply_to: &'a Event) -> Self
    where
        S: Into<String>,
    {
        Self {
            content: content.into(),
            reply_to,
            relay_hint: None,
        }
    }

    /// Set the relay hint.
    pub fn relay_hint(mut self, relay_hint: RelayUrl) -> Self {
        self.relay_hint = Some(relay_hint);
        self
    }
}

impl IntoEventBuilder for ThreadReply<'_> {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Comment)
            .content(self.content)
            .tag(Nip22Tag::Event {
                id: self.reply_to.id,
                relay_hint: self.relay_hint,
                public_key: Some(self.reply_to.pubkey),
                uppercase: true,
            })
            .tag(Nip22Tag::Kind {
                kind: Kind::Thread,
                uppercase: true,
            })
    }
}

/// Standardized NIP-7D tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/7D.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip7DTag {
    /// `title` tag
    Title(String),
}

impl_tag_codec_conversions! {
    Nip7DTag,
    fn parse(tag) {
        let mut iter = tag.into_iter();

        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            TITLE => Ok(Self::Title(take_string(&mut iter, "title")?)),
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Title(title) = self;

        tx.push_str(TITLE);
        tx.push_str(&title);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::event::FinalizeEvent;
    use crate::event::Tags;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::key::Keys;

    #[test]
    fn test_parse_title_tag() {
        let tag = vec!["title", "Lorem Ipsum"];
        let parsed = Nip7DTag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip7DTag::Title(String::from("Lorem Ipsum")));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn thread_and_reply() {
        let thread = Thread::new("content")
            .title("title")
            .finalize(&Keys::generate())
            .unwrap();
        assert_eq!(thread.kind, Kind::Thread);
        assert_eq!(
            Nip7DTag::try_from(thread.tags.first().unwrap()).unwrap(),
            Nip7DTag::Title(String::from("title"))
        );

        let reply = ThreadReply::new("reply", &thread).into_event_builder();
        assert_eq!(reply.kind, Kind::Comment);
        assert_eq!(reply.tags.len(), 2);
    }
}
