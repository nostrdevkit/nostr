// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-B7: Blossom media
//!
//! <https://github.com/nostr-protocol/nips/blob/master/B7.md>

use alloc::vec::Vec;

use super::util::{missing_tag_kind, take_and_parse_from_str, unknown_tag};
use crate::event::{EventBuilder, IntoEventBuilder, Kind, impl_tag_codec_conversions};
use crate::types::url::Url;

const SERVER: &str = "server";

/// Blossom server list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlossomServerList {
    servers: Vec<Url>,
}

impl BlossomServerList {
    /// Create a Blossom server list.
    pub fn new<I>(servers: I) -> Self
    where
        I: IntoIterator<Item = Url>,
    {
        Self {
            servers: servers.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for BlossomServerList {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::BlossomServerList)
            .tags(self.servers.into_iter().map(NipB7Tag::Server))
    }
}

/// Standardized NIP-B7 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/B7.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NipB7Tag {
    /// `server` tag
    Server(Url),
}

impl_tag_codec_conversions! {
    NipB7Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            SERVER => {
                let server_url: Url = take_and_parse_from_str(&mut iter, "server URL")?;
                Ok(Self::Server(server_url))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Server(server_url) = self;

        tx.push_str(SERVER);
        tx.push_str(server_url.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;

    #[test]
    fn test_server_tag() {
        let tag = vec!["server", "https://blossom.example.com/"];
        let parsed = NipB7Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            NipB7Tag::Server(Url::parse("https://blossom.example.com").unwrap())
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }
}
