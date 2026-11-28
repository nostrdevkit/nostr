// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-25: Reactions
//!
//! <https://github.com/nostr-protocol/nips/blob/master/25.md>

use alloc::string::{String, ToString};

use super::nip01::{Coordinate, Nip01Tag};
use super::util::{missing_tag_kind, take_and_parse_from_str, unknown_tag};
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, Tags, TagsMut, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Standardized NIP-25 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/25.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip25Tag {
    /// `k` tag
    Kind(Kind),
}

impl_tag_codec_conversions! {
    Nip25Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            "k" => {
                let kind: Kind = take_and_parse_from_str(&mut iter, "kind")?;
                Ok(Self::Kind(kind))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Kind(kind) = self;

        tx.push_str("k");
        tx.push_str(&kind.to_string());
    }
}

/// Reaction target
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReactionTarget {
    /// Event ID
    pub event_id: EventId,
    /// Public Key
    pub public_key: PublicKey,
    /// Coordinate
    pub coordinate: Option<Coordinate>,
    /// Kind
    pub kind: Option<Kind>,
    /// Relay hint
    pub relay_hint: Option<RelayUrl>,
}

/// Reaction event builder.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReactionBuilder {
    target: ReactionTarget,
    reaction: String,
}

impl ReactionBuilder {
    /// Create a reaction.
    pub fn new<T, S>(target: T, reaction: S) -> Self
    where
        T: Into<ReactionTarget>,
        S: Into<String>,
    {
        Self {
            target: target.into(),
            reaction: reaction.into(),
        }
    }
}

impl IntoEventBuilder for ReactionBuilder {
    #[inline]
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Reaction)
            .content(self.reaction)
            .tags(self.target.into_tags())
    }
}

impl ReactionTarget {
    /// Construct a new reaction target
    pub fn new(event: &Event, relay_hint: Option<RelayUrl>) -> Self {
        Self {
            event_id: event.id,
            public_key: event.pubkey,
            coordinate: event.coordinate(),
            kind: Some(event.kind),
            relay_hint,
        }
    }

    pub(crate) fn into_tags(self) -> Tags {
        let mut tags: TagsMut = TagsMut::with_capacity(
            2 + usize::from(self.coordinate.is_some()) + usize::from(self.kind.is_some()),
        );

        // Serialization order: keep the `e` and `a` tags together, followed by the `p` and other tags.

        tags.push(Nip01Tag::Event {
            id: self.event_id,
            relay_hint: self.relay_hint.clone(),
            public_key: Some(self.public_key),
        });

        if let Some(coordinate) = self.coordinate {
            tags.push(Nip01Tag::Coordinate {
                coordinate,
                relay_hint: self.relay_hint.clone(),
            });
        }

        tags.push(Nip01Tag::PublicKey {
            public_key: self.public_key,
            relay_hint: self.relay_hint,
        });

        if let Some(kind) = self.kind {
            tags.push(Nip25Tag::Kind(kind));
        }

        tags.freeze()
    }
}

impl From<&Event> for ReactionTarget {
    fn from(event: &Event) -> Self {
        Self {
            event_id: event.id,
            public_key: event.pubkey,
            coordinate: event.coordinate(),
            kind: Some(event.kind),
            relay_hint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kind_tag() {
        let tag = vec!["k", "1"];
        let parsed = Nip25Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip25Tag::Kind(Kind::TextNote));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }
}
