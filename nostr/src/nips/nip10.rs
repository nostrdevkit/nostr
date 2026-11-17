// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-10: Conventions for clients' use of `e` and `p` tags in text events
//!
//! <https://github.com/nostr-protocol/nips/blob/master/10.md>

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use super::nip01::Nip01Tag;
use super::util::{
    missing_tag_kind, take_and_parse_optional_public_key, take_and_parse_optional_relay_url,
    take_event_id, unknown_tag,
};
use crate::error::{Error, ErrorKind};
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::url::RelayUrl;

const EVENT: &str = "e";

/// Text note reply builder.
#[derive(Debug, Clone)]
pub struct TextNoteReplyBuilder<'a> {
    content: String,
    reply_to: &'a Event,
    root: Option<&'a Event>,
    relay_hint: Option<RelayUrl>,
}

impl<'a> TextNoteReplyBuilder<'a> {
    /// Create a text note reply.
    pub fn new<S>(content: S, reply_to: &'a Event) -> Self
    where
        S: Into<String>,
    {
        Self {
            content: content.into(),
            reply_to,
            root: None,
            relay_hint: None,
        }
    }

    /// Set the root event.
    #[inline]
    pub fn root(mut self, root: &'a Event) -> Self {
        self.root = Some(root);
        self
    }

    /// Set the relay hint.
    #[inline]
    pub fn relay_hint(mut self, relay_hint: RelayUrl) -> Self {
        self.relay_hint = Some(relay_hint);
        self
    }
}

impl IntoEventBuilder for TextNoteReplyBuilder<'_> {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::TextNote).content(self.content);

        match self.root {
            Some(root) => {
                if root.id != self.reply_to.id {
                    builder.tags.push(Nip10Tag::Event {
                        id: self.reply_to.id,
                        relay_hint: self.relay_hint.clone(),
                        marker: Some(Marker::Reply),
                        public_key: Some(self.reply_to.pubkey),
                    });
                    builder
                        .tags
                        .push(Nip01Tag::public_key(self.reply_to.pubkey));
                }

                builder.tags.push(Nip10Tag::Event {
                    id: root.id,
                    relay_hint: self.relay_hint,
                    marker: Some(Marker::Root),
                    public_key: Some(root.pubkey),
                });
                builder.tags.push(Nip01Tag::public_key(root.pubkey));
            }
            None => {
                builder.tags.push(Nip10Tag::Event {
                    id: self.reply_to.id,
                    relay_hint: self.relay_hint,
                    marker: Some(Marker::Reply),
                    public_key: Some(self.reply_to.pubkey),
                });
                builder
                    .tags
                    .push(Nip01Tag::public_key(self.reply_to.pubkey));
            }
        }

        builder
    }
}

/// Marker
///
/// <https://github.com/nostr-protocol/nips/blob/master/10.md>
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Marker {
    /// Root
    Root,
    /// Reply
    Reply,
}

impl Marker {
    fn as_str(&self) -> &str {
        match self {
            Self::Root => "root",
            Self::Reply => "reply",
        }
    }
}

impl fmt::Display for Marker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Marker {
    type Err = Error;

    fn from_str(marker: &str) -> Result<Self, Self::Err> {
        match marker {
            "root" => Ok(Self::Root),
            "reply" => Ok(Self::Reply),
            _ => Err(Error::with_static_message(
                ErrorKind::Invalid,
                "invalid marker",
            )),
        }
    }
}

/// Standardized NIP-10 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/10.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip10Tag {
    /// `e` tag
    Event {
        /// Event ID
        id: EventId,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
        /// Event marker
        marker: Option<Marker>,
        /// Public key hint
        public_key: Option<PublicKey>,
    },
}

impl Nip10Tag {
    /// Check if this tag is marked as a root reference.
    #[inline]
    pub fn is_root(&self) -> bool {
        matches!(
            self,
            Self::Event {
                marker: Some(Marker::Root),
                ..
            }
        )
    }

    /// Check if this tag is marked as a reply reference.
    #[inline]
    pub fn is_reply(&self) -> bool {
        matches!(
            self,
            Self::Event {
                marker: Some(Marker::Reply),
                ..
            }
        )
    }
}

impl_tag_codec_conversions! {
    Nip10Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            EVENT => {
                let (id, relay_hint, marker, public_key) = parse_e_tag(iter)?;
                Ok(Self::Event {
                    id,
                    relay_hint,
                    marker,
                    public_key,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::Event {
                id,
                relay_hint,
                marker,
                public_key,
            } => {
                // ["e", <event-id>, <relay-url>, <marker>, <pubkey>]
                // <relay-url>, <marker> and <pubkey> are optional
                // <relay-url>, if empty, may be set to "" (if there are additional fields later)
                // <marker> is optional and if present is one of "reply" or "root" (so not an empty string)

                tx.push_str(EVENT);
                tx.push_hex(id.as_bytes());

                // Check if relay hint exists or if there are additional fields after
                match (relay_hint, marker.is_some() || public_key.is_some()) {
                    (Some(relay_hint), ..) => tx.push_str(relay_hint.as_str()),
                    (None, true) => tx.push_str(""),
                    (None, false) => {}
                }

                match (marker, public_key.is_some()) {
                    (Some(marker), _) => tx.push_str(marker.as_str()),
                    (None, true) => tx.push_str(""),
                    (None, false) => {}
                }

                if let Some(public_key) = public_key {
                    tx.push_hex(public_key.as_bytes());
                }
            }
        }
    }
}

#[allow(clippy::type_complexity)]
fn parse_e_tag<T, S>(
    mut iter: T,
) -> Result<(EventId, Option<RelayUrl>, Option<Marker>, Option<PublicKey>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let id: EventId = take_event_id(&mut iter)?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;

    let marker: Option<Marker> = match iter.next() {
        Some(marker) => {
            let marker: &str = marker.as_ref();

            if !marker.is_empty() && marker != "mention" {
                Some(Marker::from_str(marker)?)
            } else {
                None
            }
        }
        _ => None,
    };

    let public_key: Option<PublicKey> = take_and_parse_optional_public_key(&mut iter)?;

    Ok((id, relay_hint, marker, public_key))
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use super::*;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::event::FinalizeEvent;
    use crate::event::Tags;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::key::Keys;
    use crate::key::PublicKey;

    #[test]
    fn test_parse_empty_tag() {
        let tag: Vec<String> = Vec::new();
        let err = Nip10Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }

    #[test]
    fn test_non_existing_tag() {
        let tag = vec!["p"];
        let err = Nip10Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn test_standardized_e_tag() {
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let public_key =
            PublicKey::from_hex("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4")
                .unwrap();
        let tag = vec![
            String::from("e"),
            EventId::all_zeros().to_hex(),
            relay_hint.to_string(),
            String::from("root"),
            public_key.to_hex(),
        ];
        let parsed = Nip10Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip10Tag::Event {
                id: EventId::all_zeros(),
                relay_hint: Some(relay_hint),
                marker: Some(Marker::Root),
                public_key: Some(public_key),
            }
        );
        assert!(parsed.is_root());
        assert!(!parsed.is_reply());
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_positional_e_tag() {
        let tag = vec![String::from("e"), EventId::all_zeros().to_hex()];
        let parsed = Nip10Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip10Tag::Event {
                id: EventId::all_zeros(),
                relay_hint: None,
                marker: None,
                public_key: None,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_standardized_e_tag_with_empty_marker() {
        let public_key =
            PublicKey::from_hex("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4")
                .unwrap();
        let tag = vec![
            String::from("e"),
            EventId::all_zeros().to_hex(),
            String::from("wss://relay.example.com"),
            String::new(),
            public_key.to_hex(),
        ];
        let parsed = Nip10Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip10Tag::Event {
                id: EventId::all_zeros(),
                relay_hint: Some(RelayUrl::parse("wss://relay.example.com").unwrap()),
                marker: None,
                public_key: Some(public_key),
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_standardized_e_tag_without_marker_is_invalid() {
        let public_key =
            PublicKey::from_hex("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4")
                .unwrap();
        let tag = vec![
            String::from("e"),
            EventId::all_zeros().to_hex(),
            String::from("wss://relay.example.com"),
            public_key.to_hex(),
        ];
        let err = Nip10Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
    }

    #[test]
    fn test_e_tag_with_mention_marker() {
        let hex = "19bb195b83fd26db217b6feebb444de4808d90eb4375c31c75ba5bb5c5c10cfc";
        let id = EventId::from_hex(hex).unwrap();

        let result = Nip10Tag::parse(["e", hex, "", "mention"]).unwrap();

        assert_eq!(
            result,
            Nip10Tag::Event {
                id,
                relay_hint: None,
                marker: None,
                public_key: None,
            }
        );
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn text_note_reply_builder() {
        let root_keys = Keys::generate();
        let root = EventBuilder::new(Kind::TextNote)
            .content("root")
            .finalize(&root_keys)
            .unwrap();

        let reply_keys = Keys::generate();
        let reply = TextNoteReplyBuilder::new("reply", &root)
            .finalize(&reply_keys)
            .unwrap();

        assert_eq!(reply.tags.public_keys().collect::<Vec<_>>(), [root.pubkey]);
        assert_eq!(reply.tags.event_ids().collect::<Vec<_>>(), [root.id]);

        let nested_reply = TextNoteReplyBuilder::new("nested reply", &reply)
            .root(&root)
            .finalize(&Keys::generate())
            .unwrap();

        assert_eq!(
            nested_reply.tags.public_keys().collect::<Vec<_>>(),
            [reply.pubkey, root.pubkey]
        );
        assert_eq!(
            nested_reply.tags.event_ids().collect::<Vec<_>>(),
            [reply.id, root.id]
        );
    }
}
