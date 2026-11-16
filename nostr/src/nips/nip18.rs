// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-18: Reposts
//!
//! <https://github.com/nostr-protocol/nips/blob/master/18.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::nip01::Coordinate;
use super::util::{
    missing_tag_kind, missing_value, take_and_parse_from_str, take_and_parse_optional_public_key,
    take_and_parse_optional_relay_url, take_event_id, take_public_key, unknown_tag,
};
use crate::error::Error;
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::url::RelayUrl;

const EVENT: &str = "e";
const KIND: &str = "k";
const PUBLIC_KEY: &str = "p";
const QUOTE: &str = "q";

/// Repost event builder.
#[derive(Debug, Clone)]
pub struct RepostBuilder<'a> {
    event: &'a Event,
    relay_url: Option<RelayUrl>,
}

impl<'a> RepostBuilder<'a> {
    /// Create a repost.
    #[inline]
    pub fn new(event: &'a Event) -> Self {
        Self {
            event,
            relay_url: None,
        }
    }

    /// Set the relay hint.
    #[inline]
    pub fn relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.relay_url = Some(relay_url);
        self
    }
}

impl IntoEventBuilder for RepostBuilder<'_> {
    fn into_event_builder(self) -> EventBuilder {
        let content: String = if self.event.is_protected() {
            String::new()
        } else {
            self.event.as_json()
        };

        if self.event.kind == Kind::TextNote {
            EventBuilder::new(Kind::Repost).content(content).tags([
                Nip18Tag::Event {
                    id: self.event.id,
                    relay_hint: self.relay_url,
                }
                .to_tag(),
                Nip18Tag::PublicKey {
                    public_key: self.event.pubkey,
                    relay_hint: None,
                }
                .to_tag(),
            ])
        } else {
            EventBuilder::new(Kind::GenericRepost)
                .content(content)
                .tag_maybe(
                    self.event
                        .coordinate()
                        .map(|coordinate| Tag::coordinate(coordinate, self.relay_url.clone())),
                )
                .tags([
                    Nip18Tag::Event {
                        id: self.event.id,
                        relay_hint: self.relay_url,
                    }
                    .to_tag(),
                    Nip18Tag::PublicKey {
                        public_key: self.event.pubkey,
                        relay_hint: None,
                    }
                    .to_tag(),
                    Nip18Tag::Kind(self.event.kind).to_tag(),
                ])
        }
    }
}

/// Standardized NIP-18 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/18.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip18Tag {
    /// `e` tag
    Event {
        /// Event ID
        id: EventId,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
    },
    /// `k` tag
    Kind(Kind),
    /// `p` tag
    PublicKey {
        /// Public key
        public_key: PublicKey,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
    },
    /// `q` tag with event ID
    Quote {
        /// Event ID
        id: EventId,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
        /// Public key hint
        public_key: Option<PublicKey>,
    },
    /// `q` tag with event coordinate
    QuoteAddress {
        /// Event coordinate
        coordinate: Coordinate,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
    },
}

impl_tag_codec_conversions! {
    Nip18Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            EVENT => {
                let (id, relay_hint) = parse_e_tag(iter)?;
                Ok(Self::Event { id, relay_hint })
            }
            KIND => {
                let kind: Kind = take_and_parse_from_str(&mut iter, "kind")?;
                Ok(Self::Kind(kind))
            }
            PUBLIC_KEY => {
                let (public_key, relay_hint) = parse_p_tag(iter)?;
                Ok(Self::PublicKey {
                    public_key,
                    relay_hint,
                })
            }
            QUOTE => parse_q_tag(iter),
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::Event { id, relay_hint } => {
                let mut tag: Vec<String> = Vec::with_capacity(2 + relay_hint.is_some() as usize);
                tag.push(String::from(EVENT));
                tag.push(id.to_hex());

                if let Some(relay_hint) = relay_hint {
                    tag.push(relay_hint.to_string());
                }

                Tag::new(tag)
            }
            Self::Kind(kind) => Tag::new(vec![String::from(KIND), kind.as_u16().to_string()]),
            Self::PublicKey {
                public_key,
                relay_hint,
            } => {
                let mut tag: Vec<String> = Vec::with_capacity(2 + relay_hint.is_some() as usize);
                tag.push(String::from(PUBLIC_KEY));
                tag.push(public_key.to_hex());

                if let Some(relay_hint) = relay_hint {
                    tag.push(relay_hint.to_string());
                }

                Tag::new(tag)
            }
            Self::Quote {
                id,
                relay_hint,
                public_key,
            } => {
                let mut tag: Vec<String> = Vec::with_capacity(
                    2 + relay_hint.is_some() as usize + public_key.is_some() as usize,
                );
                tag.push(String::from(QUOTE));
                tag.push(id.to_hex());

                if let Some(relay_hint) = relay_hint {
                    tag.push(relay_hint.to_string());
                } else if public_key.is_some() {
                    tag.push(String::new());
                }

                if let Some(public_key) = public_key {
                    tag.push(public_key.to_hex());
                }

                Tag::new(tag)
            }
            Self::QuoteAddress {
                coordinate,
                relay_hint,
            } => {
                let mut tag: Vec<String> = Vec::with_capacity(2 + relay_hint.is_some() as usize);
                tag.push(String::from(QUOTE));
                tag.push(coordinate.to_string());

                if let Some(relay_hint) = relay_hint {
                    tag.push(relay_hint.to_string());
                }

                Tag::new(tag)
            }
        }
    }
}

fn parse_e_tag<T, S>(mut iter: T) -> Result<(EventId, Option<RelayUrl>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let id: EventId = take_event_id(&mut iter)?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;

    Ok((id, relay_hint))
}

fn parse_p_tag<T, S>(mut iter: T) -> Result<(PublicKey, Option<RelayUrl>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let public_key: PublicKey = take_public_key(&mut iter)?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;

    Ok((public_key, relay_hint))
}

fn parse_q_tag<T, S>(mut iter: T) -> Result<Nip18Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let value: S = iter.next().ok_or_else(|| missing_value("event ID"))?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;

    match EventId::from_hex(value.as_ref()) {
        Ok(id) => {
            let public_key: Option<PublicKey> = take_and_parse_optional_public_key(&mut iter)?;

            Ok(Nip18Tag::Quote {
                id,
                relay_hint,
                public_key,
            })
        }
        Err(_) => Ok(Nip18Tag::QuoteAddress {
            coordinate: Coordinate::from_kpi_format(value.as_ref())?,
            relay_hint,
        }),
    }
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn test_standardized_event_tag() {
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let tag = vec![
            String::from("e"),
            EventId::all_zeros().to_hex(),
            relay_hint.to_string(),
        ];
        let parsed = Nip18Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip18Tag::Event {
                id: EventId::all_zeros(),
                relay_hint: Some(relay_hint),
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_standardized_quote_tag() {
        let keys = Keys::generate();
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let tag = vec![
            String::from("q"),
            EventId::all_zeros().to_hex(),
            relay_hint.to_string(),
            keys.public_key().to_string(),
        ];
        let parsed = Nip18Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip18Tag::Quote {
                id: EventId::all_zeros(),
                relay_hint: Some(relay_hint),
                public_key: Some(keys.public_key()),
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_standardized_quote_address_tag() {
        let keys = Keys::generate();
        let coordinate =
            Coordinate::new(Kind::LongFormTextNote, keys.public_key()).identifier("article");
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let tag = vec![
            String::from("q"),
            coordinate.to_string(),
            relay_hint.to_string(),
        ];
        let parsed = Nip18Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip18Tag::QuoteAddress {
                coordinate,
                relay_hint: Some(relay_hint),
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn replaceable_repost() {
        let keys = Keys::generate();
        let replaceable = MuteList::default().finalize(&keys).unwrap();
        let repost = RepostBuilder::new(&replaceable).finalize(&keys).unwrap();

        assert_eq!(repost.kind, Kind::GenericRepost);
        assert_eq!(
            repost
                .tags
                .iter()
                .find(|tag| tag.kind() == "a")
                .and_then(|tag| Nip01Tag::try_from(tag).ok())
                .unwrap(),
            Nip01Tag::Coordinate {
                coordinate: Coordinate::new(replaceable.kind, replaceable.pubkey),
                relay_hint: None,
            }
        );
    }

    #[test]
    fn addressable_repost() {
        let keys = Keys::generate();
        let addressable = FollowSet::new("lorem", core::iter::empty::<PublicKey>())
            .finalize(&keys)
            .unwrap();
        let repost = RepostBuilder::new(&addressable).finalize(&keys).unwrap();

        assert_eq!(repost.kind, Kind::GenericRepost);
        assert_eq!(
            repost
                .tags
                .iter()
                .find(|tag| tag.kind() == "a")
                .and_then(|tag| Nip01Tag::try_from(tag).ok())
                .unwrap(),
            Nip01Tag::Coordinate {
                coordinate: Coordinate::new(addressable.kind, addressable.pubkey)
                    .identifier("lorem"),
                relay_hint: None,
            }
        );
    }

    #[test]
    fn text_note_repost() {
        let note = EventBuilder::new(Kind::TextNote)
            .content("hello")
            .finalize(&Keys::generate())
            .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let repost = RepostBuilder::new(&note)
            .relay_url(relay_url.clone())
            .finalize(&Keys::generate())
            .unwrap();

        assert_eq!(repost.kind, Kind::Repost);
        assert_eq!(repost.content, note.as_json());
        assert_eq!(
            Nip18Tag::try_from(&repost.tags[0]).unwrap(),
            Nip18Tag::Event {
                id: note.id,
                relay_hint: Some(relay_url),
            }
        );
    }

    #[test]
    fn protected_repost_has_empty_content() {
        let keys = Keys::generate();
        let protected = EventBuilder::new(Kind::TextNote)
            .content("protected")
            .tag(Tag::protected())
            .finalize(&keys)
            .unwrap();
        let repost = RepostBuilder::new(&protected).finalize(&keys).unwrap();

        assert!(repost.content.is_empty());
    }
}
