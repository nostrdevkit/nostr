// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP22: Comment
//!
//! <https://github.com/nostr-protocol/nips/blob/master/22.md>

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use core::str::FromStr;

use url::Url;

use crate::error::Error;
#[cfg(all(test, feature = "std", feature = "os-rng"))]
use crate::event::Tags;
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, TagsMut, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::nips::nip01::{self, Coordinate};
use crate::nips::nip73::{self, ExternalContentId, Nip73Kind};
use crate::nips::util::{missing_tag_kind, missing_value, unknown_tag};
use crate::types::RelayUrl;

/// Standardized NIP-22 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/22.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip22Tag {
    /// `a` and `A` tags
    Coordinate {
        /// Coordinate
        coordinate: Coordinate,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
        /// Uppercase variant
        uppercase: bool,
    },
    /// `e` and `E` tags
    Event {
        /// Event ID
        id: EventId,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
        /// Public key hint
        public_key: Option<PublicKey>,
        /// Uppercase variant
        uppercase: bool,
    },
    /// `i` and `I` tags
    ExternalContent {
        /// External content
        content: ExternalContentId,
        /// Optional URL hint
        hint: Option<Url>,
        /// Uppercase variant
        uppercase: bool,
    },
    /// Numeric `k` and `K` tags
    Kind {
        /// Event kind
        kind: Kind,
        /// Uppercase variant
        uppercase: bool,
    },
    /// NIP-73 `k` and `K` tags
    Nip73Kind {
        /// NIP-73 kind
        kind: Nip73Kind,
        /// Uppercase variant
        uppercase: bool,
    },
    /// `p` and `P` tags
    PublicKey {
        /// Public key
        public_key: PublicKey,
        /// Relay hint
        relay_hint: Option<RelayUrl>,
        /// Uppercase variant
        uppercase: bool,
    },
}

impl_tag_codec_conversions! {
    Nip22Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            "a" => parse_a_tag(iter, false),
            "A" => parse_a_tag(iter, true),
            "e" => parse_e_tag(iter, false),
            "E" => parse_e_tag(iter, true),
            "i" => parse_i_tag(iter, false),
            "I" => parse_i_tag(iter, true),
            "k" => parse_k_tag(iter, false),
            "K" => parse_k_tag(iter, true),
            "p" => parse_p_tag(iter, false),
            "P" => parse_p_tag(iter, true),
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::Coordinate {
                coordinate,
                relay_hint,
                uppercase,
            } => nip01::serialize_a_tag(tx, uppercase, &coordinate, relay_hint.as_ref()),
            Self::Event {
                id,
                relay_hint,
                public_key,
                uppercase,
            } => nip01::serialize_e_tag(tx, uppercase, &id, relay_hint.as_ref(), public_key.as_ref()),
            Self::ExternalContent {
                content,
                hint,
                uppercase,
            } => nip73::serialize_i_tag(tx, uppercase, &content, hint.as_ref()),
            Self::Kind { kind, uppercase } => {
                tx.push_str(if uppercase { "K" } else { "k" });
                tx.push_str(&kind.to_string());
            }
            Self::Nip73Kind { kind, uppercase } => nip73::serialize_k_tag(tx, uppercase, &kind),
            Self::PublicKey {
                public_key,
                relay_hint,
                uppercase,
            } => nip01::serialize_p_tag(tx, uppercase, &public_key, relay_hint.as_ref()),
        }
    }
}

/// Comment target
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CommentTarget<'a> {
    /// Event
    Event {
        /// Event ID
        id: EventId,
        /// Relay hint
        relay_hint: Option<Cow<'a, RelayUrl>>,
        /// Public key hint
        pubkey_hint: Option<PublicKey>,
        /// Kind
        kind: Option<Kind>,
    },
    /// Coordinate
    Coordinate {
        /// Coordinate
        address: Cow<'a, Coordinate>,
        /// Relay hint
        relay_hint: Option<Cow<'a, RelayUrl>>,
    },
    /// External content
    External {
        /// Content
        content: Cow<'a, ExternalContentId>,
        /// Web hint
        hint: Option<Cow<'a, Url>>,
    },
}

/// Comment event builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentBuilder<'a> {
    content: String,
    comment_to: CommentTarget<'a>,
    root: Option<CommentTarget<'a>>,
}

impl<'a> CommentBuilder<'a> {
    /// Create a comment.
    pub fn new<S, T>(content: S, comment_to: T) -> Self
    where
        S: Into<String>,
        T: Into<CommentTarget<'a>>,
    {
        Self {
            content: content.into(),
            comment_to: comment_to.into(),
            root: None,
        }
    }

    /// Set the root comment target.
    pub fn root<T>(mut self, root: T) -> Self
    where
        T: Into<CommentTarget<'a>>,
    {
        self.root = Some(root.into());
        self
    }
}

impl IntoEventBuilder for CommentBuilder<'_> {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::Comment).content(self.content);

        if let Some(root) = self.root {
            root.extend_tags(&mut builder.tags, true);
        }

        self.comment_to.extend_tags(&mut builder.tags, false);

        builder
    }
}

impl<'a> CommentTarget<'a> {
    /// Creates a new [`CommentTarget`] pointing to a specific event.
    #[inline]
    pub fn event(
        id: EventId,
        kind: Kind,
        author: Option<PublicKey>,
        relay_hint: Option<Cow<'a, RelayUrl>>,
    ) -> Self {
        Self::Event {
            id,
            pubkey_hint: author,
            kind: Some(kind),
            relay_hint,
        }
    }

    /// Create a new [`CommentTarget`] pointing to a specific coordinate.
    #[inline]
    pub fn coordinate(
        coordinate: Cow<'a, Coordinate>,
        relay_hint: Option<Cow<'a, RelayUrl>>,
    ) -> Self {
        Self::Coordinate {
            address: coordinate,
            relay_hint,
        }
    }

    /// Create a new [`CommentTarget`] pointing to a specific external content.
    #[inline]
    pub fn external(content: Cow<'a, ExternalContentId>, hint: Option<Cow<'a, Url>>) -> Self {
        Self::External { content, hint }
    }

    /// Sets the relay hint for the event or coordinate.
    #[inline]
    pub fn relay_hint(self, relay_hint: Cow<'a, RelayUrl>) -> Self {
        match self {
            Self::Event {
                id,
                pubkey_hint,
                kind,
                ..
            } => Self::Event {
                id,
                pubkey_hint,
                kind,
                relay_hint: Some(relay_hint),
            },
            #[allow(deprecated)]
            Self::Coordinate { address, .. } => Self::Coordinate {
                address,
                relay_hint: Some(relay_hint),
            },
            _ => self,
        }
    }

    pub(crate) fn extend_tags(&self, tags: &mut TagsMut, is_root: bool) {
        match self {
            Self::Event {
                id,
                relay_hint,
                pubkey_hint,
                kind,
            } => {
                tags.push(Nip22Tag::Event {
                    id: *id,
                    relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                    public_key: pubkey_hint.as_ref().copied(),
                    uppercase: is_root,
                });

                if let Some(pubkey) = pubkey_hint {
                    tags.push(Nip22Tag::PublicKey {
                        public_key: *pubkey,
                        relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                        uppercase: is_root,
                    });
                }

                if let Some(kind) = kind {
                    tags.push(Nip22Tag::Kind {
                        kind: *kind,
                        uppercase: is_root,
                    });
                }
            }
            Self::Coordinate {
                address,
                relay_hint,
                ..
            } => {
                tags.push(Nip22Tag::Coordinate {
                    coordinate: address.clone().into_owned(),
                    relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                    uppercase: is_root,
                });
                tags.push(Nip22Tag::PublicKey {
                    public_key: address.public_key,
                    relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                    uppercase: is_root,
                });
                tags.push(Nip22Tag::Kind {
                    kind: address.kind,
                    uppercase: is_root,
                });
            }
            Self::External { content, hint } => {
                tags.push(Nip22Tag::ExternalContent {
                    content: ExternalContentId::clone(content),
                    hint: hint.clone().map(|r| r.into_owned()),
                    uppercase: is_root,
                });
                tags.push(Nip22Tag::Nip73Kind {
                    kind: content.kind(),
                    uppercase: is_root,
                });
            }
        }
    }

    #[cfg(all(test, feature = "std", feature = "os-rng"))]
    fn to_tags(&self, is_root: bool) -> Tags {
        let mut tags: TagsMut = TagsMut::new();
        self.extend_tags(&mut tags, is_root);
        tags.freeze()
    }
}

impl<'e> From<&'e Event> for CommentTarget<'_> {
    fn from(event: &'e Event) -> Self {
        if let Some(coordinate) = event.coordinate() {
            CommentTarget::coordinate(Cow::Owned(coordinate), None)
        } else {
            CommentTarget::event(event.id, event.kind, Some(event.pubkey), None)
        }
    }
}

/// Extract NIP22 root target
pub fn extract_root(event: &Event) -> Option<CommentTarget<'_>> {
    extract_data(event, true)
}

/// Extract NIP22 parent target
pub fn extract_parent(event: &Event) -> Option<CommentTarget<'_>> {
    extract_data(event, false)
}

fn extract_data(event: &Event, is_root: bool) -> Option<CommentTarget<'_>> {
    // Try to extract event
    if let Some((event_id, relay_hint, public_key)) = extract_event(event, is_root) {
        return Some(CommentTarget::Event {
            id: event_id,
            relay_hint: relay_hint.map(Cow::Owned),
            pubkey_hint: public_key,
            kind: extract_kind(event, is_root),
        });
    }

    // Try to extract coordinate
    if let Some((address, relay_hint)) = extract_coordinate(event, is_root) {
        let kind: Kind = extract_kind(event, is_root)?;

        // Check if matches the address kind
        if kind != address.kind {
            return None;
        }

        return Some(CommentTarget::Coordinate {
            address: Cow::Owned(address),
            relay_hint: relay_hint.map(Cow::Owned),
        });
    }

    if let Some((content, hint)) = extract_external(event, is_root) {
        let kind: Nip73Kind = extract_nip73_kind(event, is_root)?;

        if kind != content.kind() {
            return None;
        }

        return Some(CommentTarget::External {
            content: Cow::Owned(content),
            hint: hint.map(Cow::Owned),
        });
    }

    None
}

fn check_return<T>(val: T, is_root: bool, uppercase: bool) -> Option<T> {
    if (is_root && uppercase) || (!is_root && !uppercase) {
        return Some(val);
    }

    None
}

/// Returns the first kind tag that matches the `is_root` condition.
///
/// # Example:
/// * is_root = true -> returns first `K` tag
/// * is_root = false -> returns first `k` tag
fn extract_kind(event: &Event, is_root: bool) -> Option<Kind> {
    event
        .tags
        .iter()
        .find_map(|tag| match Nip22Tag::try_from(tag) {
            Ok(Nip22Tag::Kind { kind, uppercase }) => check_return(kind, is_root, uppercase),
            _ => None,
        })
}

/// Returns the first NIP-73 kind tag that matches the `is_root` condition.
fn extract_nip73_kind(event: &Event, is_root: bool) -> Option<Nip73Kind> {
    event
        .tags
        .iter()
        .find_map(|tag| match Nip22Tag::try_from(tag) {
            Ok(Nip22Tag::Nip73Kind { kind, uppercase }) => check_return(kind, is_root, uppercase),
            _ => None,
        })
}

/// Returns the first event tag that matches the `is_root` condition.
///
/// # Example:
/// * is_root = true -> returns first `E` tag
/// * is_root = false -> returns first `e` tag
fn extract_event(
    event: &Event,
    is_root: bool,
) -> Option<(EventId, Option<RelayUrl>, Option<PublicKey>)> {
    event
        .tags
        .iter()
        .find_map(|tag| match Nip22Tag::try_from(tag) {
            Ok(Nip22Tag::Event {
                id,
                relay_hint,
                public_key,
                uppercase,
            }) => check_return((id, relay_hint, public_key), is_root, uppercase),
            _ => None,
        })
}

/// Returns the first coordinate tag that matches the `is_root` condition.
///
/// # Example:
/// * is_root = true -> returns first `A` tag
/// * is_root = false -> returns first `a` tag
fn extract_coordinate(event: &Event, is_root: bool) -> Option<(Coordinate, Option<RelayUrl>)> {
    event
        .tags
        .iter()
        .find_map(|tag| match Nip22Tag::try_from(tag) {
            Ok(Nip22Tag::Coordinate {
                coordinate,
                relay_hint,
                uppercase,
            }) => check_return((coordinate, relay_hint), is_root, uppercase),
            _ => None,
        })
}

/// Returns the first external content tag that matches the `is_root` condition.
///
/// # Example:
/// * is_root = true -> returns first `I` tag
/// * is_root = false -> returns first `i` tag
fn extract_external(event: &Event, is_root: bool) -> Option<(ExternalContentId, Option<Url>)> {
    event
        .tags
        .iter()
        .find_map(|tag| match Nip22Tag::try_from(tag) {
            Ok(Nip22Tag::ExternalContent {
                content,
                hint,
                uppercase,
            }) => check_return((content, hint), is_root, uppercase),
            _ => None,
        })
}

fn parse_a_tag<T, S>(iter: T, uppercase: bool) -> Result<Nip22Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    // At the moment the NIP-22 "a" tag is the same as the NIP-01, but with possibility of uppercasing.
    let (coordinate, relay_hint) = nip01::parse_a_tag(iter)?;

    Ok(Nip22Tag::Coordinate {
        coordinate,
        relay_hint,
        uppercase,
    })
}

fn parse_e_tag<T, S>(iter: T, uppercase: bool) -> Result<Nip22Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    // At the moment the NIP-22 "e" tag is the same as the NIP-01, but with possibility of uppercasing.
    let (id, relay_hint, public_key) = nip01::parse_e_tag(iter)?;

    Ok(Nip22Tag::Event {
        id,
        relay_hint,
        public_key,
        uppercase,
    })
}

fn parse_i_tag<T, S>(iter: T, uppercase: bool) -> Result<Nip22Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let (content, hint) = nip73::parse_i_tag(iter)?;

    Ok(Nip22Tag::ExternalContent {
        content,
        hint,
        uppercase,
    })
}

fn parse_k_tag<T, S>(mut iter: T, uppercase: bool) -> Result<Nip22Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let kind: S = iter.next().ok_or_else(|| missing_value("kind"))?;

    if let Ok(kind_number) = u16::from_str(kind.as_ref()) {
        Ok(Nip22Tag::Kind {
            kind: Kind::from_u16(kind_number),
            uppercase,
        })
    } else {
        Ok(Nip22Tag::Nip73Kind {
            kind: Nip73Kind::from_str(kind.as_ref())?,
            uppercase,
        })
    }
}

fn parse_p_tag<T, S>(iter: T, uppercase: bool) -> Result<Nip22Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    // At the moment the NIP-22 "p" tag is the same as the NIP-01, but with possibility of uppercasing.
    let (public_key, relay_hint) = nip01::parse_p_tag(iter)?;

    Ok(Nip22Tag::PublicKey {
        public_key,
        relay_hint,
        uppercase,
    })
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn test_standardized_event_tag() {
        let keys = Keys::generate();
        let kind = Kind::GitPatch;
        let id = EventId::compute(
            &keys.public_key(),
            &Timestamp::from_secs(1),
            &kind,
            &Tags::new(),
            "",
        );
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let tag = vec![
            String::from("E"),
            id.to_hex(),
            relay_hint.to_string(),
            keys.public_key().to_string(),
        ];
        let parsed = Nip22Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip22Tag::Event {
                id,
                relay_hint: Some(relay_hint),
                public_key: Some(keys.public_key()),
                uppercase: true,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_standardized_event_tag_with_empty_relay_hint() {
        let keys = Keys::generate();
        let id = EventId::all_zeros();
        let tag = vec![
            String::from("E"),
            id.to_hex(),
            String::new(),
            keys.public_key().to_string(),
        ];
        let parsed = Nip22Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip22Tag::Event {
                id,
                relay_hint: None,
                public_key: Some(keys.public_key()),
                uppercase: true,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_standardized_external_content_tag() {
        let content = ExternalContentId::Url(Url::parse("https://nostrdevkit.org").unwrap());
        let hint = Url::parse("https://example.com").unwrap();
        let tag = vec![String::from("I"), content.to_string(), hint.to_string()];
        let parsed = Nip22Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip22Tag::ExternalContent {
                content,
                hint: Some(hint),
                uppercase: true,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_event() {
        let keys = Keys::generate();
        let kind = Kind::GitPatch;
        let event_id = EventId::compute(
            &keys.public_key(),
            &Timestamp::from_secs(1),
            &kind,
            &Tags::new(),
            "",
        );
        let pubkey = keys.public_key();

        let comment_target = CommentTarget::event(event_id, kind, Some(pubkey), None);

        // Root
        let expected: Tags = Tags::parse([
            vec![
                "E".to_string(),
                event_id.to_hex(),
                String::new(),
                pubkey.to_string(),
            ],
            vec!["P".to_string(), pubkey.to_string()],
            vec!["K".to_string(), kind.to_string()],
        ])
        .unwrap();
        assert_eq!(comment_target.to_tags(true), expected);

        // Parent
        let expected: Tags = Tags::parse([
            vec![
                "e".to_string(),
                event_id.to_hex(),
                String::new(),
                pubkey.to_string(),
            ],
            vec!["p".to_string(), pubkey.to_string()],
            vec!["k".to_string(), kind.to_string()],
        ])
        .unwrap();
        assert_eq!(comment_target.to_tags(false), expected);
    }

    #[test]
    fn test_invalid_event_tag_pubkey() {
        let event_id = EventId::all_zeros();
        let relay_hint = RelayUrl::parse("wss://relay.example.com").unwrap();
        let tag = vec![
            String::from("E"),
            event_id.to_hex(),
            relay_hint.to_string(),
            String::from("not-a-pubkey"),
        ];

        let err = Nip22Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn test_coordinate() {
        let keys = Keys::generate();
        let kind = Kind::ContactList;
        let coordinate = Coordinate::new(kind, keys.public_key());
        let pubkey = keys.public_key();

        let comment_target = CommentTarget::coordinate(Cow::Borrowed(&coordinate), None);

        // Root
        let expected: Tags = Tags::parse([
            vec!["A".to_string(), coordinate.to_string()],
            vec!["P".to_string(), pubkey.to_string()],
            vec!["K".to_string(), kind.to_string()],
        ])
        .unwrap();
        assert_eq!(comment_target.to_tags(true), expected);

        // Parent
        let expected: Tags = Tags::parse([
            vec!["a".to_string(), coordinate.to_string()],
            vec!["p".to_string(), pubkey.to_string()],
            vec!["k".to_string(), kind.to_string()],
        ])
        .unwrap();
        assert_eq!(comment_target.to_tags(false), expected);
    }

    #[test]
    fn test_external_content() {
        let external_content = ExternalContentId::Url("https://nostrdevkit.org".parse().unwrap());
        let nip73_kind = external_content.kind();

        let comment_target = CommentTarget::external(Cow::Borrowed(&external_content), None);

        // Root
        let expected: Tags = Tags::parse([
            vec!["I".to_string(), external_content.to_string()],
            vec!["K".to_string(), nip73_kind.to_string()],
        ])
        .unwrap();
        assert_eq!(comment_target.to_tags(true), expected);

        // Parent
        let expected: Tags = Tags::parse([
            vec!["i".to_string(), external_content.to_string()],
            vec!["k".to_string(), nip73_kind.to_string()],
        ])
        .unwrap();
        assert_eq!(comment_target.to_tags(false), expected);
    }
}
