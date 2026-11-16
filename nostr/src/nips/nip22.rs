// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP22: Comment
//!
//! <https://github.com/nostr-protocol/nips/blob/master/22.md>

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use url::Url;

use crate::error::Error;
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions,
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

    fn to_tag(&self) {
        match self {
            Self::Coordinate {
                coordinate,
                relay_hint,
                uppercase,
            } => maybe_uppercase(
                nip01::serialize_a_tag(coordinate, relay_hint.as_ref()),
                *uppercase,
            ),
            Self::Event {
                id,
                relay_hint,
                public_key,
                uppercase,
            } => maybe_uppercase(
                nip01::serialize_e_tag(id, relay_hint.as_ref(), public_key.as_ref()),
                *uppercase,
            ),
            Self::ExternalContent {
                content,
                hint,
                uppercase,
            } => maybe_uppercase(nip73::serialize_i_tag(content, hint.as_ref()), *uppercase),
            Self::Kind { kind, uppercase } => Tag::new(vec![
                if *uppercase {
                    String::from("K")
                } else {
                    String::from("k")
                },
                kind.to_string(),
            ]),
            Self::Nip73Kind { kind, uppercase } => {
                maybe_uppercase(nip73::serialize_k_tag(kind), *uppercase)
            }
            Self::PublicKey {
                public_key,
                relay_hint,
                uppercase,
            } => maybe_uppercase(
                nip01::serialize_p_tag(public_key, relay_hint.as_ref()),
                *uppercase,
            ),
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
        EventBuilder::new(Kind::Comment)
            .content(self.content)
            .tags(
                self.root
                    .map(|target| target.as_vec(true))
                    .unwrap_or_default(),
            )
            .tags(self.comment_to.as_vec(false))
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

    /// Converts the comment target into a vector of tags
    ///
    /// ## Example
    ///
    /// If the target is `event` and `is_root` is true will return
    ///
    /// ```json
    /// [
    ///   ["E", "<event-id>", "<relay-hint>", "<public-key>"],
    ///   ["P", "<public-key>"],
    ///   ["K", "<event-kind>"]
    /// ]
    /// ```
    pub fn as_vec(&self, is_root: bool) -> Vec<Tag> {
        let mut tags = Vec::new();

        match self {
            Self::Event {
                id,
                relay_hint,
                pubkey_hint,
                kind,
            } => {
                tags.reserve_exact(
                    1 + usize::from(pubkey_hint.is_some()) + usize::from(kind.is_some()),
                );
                tags.push(
                    Nip22Tag::Event {
                        id: *id,
                        relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                        public_key: pubkey_hint.as_ref().copied(),
                        uppercase: is_root,
                    }
                    .to_tag(),
                );

                if let Some(pubkey) = pubkey_hint {
                    tags.push(
                        Nip22Tag::PublicKey {
                            public_key: *pubkey,
                            relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                            uppercase: is_root,
                        }
                        .to_tag(),
                    );
                }

                if let Some(kind) = kind {
                    tags.push(
                        Nip22Tag::Kind {
                            kind: *kind,
                            uppercase: is_root,
                        }
                        .to_tag(),
                    );
                }
            }
            Self::Coordinate {
                address,
                relay_hint,
                ..
            } => {
                let public_key: PublicKey = address.public_key;
                let kind: Kind = address.kind;

                tags.reserve_exact(3);
                tags.push(
                    Nip22Tag::Coordinate {
                        coordinate: address.clone().into_owned(),
                        relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                        uppercase: is_root,
                    }
                    .to_tag(),
                );
                tags.push(
                    Nip22Tag::PublicKey {
                        public_key,
                        relay_hint: relay_hint.clone().map(|r| r.into_owned()),
                        uppercase: is_root,
                    }
                    .to_tag(),
                );
                tags.push(
                    Nip22Tag::Kind {
                        kind,
                        uppercase: is_root,
                    }
                    .to_tag(),
                );
            }
            Self::External { content, hint } => {
                tags.reserve_exact(2);
                tags.push(
                    Nip22Tag::ExternalContent {
                        content: ExternalContentId::clone(content),
                        hint: hint.clone().map(|r| r.into_owned()),
                        uppercase: is_root,
                    }
                    .to_tag(),
                );
                tags.push(
                    Nip22Tag::Nip73Kind {
                        kind: content.kind(),
                        uppercase: is_root,
                    }
                    .to_tag(),
                )
            }
        }

        tags
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

#[inline]
fn maybe_uppercase(mut tag: Tag, uppercase: bool) -> Tag {
    if uppercase {
        tag[0] = tag[0].to_ascii_uppercase();
    }
    tag
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use super::*;
    use crate::event::Tags;
    use crate::prelude::*;

    fn check_kind(tags: &[Tag], kind: Kind, uppercase: bool) {
        assert!(tags.contains(&Tag::from(Nip22Tag::Kind { kind, uppercase })));
    }

    fn check_nip73_kind(tags: &[Tag], kind: Nip73Kind, uppercase: bool) {
        assert!(tags.contains(&Tag::from(Nip22Tag::Nip73Kind { kind, uppercase })));
    }

    fn check_pubkey(tags: &[Tag], public_key: PublicKey, uppercase: bool) {
        assert!(tags.contains(&Tag::from(Nip22Tag::PublicKey {
            public_key,
            relay_hint: None,
            uppercase,
        })));
    }

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
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
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
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_standardized_external_content_tag() {
        let content = ExternalContentId::Url(Url::parse("https://rust-nostr.org").unwrap());
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
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
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

        let comment_target = CommentTarget::event(event_id, kind, Some(keys.public_key()), None);

        // Root
        let root_vec = comment_target.as_vec(true);
        assert!(root_vec.contains(&Tag::from(Nip22Tag::Event {
            id: event_id,
            relay_hint: None,
            public_key: Some(keys.public_key()),
            uppercase: true,
        })));
        check_pubkey(&root_vec, keys.public_key(), true);
        check_kind(&root_vec, kind, true);

        // Parent
        let parent_vec = comment_target.as_vec(false);
        assert!(parent_vec.contains(&Tag::from(Nip22Tag::Event {
            id: event_id,
            relay_hint: None,
            public_key: Some(keys.public_key()),
            uppercase: false,
        })));
        check_pubkey(&parent_vec, keys.public_key(), false);
        check_kind(&parent_vec, kind, false);
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

        let comment_target = CommentTarget::coordinate(Cow::Borrowed(&coordinate), None);

        // Root
        let root_vec = comment_target.as_vec(true);
        assert!(root_vec.contains(&Tag::from(Nip22Tag::Coordinate {
            coordinate: coordinate.clone(),
            relay_hint: None,
            uppercase: true,
        })));
        check_pubkey(&root_vec, keys.public_key(), true);
        check_kind(&root_vec, kind, true);

        // Parent
        let parent_vec = comment_target.as_vec(false);
        assert!(parent_vec.contains(&Tag::from(Nip22Tag::Coordinate {
            coordinate,
            relay_hint: None,
            uppercase: false,
        })));
        check_pubkey(&parent_vec, keys.public_key(), false);
        check_kind(&parent_vec, kind, false);
    }

    #[test]
    fn test_external_content() {
        let external_content = ExternalContentId::Url("https://rust-nostr.org".parse().unwrap());
        let kind = external_content.kind();

        let comment_target = CommentTarget::external(Cow::Borrowed(&external_content), None);

        // Root
        let root_vec = comment_target.as_vec(true);
        assert!(root_vec.contains(&Tag::from(Nip22Tag::ExternalContent {
            content: external_content.clone(),
            hint: None,
            uppercase: true,
        })));
        check_nip73_kind(&root_vec, kind.clone(), true);

        // Parent
        let parent_vec = comment_target.as_vec(false);
        assert!(parent_vec.contains(&Tag::from(Nip22Tag::ExternalContent {
            content: external_content.clone(),
            hint: None,
            uppercase: false,
        })));
        check_nip73_kind(&parent_vec, kind, false);
    }
}
