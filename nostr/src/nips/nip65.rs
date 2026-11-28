// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-65: Relay List Metadata
//!
//! <https://github.com/nostr-protocol/nips/blob/master/65.md>

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::error::{Error, ErrorKind};
use crate::event::{Event, EventBuilder, IntoEventBuilder, Kind, impl_tag_codec_conversions};
use crate::nips::util::{missing_tag_kind, take_relay_url, unknown_tag};
use crate::types::RelayUrl;

const RELAY_METADATA: &str = "r";

/// Relay Metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayMetadata {
    /// Read
    Read,
    /// Write
    Write,
}

/// Relay list event.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayList {
    relays: Vec<(RelayUrl, Option<RelayMetadata>)>,
}

impl RelayList {
    /// Create a relay list.
    pub fn new<I>(relays: I) -> Self
    where
        I: IntoIterator<Item = (RelayUrl, Option<RelayMetadata>)>,
    {
        Self {
            relays: relays.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for RelayList {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::RelayList).tags(self.relays.into_iter().map(
            |(relay_url, metadata)| Nip65Tag::RelayMetadata {
                relay_url,
                metadata,
            },
        ))
    }
}

impl RelayMetadata {
    /// Get as `&str`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Check if is [RelayMetadata::Read]
    #[inline]
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Read)
    }

    /// Check if is [RelayMetadata::Write]
    #[inline]
    pub fn is_write(&self) -> bool {
        matches!(self, Self::Write)
    }
}

impl fmt::Display for RelayMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RelayMetadata {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            _ => Err(Error::with_static_message(
                ErrorKind::Invalid,
                "invalid relay metadata",
            )),
        }
    }
}

/// Standardized NIP-65 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/65.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip65Tag {
    /// Relay metadata
    RelayMetadata {
        /// Relay URL
        relay_url: RelayUrl,
        /// Relay metadata
        metadata: Option<RelayMetadata>,
    },
}

impl_tag_codec_conversions! {
    Nip65Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            RELAY_METADATA => {
                let relay_url: RelayUrl = take_relay_url(&mut iter)?;

                let metadata: Option<RelayMetadata> = match iter.next() {
                    Some(metadata) => Some(RelayMetadata::from_str(metadata.as_ref())?),
                    None => None,
                };

                Ok(Self::RelayMetadata {
                    relay_url,
                    metadata,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::RelayMetadata {
                relay_url,
                metadata,
            } => {
                tx.reserve(2 + metadata.is_some() as usize);

                tx.push_str(RELAY_METADATA);
                tx.push_str(relay_url.as_str());

                if let Some(metadata) = metadata {
                    tx.push_str(metadata.as_str());
                }
            }
        }
    }
}

/// Extracts the relay info (url, optional read/write flag) from the event
#[inline]
pub fn extract_relay_list(
    event: &Event,
) -> impl Iterator<Item = (RelayUrl, Option<RelayMetadata>)> + '_ {
    event
        .tags
        .iter()
        .filter_map(|tag| match Nip65Tag::try_from(tag) {
            Ok(Nip65Tag::RelayMetadata {
                relay_url,
                metadata,
            }) => Some((relay_url, metadata)),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;

    #[test]
    fn test_standardized_relay_metadata_tag() {
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let tag = vec!["r", relay_url.as_str(), "read"];
        let parsed = Nip65Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip65Tag::RelayMetadata {
                relay_url: relay_url.clone(),
                metadata: Some(RelayMetadata::Read),
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_standardized_relay_metadata_tag_without_marker() {
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let tag = vec!["r", relay_url.as_str()];
        let parsed = Nip65Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip65Tag::RelayMetadata {
                relay_url: relay_url.clone(),
                metadata: None,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }
}
