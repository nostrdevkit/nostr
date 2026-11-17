// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-40: Expiration Timestamp
//!
//! <https://github.com/nostr-protocol/nips/blob/master/40.md>

use crate::event::impl_tag_codec_conversions;
use crate::nips::util::{missing_tag_kind, take_timestamp, unknown_tag};
use crate::types::time::Timestamp;

const EXPIRATION: &str = "expiration";

/// Standardized NIP-40 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/40.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip40Tag {
    /// Expiration timestamp
    Expiration(Timestamp),
}

impl_tag_codec_conversions! {
    Nip40Tag,
    fn parse(tag) {
        // Take iterator
        let mut iter = tag.into_iter();

        // Extract first value
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        // Match kind
        match kind.as_ref() {
            EXPIRATION => {
                let timestamp: Timestamp = take_timestamp(&mut iter)?;
                Ok(Self::Expiration(timestamp))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Expiration(timestamp) = self;
        tx.push_str(EXPIRATION);
        tx.push_u64(timestamp.as_secs());
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn test_parse_empty_tag() {
        let tag: Vec<String> = Vec::new();
        let err = Nip40Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }

    #[test]
    fn test_non_existing_tag() {
        let tag = vec!["hello"];
        let err = Nip40Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn test_standardized_expiration_tag() {
        let raw = 1600000000;
        let timestamp = Timestamp::from_secs(raw);

        // Simple
        let tag = vec!["expiration".to_string(), raw.to_string()];
        let parsed = Nip40Tag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip40Tag::Expiration(timestamp));

        // Invalid timestamp
        let tag = vec!["expiration", "hello"];
        let err = Nip40Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);

        // Missing timestamp
        let tag = vec!["expiration"];
        let err = Nip40Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }
}
