// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-70: Protected Events
//!
//! <https://github.com/nostr-protocol/nips/blob/master/70.md>

use crate::event::impl_tag_codec_conversions;
use crate::nips::util::{missing_tag_kind, unknown_tag};

/// Standardized NIP-70 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/70.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip70Tag {
    /// Protected event tag
    ///
    /// `["-"]`
    Protected,
}

impl_tag_codec_conversions! {
    Nip70Tag,
    fn parse(tag) {
        // Take iterator
        let mut iter = tag.into_iter();

        // Extract first value
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        // Match kind
        match kind.as_ref() {
            "-" => Ok(Self::Protected),
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Protected = self;
        tx.push_str("-");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;

    #[test]
    fn test_standardized_protected_tag() {
        let tag = vec!["-"];
        let parsed = Nip70Tag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip70Tag::Protected);
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }
}
