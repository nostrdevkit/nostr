// Copyright (c) 2026 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-67: EOSE Completeness Hint
//!
//! <https://github.com/nostr-protocol/nips/blob/master/67.md>

use alloc::string::String;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A relay's completeness hint for the stored events of one subscription.
///
/// Hints describe stored events only and do not affect real-time delivery.
/// Without a `Finish` or `More` hint, completeness remains unknown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EoseHint {
    /// The relay has sent every matching stored event.
    Finish,
    /// The relay has more matching stored events to paginate.
    More,
    /// More stored events may become visible after authentication.
    Auth,
    /// An unrecognized hint, preserved for serialization.
    ///
    /// Callers must ignore this hint when interpreting completeness.
    Unknown(String),
}

impl EoseHint {
    /// Get the hint as a string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Finish => "finish",
            Self::More => "more",
            Self::Auth => "auth",
            Self::Unknown(hint) => hint,
        }
    }
}

impl Serialize for EoseHint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EoseHint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hint: String = String::deserialize(deserializer)?;
        Ok(match hint.as_str() {
            "finish" => Self::Finish,
            "more" => Self::More,
            "auth" => Self::Auth,
            _ => Self::Unknown(hint),
        })
    }
}
