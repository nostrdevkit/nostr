// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-39: External Identities in Profiles
//!
//! <https://github.com/nostr-protocol/nips/blob/master/39.md>

use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use super::util::{missing_tag_kind, take_string, unknown_tag};
use crate::error::{Error, ErrorKind};
use crate::event::impl_tag_codec_conversions;

const IDENTITY: &str = "i";

fn invalid_identity() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "invalid identity")
}

/// Supported external identity providers
///
/// <https://github.com/nostr-protocol/nips/blob/master/39.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExternalIdentity {
    /// github.com
    GitHub,
    /// twitter.com
    Twitter,
    /// mastodon.social
    Mastodon,
    /// telegram.org
    Telegram,
}

impl fmt::Display for ExternalIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ExternalIdentity {
    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::GitHub => "github",
            Self::Twitter => "twitter",
            Self::Mastodon => "mastodon",
            Self::Telegram => "telegram",
        }
    }
}

impl FromStr for ExternalIdentity {
    type Err = Error;

    fn from_str(identity: &str) -> Result<Self, Self::Err> {
        match identity {
            "github" => Ok(Self::GitHub),
            "twitter" => Ok(Self::Twitter),
            "mastodon" => Ok(Self::Mastodon),
            "telegram" => Ok(Self::Telegram),
            _ => Err(invalid_identity()),
        }
    }
}

/// External identity
///
/// <https://github.com/nostr-protocol/nips/blob/master/39.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identity {
    /// The external identity provider
    pub platform: ExternalIdentity,
    /// The user's identity (username) on the provider
    pub ident: String,
    /// The user's proof on the provider
    pub proof: String,
}

impl Identity {
    /// Construct new identity
    pub fn new<S1, S2>(platform_iden: S1, proof: S2) -> Result<Self, Error>
    where
        S1: AsRef<str>,
        S2: Into<String>,
    {
        let i: &str = platform_iden.as_ref();
        let (platform, ident) = i.rsplit_once(':').ok_or_else(invalid_identity)?;

        Ok(Self {
            platform: ExternalIdentity::from_str(platform)?,
            ident: ident.to_string(),
            proof: proof.into(),
        })
    }

    #[inline]
    fn tag_platform_identity(&self) -> String {
        format!("{}:{}", self.platform, self.ident)
    }
}

/// Standardized NIP-39 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/39.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip39Tag {
    /// `i` tag
    Identity(Identity),
}

impl_tag_codec_conversions! {
    Nip39Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            IDENTITY => {
                let platform_ident: String = take_string(&mut iter, "identity")?;
                let proof: String = take_string(&mut iter, "proof")?;

                Ok(Self::Identity(Identity::new(platform_ident, proof)?))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Identity(identity) = self;

        tx.push_str(IDENTITY);
        tx.push_str(&identity.tag_platform_identity());
        tx.push_str(&identity.proof);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;

    #[test]
    fn test_identity_tag() {
        let parsed =
            Nip39Tag::parse(["i", "github:semisol", "9721ce4ee4fceb91c9711ca2a6c9a5ab"]).unwrap();

        assert_eq!(
            parsed,
            Nip39Tag::Identity(Identity {
                platform: ExternalIdentity::GitHub,
                ident: String::from("semisol"),
                proof: String::from("9721ce4ee4fceb91c9711ca2a6c9a5ab"),
            })
        );
        assert_eq!(
            Tags::from_iter([parsed]),
            Tags::parse([["i", "github:semisol", "9721ce4ee4fceb91c9711ca2a6c9a5ab"]]).unwrap()
        );
    }

    #[test]
    fn test_identity_tag_with_extra_values() {
        let parsed = Nip39Tag::parse([
            "i",
            "twitter:semisol_public",
            "1619358434134196225",
            "extra",
        ])
        .unwrap();

        assert_eq!(
            parsed,
            Nip39Tag::Identity(Identity {
                platform: ExternalIdentity::Twitter,
                ident: String::from("semisol_public"),
                proof: String::from("1619358434134196225"),
            })
        );
    }

    #[test]
    fn test_identity_tag_missing_proof() {
        let err = Nip39Tag::parse(["i", "github:semisol"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }
}
