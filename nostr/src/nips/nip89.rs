// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-89: Recommended Application Handlers
//!
//! <https://github.com/nostr-protocol/nips/blob/master/89.md>

use alloc::string::{String, ToString};

use super::nip01::Coordinate;
use super::util::{missing_tag_kind, take_string, unknown_tag};
use crate::error::Error;
use crate::event::impl_tag_codec_conversions;
use crate::types::url::RelayUrl;

const CLIENT: &str = "client";

/// Standardized NIP-89 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/89.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip89Tag {
    /// `client` tag
    Client {
        /// Client name
        name: String,
        /// Client address and optional hint
        address: Option<(Coordinate, Option<RelayUrl>)>,
    },
}

impl_tag_codec_conversions! {
    Nip89Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            CLIENT => {
                let (name, address) = parse_client_tag(iter)?;
                Ok(Self::Client { name, address })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Client { name, address } = self;

        tx.push_str(CLIENT);
        tx.push_str(&name);

        match address {
            Some((coordinate, Some(hint))) => {
                tx.push_str(&coordinate.to_string());
                tx.push_str(hint.as_str());
            }
            Some((coordinate, None)) => tx.push_str(&coordinate.to_string()),
            None => {}
        }
    }
}

#[allow(clippy::type_complexity)]
fn parse_client_tag<T, S>(
    mut iter: T,
) -> Result<(String, Option<(Coordinate, Option<RelayUrl>)>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    // Possible cases:
    // - ["client", "My Client"]
    // - ["client", "My Client", "31990:app1-pubkey:<d-identifier>"]
    // - ["client", "My Client", "31990:app1-pubkey:<d-identifier>", "wss://relay1"]

    let name: String = take_string(&mut iter, "client name")?;

    let coordinate: Option<S> = iter.next();

    // Since the address is optional,
    // don't return an error if the coordinate or relay hint parsing fails.
    let address: Option<(Coordinate, Option<RelayUrl>)> = match coordinate {
        // Try to parse the coordinate
        Some(coordinate) => match Coordinate::parse(coordinate.as_ref()) {
            // Coordinate parsing success
            Ok(coordinate) => {
                let relay_url: Option<S> = iter.next();
                let relay_url: Option<RelayUrl> =
                    relay_url.and_then(|url| RelayUrl::parse(url.as_ref()).ok());
                Some((coordinate, relay_url))
            }
            // Failed to parse the coordinate
            Err(..) => None,
        },
        // Nothing to parse
        None => None,
    };

    Ok((name, address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;

    #[test]
    fn test_client_tag() {
        let tag = vec!["client", "voyage"];
        let parsed = Nip89Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip89Tag::Client {
                name: String::from("voyage"),
                address: None
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_client_tag_with_coordinate() {
        let tag = vec![
            "client",
            "voyage",
            "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
        ];
        let parsed = Nip89Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip89Tag::Client {name: String::from("voyage"), address: Some((Coordinate::parse("30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum").unwrap(), None))});
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_client_tag_with_coordinate_and_relay_hint() {
        let tag = vec![
            "client",
            "voyage",
            "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
            "wss://relay.damus.io",
        ];
        let parsed = Nip89Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip89Tag::Client {name: String::from("voyage"), address: Some((Coordinate::parse("30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum").unwrap(), Some(RelayUrl::parse("wss://relay.damus.io").unwrap())))});
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_client_tag_with_coordinate_and_empty_relay_hint() {
        let tag = vec![
            "client",
            "voyage",
            "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
            "",
        ];
        let parsed = Nip89Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip89Tag::Client {name: String::from("voyage"), address: Some((Coordinate::parse("30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum").unwrap(), None))});
        assert_eq!(
            Tags::from_iter([parsed]),
            Tags::parse([tag[..=2].iter().copied()]).unwrap()
        ); // The empty relay-hint is not serialized
    }
}
