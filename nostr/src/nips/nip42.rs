// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP42: Authentication of clients to relays
//!
//! <https://github.com/nostr-protocol/nips/blob/master/42.md>

use alloc::string::String;

use crate::event::{Event, EventBuilder, IntoEventBuilder, Kind, impl_tag_codec_conversions};
use crate::nips::util::{missing_tag_kind, take_relay_url, take_string, unknown_tag};
use crate::types::RelayUrl;

const CHALLENGE: &str = "challenge";
const RELAY: &str = "relay";

/// Client authentication event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientAuthentication {
    challenge: String,
    relay: RelayUrl,
}

impl ClientAuthentication {
    /// Create a client authentication event.
    pub fn new<S>(challenge: S, relay: RelayUrl) -> Self
    where
        S: Into<String>,
    {
        Self {
            challenge: challenge.into(),
            relay,
        }
    }
}

impl IntoEventBuilder for ClientAuthentication {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Authentication).tags([
            Nip42Tag::Challenge(self.challenge),
            Nip42Tag::Relay(self.relay),
        ])
    }
}

/// Standardized NIP-42 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/42.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip42Tag {
    /// Authentication challenge
    Challenge(String),
    /// Relay URL
    Relay(RelayUrl),
}

impl_tag_codec_conversions! {
    Nip42Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            CHALLENGE => Ok(Self::Challenge(take_string(&mut iter, "challenge")?)),
            RELAY => {
                let relay_url: RelayUrl = take_relay_url(&mut iter)?;
                Ok(Self::Relay(relay_url))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::Challenge(challenge) => {
                tx.push_str(CHALLENGE);
                tx.push_str(&challenge);
            }
            Self::Relay(relay) => {
                tx.push_str(RELAY);
                tx.push_str(relay.as_str());
            }
        }
    }
}

/// Check if the [`Event`] is a valid authentication.
///
/// This function checks for:
/// - event kind, that must be [`Kind::Authentication`];
/// - `relay` tag, that must match `relay_url` arg;
/// - `challenge` tag, that must match `challenge` arg.
///
/// If all the above checks pass, returns `true`.
pub fn is_valid_auth_event(event: &Event, relay_url: &RelayUrl, challenge: &str) -> bool {
    // Check event kind
    if event.kind != Kind::Authentication {
        return false;
    }

    // Check if it has "relay" tag
    let relay_matches: bool = event.tags.iter().any(|tag| match Nip42Tag::try_from(tag) {
        Ok(Nip42Tag::Relay(url)) => &url == relay_url,
        _ => false,
    });

    if !relay_matches {
        return false;
    }

    // Check if it has the challenge
    let challenge_matches: bool = event.tags.iter().any(|tag| match Nip42Tag::try_from(tag) {
        Ok(Nip42Tag::Challenge(value)) => value == challenge,
        _ => false,
    });

    if !challenge_matches {
        return false;
    }

    // Valid
    true
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use super::*;
    use crate::event::{EventBuilder, FinalizeEvent, Tags};
    use crate::key::Keys;

    #[test]
    fn test_standardized_challenge_tag() {
        let tag = vec!["challenge".to_string(), "1234567890".to_string()];
        let parsed = Nip42Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip42Tag::Challenge(String::from("1234567890")));
    }

    #[test]
    fn test_standardized_relay_tag() {
        let relay = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let tag = vec!["relay".to_string(), relay.to_string()];
        let parsed = Nip42Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip42Tag::Relay(relay.clone()));
        assert_eq!(
            Nip42Tag::try_from(
                Tags::parse([["relay", "wss://relay.damus.io"]])
                    .unwrap()
                    .first()
                    .unwrap()
            )
            .unwrap(),
            Nip42Tag::Relay(relay)
        );
    }

    #[test]
    fn test_valid_auth_event() {
        let keys = Keys::generate();
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let challenge = "1234567890";

        let event = ClientAuthentication::new(challenge, relay_url.clone())
            .finalize(&keys)
            .unwrap();

        assert!(is_valid_auth_event(&event, &relay_url, challenge));
    }

    #[test]
    fn test_invalid_auth_event() {
        let keys = Keys::generate();
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let challenge = "1234567890";

        // Wrong challenge
        let event = ClientAuthentication::new("abcd", relay_url.clone())
            .finalize(&keys)
            .unwrap();
        assert!(!is_valid_auth_event(&event, &relay_url, challenge));

        // Wrong relay url
        let event =
            ClientAuthentication::new(challenge, RelayUrl::parse("wss://example.com").unwrap())
                .finalize(&keys)
                .unwrap();
        assert!(!is_valid_auth_event(&event, &relay_url, challenge));

        // Wrong kind
        let event = EventBuilder::new(Kind::TextNote)
            .content("abcd")
            .finalize(&keys)
            .unwrap();
        assert!(!is_valid_auth_event(&event, &relay_url, challenge));
    }
}
