// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-02: Follow List
//!
//! <https://github.com/nostr-protocol/nips/blob/master/02.md>

use alloc::string::String;
use alloc::vec::Vec;

use super::util::{
    missing_tag_kind, take_and_parse_optional_relay_url, take_optional_string, take_public_key,
    unknown_tag,
};
use crate::error::Error;
use crate::event::{
    EventBuilder, IntoEventBuilder, Kind, TagWriter, WriteTag, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::url::RelayUrl;

/// Contact
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Contact {
    /// Public key
    pub public_key: PublicKey,
    /// Relay url
    pub relay_url: Option<RelayUrl>,
    /// Alias
    pub alias: Option<String>,
}

impl Contact {
    /// Create new contact
    #[inline]
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            relay_url: None,
            alias: None,
        }
    }
}

impl WriteTag for Contact {
    fn write(self, tx: &mut TagWriter<'_>) {
        Nip02Tag::PublicKey {
            public_key: self.public_key,
            relay_hint: self.relay_url,
            alias: self.alias,
        }
        .write(tx)
    }
}

/// Standardized NIP-02 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/02.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip02Tag {
    /// Contact public key
    ///
    /// `["p", <32-bytes hex key>, <main relay URL>, <petname>]`
    PublicKey {
        /// Public key
        public_key: PublicKey,
        /// Recommended relay URL
        relay_hint: Option<RelayUrl>,
        /// Alias
        alias: Option<String>,
    },
}

impl_tag_codec_conversions! {
    Nip02Tag,
    fn parse(tag) {
        // Take iterator
        let mut iter = tag.into_iter();

        // Extract first value
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        // Match kind
        match kind.as_ref() {
            "p" => {
                let (public_key, relay_hint, alias) = parse_p_tag(iter)?;
                Ok(Self::PublicKey {
                    public_key,
                    relay_hint,
                    alias,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::PublicKey {
            public_key,
            relay_hint,
            alias,
        } = self;

        tx.push_str("p");
        tx.push_hex(public_key.as_bytes());

        if let Some(relay_hint) = relay_hint {
            tx.push_str(relay_hint.as_str());
        } else if alias.is_some() {
            tx.push_str("");
        }

        if let Some(alias) = alias {
            tx.push_str(&alias);
        }
    }
}

fn parse_p_tag<T, S>(mut iter: T) -> Result<(PublicKey, Option<RelayUrl>, Option<String>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let public_key: PublicKey = take_public_key(&mut iter)?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;
    let alias: Option<String> = take_optional_string(&mut iter);

    Ok((public_key, relay_hint, alias))
}

/// Contact list event builder
///
/// <https://github.com/nostr-protocol/nips/blob/master/02.md>
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ContactListBuilder {
    /// Contacts
    pub contacts: Vec<Contact>,
}

impl ContactListBuilder {
    /// Create a new contact list builder
    #[inline]
    pub fn new<I>(contacts: I) -> Self
    where
        I: IntoIterator<Item = Contact>,
    {
        Self {
            contacts: contacts.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for ContactListBuilder {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::ContactList).tags(self.contacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn test_standardized_p_tag() {
        let raw = "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9";
        let public_key = PublicKey::from_hex(raw).unwrap();

        // Simple
        let tag = vec!["p", raw];
        let parsed = Nip02Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip02Tag::PublicKey {
                public_key,
                relay_hint: None,
                alias: None
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

        // With relay hint
        let tag = vec!["p", raw, "wss://relay.damus.io/"];
        let parsed = Nip02Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip02Tag::PublicKey {
                public_key,
                relay_hint: Some(RelayUrl::parse("wss://relay.damus.io/").unwrap()),
                alias: None
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

        // With relay hint and alias
        let tag = vec!["p", raw, "wss://relay.damus.io/", "alice"];
        let parsed = Nip02Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip02Tag::PublicKey {
                public_key,
                relay_hint: Some(RelayUrl::parse("wss://relay.damus.io/").unwrap()),
                alias: Some(String::from("alice"))
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

        // With alias and no relay hint
        let tag = vec!["p", raw, "", "alice"];
        let parsed = Nip02Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip02Tag::PublicKey {
                public_key,
                relay_hint: None,
                alias: Some(String::from("alice"))
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

        // Invalid public key
        let tag = vec!["p", "hello"];
        let err = Nip02Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);

        // Missing public key
        let tag = vec!["p"];
        let err = Nip02Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn test_make_contact_list_event() {
        let keys = Keys::generate();

        let contact = Contact {
            public_key: PublicKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            relay_url: None,
            alias: None,
        };

        let event = ContactListBuilder::new([contact.clone()])
            .finalize(&keys)
            .unwrap();

        assert_eq!(event.kind, Kind::ContactList);
        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(event.tags.len(), 1);
        assert_eq!(
            Nip02Tag::try_from(event.tags.first().unwrap()).unwrap(),
            Nip02Tag::PublicKey {
                public_key: contact.public_key,
                relay_hint: contact.relay_url,
                alias: contact.alias,
            }
        );
    }
}
