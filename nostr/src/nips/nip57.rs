// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-57: Lightning Zaps
//!
//! <https://github.com/nostr-protocol/nips/blob/master/57.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::nip01::{Coordinate, Nip01Tag};
use super::util::{
    missing_tag_kind, take_and_parse_from_str, take_and_parse_optional_from_str, take_public_key,
    take_relay_url, take_string, unknown_tag,
};
use crate::error::Error;
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::RelayUrl;

const AMOUNT: &str = "amount";
const BOLT11: &str = "bolt11";
const DESCRIPTION: &str = "description";
const LNURL: &str = "lnurl";
const PREIMAGE: &str = "preimage";
const RELAYS: &str = "relays";
const SENDER: &str = "P";
const ZAP: &str = "zap";

/// Standardized NIP-57 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/57.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip57Tag {
    /// `relays` tag
    Relays(Vec<RelayUrl>),
    /// `amount` tag
    Amount {
        /// Amount in millisats
        millisats: u64,
        /// Optional bolt11 invoice
        bolt11: Option<String>,
    },
    /// `lnurl` tag
    Lnurl(String),
    /// `bolt11` tag
    Bolt11(String),
    /// `description` tag
    Description(String),
    /// `preimage` tag
    Preimage(String),
    /// `P` tag
    Sender(PublicKey),
    /// `zap` tag
    Zap {
        /// Receiver public key
        public_key: PublicKey,
        /// Relay used to fetch the receiver metadata
        relay_url: RelayUrl,
        /// Optional split weight
        weight: Option<u64>,
    },
}

impl_tag_codec_conversions! {
    Nip57Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            RELAYS => Ok(Self::Relays(parse_relays(iter)?)),
            AMOUNT => {
                let (millisats, bolt11) = parse_amount_tag(iter)?;
                Ok(Self::Amount { millisats, bolt11 })
            }
            LNURL => Ok(Self::Lnurl(take_string(&mut iter, "LNURL")?)),
            BOLT11 => Ok(Self::Bolt11(take_string(&mut iter, "BOLT11")?)),
            DESCRIPTION => Ok(Self::Description(take_string(&mut iter, "description")?)),
            PREIMAGE => Ok(Self::Preimage(take_string(&mut iter, "preimage")?)),
            SENDER => {
                let public_key: PublicKey = take_public_key(&mut iter)?;
                Ok(Self::Sender(public_key))
            }
            ZAP => {
                let (public_key, relay_url, weight) = parse_zap_tag(iter)?;
                Ok(Self::Zap {
                    public_key,
                    relay_url,
                    weight,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::Relays(relays) => {
                tx.push_str(RELAYS);

                for relay in &relays {
                    tx.push_str(relay.as_str());
                }
            }
            Self::Amount { millisats, bolt11 } => {
                tx.push_str(AMOUNT);
                tx.push_u64(millisats);

                if let Some(bolt11) = bolt11 {
                    tx.push_str(&bolt11);
                }
            }
            Self::Lnurl(lnurl) => {
                tx.push_str(LNURL);
                tx.push_str(&lnurl);
            }
            Self::Bolt11(bolt11) => {
                tx.push_str(BOLT11);
                tx.push_str(&bolt11);
            }
            Self::Description(description) => {
                tx.push_str(DESCRIPTION);
                tx.push_str(&description);
            }
            Self::Preimage(preimage) => {
                tx.push_str(PREIMAGE);
                tx.push_str(&preimage);
            }
            Self::Sender(public_key) => {
                tx.push_str(SENDER);
                tx.push_hex(public_key.as_bytes());
            }
            Self::Zap {
                public_key,
                relay_url,
                weight,
            } => {
                tx.push_str(ZAP);
                tx.push_hex(public_key.as_bytes());
                tx.push_str(relay_url.as_str());

                if let Some(weight) = weight {
                    tx.push_u64(weight);
                }
            }
        }
    }
}

fn parse_relays<T, S>(iter: T) -> Result<Vec<RelayUrl>, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let mut relays: Vec<RelayUrl> = Vec::new();

    for relay in iter {
        relays.push(RelayUrl::parse(relay.as_ref())?);
    }

    Ok(relays)
}

fn parse_amount_tag<T, S>(mut iter: T) -> Result<(u64, Option<String>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let millisats: u64 = take_and_parse_from_str(&mut iter, "amount")?;
    let bolt11: Option<String> = iter.next().map(|bolt11| bolt11.as_ref().to_string());

    Ok((millisats, bolt11))
}

fn parse_zap_tag<T, S>(mut iter: T) -> Result<(PublicKey, RelayUrl, Option<u64>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let public_key: PublicKey = take_public_key(&mut iter)?;
    let relay_url: RelayUrl = take_relay_url(&mut iter)?;
    let weight: Option<u64> =
        take_and_parse_optional_from_str(&mut iter).map_err(Error::malformed)?;

    Ok((public_key, relay_url, weight))
}

/// Zap Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ZapType {
    /// Public
    Public,
}

/// Zap Request Data
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZapRequestData {
    /// Public key of the recipient
    pub public_key: PublicKey,
    /// List of relays the recipient's wallet should publish its zap receipt to
    pub relays: Vec<RelayUrl>,
    /// Message
    pub message: String,
    /// Amount in `millisats` the sender intends to pay
    pub amount: Option<u64>,
    /// Lnurl pay url of the recipient, encoded using bech32 with the prefix lnurl.
    pub lnurl: Option<String>,
    /// Event ID
    pub event_id: Option<EventId>,
    /// The coordinate of an addressable event (e.g., NIP-23 long-form note) to tip, if any.
    pub event_coordinate: Option<Coordinate>,
}

/// Zap receipt event.
#[derive(Debug, Clone)]
pub struct ZapReceipt<'a> {
    bolt11: String,
    preimage: Option<String>,
    zap_request: &'a Event,
}

impl<'a> ZapReceipt<'a> {
    /// Create a zap receipt.
    pub fn new<S>(bolt11: S, zap_request: &'a Event) -> Self
    where
        S: Into<String>,
    {
        Self {
            bolt11: bolt11.into(),
            preimage: None,
            zap_request,
        }
    }

    /// Set the payment preimage.
    pub fn preimage<S>(mut self, preimage: S) -> Self
    where
        S: Into<String>,
    {
        self.preimage = Some(preimage.into());
        self
    }
}

impl IntoEventBuilder for ZapReceipt<'_> {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::ZapReceipt);

        builder.tags.reserve(6);

        builder.tags.push(Nip57Tag::Bolt11(self.bolt11));
        builder
            .tags
            .push(Nip57Tag::Description(self.zap_request.as_json()));

        if let Some(preimage) = self.preimage {
            builder.tags.push(Nip57Tag::Preimage(preimage));
        }

        for kind in ["e", "a", "p"] {
            if let Some(tag) = self.zap_request.tags.iter().find(|tag| tag.kind() == kind) {
                builder.tags.push(tag);
            }
        }

        builder.tags.push(Nip57Tag::Sender(self.zap_request.pubkey));

        builder
    }
}

impl ZapRequestData {
    /// New Zap Request Data
    pub fn new<I>(public_key: PublicKey, relays: I) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        Self {
            public_key,
            relays: relays.into_iter().collect(),
            message: String::new(),
            amount: None,
            lnurl: None,
            event_id: None,
            event_coordinate: None,
        }
    }

    /// Message
    pub fn message<S>(self, message: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            message: message.into(),
            ..self
        }
    }

    /// Amount in `millisats` the sender intends to pay
    pub fn amount(self, amount: u64) -> Self {
        Self {
            amount: Some(amount),
            ..self
        }
    }

    /// Lnurl pay url of the recipient, encoded using bech32 with the prefix lnurl.
    pub fn lnurl<S>(self, lnurl: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            lnurl: Some(lnurl.into()),
            ..self
        }
    }

    /// Event ID
    pub fn event_id(self, event_id: EventId) -> Self {
        Self {
            event_id: Some(event_id),
            ..self
        }
    }

    /// Sets the event coordinate for tipping an addressable event (e.g., NIP-23 long-form notes).
    pub fn event_coordinate(self, event_coordinate: Coordinate) -> Self {
        Self {
            event_coordinate: Some(event_coordinate),
            ..self
        }
    }
}

impl IntoEventBuilder for ZapRequestData {
    fn into_event_builder(self) -> EventBuilder {
        let ZapRequestData {
            public_key,
            relays,
            message,
            amount,
            lnurl,
            event_id,
            event_coordinate,
        } = self;

        let mut builder: EventBuilder = EventBuilder::new(Kind::ZapRequest).content(message);

        builder.tags.reserve(4);

        builder.tags.push(Nip01Tag::public_key(public_key));

        if !relays.is_empty() {
            builder.tags.push(Nip57Tag::Relays(relays));
        }

        if let Some(event_id) = event_id {
            builder.tags.push(Nip01Tag::event(event_id));
        }

        if let Some(event_coordinate) = event_coordinate {
            builder.tags.push(event_coordinate);
        }

        if let Some(amount) = amount {
            builder.tags.push(Nip57Tag::Amount {
                millisats: amount,
                bolt11: None,
            });
        }

        if let Some(lnurl) = lnurl {
            builder.tags.push(Nip57Tag::Lnurl(lnurl));
        }

        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::event::{FinalizeEvent, IntoEventBuilder};
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::key::Keys;

    #[test]
    fn test_relays_tag() {
        let tag = vec!["relays", "wss://relay.damus.io", "wss://relay.primal.net"];
        let parsed = Nip57Tag::parse(tag).unwrap();

        assert_eq!(
            parsed,
            Nip57Tag::Relays(vec![
                RelayUrl::parse("wss://relay.damus.io").unwrap(),
                RelayUrl::parse("wss://relay.primal.net").unwrap(),
            ])
        );
        assert_eq!(
            Tags::from_iter([parsed]),
            Tags::parse([["relays", "wss://relay.damus.io", "wss://relay.primal.net"]]).unwrap()
        );
    }

    #[test]
    fn test_amount_tag() {
        let tag = vec!["amount", "21000", "lnbc21u1p0test"];
        let parsed = Nip57Tag::parse(tag).unwrap();

        assert_eq!(
            parsed,
            Nip57Tag::Amount {
                millisats: 21000,
                bolt11: Some(String::from("lnbc21u1p0test")),
            }
        );
        assert_eq!(
            Tags::from_iter([parsed]),
            Tags::parse([["amount", "21000", "lnbc21u1p0test"]]).unwrap()
        );
    }

    #[test]
    fn test_sender_tag() {
        let public_key =
            PublicKey::from_hex("97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322")
                .unwrap();
        let parsed = Nip57Tag::parse([
            "P",
            "97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322",
        ])
        .unwrap();

        assert_eq!(parsed, Nip57Tag::Sender(public_key));
        assert_eq!(
            Tags::from_iter([parsed]),
            Tags::parse([[
                "P",
                "97c70a44366a6535c145b333f973ea86dfdc2d7a99da618c40c64705ad98e322",
            ]])
            .unwrap()
        );
    }

    #[test]
    fn test_zap_tag() {
        let public_key =
            PublicKey::from_hex("82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://nostr.oxtr.dev").unwrap();
        let parsed = Nip57Tag::parse([
            "zap",
            "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2",
            "wss://nostr.oxtr.dev",
            "2",
        ])
        .unwrap();

        assert_eq!(
            parsed,
            Nip57Tag::Zap {
                public_key,
                relay_url,
                weight: Some(2),
            }
        );
        assert_eq!(
            Tags::from_iter([parsed]),
            Tags::parse([[
                "zap",
                "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2",
                "wss://nostr.oxtr.dev",
                "2",
            ]])
            .unwrap()
        );
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn zap_receipt_builder_handles_optional_preimage() {
        let keys = Keys::generate();
        let request = ZapRequestData::new(
            keys.public_key(),
            [RelayUrl::parse("wss://relay.example.com").unwrap()],
        )
        .finalize(&keys)
        .unwrap();

        let with_preimage = ZapReceipt::new("bolt11", &request)
            .preimage("preimage")
            .into_event_builder();
        let tags_with_preimage = with_preimage.tags.freeze();

        let without_preimage = ZapReceipt::new("bolt11", &request).into_event_builder();
        let tags_without_preimage = without_preimage.tags.freeze();

        assert!(tags_with_preimage.iter().any(|tag| tag.kind() == PREIMAGE));
        assert!(
            !tags_without_preimage
                .iter()
                .any(|tag| tag.kind() == PREIMAGE)
        );
        assert_eq!(with_preimage.tags.len(), without_preimage.tags.len() + 1);
    }
}
