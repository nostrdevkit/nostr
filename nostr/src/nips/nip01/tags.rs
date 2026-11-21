use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::super::util::{
    missing_tag_kind, take_and_parse_optional_public_key, take_and_parse_optional_relay_url,
    take_coordinate, take_event_id, take_public_key, take_string, unknown_tag,
};
use super::{Coordinate, Error};
use crate::event::{EventId, Tag, impl_tag_codec_conversions};
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Standardized NIP-01 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/01.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip01Tag {
    /// `a` tag
    Coordinate {
        /// Coordinate
        coordinate: Coordinate,
        /// Relay hint (optional but recommended)
        relay_hint: Option<RelayUrl>,
    },
    /// `e` tag
    Event {
        /// Event ID
        id: EventId,
        /// Relay hint (optional but recommended)
        relay_hint: Option<RelayUrl>,
        /// Public key hint
        public_key: Option<PublicKey>,
    },
    /// `d` tag
    Identifier(String),
    /// `p` tag
    PublicKey {
        /// Public key
        public_key: PublicKey,
        /// Relay hint (optional but recommended)
        relay_hint: Option<RelayUrl>,
    },
}

impl_tag_codec_conversions! {
    Nip01Tag,
    fn parse(tag) {
        // Take iterator
        let mut iter = tag.into_iter();

        // Extract first value
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        // Match kind
        match kind.as_ref() {
            "a" => {
                let (coordinate, relay_hint) = parse_a_tag(iter)?;
                Ok(Self::Coordinate {
                    coordinate,
                    relay_hint,
                })
            }
            "e" => {
                let (id, relay_hint, public_key) = parse_e_tag(iter)?;
                Ok(Self::Event {
                    id,
                    relay_hint,
                    public_key,
                })
            }
            "d" => Ok(Self::Identifier(take_string(&mut iter, "identifier")?)),
            "p" => {
                let (public_key, relay_hint) = parse_p_tag(iter)?;
                Ok(Self::PublicKey {
                    public_key,
                    relay_hint,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::Coordinate {
                coordinate,
                relay_hint,
            } => serialize_a_tag(coordinate, relay_hint.as_ref()),
            Self::Event {
                id,
                relay_hint,
                public_key,
            } => serialize_e_tag(id, relay_hint.as_ref(), public_key.as_ref()),
            Self::Identifier(identifier) => {
                Tag::new(vec![String::from("d"), identifier.to_string()])
            }
            Self::PublicKey {
                public_key,
                relay_hint,
            } => serialize_p_tag(public_key, relay_hint.as_ref()),
        }
    }
}

pub(in super::super) fn parse_a_tag<T, S>(
    mut iter: T,
) -> Result<(Coordinate, Option<RelayUrl>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let coordinate: Coordinate = take_coordinate(&mut iter)?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;

    Ok((coordinate, relay_hint))
}

pub(in super::super) fn serialize_a_tag(
    coordinate: &Coordinate,
    relay_hint: Option<&RelayUrl>,
) -> Tag {
    let mut tag: Vec<String> = Vec::with_capacity(2 + relay_hint.is_some() as usize);

    tag.push(String::from("a"));
    tag.push(coordinate.to_string());

    if let Some(relay_hint) = relay_hint {
        tag.push(relay_hint.to_string());
    }

    Tag::new(tag)
}

pub(in super::super) fn parse_e_tag<T, S>(
    mut iter: T,
) -> Result<(EventId, Option<RelayUrl>, Option<PublicKey>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let id: EventId = take_event_id(&mut iter)?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;
    let public_key: Option<PublicKey> = take_and_parse_optional_public_key(&mut iter)?;

    Ok((id, relay_hint, public_key))
}

pub(in super::super) fn serialize_e_tag(
    id: &EventId,
    relay_hint: Option<&RelayUrl>,
    public_key: Option<&PublicKey>,
) -> Tag {
    let mut tag: Vec<String> =
        Vec::with_capacity(2 + relay_hint.is_some() as usize + public_key.is_some() as usize);

    tag.push(String::from("e"));
    tag.push(id.to_hex());

    if let Some(relay_hint) = relay_hint {
        tag.push(relay_hint.to_string());
    } else if public_key.is_some() {
        tag.push(String::new());
    }

    if let Some(public_key) = public_key {
        tag.push(public_key.to_string());
    }

    Tag::new(tag)
}

pub(in super::super) fn parse_p_tag<T, S>(
    mut iter: T,
) -> Result<(PublicKey, Option<RelayUrl>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let public_key: PublicKey = take_public_key(&mut iter)?;
    let relay_hint: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;

    Ok((public_key, relay_hint))
}

pub(in super::super) fn serialize_p_tag(
    public_key: &PublicKey,
    relay_hint: Option<&RelayUrl>,
) -> Tag {
    let mut tag: Vec<String> = Vec::with_capacity(2 + relay_hint.is_some() as usize);

    tag.push(String::from("p"));
    tag.push(public_key.to_hex());

    if let Some(relay_hint) = relay_hint {
        tag.push(relay_hint.to_string());
    }

    Tag::new(tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn test_standardized_a_tag() {
        let raw = "30617:00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9:n34";
        let coordinate = Coordinate::from_kpi_format(raw).unwrap();

        // Simple
        let tag = vec!["a", raw];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::Coordinate {
                coordinate: coordinate.clone(),
                relay_hint: None
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // With relay hint
        let tag = vec!["a", raw, "wss://relay.damus.io/"];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::Coordinate {
                coordinate,
                relay_hint: Some(RelayUrl::parse("wss://relay.damus.io/").unwrap())
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // Invalid coordinate
        let tag = vec!["a", "hello"];
        let err = Nip01Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);

        // Missing coordinate
        let tag = vec!["a"];
        let err = Nip01Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }

    #[test]
    fn test_standardized_e_tag() {
        let raw = "a3ce0a22c5c25e5a41a17004d38ed2aa8f815dda918c92400c6b611c41acbc78";
        let id = EventId::from_hex(raw).unwrap();

        // Simple
        let tag = vec!["e", raw];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::Event {
                id,
                relay_hint: None,
                public_key: None
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // With relay hint
        let tag = vec!["e", raw, "wss://relay.damus.io/"];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::Event {
                id,
                relay_hint: Some(RelayUrl::parse("wss://relay.damus.io/").unwrap()),
                public_key: None
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // With relay hint and public key
        let tag = vec![
            "e",
            raw,
            "wss://relay.damus.io/",
            "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9",
        ];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::Event {
                id,
                relay_hint: Some(RelayUrl::parse("wss://relay.damus.io/").unwrap()),
                public_key: Some(
                    PublicKey::from_hex(
                        "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9"
                    )
                    .unwrap()
                )
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // With public key and no relay hint
        let tag = vec![
            "e",
            raw,
            "",
            "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9",
        ];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::Event {
                id,
                relay_hint: None,
                public_key: Some(
                    PublicKey::from_hex(
                        "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9"
                    )
                    .unwrap()
                )
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // Invalid ID
        let tag = vec!["e", "hello"];
        let err = Nip01Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);

        // Missing ID
        let tag = vec!["e"];
        let err = Nip01Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);

        // Issue: https://gitworkshop.dev/yukikishimoto.com/nostr/issues/note15xl8ae8dnmt26adfw6ec8gshxxs242vrvsa3v36ctwq2x9gglkustlxlwa
        let result = Nip01Tag::parse(["e", raw, "", "", ""]).unwrap();
        assert_eq!(
            result,
            Nip01Tag::Event {
                id,
                relay_hint: None,
                public_key: None,
            }
        )
    }

    #[test]
    fn test_standardized_d_tag() {
        let tag = vec!["d", "raw"];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip01Tag::Identifier(String::from("raw")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // Missing identifier
        let tag = vec!["d"];
        let err = Nip01Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }

    #[test]
    fn test_standardized_p_tag() {
        let raw = "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9";
        let public_key = PublicKey::from_hex(raw).unwrap();

        // Simple
        let tag = vec!["p", raw];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::PublicKey {
                public_key,
                relay_hint: None
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // With relay hint
        let tag = vec!["p", raw, "wss://relay.damus.io/"];
        let parsed = Nip01Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip01Tag::PublicKey {
                public_key,
                relay_hint: Some(RelayUrl::parse("wss://relay.damus.io/").unwrap())
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());

        // Invalid public key
        let tag = vec!["p", "hello"];
        let err = Nip01Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);

        // Missing public key
        let tag = vec!["p"];
        let err = Nip01Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    #[bench]
    pub fn nip01_e_to_tag(bh: &mut Bencher) {
        let id = EventId::all_zeros();
        let tag: Nip01Tag = Nip01Tag::Event {
            id,
            relay_hint: None,
            public_key: None,
        };
        bh.iter(|| {
            let tag: Tag = (&tag).into();
            black_box(tag);
        });
    }

    #[bench]
    pub fn nip01_d_to_tag(bh: &mut Bencher) {
        let tag: Nip01Tag = Nip01Tag::Identifier(String::from("test"));
        bh.iter(|| {
            let tag: Tag = (&tag).into();
            black_box(tag);
        });
    }
}
