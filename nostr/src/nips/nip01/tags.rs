use alloc::string::{String, ToString};

use super::super::util::{
    missing_tag_kind, take_and_parse_optional_public_key, take_and_parse_optional_relay_url,
    take_coordinate, take_event_id, take_public_key, take_string, unknown_tag,
};
use super::{Coordinate, Error};
use crate::event::{EventId, TagWriter, impl_tag_codec_conversions};
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

impl Nip01Tag {
    /// New "a" tag
    #[inline]
    pub fn coordinate(coordinate: Coordinate) -> Self {
        Self::Coordinate {
            coordinate,
            relay_hint: None,
        }
    }

    /// New "e" tag
    #[inline]
    pub fn event(id: EventId) -> Self {
        Self::Event {
            id,
            relay_hint: None,
            public_key: None,
        }
    }

    /// New "d" tag
    #[inline]
    pub fn identifier<T>(identifier: T) -> Self
    where
        T: Into<String>,
    {
        Self::Identifier(identifier.into())
    }

    /// New "p" tag
    #[inline]
    pub fn public_key(public_key: PublicKey) -> Self {
        Self::PublicKey {
            public_key,
            relay_hint: None,
        }
    }
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

    fn write(self, tx) {
        match self {
            Self::Coordinate {
                coordinate,
                relay_hint,
            } => serialize_a_tag(tx, false, &coordinate, relay_hint.as_ref()),
            Self::Event {
                id,
                relay_hint,
                public_key,
            } => serialize_e_tag(tx, false, &id, relay_hint.as_ref(), public_key.as_ref()),
            Self::Identifier(identifier) => {
                tx.push_str("d");
                tx.push_str(&identifier);
            }
            Self::PublicKey {
                public_key,
                relay_hint,
            } => serialize_p_tag(tx, false, &public_key, relay_hint.as_ref()),
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
    tx: &mut TagWriter,
    uppercase: bool,
    coordinate: &Coordinate,
    relay_hint: Option<&RelayUrl>,
) {
    tx.reserve(2 + relay_hint.is_some() as usize);

    tx.push_str(if uppercase { "A" } else { "a" });
    tx.push_str(&coordinate.to_string());

    if let Some(relay_hint) = relay_hint {
        tx.push_str(relay_hint.as_str());
    }
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
    tx: &mut TagWriter,
    uppercase: bool,
    id: &EventId,
    relay_hint: Option<&RelayUrl>,
    public_key: Option<&PublicKey>,
) {
    tx.reserve(2 + relay_hint.is_some() as usize + public_key.is_some() as usize);

    tx.push_str(if uppercase { "E" } else { "e" });
    tx.push_hex(id.as_bytes());

    if let Some(relay_hint) = relay_hint {
        tx.push_str(relay_hint.as_str());
    } else if public_key.is_some() {
        tx.push_str("");
    }

    if let Some(public_key) = public_key {
        tx.push_hex(public_key.as_bytes());
    }
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
    tx: &mut TagWriter,
    uppercase: bool,
    public_key: &PublicKey,
    relay_hint: Option<&RelayUrl>,
) {
    tx.reserve(2 + relay_hint.is_some() as usize);

    tx.push_str(if uppercase { "P" } else { "p" });
    tx.push_hex(public_key.as_bytes());

    if let Some(relay_hint) = relay_hint {
        tx.push_str(relay_hint.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::event::Tags;

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());

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
    use crate::event::TagsMut;

    /// Compose the tag and pack it, reusing the same packer.
    #[bench]
    pub fn nip01_a_to_tags(bh: &mut Bencher) {
        let mut tags: TagsMut = TagsMut::with_capacity(1);
        bh.iter(|| {
            tags.clear();
            tags.push(Nip01Tag::Coordinate {
                coordinate: Coordinate::from_kpi_format(
                    "30617:00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9:n34",
                )
                .unwrap(),
                relay_hint: None,
            });
            black_box(tags.freeze());
        });
    }

    /// Compose the tag and pack it, reusing the same packer.
    #[bench]
    pub fn nip01_d_to_tags(bh: &mut Bencher) {
        let mut tags: TagsMut = TagsMut::with_capacity(1);
        bh.iter(|| {
            tags.clear();
            tags.push(Nip01Tag::identifier("test"));
            black_box(tags.freeze());
        });
    }

    /// Compose the tag and pack it, reusing the same packer.
    #[bench]
    pub fn nip01_e_to_tags(bh: &mut Bencher) {
        let id = EventId::all_zeros();
        let mut tags: TagsMut = TagsMut::with_capacity(1);
        bh.iter(|| {
            tags.clear();
            tags.push(Nip01Tag::event(id));
            black_box(tags.freeze());
        });
    }

    /// Compose the tag and pack it, reusing the same packer.
    #[bench]
    pub fn nip01_p_to_tags(bh: &mut Bencher) {
        let public_key = PublicKey::from_byte_array([0; 32]);
        let mut tags: TagsMut = TagsMut::with_capacity(1);
        bh.iter(|| {
            tags.clear();
            tags.push(Nip01Tag::public_key(public_key));
            black_box(tags.freeze());
        });
    }
}
