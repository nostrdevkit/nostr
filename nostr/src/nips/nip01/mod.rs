// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-01: Basic protocol flow description
//!
//! <https://github.com/nostr-protocol/nips/blob/master/01.md>

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod tags;

pub use self::tags::*;
use super::nip19::{self, FromBech32, Nip19Coordinate, ToBech32};
use super::nip21::{FromNostrUri, ToNostrUri};
use crate::error::{Error, ErrorKind};
use crate::event::{EventBuilder, IntoEventBuilder, Kind, TagWriter, WriteTag};
use crate::filter::Filter;
use crate::key::PublicKey;
use crate::types::url::Url;
use crate::util::impl_json_methods;

#[inline]
fn invalid_coordinate() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "invalid coordinate")
}

/// Coordinate for event (`a` tag)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Coordinate {
    /// Kind
    pub kind: Kind,
    /// Public Key
    pub public_key: PublicKey,
    /// `d` tag identifier
    ///
    /// Needed for a parametrized replaceable event.
    /// Leave empty for a replaceable event.
    pub identifier: String,
}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.borrow().fmt(f)
    }
}

impl Coordinate {
    /// Create new event coordinate
    #[inline]
    pub fn new(kind: Kind, public_key: PublicKey) -> Self {
        Self {
            kind,
            public_key,
            identifier: String::new(),
        }
    }

    /// Parse coordinate from `<kind>:<pubkey>:[<d-tag>]` format, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    pub fn parse(coordinate: &str) -> Result<Self, Error> {
        // Try from hex
        if let Ok(coordinate) = Self::from_kpi_format(coordinate) {
            return Ok(coordinate);
        }

        // Try from bech32
        if let Ok(coordinate) = Self::from_bech32(coordinate) {
            return Ok(coordinate);
        }

        // Try from NIP21 URI
        if let Ok(coordinate) = Self::from_nostr_uri(coordinate) {
            return Ok(coordinate);
        }

        Err(invalid_coordinate())
    }

    /// Try to parse from `<kind>:<pubkey>:[<d-tag>]` format
    pub fn from_kpi_format(coordinate: &str) -> Result<Self, Error> {
        let mut kpi = coordinate.split(':');
        match (kpi.next(), kpi.next(), kpi.next()) {
            (Some(kind_str), Some(public_key_str), Some(identifier)) => Ok(Self {
                kind: Kind::from_str(kind_str)?,
                public_key: PublicKey::from_hex(public_key_str)?,
                identifier: identifier.to_string(),
            }),
            _ => Err(invalid_coordinate()),
        }
    }

    /// Set a `d` tag identifier
    ///
    /// Needed for a parametrized replaceable event.
    pub fn identifier<S>(mut self, identifier: S) -> Self
    where
        S: Into<String>,
    {
        self.identifier = identifier.into();
        self
    }

    /// Check if coordinate has identifier
    #[inline]
    pub fn has_identifier(&self) -> bool {
        !self.identifier.is_empty()
    }

    /// Check if the coordinate is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the [`Kind`] is `replaceable` and the identifier is not empty
    /// - the [`Kind`] is `addressable` and the identifier is empty
    #[inline]
    pub fn verify(&self) -> Result<(), Error> {
        verify_coordinate(&self.kind, &self.identifier)
    }

    /// Borrow coordinate
    pub fn borrow(&self) -> CoordinateBorrow<'_> {
        CoordinateBorrow {
            kind: &self.kind,
            public_key: &self.public_key,
            identifier: Some(&self.identifier),
        }
    }
}

fn verify_coordinate(kind: &Kind, identifier: &str) -> Result<(), Error> {
    let is_replaceable: bool = kind.is_replaceable();
    let is_addressable: bool = kind.is_addressable();

    if !is_replaceable && !is_addressable {
        return Err(invalid_coordinate());
    }

    if is_replaceable && !identifier.is_empty() {
        return Err(invalid_coordinate());
    }

    if is_addressable && identifier.is_empty() {
        return Err(invalid_coordinate());
    }

    Ok(())
}

impl WriteTag for Coordinate {
    fn write(self, tx: &mut TagWriter<'_>) {
        Nip01Tag::coordinate(self).write(tx)
    }
}

impl From<Coordinate> for Nip01Tag {
    fn from(coordinate: Coordinate) -> Self {
        Self::coordinate(coordinate)
    }
}

impl From<Coordinate> for Filter {
    fn from(value: Coordinate) -> Self {
        if value.identifier.is_empty() {
            Filter::new().kind(value.kind).author(value.public_key)
        } else {
            Filter::new()
                .kind(value.kind)
                .author(value.public_key)
                .identifier(value.identifier)
        }
    }
}

impl From<&Coordinate> for Filter {
    fn from(value: &Coordinate) -> Self {
        if value.identifier.is_empty() {
            Filter::new().kind(value.kind).author(value.public_key)
        } else {
            Filter::new()
                .kind(value.kind)
                .author(value.public_key)
                .identifier(value.identifier.clone())
        }
    }
}

impl FromStr for Coordinate {
    type Err = Error;

    /// Try to parse [Coordinate] from `<kind>:<pubkey>:[<d-tag>]` format, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    #[inline]
    fn from_str(coordinate: &str) -> Result<Self, Self::Err> {
        Self::parse(coordinate)
    }
}

impl ToBech32 for Coordinate {
    type Err = Error;

    #[inline]
    fn to_bech32(&self) -> Result<String, Self::Err> {
        self.borrow().to_bech32()
    }
}

impl FromBech32 for Coordinate {
    type Err = Error;

    fn from_bech32(addr: &str) -> Result<Self, Self::Err> {
        let coordinate: Nip19Coordinate = Nip19Coordinate::from_bech32(addr)?;
        Ok(coordinate.coordinate)
    }
}

impl ToNostrUri for Coordinate {}
impl FromNostrUri for Coordinate {}

/// Borrowed coordinate
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoordinateBorrow<'a> {
    /// Kind
    pub kind: &'a Kind,
    /// Public key
    pub public_key: &'a PublicKey,
    /// `d` tag identifier
    ///
    /// Needed for a parametrized replaceable event.
    pub identifier: Option<&'a str>,
}

impl CoordinateBorrow<'_> {
    /// Into owned coordinate
    pub fn into_owned(self) -> Coordinate {
        Coordinate {
            kind: *self.kind,
            public_key: *self.public_key,
            identifier: self.identifier.map(|s| s.to_string()).unwrap_or_default(),
        }
    }
}

impl fmt::Display for CoordinateBorrow<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.kind,
            self.public_key,
            self.identifier.unwrap_or_default()
        )
    }
}

impl ToBech32 for CoordinateBorrow<'_> {
    type Err = Error;

    #[inline]
    fn to_bech32(&self) -> Result<String, Self::Err> {
        nip19::coordinate_to_bech32(*self, &[])
    }
}

impl ToNostrUri for CoordinateBorrow<'_> {}

/// Metadata
///
/// # Examples
///
/// ## Building a user metadata event
///
/// ```rust,no_run
/// # use nostr::prelude::*;
/// # use nostr::nips::nip01::Metadata;
/// # use nostr::types::Url;
/// # #[cfg(all(feature = "std", feature = "os-rng"))]
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let metadata = Metadata::new()
///     .name("username")
///     .display_name("My Username")
///     .about("Description")
///     .picture(Url::parse("https://example.com/avatar.png")?)
///     .nip05("username@example.com")
///     .lud16("pay@yukikishimoto.com");
///
/// let keys = Keys::parse("nsec...")?;
/// let event: Event = metadata.finalize(&keys)?;
/// # _ = event;
/// # Ok(())
/// # }
/// # fn main() {}
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Metadata {
    /// Name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub name: Option<String>,
    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub display_name: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub about: Option<String>,
    /// Website url
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub website: Option<String>,
    /// Picture url
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub picture: Option<String>,
    /// Banner url
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub banner: Option<String>,
    /// NIP05 (ex. name@example.com)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub nip05: Option<String>,
    /// LNURL
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub lud06: Option<String>,
    /// Lightning Address
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub lud16: Option<String>,
    /// Custom fields
    #[serde(
        flatten,
        serialize_with = "serialize_custom_fields",
        deserialize_with = "deserialize_custom_fields"
    )]
    #[serde(default)]
    pub custom: BTreeMap<String, Value>,
}

impl Metadata {
    /// New empty [`Metadata`]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set name
    pub fn name<S>(self, name: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            name: Some(name.into()),
            ..self
        }
    }

    /// Set display name
    pub fn display_name<S>(self, display_name: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            display_name: Some(display_name.into()),
            ..self
        }
    }

    /// Set about
    pub fn about<S>(self, about: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            about: Some(about.into()),
            ..self
        }
    }

    /// Set website
    pub fn website(self, url: Url) -> Self {
        Self {
            website: Some(url.into()),
            ..self
        }
    }

    /// Set picture
    pub fn picture(self, url: Url) -> Self {
        Self {
            picture: Some(url.into()),
            ..self
        }
    }

    /// Set banner
    pub fn banner(self, url: Url) -> Self {
        Self {
            banner: Some(url.into()),
            ..self
        }
    }

    /// Set nip05
    pub fn nip05<S>(self, nip05: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            nip05: Some(nip05.into()),
            ..self
        }
    }

    /// Set lud06 (LNURL)
    pub fn lud06<S>(self, lud06: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            lud06: Some(lud06.into()),
            ..self
        }
    }

    /// Set lud16 (Lightning Address)
    pub fn lud16<S>(self, lud16: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            lud16: Some(lud16.into()),
            ..self
        }
    }

    /// Set custom metadata field
    pub fn custom_field<K, S>(mut self, field_name: K, value: S) -> Self
    where
        K: Into<String>,
        S: Into<Value>,
    {
        self.custom.insert(field_name.into(), value.into());
        self
    }
}

impl_json_methods!(Metadata);

fn serialize_custom_fields<S>(
    custom_fields: &BTreeMap<String, Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = serializer.serialize_map(Some(custom_fields.len()))?;
    for (field_name, value) in custom_fields {
        map.serialize_entry(field_name, value)?;
    }
    map.end()
}

fn deserialize_custom_fields<'de, D>(deserializer: D) -> Result<BTreeMap<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    struct GenericTagsVisitor;

    impl<'de> Visitor<'de> for GenericTagsVisitor {
        type Value = BTreeMap<String, Value>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("map where keys are strings and values are valid json")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut custom_fields: BTreeMap<String, Value> = BTreeMap::new();
            while let Some(field_name) = map.next_key::<String>()? {
                if let Ok(value) = map.next_value::<Value>() {
                    custom_fields.insert(field_name, value);
                }
            }
            Ok(custom_fields)
        }
    }

    deserializer.deserialize_map(GenericTagsVisitor)
}

impl IntoEventBuilder for &Metadata {
    #[inline]
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Metadata).content(self.as_json())
    }
}

impl IntoEventBuilder for Metadata {
    #[inline]
    fn into_event_builder(self) -> EventBuilder {
        (&self).into_event_builder()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_metadata() {
        let content = r#"{"name":"myname","about":"Description","display_name":""}"#;
        let metadata = Metadata::from_json(content).unwrap();
        assert_eq!(
            metadata,
            Metadata::new()
                .name("myname")
                .about("Description")
                .display_name("")
        );

        let content = r#"{"name":"myname","about":"Description","displayName":"Jack"}"#;
        let metadata = Metadata::from_json(content).unwrap();
        assert_eq!(
            metadata,
            Metadata::new()
                .name("myname")
                .about("Description")
                .custom_field("displayName", "Jack")
        );

        let content = r#"{"lud16":"thesimplekid@cln.thesimplekid.com","nip05":"_@thesimplekid.com","display_name":"thesimplekid","about":"Wannabe open source dev","name":"thesimplekid","username":"thesimplekid","displayName":"thesimplekid","lud06":"","reactions":false,"damus_donation_v2":0}"#;
        let metadata = Metadata::from_json(content).unwrap();
        assert_eq!(
            metadata,
            Metadata::new()
                .name("thesimplekid")
                .display_name("thesimplekid")
                .about("Wannabe open source dev")
                .nip05("_@thesimplekid.com")
                .lud06("")
                .lud16("thesimplekid@cln.thesimplekid.com")
                .custom_field("username", "thesimplekid")
                .custom_field("displayName", "thesimplekid")
                .custom_field("reactions", false)
                .custom_field("damus_donation_v2", 0)
        );
        assert_eq!(metadata, Metadata::from_json(metadata.as_json()).unwrap());
    }

    #[test]
    fn parse_valid_coordinate() {
        let coordinate: &str =
            "30023:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:ipsum";
        let coordinate: Coordinate = Coordinate::parse(coordinate).unwrap();

        let expected_public_key: PublicKey =
            PublicKey::from_hex("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4")
                .unwrap();

        assert_eq!(coordinate.kind.as_u16(), 30023);
        assert_eq!(coordinate.public_key, expected_public_key);
        assert_eq!(coordinate.identifier, "ipsum");

        let coordinate: &str =
            "20500:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:";
        let coordinate: Coordinate = Coordinate::parse(coordinate).unwrap();

        assert_eq!(coordinate.kind.as_u16(), 20500);
        assert_eq!(coordinate.public_key, expected_public_key);
        assert_eq!(coordinate.identifier, "");
    }

    #[test]
    fn test_verify_coordinate() {
        // Valid: replaceable
        let coordinate: &str =
            "15000:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:";
        let coordinate: Coordinate = Coordinate::parse(coordinate).unwrap();
        assert!(coordinate.verify().is_ok());

        // Valid: addressable
        let coordinate: &str =
            "30023:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:ipsum";
        let coordinate: Coordinate = Coordinate::parse(coordinate).unwrap();
        assert!(coordinate.verify().is_ok());

        // Invalid: ephemeral kind
        let coordinate: &str =
            "20500:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:";
        let coordinate: Coordinate = Coordinate::parse(coordinate).unwrap();
        assert!(coordinate.verify().is_err());

        // Invalid: replaceable with identifier
        let coordinate: &str =
            "11111:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:test";
        let coordinate: Coordinate = Coordinate::parse(coordinate).unwrap();
        assert!(coordinate.verify().is_err());

        // Invalid: addressable without identifier
        let coordinate: &str =
            "30023:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:";
        let coordinate: Coordinate = Coordinate::parse(coordinate).unwrap();
        assert!(coordinate.verify().is_err());
    }

    #[test]
    fn display_addressable_coordinate() {
        let pkey = "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9";
        let coordinate = Coordinate::new(
            Kind::GitRepoAnnouncement,
            PublicKey::from_hex(pkey).unwrap(),
        )
        .identifier("n34");

        assert_eq!(
            coordinate.to_string(),
            "30617:00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9:n34"
        )
    }

    #[test]
    fn display_replaceable_coordinate() {
        let pkey = "00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9";
        let coordinate = Coordinate::new(Kind::MuteList, PublicKey::from_hex(pkey).unwrap());

        assert_eq!(
            coordinate.to_string(),
            "10000:00000001505e7e48927046e9bbaa728b1f3b511227e2200c578d6e6bb0c77eb9:"
        )
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    #[bench]
    pub fn parse_coordinate(bh: &mut Bencher) {
        let coordinate: &str =
            "30023:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:ipsum";
        bh.iter(|| {
            black_box(Coordinate::parse(coordinate)).unwrap();
        });
    }
}
