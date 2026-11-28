// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Event ID

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::{self, FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use super::{Kind, TagWriter, Tags, TagsMut, WriteTag};
use crate::error::{Error, ErrorKind};
use crate::key::PublicKey;
use crate::nips::nip01::Nip01Tag;
use crate::nips::nip13;
use crate::nips::nip19::FromBech32;
use crate::nips::nip21::FromNostrUri;
use crate::types::Timestamp;
use crate::util::sha256::Sha256Hash;

/// Event ID
///
/// 32-bytes lowercase hex-encoded sha256 of the serialized event data
///
/// <https://github.com/nostr-protocol/nips/blob/master/01.md>
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(Sha256Hash);

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventId({})", self.to_hex())
    }
}

impl EventId {
    /// Event ID len
    pub const LEN: usize = 32;

    /// Computes the NIP-01 event identifier from unsigned event fields.
    ///
    /// The fields are serialized as the compact UTF-8 JSON array
    /// `[0, public_key, created_at, kind, tags, content]` and hashed with
    /// SHA-256.
    ///
    /// # Panics
    ///
    /// Panics only if one of the crate-owned event field types unexpectedly
    /// fails to serialize to a JSON value. Such a failure indicates an
    /// internal invariant violation rather than invalid caller input.
    #[must_use]
    pub fn compute(
        public_key: &PublicKey,
        created_at: &Timestamp,
        kind: &Kind,
        tags: &Tags,
        content: &str,
    ) -> Self {
        let serialized: Vec<u8> =
            serde_json::to_vec(&(0u8, public_key, created_at, kind, tags, content))
                .expect("serializing valid Nostr event fields must not fail");
        let hash: Sha256Hash = Sha256Hash::hash(&serialized);
        Self(hash)
    }

    #[must_use]
    pub(crate) fn compute_staged(
        public_key: &PublicKey,
        created_at: &Timestamp,
        kind: &Kind,
        tags: &TagsMut,
        content: &str,
    ) -> Self {
        let serialized: Vec<u8> =
            serde_json::to_vec(&(0u8, public_key, created_at, kind, tags, content))
                .expect("serializing valid Nostr event fields must not fail");
        Self(Sha256Hash::hash(&serialized))
    }

    /// Construct from a 32-byte array
    #[inline]
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; Self::LEN]) -> Self {
        Self(Sha256Hash::from_byte_array(bytes))
    }

    #[cfg(test)]
    pub(crate) fn all_zeros() -> Self {
        Self(Sha256Hash::from_byte_array([0; Self::LEN]))
    }

    /// Parses an event identifier.
    ///
    /// The accepted representations are:
    ///
    /// - a 64-character hexadecimal event identifier;
    /// - a NIP-19 `note` or `nevent` identifier accepted by [`FromBech32::from_bech32`];
    /// - a NIP-21 `nostr:` URI accepted by [`FromNostrUri::from_nostr_uri`].
    pub fn parse(id: &str) -> Result<Self, Error> {
        // Try from hex
        if let Ok(id) = Self::from_hex(id) {
            return Ok(id);
        }

        // Try from bech32
        if let Ok(id) = Self::from_bech32(id) {
            return Ok(id);
        }

        // Try from NIP21 URI
        if let Ok(id) = Self::from_nostr_uri(id) {
            return Ok(id);
        }

        Err(Error::with_static_message(
            ErrorKind::Invalid,
            "invalid event ID",
        ))
    }

    /// Parse from hex string
    #[inline]
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        Ok(Self(Sha256Hash::from_hex(hex)?))
    }

    /// Parse from bytes
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; Self::LEN] = slice
            .try_into()
            .map_err(|_| Error::with_static_message(ErrorKind::Invalid, "invalid event ID"))?;

        Ok(Self::from_byte_array(bytes))
    }

    /// Get as bytes
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        self.0.as_bytes()
    }

    /// Consume and get bytes
    #[inline]
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        self.0.to_bytes()
    }

    /// Get as hex string
    #[inline]
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Check POW
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/13.md>
    #[inline]
    #[must_use]
    pub fn check_pow(&self, difficulty: u8) -> bool {
        nip13::get_leading_zero_bits(self.as_bytes()) >= difficulty
    }
}

impl FromStr for EventId {
    type Err = Error;

    /// Try to parse [EventId] from `hex` or `bech32`
    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Self::parse(id)
    }
}

impl AsRef<[u8]> for EventId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8; EventId::LEN]> for EventId {
    fn as_ref(&self) -> &[u8; EventId::LEN] {
        self.as_bytes()
    }
}

impl fmt::LowerHex for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

// Required to keep clean the methods of `Filter` struct
impl From<EventId> for String {
    fn from(event_id: EventId) -> Self {
        event_id.to_hex()
    }
}

impl WriteTag for EventId {
    fn write(self, tx: &mut TagWriter<'_>) {
        Nip01Tag::event(self).write(tx)
    }
}

impl From<EventId> for Nip01Tag {
    fn from(event_id: EventId) -> Self {
        Self::event(event_id)
    }
}

impl Serialize for EventId {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let id: String = String::deserialize(deserializer)?;
        Self::parse(&id).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_pow() {
        let id =
            EventId::from_hex("2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45")
                .unwrap();
        assert!(!id.check_pow(16));

        // POW 20
        let id =
            EventId::from_hex("00000340cb60be5829fbf2712a285f12cf89e5db951c5303b731651f0d71ac1b")
                .unwrap();
        assert!(id.check_pow(16));
        assert!(id.check_pow(20));
        assert!(!id.check_pow(25));
    }
}

#[cfg(bench)]
mod benches {
    use super::*;
    use crate::test::{Bencher, black_box};

    const ID: &str = "2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45";

    #[bench]
    pub fn parse_event_id_from_hex(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(EventId::from_hex(ID)).unwrap();
        });
    }
}
