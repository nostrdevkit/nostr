// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Public key

use alloc::boxed::Box;
use alloc::string::String;
use core::any::Any;
use core::cmp::Ordering;
use core::convert::Infallible;
use core::fmt;
use core::fmt::Debug;
use core::future::Future;
use core::hash::{Hash, Hasher};
use core::pin::Pin;
use core::str::{self, FromStr};

use secp256k1::{Secp256k1, Signing, XOnlyPublicKey};
use serde::{Deserialize, Deserializer, Serialize};

use super::secret_key::SecretKey;
use crate::error::{Error, ErrorKind};
use crate::event::{TagWriter, WriteTag};
use crate::nips::nip01::Nip01Tag;
use crate::nips::nip19::{FromBech32, PREFIX_BECH32_PROFILE, PREFIX_BECH32_PUBLIC_KEY};
use crate::nips::nip21::{FromNostrUri, SCHEME_WITH_COLON};
use crate::util;

/// Get public key
pub trait GetPublicKey: Any + Debug + Send + Sync {
    /// Error type
    type Error: core::error::Error + Send + Sync;

    /// Get public key
    fn get_public_key(&self) -> Result<PublicKey, Self::Error>;
}

/// Get public key
pub trait AsyncGetPublicKey: Any + Debug + Send + Sync {
    /// Error type
    type Error: core::error::Error + Send + Sync;

    /// Get public key
    fn get_public_key_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PublicKey, Self::Error>> + Send + '_>>;
}

/// Public Key
#[derive(Clone, Copy)]
pub struct PublicKey {
    buf: [u8; 32],
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.buf == other.buf
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.buf.cmp(&other.buf)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.buf.hash(state);
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<XOnlyPublicKey> for PublicKey {
    fn from(inner: XOnlyPublicKey) -> Self {
        Self {
            buf: inner.serialize(),
        }
    }
}

impl PublicKey {
    /// Public Key len
    pub const LEN: usize = 32;

    /// Construct from 32-byte array
    #[inline]
    pub const fn from_byte_array(bytes: [u8; Self::LEN]) -> Self {
        Self { buf: bytes }
    }

    /// Parse from `hex`, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    pub fn parse(public_key: &str) -> Result<Self, Error> {
        if public_key.starts_with(PREFIX_BECH32_PUBLIC_KEY)
            || public_key.starts_with(PREFIX_BECH32_PROFILE)
        {
            Self::from_bech32(public_key)
        } else if public_key.starts_with(SCHEME_WITH_COLON) {
            Self::from_nostr_uri(public_key)
        } else {
            Self::from_hex(public_key)
        }
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let bytes: [u8; Self::LEN] = util::hex_decode(hex)?;
        Ok(Self::from_byte_array(bytes))
    }

    /// Parse from bytes
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        // Check len
        if slice.len() != Self::LEN {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "public key must be 32 bytes long",
            ));
        }

        // Copy bytes
        let mut bytes: [u8; Self::LEN] = [0u8; Self::LEN];
        bytes.copy_from_slice(slice);

        // Construct
        Ok(Self::from_byte_array(bytes))
    }

    /// Derive public key from [`SecretKey`].
    pub fn from_secret_key<C>(secp: &Secp256k1<C>, secret_key: &SecretKey) -> Self
    where
        C: Signing,
    {
        let pk: secp256k1::PublicKey = secp256k1::PublicKey::from_secret_key(secp, secret_key);
        let (xonly, _): (XOnlyPublicKey, _) = pk.x_only_public_key();
        Self::from(xonly)
    }

    /// Get as bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.buf
    }

    /// Get public key as `bytes`
    #[inline]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        self.buf
    }

    /// Get public key as `hex` string
    #[inline]
    pub fn to_hex(&self) -> String {
        // SAFETY: hex is a valid UTF-8
        unsafe { String::from_utf8_unchecked(self.to_hex_byte_array().to_vec()) }
    }

    /// Get hex 64-byte array
    #[inline]
    pub fn to_hex_byte_array(&self) -> [u8; Self::LEN * 2] {
        let mut buf = [0u8; Self::LEN * 2];
        faster_hex::hex_encode(self.as_bytes(), &mut buf).expect("Buffer size is correct");
        buf
    }

    /// Get the x-only public key
    pub fn xonly(&self) -> Result<XOnlyPublicKey, Error> {
        XOnlyPublicKey::from_slice(self.as_bytes()).map_err(Error::invalid_display)
    }
}

impl GetPublicKey for PublicKey {
    type Error = Infallible;

    #[inline]
    fn get_public_key(&self) -> Result<PublicKey, Self::Error> {
        Ok(*self)
    }
}

impl AsyncGetPublicKey for PublicKey {
    type Error = Infallible;

    #[inline]
    fn get_public_key_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PublicKey, Self::Error>> + Send + '_>> {
        Box::pin(async move { GetPublicKey::get_public_key(self) })
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    /// Try to parse [PublicKey] from `hex`, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    #[inline]
    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        Self::parse(public_key)
    }
}

// Required to keep clean the methods of `Filter` struct
impl From<PublicKey> for String {
    fn from(public_key: PublicKey) -> Self {
        public_key.to_hex()
    }
}

impl WriteTag for PublicKey {
    fn write(self, tx: &mut TagWriter<'_>) {
        Nip01Tag::public_key(self).write(tx)
    }
}

impl From<PublicKey> for Nip01Tag {
    fn from(pkey: PublicKey) -> Self {
        Self::public_key(pkey)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes: [u8; Self::LEN * 2] = self.to_hex_byte_array();
        // SAFETY: hex is a valid UTF-8
        let encoded: &str = unsafe { str::from_utf8_unchecked(&bytes) };
        serializer.serialize_str(encoded)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let public_key: String = String::deserialize(deserializer)?;
        Self::parse(&public_key).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_parse() {
        let public_key = PublicKey::parse(
            "nostr:npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy",
        )
        .unwrap();
        assert_eq!(
            public_key.to_hex(),
            "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4"
        );
    }

    #[test]
    fn test_as_xonly() {
        let hex_pk: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";

        let public_key = PublicKey::from_hex(hex_pk).unwrap();

        //assert!(public_key.xonly.is_null());

        let expected = XOnlyPublicKey::from_str(hex_pk).unwrap();
        let xonly = public_key.xonly().unwrap();
        assert_eq!(&xonly, &expected);

        let public_key = PublicKey::from(expected);
        let xonly = public_key.xonly().unwrap();
        assert_eq!(&xonly, &expected);
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;
    use crate::nips::nip19::ToBech32;

    const NIP21_URI: &str = "nostr:npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";
    const HEX: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    const BECH32: &str = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";

    #[bench]
    pub fn parse_public_key_nip21_uri(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(PublicKey::parse(NIP21_URI)).unwrap();
        });
    }

    #[bench]
    pub fn parse_public_key_hex(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(PublicKey::parse(HEX)).unwrap();
        });
    }

    #[bench]
    pub fn public_key_from_hex(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(PublicKey::from_hex(HEX)).unwrap();
        });
    }

    #[bench]
    pub fn parse_public_key_bech32(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(PublicKey::parse(BECH32)).unwrap();
        });
    }

    #[bench]
    pub fn public_key_from_bech32(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(PublicKey::from_bech32(BECH32)).unwrap();
        });
    }

    #[bench]
    pub fn public_key_to_hex(bh: &mut Bencher) {
        let public_key = PublicKey::from_hex(HEX).unwrap();
        bh.iter(|| {
            black_box(public_key.to_bech32()).unwrap();
        });
    }

    #[bench]
    pub fn public_key_to_bech32(bh: &mut Bencher) {
        let public_key = PublicKey::from_hex(HEX).unwrap();
        bh.iter(|| {
            black_box(public_key.to_bech32()).unwrap();
        });
    }
}
