// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

#[cfg(feature = "rand")]
use alloc::string::String;
#[cfg(feature = "std")]
use std::sync::LazyLock;

#[cfg(feature = "rand")]
use rand::Rng;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rand_core::UnwrapErr;
#[cfg(feature = "os-rng")]
use rand::rngs::SysRng;
#[cfg(feature = "std")]
use secp256k1::{All, Secp256k1};
#[cfg(any(feature = "nip04", feature = "nip44"))]
use secp256k1::{PublicKey as NormalizedPublicKey, ecdh};
#[cfg(any(feature = "nip04", feature = "nip44"))]
use zeroize::Zeroizing;

#[cfg(feature = "nip44")]
pub(crate) mod hkdf;
mod json;
pub(crate) mod sha256;

#[cfg(feature = "nip47")]
pub(crate) use self::json::parse_json_from_value;
pub(crate) use self::json::{impl_json_methods, parse_json};
use crate::error::Error;
#[cfg(any(feature = "nip04", feature = "nip44"))]
use crate::key::{PublicKey, SecretKey};

#[cfg(feature = "rand")]
fn random_bytes<R, const N: usize>(rng: &mut R) -> [u8; N]
where
    R: Rng,
{
    let mut ret: [u8; N] = [0u8; N];
    rng.fill_bytes(&mut ret);
    ret
}

#[inline]
#[cfg(feature = "rand")]
pub(crate) fn random_32_bytes<R>(rng: &mut R) -> [u8; 32]
where
    R: Rng,
{
    random_bytes(rng)
}

#[cfg(feature = "rand")]
pub(crate) fn random_hex_string<R, const N: usize>(rng: &mut R) -> String
where
    R: Rng,
{
    let bytes: [u8; N] = random_bytes(rng);
    faster_hex::hex_string(&bytes)
}

#[inline]
pub(crate) fn hex_decode<const SIZE: usize>(hex: &str) -> Result<[u8; SIZE], Error> {
    let mut bytes: [u8; SIZE] = [0u8; SIZE];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes).map_err(Error::malformed_display)?;
    Ok(bytes)
}

/// Generate shared key
///
/// **Important: use of a strong cryptographic hash function may be critical to security! Do NOT use
/// unless you understand cryptographical implications.**
#[cfg(any(feature = "nip04", feature = "nip44"))]
pub(crate) fn generate_shared_key(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    // `from_x_only_public_key(pk, Parity::Even)` builds exactly this form and
    // parses it again, so building it directly is equivalent and parses once.
    let mut compressed: [u8; 33] = [0u8; 33];
    compressed[0] = 0x02; // Even parity
    compressed[1..].copy_from_slice(public_key.as_bytes());
    let public_key_normalized: NormalizedPublicKey =
        NormalizedPublicKey::from_slice(&compressed).map_err(Error::invalid_display)?;

    let ssp: Zeroizing<[u8; 64]> = Zeroizing::new(ecdh::shared_secret_point(
        &public_key_normalized,
        secret_key,
    ));
    let mut shared_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    shared_key.copy_from_slice(&ssp[..32]);

    Ok(shared_key)
}

/// Secp256k1 global context
#[cfg(feature = "std")]
pub(crate) static SECP256K1: LazyLock<Secp256k1<All>> = LazyLock::new(|| {
    #[cfg(feature = "os-rng")]
    let mut ctx: Secp256k1<All> = Secp256k1::new();
    #[cfg(not(feature = "os-rng"))]
    let ctx: Secp256k1<All> = Secp256k1::new();

    // Randomize
    #[cfg(feature = "os-rng")]
    {
        let seed: [u8; 32] = random_32_bytes(&mut UnwrapErr(SysRng));
        ctx.seeded_randomize(&seed);
    }

    ctx
});
