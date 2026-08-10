// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIPs
//!
//! See all at <https://github.com/nostr-protocol/nips>

mod image;
pub mod nip01;
pub mod nip02;
pub mod nip04;
pub mod nip05;
#[cfg(feature = "nip06")]
pub mod nip06;
pub mod nip09;
pub mod nip10;
pub mod nip11;
#[cfg(feature = "nip117")]
pub mod nip117;
#[cfg(feature = "nip118")]
pub mod nip118;
pub mod nip13;
pub mod nip17;
pub mod nip18;
pub mod nip19;
pub mod nip21;
pub mod nip22;
pub mod nip23;
pub mod nip25;
pub mod nip30;
pub mod nip32;
pub mod nip34;
pub mod nip35;
pub mod nip38;
pub mod nip39;
pub mod nip40;
pub mod nip42;
pub mod nip44;
#[cfg(all(feature = "std", feature = "nip46"))]
pub mod nip46;
#[cfg(feature = "nip47")]
pub mod nip47;
pub mod nip48;
#[cfg(feature = "nip49")]
pub mod nip49;
pub mod nip51;
pub mod nip53;
pub mod nip56;
pub mod nip57;
pub mod nip58;
#[cfg(feature = "nip59")]
pub mod nip59;
#[cfg(feature = "nip60")]
pub mod nip60;
pub mod nip62;
pub mod nip65;
pub mod nip66;
pub mod nip70;
pub mod nip73;
pub mod nip7d;
pub mod nip88;
pub mod nip89;
pub mod nip94;
#[cfg(feature = "nip98")]
pub mod nip98;
pub mod nipa0;
pub mod nipb0;
pub mod nipb7;
pub mod nipc0;
pub mod nipc7;
mod util;
