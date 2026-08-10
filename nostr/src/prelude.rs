// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Prelude

#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(ambiguous_glob_reexports)]
#![doc(hidden)]

pub use crate::error::{self, Error, ErrorKind};
pub use crate::event::{self, *};
pub use crate::filter::{self, *};
pub use crate::key::{self, *};
pub use crate::message::{self, *};
pub use crate::nips::nip01::{self, *};
pub use crate::nips::nip02::{self, *};
pub use crate::nips::nip04::{self, *};
pub use crate::nips::nip05::{self, *};
#[cfg(feature = "nip06")]
pub use crate::nips::nip06::{self, *};
pub use crate::nips::nip7d::{self, *};
pub use crate::nips::nip09::{self, *};
pub use crate::nips::nip10::{self, *};
pub use crate::nips::nip11::{self, *};
pub use crate::nips::nip13::{self, *};
pub use crate::nips::nip17::{self, *};
pub use crate::nips::nip18::{self, *};
pub use crate::nips::nip19::{self, *};
pub use crate::nips::nip21::{self, *};
pub use crate::nips::nip22::{self, *};
pub use crate::nips::nip23::{self, *};
pub use crate::nips::nip25::{self, *};
pub use crate::nips::nip30::{self, *};
pub use crate::nips::nip32::{self, *};
pub use crate::nips::nip34::{self, *};
pub use crate::nips::nip35::{self, *};
pub use crate::nips::nip38::{self, *};
pub use crate::nips::nip39::{self, *};
pub use crate::nips::nip40::{self, *};
pub use crate::nips::nip42::{self, *};
pub use crate::nips::nip44::{self, *};
#[cfg(all(feature = "std", feature = "nip46"))]
pub use crate::nips::nip46::{self, *};
#[cfg(feature = "nip47")]
pub use crate::nips::nip47::{self, *};
pub use crate::nips::nip48::{self, *};
#[cfg(feature = "nip49")]
pub use crate::nips::nip49::{self, *};
pub use crate::nips::nip51::{self, *};
pub use crate::nips::nip53::{self, *};
pub use crate::nips::nip56::{self, *};
pub use crate::nips::nip57::{self, *};
pub use crate::nips::nip58;
#[cfg(feature = "nip59")]
pub use crate::nips::nip59::{self, *};
#[cfg(feature = "nip60")]
pub use crate::nips::nip60::{self, *};
pub use crate::nips::nip62::{self, *};
pub use crate::nips::nip65::{self, *};
pub use crate::nips::nip66::{self, *};
pub use crate::nips::nip70::{self, *};
pub use crate::nips::nip73::{self, *};
pub use crate::nips::nip88::{self, *};
pub use crate::nips::nip89::{self, *};
pub use crate::nips::nip94::{self, *};
#[cfg(feature = "nip98")]
pub use crate::nips::nip98::{self, *};
#[cfg(feature = "nip117")]
pub use crate::nips::nip117::{self, *};
#[cfg(feature = "nip118")]
pub use crate::nips::nip118::{self, *};
pub use crate::nips::nipa0::{self, *};
pub use crate::nips::nipb0::{self, *};
pub use crate::nips::nipb7::{self, *};
pub use crate::nips::nipc0::{self, *};
pub use crate::nips::nipc7::{self, *};
pub use crate::parser::{self, *};
pub use crate::types::*;
