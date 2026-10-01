// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Prelude

#![allow(unknown_lints)]
#![allow(ambiguous_glob_reexports)]
#![doc(hidden)]

pub use futures::StreamExt;
pub use nostr::prelude::*;
pub use nostr_database::prelude::*;
pub use nostr_gossip::prelude::*;

pub use crate::authenticator::{self, *};
pub use crate::client::{self, *};
pub use crate::error::{self, Error, ErrorKind};
#[cfg(feature = "local-relay")]
pub use crate::local_relay::{self, *};
pub use crate::monitor::{self, *};
pub use crate::policy::*;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::proxy::{self, *};
pub use crate::relay::{self, *};
pub use crate::stream::{self, *};
pub use crate::*;
