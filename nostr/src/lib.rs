// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Rust implementation of the Nostr protocol.

#![cfg_attr(test, allow(missing_docs))]
#![cfg_attr(not(test), warn(missing_docs))]
#![warn(rustdoc::bare_urls)]
#![allow(clippy::arc_with_non_send_sync)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(bench, feature(test))]
#![cfg_attr(all(feature = "std", feature = "os-rng", feature = "all-nips"), doc = include_str!("../README.md"))]

#[cfg(not(any(feature = "std", feature = "alloc")))]
compile_error!("at least one of the `std` or `alloc` features must be enabled");

// See event tag and tags modules ("usize as u32" castings).
#[cfg(target_pointer_width = "16")]
compile_error!("16-bit pointer sizes are not supported.");

#[cfg(bench)]
extern crate test;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate serde;

pub mod error;
pub mod event;
pub mod filter;
pub mod key;
pub mod message;
pub mod nips;
pub mod parser;
pub mod prelude;
#[cfg(all(test, feature = "std"))]
mod test_utils;
pub mod types;
mod util;
