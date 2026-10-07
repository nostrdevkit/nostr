#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]
#![warn(clippy::large_futures)]
#![allow(clippy::arc_with_non_send_sync)]
#![doc = include_str!("../README.md")]

pub mod authenticator;
pub mod client;
pub mod error;
mod events_tracker;
mod future;
#[cfg(any(feature = "local-relay", test))]
pub mod local_relay;
pub mod monitor;
mod mutex;
pub mod policy;
mod pool;
pub mod prelude;
#[cfg(not(target_arch = "wasm32"))]
pub mod proxy;
pub mod relay;
mod shared;
pub mod stream;
#[cfg(test)]
mod test_utils;
pub mod transport;
