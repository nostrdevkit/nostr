#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]
#![warn(clippy::large_futures)]
#![doc = include_str!("../README.md")]

pub mod builder;
pub mod client;
pub mod error;
pub mod prelude;
