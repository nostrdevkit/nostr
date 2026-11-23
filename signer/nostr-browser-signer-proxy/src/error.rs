// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Error

use hyper::http;
use tokio::sync::oneshot::error::RecvError;

opaquerr::define_kind! {
    /// Nostr browser signer proxy error kind.
    pub ErrorKind {
        /// Nostr protocol error.
        Protocol => "nostr protocol error",
        /// I/O error.
        IO => "I/O error",
        /// HTTP error.
        Http => "HTTP error",
        /// JSON error.
        Json => "JSON error",
        /// The operation timed out.
        Timeout => "timeout",
        /// The operation cannot be completed in the current state.
        State => "invalid state",
        /// Anything not covered by the stable categories above.
        Other => "other error",
    }
}

opaquerr::define_error! {
    /// Nostr browser signer proxy error.
    pub Error(ErrorKind)

    from {
        nostr::error::Error => ErrorKind::Protocol,
        std::io::Error => ErrorKind::IO,
        http::Error => ErrorKind::Http,
        serde_json::Error => ErrorKind::Json,
        RecvError => ErrorKind::Other,
    }
}

impl Error {
    pub(crate) fn generic<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::new(ErrorKind::Other, message.into())
    }

    pub(crate) fn timeout() -> Self {
        Self::simple(ErrorKind::Timeout)
    }

    pub(crate) fn shutdown() -> Self {
        Self::with_static_message(ErrorKind::State, "server is shutdown")
    }

    pub(crate) fn mismatch() -> Self {
        Self::with_static_message(
            ErrorKind::Other,
            "The received response doesn't match the request",
        )
    }
}
