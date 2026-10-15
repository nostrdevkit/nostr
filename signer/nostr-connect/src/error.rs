// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Nostr Connect error

use nostr::key::PublicKey;
use tokio::sync::SetError;

opaquerr::define_kind! {
    /// Nostr Connect error kind.
    pub ErrorKind {
        /// Nostr protocol error.
        Protocol => "nostr protocol error",
        /// SDK error.
        Sdk => "SDK error",
        /// Input is well-formed, but violates a signer invariant.
        Invalid => "input violates a signer invariant",
        /// The operation was rejected by the remote signer.
        Rejected => "operation rejected",
        /// The operation timed out.
        Timeout => "timeout",
        /// Required data was not found.
        NotFound => "not found",
        /// The operation cannot be completed in the current state.
        State => "invalid state",
        /// Anything not covered by the stable categories above.
        Other => "other error",
    }
}

opaquerr::define_error! {
    /// Nostr Connect error.
    pub Error(ErrorKind)

    from {
        nostr::error::Error => ErrorKind::Protocol,
        nostr_sdk::error::Error => ErrorKind::Sdk,
        SetError<PublicKey> => ErrorKind::State,
    }
}

impl Error {
    /// Creates a new Nostr error from a known kind of error as well as an arbitrary error payload.
    ///
    /// It is a shortcut for [`Error::new`] with [`ErrorKind::Other`].
    #[inline]
    pub fn other<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Other, error)
    }

    pub(crate) fn invalid_response<S>(response: S) -> Self
    where
        S: Into<String>,
    {
        Self::new(ErrorKind::Invalid, response.into())
    }

    pub(crate) fn response<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::new(ErrorKind::Rejected, message.into())
    }

    pub(crate) fn signer_public_key_not_found() -> Self {
        Self::with_static_message(ErrorKind::NotFound, "signer public key not found")
    }

    pub(crate) fn timeout() -> Self {
        Self::simple(ErrorKind::Timeout)
    }

    pub(crate) fn public_key_not_match_app_keys() -> Self {
        Self::with_static_message(ErrorKind::Invalid, "public key not match app keys")
    }
}
