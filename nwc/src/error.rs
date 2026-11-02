// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Nostr Wallet Connect error

opaquerr::define_kind! {
    /// Nostr Wallet Connect error kind.
    pub ErrorKind {
        /// Nostr protocol error.
        Protocol => "nostr protocol error",
        /// SDK error
        Sdk => "SDK error",
        /// Wallet response was not received.
        NoResponse => "response not received",
        /// Wallet response was not correlated with the sent request.
        UnrelatedResponse => "unrelated wallet response",
        /// Anything not covered by the stable categories above.
        Other => "other error",
    }
}

opaquerr::define_error! {
    /// Nostr Wallet Connect error.
    pub Error(ErrorKind)

    from {
        nostr::error::Error => ErrorKind::Protocol,
        nostr_sdk::error::Error => ErrorKind::Sdk,
    }
}

impl Error {
    #[inline]
    pub(super) fn no_response() -> Self {
        Self::simple(ErrorKind::NoResponse)
    }

    #[inline]
    pub(super) fn unrelated_response() -> Self {
        Self::simple(ErrorKind::UnrelatedResponse)
    }
}
