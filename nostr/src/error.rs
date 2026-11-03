//! Nostr error.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::{error, fmt};

opaquerr::define_kind! {
    /// Nostr error kind.
    pub ErrorKind {
        /// Input is not well-formed and cannot be parsed.
        Malformed => "input is malformed",
        /// Input is well-formed, but violates a protocol/library invariant.
        Invalid => "input violates a protocol/library invariant",
        /// Required data is missing.
        Missing => "required data is missing",
        /// The value/operation is known but not supported.
        Unsupported => "the value/operation is known but not supported",
        /// Cryptographic operation failed.
        Crypto => "cryptographic operation failed.",
        /// Anything not covered by the stable categories above.
        Other => "other error",
    }
}

opaquerr::define_error! {
    /// Nostr error.
    pub Error(ErrorKind)

    from {
        serde_json::Error => ErrorKind::Malformed,
    }
}

#[derive(Debug)]
struct DisplayError(String);

impl fmt::Display for DisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl error::Error for DisplayError {}

impl Error {
    #[inline]
    pub(crate) fn invalid<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Invalid, error.into())
    }

    #[inline]
    pub(crate) fn invalid_display<E>(error: E) -> Self
    where
        E: fmt::Display,
    {
        Self::invalid(DisplayError(error.to_string()))
    }

    #[inline]
    pub(crate) fn malformed<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Malformed, error.into())
    }

    #[inline]
    pub(crate) fn malformed_display<E>(error: E) -> Self
    where
        E: fmt::Display,
    {
        Self::malformed(DisplayError(error.to_string()))
    }

    #[inline]
    #[cfg(any(feature = "nip46", feature = "nip49", feature = "nip59"))]
    pub(crate) fn crypto<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Crypto, error.into())
    }

    #[inline]
    #[cfg(feature = "nip49")]
    pub(crate) fn crypto_display<E>(error: E) -> Self
    where
        E: fmt::Display,
    {
        Self::crypto(DisplayError(error.to_string()))
    }

    /// Creates a new Nostr error from a known kind of error as well as an arbitrary error payload.
    ///
    /// It is a shortcut for [`Error::new`] with [`ErrorKind::Other`].
    #[inline]
    pub fn other<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Other, error.into())
    }
}
