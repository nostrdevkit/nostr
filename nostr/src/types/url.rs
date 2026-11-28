// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Urls

use alloc::string::String;
use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::net::Ipv4Addr;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use url::*;

use crate::error::{Error, ErrorKind};

/// Relay URL scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayUrlScheme {
    /// WebSocket (no SSL/TLS)
    Ws,
    /// WebSocket Secure
    Wss,
}

impl RelayUrlScheme {
    /// Parse relay URL scheme
    #[inline]
    pub fn parse(scheme: &str) -> Result<Self, Error> {
        match scheme {
            "ws" => Ok(Self::Ws),
            "wss" => Ok(Self::Wss),
            _ => Err(Error::with_static_message(
                ErrorKind::Unsupported,
                "unsupported URL scheme",
            )),
        }
    }

    /// Check if the scheme is secure (uses SSL/TLS)
    #[inline]
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Wss)
    }

    /// Get as `&str`
    #[inline]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }
}

/// Relay URL
#[derive(Clone)]
pub struct RelayUrl {
    scheme: RelayUrlScheme,
    url: Url,
    has_trailing_slash: bool,
}

impl fmt::Debug for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url: &str = self.as_str();
        f.debug_tuple("RelayUrl").field(&url).finish()
    }
}

impl PartialEq for RelayUrl {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for RelayUrl {}

impl PartialOrd for RelayUrl {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RelayUrl {
    fn cmp(&self, other: &Self) -> Ordering {
        self.url.cmp(&other.url)
    }
}

impl Hash for RelayUrl {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl RelayUrl {
    /// Parse relay URL
    #[inline]
    pub fn parse(url: &str) -> Result<Self, Error> {
        // Check if "://" appears more than once in the URL.
        // Instead of using "count", we use the "next", to avoid iterating over the entire string.
        let mut matches = url.matches("://");
        if let (Some(_), Some(_)) = (matches.next(), matches.next()) {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "multiple scheme separators",
            ));
        }

        // Check if it has a trailing slash
        let has_trailing_slash: bool = url.ends_with('/');

        // Parse URL
        let url: Url = Url::parse(url).map_err(Error::malformed)?;

        // Parse scheme
        let scheme: RelayUrlScheme = RelayUrlScheme::parse(url.scheme())?;

        Ok(Self {
            scheme,
            url,
            has_trailing_slash,
        })
    }

    /// Get scheme
    #[inline]
    pub fn scheme(&self) -> RelayUrlScheme {
        self.scheme
    }

    /// Check if the host is localhost.
    ///
    /// Returns `true` for the `localhost` domain and loopback IP addresses.
    /// Private network addresses, such as `10.0.0.0/8` or `192.168.0.0/16`,
    /// are not considered localhost. Use [`Self::is_local_addr`] to check for
    /// local network addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// # use nostr::types::url::RelayUrl;
    /// let url = RelayUrl::parse("ws://localhost:7777").unwrap();
    /// assert!(url.is_localhost());
    ///
    /// let url = RelayUrl::parse("ws://127.0.0.1:7777").unwrap();
    /// assert!(url.is_localhost());
    ///
    /// let url = RelayUrl::parse("ws://192.168.1.10:7777").unwrap();
    /// assert!(!url.is_localhost());
    /// ```
    #[inline]
    pub fn is_localhost(&self) -> bool {
        match self.url.host() {
            Some(Host::Domain(host)) => host == "localhost",
            Some(Host::Ipv4(host)) => host.is_loopback(),
            Some(Host::Ipv6(host)) => host.is_loopback(),
            None => false,
        }
    }

    /// Check if the host is a local network address.
    ///
    /// Domains:
    /// - localhost
    /// - *.localhost
    ///
    /// IPv4 address ranges:
    /// - `127.0.0.0/8`
    /// - `10.0.0.0/8`
    /// - `172.16.0.0/12`
    /// - `192.168.0.0/16`
    ///
    /// IPv6 address ranges:
    /// - `::1`
    pub fn is_local_addr(&self) -> bool {
        match self.url.host() {
            Some(Host::Domain(host)) => {
                // localhost and *.localhost (RFC 6761) resolve to the local host
                host == "localhost" || host.ends_with(".localhost")
            }
            Some(Host::Ipv4(ipv4)) => is_local_ipv4(ipv4),
            Some(Host::Ipv6(ipv6)) => {
                // ::ffff:x.y.z.w is an IPv4 address in disguise
                if let Some(mapped) = ipv6.to_ipv4_mapped() {
                    is_local_ipv4(mapped)
                } else {
                    ipv6.is_loopback()           // ::1
                        || ipv6.is_unspecified() // ::
                        || (ipv6.segments()[0] & 0xfe00) == 0xfc00  // fc00::/7 ULA
                        || (ipv6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                }
            }
            None => false,
        }
    }

    /// Check if the URL is a hidden onion service address
    #[inline]
    pub fn is_onion(&self) -> bool {
        self.url
            .domain()
            .is_some_and(|host| host.ends_with(".onion"))
    }

    /// If this URL has a host, and it is a domain name (not an IP address), return it.
    /// Non-ASCII domains are punycode-encoded per IDNA if this is the host
    /// of a special URL, or percent encoded for non-special URLs.
    ///
    /// # Examples
    ///
    /// ```
    /// use nostr::types::url::RelayUrl;
    ///
    /// let url = RelayUrl::parse("wss://127.0.0.1:7777").unwrap();
    /// assert_eq!(url.domain(), None);
    ///
    /// let url = RelayUrl::parse("wss://relay.example.com").unwrap();
    /// assert_eq!(url.domain(), Some("relay.example.com"));
    /// ```
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        self.url.domain()
    }

    /// Return the parsed representation of the host for this URL.
    /// Non-ASCII domain labels are punycode-encoded per IDNA if this is the host
    /// of a special URL, or percent encoded for non-special URLs.
    #[inline]
    pub fn host(&self) -> Option<Host<&str>> {
        self.url.host()
    }

    /// Return the serialization of this relay URL without the trailing slash.
    ///
    /// This method will always remove the trailing slash.
    #[inline]
    pub fn as_str_without_trailing_slash(&self) -> &str {
        self.url.as_str().trim_end_matches('/')
    }

    /// Return the serialization of this relay URL.
    ///
    /// The trailing slash will be removed only if the parsed URL hadn't it.
    #[inline]
    pub fn as_str(&self) -> &str {
        if !self.has_trailing_slash {
            return self.as_str_without_trailing_slash();
        }

        self.url.as_str()
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RelayUrl {
    type Err = Error;

    fn from_str(relay_url: &str) -> Result<Self, Self::Err> {
        Self::parse(relay_url)
    }
}

impl Serialize for RelayUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RelayUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let url: String = String::deserialize(deserializer)?;
        Self::parse(&url).map_err(serde::de::Error::custom)
    }
}

impl From<RelayUrl> for Url {
    fn from(relay_url: RelayUrl) -> Self {
        relay_url.url
    }
}

impl<'a> From<&'a RelayUrl> for &'a Url {
    fn from(relay_url: &'a RelayUrl) -> Self {
        &relay_url.url
    }
}

/// Check if the given IPv4 address is a local/non-global address.
///
/// Covered ranges:
/// * `127.0.0.0/8`     (loopback)
/// * `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private)
/// * `169.254.0.0/16`  (link-local / cloud metadata)
/// * `0.0.0.0`         (unspecified)
/// * `255.255.255.255` (broadcast)
/// * `100.64.0.0/10`   (CGNAT / shared address space)
fn is_local_ipv4(ipv4: Ipv4Addr) -> bool {
    let [o1, o2, ..] = ipv4.octets();

    ipv4.is_loopback()
        || ipv4.is_private()
        || ipv4.is_link_local()
        || ipv4.is_unspecified()
        || ipv4.is_broadcast()
        // 100.64.0.0/10
        || (o1 == 100 && o2 & 0b1100_0000 == 0b0100_0000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_url_scheme_parse() {
        // Valid
        assert!(RelayUrlScheme::parse("ws").is_ok());
        assert!(RelayUrlScheme::parse("wss").is_ok());

        // Invalid
        assert_eq!(
            RelayUrlScheme::parse("http").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            RelayUrlScheme::parse("https").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn test_relay_url_valid() {
        assert!(RelayUrl::parse("ws://127.0.0.1:7777").is_ok());
        assert!(RelayUrl::parse("wss://relay.damus.io").is_ok());
        assert!(RelayUrl::parse("ws://example.com").is_ok());
        assert!(RelayUrl::parse("wss://example.com/path/to/resource").is_ok());
    }

    #[test]
    fn test_relay_url_invalid() {
        assert_eq!(
            RelayUrl::parse("https://relay.damus.io")
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            RelayUrl::parse("ftp://relay.damus.io").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(
            RelayUrl::parse("wss://relay.damus.io,ws://127.0.0.1:7777")
                .unwrap_err()
                .kind(),
            ErrorKind::Invalid
        );
        assert_eq!(
            RelayUrl::parse("wss://relay.damus.iowss://127.0.0.1:8888")
                .unwrap_err()
                .kind(),
            ErrorKind::Invalid
        );
        assert_eq!(
            RelayUrl::parse("wss://").unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }

    #[test]
    fn test_relay_url_with_multiple_separators() {
        assert_eq!(
            RelayUrl::parse("wss://test://again").unwrap_err(),
            Error::with_static_message(ErrorKind::Invalid, "multiple scheme separators")
        );

        assert_eq!(
            RelayUrl::parse("wss://test://test://test://").unwrap_err(),
            Error::with_static_message(ErrorKind::Invalid, "multiple scheme separators")
        );
    }

    #[test]
    fn test_relay_url_as_str() {
        let relay_url = RelayUrl::parse("ws://example.com").unwrap();
        assert_eq!(relay_url.as_str(), "ws://example.com");

        let relay_url = RelayUrl::parse("ws://example.com/").unwrap();
        assert_eq!(relay_url.as_str(), "ws://example.com/");

        let relay_url = RelayUrl::parse("ws://example.com/").unwrap();
        assert_eq!(
            relay_url.as_str_without_trailing_slash(),
            "ws://example.com"
        );
    }

    #[test]
    fn test_relay_url_from_str() {
        let relay_url: Result<RelayUrl, _> = "ws://example.com".parse();
        assert!(relay_url.is_ok());
    }

    #[test]
    fn test_serde_relay_url() {
        let relay_url = RelayUrl::parse("ws://example.com").unwrap();
        let serialized = serde_json::to_string(&relay_url).unwrap();
        let deserialized: RelayUrl = serde_json::from_str(&serialized).unwrap();
        assert_eq!(relay_url, deserialized);
    }

    #[test]
    fn test_is_localhost() {
        // Localhost
        let url = RelayUrl::parse("ws://localhost:7777").unwrap();
        assert!(url.is_localhost());
        let url = RelayUrl::parse("ws://LOCALHOST:7777").unwrap();
        assert!(url.is_localhost());
        let url = RelayUrl::parse("ws://127.0.0.1:7777").unwrap();
        assert!(url.is_localhost());
        let url = RelayUrl::parse("ws://127.1.2.3:7777").unwrap();
        assert!(url.is_localhost());
        let url = RelayUrl::parse("ws://[::1]:7777").unwrap();
        assert!(url.is_localhost());

        // Non localhost
        let url = RelayUrl::parse("ws://10.10.10.10:7777").unwrap();
        assert!(!url.is_localhost());
        let url = RelayUrl::parse("ws://192.168.1.10:7777").unwrap();
        assert!(!url.is_localhost());
        let url = RelayUrl::parse("ws://localhost.example:7777").unwrap();
        assert!(!url.is_localhost());
        let url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        assert!(!url.is_localhost());
    }

    #[test]
    fn test_is_local_addr() {
        // Local
        let url = RelayUrl::parse("ws://127.0.0.1:7777").unwrap();
        assert!(url.is_local_addr());
        let url = RelayUrl::parse("ws://10.10.10.10:7777").unwrap();
        assert!(url.is_local_addr());
        let url = RelayUrl::parse("ws://172.16.10.11:7777").unwrap();
        assert!(url.is_local_addr());
        let url = RelayUrl::parse("ws://192.168.1.10:7777").unwrap();
        assert!(url.is_local_addr());
        let url = RelayUrl::parse("ws://[::1]:7777").unwrap();
        assert!(url.is_local_addr());

        // Non local
        let onion_url =
            RelayUrl::parse("ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion")
                .unwrap();
        assert!(!onion_url.is_local_addr());
        let url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        assert!(!url.is_local_addr());
    }

    #[test]
    fn test_is_onion() {
        // Onion
        let onion_url =
            RelayUrl::parse("ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion")
                .unwrap();
        assert!(onion_url.is_onion());

        // Non onion
        let non_onion_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        assert!(!non_onion_url.is_onion());
        let non_onion_url = RelayUrl::parse("ws://example.com:81").unwrap();
        assert!(!non_onion_url.is_onion());
        let non_onion_url = RelayUrl::parse("ws://127.0.0.1:7777").unwrap();
        assert!(!non_onion_url.is_onion());
    }

    #[test]
    fn test_domain() {
        let url = RelayUrl::parse("wss://example.com").unwrap();
        assert_eq!(url.domain(), Some("example.com"));

        let url = RelayUrl::parse("wss://relay.example.com/").unwrap();
        assert_eq!(url.domain(), Some("relay.example.com"));

        let url = RelayUrl::parse("wss://example.com/path/to/resource").unwrap();
        assert_eq!(url.domain(), Some("example.com"));

        let url = RelayUrl::parse("wss://127.0.0.1:7777").unwrap();
        assert_eq!(url.domain(), None);
    }
}

#[cfg(bench)]
mod benches {
    use super::*;
    use crate::test::{Bencher, black_box};

    const LOCAL_URL: &str = "ws://127.0.0.1:7777";
    const CLEARNET_URL: &str = "wss://relay.damus.io";
    const ONION_URL: &str = "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion";

    #[bench]
    pub fn parse_local_relay_url(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(RelayUrl::parse(LOCAL_URL)).unwrap();
        });
    }

    #[bench]
    pub fn parse_clearnet_relay_url(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(RelayUrl::parse(CLEARNET_URL)).unwrap();
        });
    }

    #[bench]
    pub fn parse_onion_relay_url(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(RelayUrl::parse(ONION_URL)).unwrap();
        });
    }
}
