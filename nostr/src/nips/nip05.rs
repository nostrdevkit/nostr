// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP05: Mapping Nostr keys to DNS-based internet identifiers
//!
//! <https://github.com/nostr-protocol/nips/blob/master/05.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::Split;

use serde_json::Value;

use crate::error::{Error, ErrorKind};
use crate::key::PublicKey;
use crate::types::RelayUrl;
use crate::types::url::Url;
use crate::util::parse_json;

/// NIP-05 address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nip05Address {
    name: String,
    domain: String,
    url: Url,
}

impl fmt::Display for Nip05Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.domain)
    }
}

/// Check if a NIP-05 local-part is valid
///
/// The allowed characters are the ones allowed by the NIP-05 specification:
/// letters, digits, `-` and `_` (the `_` local-part is the root identifier).
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Check if a NIP-05 domain is a valid hostname
///
/// Only DNS hostnames are accepted: dot-separated labels of alphanumeric
/// characters and `-`. IP addresses, ports, paths, query strings, fragments
/// and percent-encoded characters are rejected, ensuring that the composed
/// URL is always `https://<domain>/.well-known/nostr.json?name=<name>`.
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return false;
    }

    domain.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

impl Nip05Address {
    /// Parse a NIP-05 address (i.e., `yuki@yukikishimoto.com`).
    pub fn parse(address: &str) -> Result<Self, Error> {
        // Split the address into parts
        let mut split: Split<char> = address.split('@');

        // Get first and second parts
        // The third is checked to make sure there aren't others "@"
        let (name, domain): (&str, &str) = match (split.next(), split.next(), split.next()) {
            // First and second parts found
            (Some(name), Some(domain), None) => (name, domain),
            // Found only a part, meaning that `@` is missing
            (Some(address), None, None) => ("_", address),
            // Invalid format
            _ => {
                return Err(Error::with_static_message(
                    ErrorKind::Malformed,
                    "invalid format",
                ));
            }
        };

        if !is_valid_name(name) || !is_valid_domain(domain) {
            return Err(Error::with_static_message(
                ErrorKind::Malformed,
                "invalid name or domain",
            ));
        }

        // Compose and parse the URL
        //
        // Both `name` and `domain` are validated, so the resulting URL is
        // always `https://<domain>/.well-known/nostr.json?name=<name>`.
        let url: String = format!("https://{domain}");
        let mut url: Url = Url::parse(&url).map_err(Error::malformed)?;

        // The host must be a DNS domain (not an IP
        // address) and the URL must have no port, fragment, username or
        // password.
        if url.domain().is_none()
            || url.port().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "invalid NIP-05 address",
            ));
        }

        url.set_path(".well-known/nostr.json");
        url.query_pairs_mut().append_pair("name", name);

        Ok(Self {
            name: name.to_string(),
            domain: domain.to_string(),
            url,
        })
    }

    /// Get the name value
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the domain value
    #[inline]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Get url for NIP05 address
    ///
    /// This can be used to make a `GET` HTTP request and get the NIP-05 JSON.
    #[inline]
    pub fn url(&self) -> &Url {
        &self.url
    }
}

/// NIP-05 profile
///
/// <https://github.com/nostr-protocol/nips/blob/master/05.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nip05Profile {
    /// Public key
    pub public_key: PublicKey,
    /// Relays
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/05.md>
    pub relays: Vec<RelayUrl>,
    /// NIP46 relays
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/46.md>
    pub nip46: Vec<RelayUrl>,
}

impl Nip05Profile {
    /// Extract a NIP-05 profile from JSON
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/05.md>
    pub fn from_json(address: &Nip05Address, json: &Value) -> Result<Self, Error> {
        let public_key: PublicKey = get_key_from_json(json, address).ok_or_else(|| {
            Error::with_static_message(ErrorKind::Invalid, "impossible to verify")
        })?;
        let relays: Vec<RelayUrl> = get_relays_from_json(json, &public_key);
        let nip46: Vec<RelayUrl> = get_nip46_relays_from_json(json, &public_key);

        Ok(Self {
            public_key,
            relays,
            nip46,
        })
    }

    /// Extract a NIP-05 profile from raw JSON
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/05.md>
    #[inline]
    pub fn from_raw_json(address: &Nip05Address, raw_json: &str) -> Result<Self, Error> {
        let json: Value = parse_json(&raw_json)?;
        Self::from_json(address, &json)
    }
}

#[inline]
fn get_key_from_json(json: &Value, address: &Nip05Address) -> Option<PublicKey> {
    json.get("names")
        .and_then(|names| names.get(&address.name))
        .and_then(|value| value.as_str())
        .and_then(|pubkey| PublicKey::from_hex(pubkey).ok())
}

#[inline]
fn get_relays_from_json(json: &Value, pk: &PublicKey) -> Vec<RelayUrl> {
    json.get("relays")
        .and_then(|relays| relays.get(pk.to_hex()))
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

#[inline]
fn get_nip46_relays_from_json(json: &Value, pk: &PublicKey) -> Vec<RelayUrl> {
    json.get("nip46")
        .and_then(|relays| relays.get(pk.to_hex()))
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

/// Verify a NIP-05 from JSON
///
/// <https://github.com/nostr-protocol/nips/blob/master/05.md>
pub fn verify_from_json(public_key: &PublicKey, address: &Nip05Address, json: &Value) -> bool {
    if let Some(pubkey) = get_key_from_json(json, address) {
        if &pubkey == public_key {
            return true;
        }
    }

    false
}

/// Verify a NIP-05 from raw JSON
#[inline]
pub fn verify_from_raw_json(
    public_key: &PublicKey,
    address: &Nip05Address,
    raw_json: &str,
) -> Result<bool, Error> {
    let json: Value = parse_json(&raw_json)?;
    Ok(verify_from_json(public_key, address, &json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_nip05() {
        // nostr.json
        let json: &str = r#"{
            "names": {
              "yuki": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
              "_": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272"
            }
          }"#;
        let json: Value = serde_json::from_str(json).unwrap();

        let address = Nip05Address::parse("_@yukikishimoto.com").unwrap();
        assert_eq!(
            address.url().to_string(),
            "https://yukikishimoto.com/.well-known/nostr.json?name=_"
        );
        assert_eq!(address.name(), "_");

        let public_key =
            PublicKey::from_hex("68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272")
                .unwrap();
        assert!(verify_from_json(&public_key, &address, &json));

        let public_key =
            PublicKey::from_hex("b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a")
                .unwrap();
        assert!(!verify_from_json(&public_key, &address, &json));
    }

    #[test]
    fn test_verify_nip05_without_local() {
        // nostr.json
        let json: &str = r#"{
            "names": {
              "yuki": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
              "_": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272"
            }
          }"#;
        let json: Value = serde_json::from_str(json).unwrap();

        let address = Nip05Address::parse("yukikishimoto.com").unwrap();
        assert_eq!(
            address.url().to_string(),
            "https://yukikishimoto.com/.well-known/nostr.json?name=_"
        );
        assert_eq!(address.name(), "_");

        let public_key =
            PublicKey::from_hex("68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272")
                .unwrap();
        assert!(verify_from_json(&public_key, &address, &json));

        let public_key =
            PublicKey::from_hex("b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a")
                .unwrap();
        assert!(!verify_from_json(&public_key, &address, &json));
    }

    #[test]
    fn test_nip05_profile_from_json() {
        // nostr.json
        let json = r#"{
  "names": {
    "nostr-tool-test-user": "94a9eb13c37b3c1519169a426d383c51530f4fe8f693c62f32b321adfdd4ec7f",
    "robosatsob": "3b57518d02e6acfd5eb7198530b2e351e5a52278fb2499d14b66db2b5791c512",
    "0xtr": "b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a",
    "_": "b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a"
  },
  "relays": {
    "b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a": [ "wss://nostr.oxtr.dev", "wss://relay.damus.io", "wss://relay.nostr.band" ]
  }
}"#;
        let json: Value = serde_json::from_str(json).unwrap();

        let pubkey =
            PublicKey::from_hex("b2d670de53b27691c0c3400225b65c35a26d06093bcc41f48ffc71e0907f9d4a")
                .unwrap();
        let address = Nip05Address::parse("0xtr@oxtr.dev").unwrap();

        let profile = Nip05Profile::from_json(&address, &json).unwrap();

        assert_eq!(profile.public_key, pubkey);
        assert_eq!(
            profile.relays,
            vec![
                RelayUrl::parse("wss://nostr.oxtr.dev").unwrap(),
                RelayUrl::parse("wss://relay.damus.io").unwrap(),
                RelayUrl::parse("wss://relay.nostr.band").unwrap()
            ]
        );
        assert!(profile.nip46.is_empty());
    }

    #[test]
    fn test_nip05_address_parse() {
        assert!(Nip05Address::parse("alice@example.com").is_ok());
        assert!(Nip05Address::parse("yuki@sub.example.com").is_ok());
        assert!(Nip05Address::parse("alice-1_x@example.com").is_ok());

        // Invalid names
        assert!(Nip05Address::parse("@example.com").is_err());
        assert!(Nip05Address::parse("bad name@example.com").is_err());
        assert!(Nip05Address::parse("bad/slash@example.com").is_err());
        assert!(Nip05Address::parse("bad@name@example.com").is_err());
        assert!(Nip05Address::parse("üñí@example.com").is_err());

        // Invalid domains
        assert!(Nip05Address::parse("yuki@").is_err());
        assert!(Nip05Address::parse("yuki@example.com:8443").is_err());
        assert!(Nip05Address::parse("yuki@127.0.0.1").is_err());
        assert!(Nip05Address::parse("yuki@example.com/path").is_err());
        assert!(Nip05Address::parse("yuki@example.com?name=x").is_err());
        assert!(Nip05Address::parse("yuki@example.com#fragment").is_err());
        assert!(Nip05Address::parse("yuki@ex%ample.com").is_err());
        assert!(Nip05Address::parse("yuki@-example.com").is_err());

        // Redirect the verifier to an attacker-controlled path on the domain
        assert!(Nip05Address::parse("alice@trusted.example/uploads/attacker.json#").is_err());

        // Point the verifier to an internal endpoint on an arbitrary port
        assert!(Nip05Address::parse("alice@127.0.0.1:8443/internal/api?action=1#").is_err());

        // Silently drop an extra `@` segment to bypass domain validation
        assert!(Nip05Address::parse("alice@victim.example@evil.example").is_err());
    }

    #[test]
    fn test_url_is_always_the_standard_one() {
        // Whatever the input, the URL must always be the NIP-05 standard one
        let address = Nip05Address::parse("alice@example.com").unwrap();
        assert_eq!(
            address.url().to_string(),
            "https://example.com/.well-known/nostr.json?name=alice"
        );
        assert_eq!(address.domain(), "example.com");
        assert_eq!(address.to_string(), "alice@example.com");
    }
}
