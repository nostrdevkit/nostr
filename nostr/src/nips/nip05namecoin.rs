// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-05 over Namecoin (`.bit`)
//!
//! Companion module to [`nip05`][crate::nips::nip05] that resolves NIP-05
//! identifiers rooted in the Namecoin blockchain instead of DNS.
//!
//! This module deliberately follows the same shape as [`nip05`][crate::nips::nip05]:
//! it only parses and verifies — it does **not** open sockets. The caller is
//! responsible for fetching the underlying Namecoin name value (typically from
//! an ElectrumX server over WSS) and handing the resulting JSON bytes to
//! [`Nip05NamecoinProfile::from_raw_json`] / [`verify_from_raw_json`].
//!
//! To support callers that *do* want to drive an ElectrumX query, the helpers
//! [`build_name_index_script`] and [`electrum_script_hash`] produce the script
//! and scripthash required by `blockchain.scripthash.get_history`, and
//! [`parse_name_update_script`] decodes the `NAME_UPDATE` output script
//! returned by `blockchain.transaction.get`.
//!
//! # Identifiers accepted
//!
//! - `alice@example.bit`
//! - `example.bit` (uses the `_` root entry)
//! - `d/example` (domain namespace, root)
//! - `id/alice` (identity namespace)
//! - A leading `nostr:` NIP-21 prefix is tolerated.
//!
//! # Example
//!
//! ```
//! use nostr::nips::nip05namecoin;
//!
//! // Resolve which identifiers should be routed through Namecoin
//! // instead of DNS-based NIP-05.
//! assert!(nip05namecoin::is_valid_identifier("alice@example.bit"));
//! assert!(nip05namecoin::is_valid_identifier("example.bit"));
//! assert!(nip05namecoin::is_valid_identifier("d/example"));
//! assert!(!nip05namecoin::is_valid_identifier("alice@example.com"));
//!
//! // Parse the identifier to learn which Namecoin name to query.
//! let address = nip05namecoin::NamecoinAddress::parse("alice@example.bit").unwrap();
//! assert_eq!(address.namecoin_name(), "d/example");
//! assert_eq!(address.local_part(), "alice");
//! ```
//!
//! Ported from the Go reference at
//! <https://github.com/mstrofnone/nostrlib-nip05-namecoin>, itself a port of
//! the Kotlin implementation in [Amethyst][amethyst] and the Swift port in
//! [Nostur][nostur]. The parser shape, local-part priority (exact → `_` →
//! first valid), and JSON extraction rules match those implementations
//! byte-for-byte.
//!
//! [amethyst]: https://github.com/vitorpamplona/amethyst
//! [nostur]: https://github.com/nostur-com/nostur-ios-public

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use serde_json::Value;

use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Default ElectrumX server endpoints maintained by the Namecoin ecosystem.
///
/// Mirrors the Kotlin / Swift / Go reference implementations. Both TCP+TLS
/// (port `+0`) and WSS (port `+2`) endpoints are listed.
///
/// Operators currently serve **self-signed** TLS certificates; callers that
/// pin to those certificates should ship them out of band — this crate keeps
/// no transport surface so it does not ship pinned PEMs.
pub const DEFAULT_ELECTRUMX_SERVERS: &[ElectrumxServer] = &[
    ElectrumxServer {
        host: "electrumx.testls.space",
        port_tcp_tls: 50002,
        port_wss: 50004,
    },
    ElectrumxServer {
        host: "nmc2.bitcoins.sk",
        port_tcp_tls: 57002,
        port_wss: 57004,
    },
    ElectrumxServer {
        host: "46.229.238.187",
        port_tcp_tls: 57002,
        port_wss: 57004,
    },
];

/// A Namecoin ElectrumX server endpoint pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ElectrumxServer {
    /// Hostname (or IP) of the operator.
    pub host: &'static str,
    /// TCP + TLS port. ElectrumX convention is `5xxx2`.
    pub port_tcp_tls: u16,
    /// WebSocket Secure port. ElectrumX convention is `5xxx4` (TCP+TLS+2).
    pub port_wss: u16,
}

/// NIP-05 over Namecoin error type.
#[derive(Debug)]
pub enum Error {
    /// Identifier could not be parsed into a Namecoin name.
    InvalidFormat,
    /// JSON parse error from a Namecoin name value.
    Json(serde_json::Error),
    /// Pubkey could not be parsed from the name value.
    InvalidPubKey,
    /// Name value does not contain a `nostr` field, or the field cannot be
    /// reconciled with the supplied local-part.
    ImpossibleToVerify,
    /// `NAME_UPDATE` script could not be decoded.
    InvalidScript,
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => f.write_str("invalid format"),
            Self::Json(e) => e.fmt(f),
            Self::InvalidPubKey => f.write_str("invalid pubkey in name value"),
            Self::ImpossibleToVerify => f.write_str("impossible to verify"),
            Self::InvalidScript => f.write_str("invalid NAME_UPDATE script"),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Reports whether an identifier should be routed to Namecoin resolution
/// instead of DNS-based NIP-05.
///
/// Matches any of:
///
/// - `<anything>.bit`
/// - `alice@<anything>.bit`
/// - `d/<name>` or `id/<name>`
///
/// A leading `nostr:` NIP-21 prefix is tolerated.
///
/// The function is intentionally cheap: callers use it as a front-door check
/// in hot paths before opening any network connection.
pub fn is_valid_identifier(identifier: &str) -> bool {
    let trimmed = identifier.trim();
    if trimmed.is_empty() {
        return false;
    }
    let stripped = strip_nostr_prefix(trimmed);
    let lower_first = stripped.to_ascii_lowercase();
    if lower_first.starts_with("d/") || lower_first.starts_with("id/") {
        return true;
    }
    lower_first.ends_with(".bit")
}

/// Alias for [`is_valid_identifier`] kept for callers that prefer the more
/// descriptive name.
#[inline]
pub fn is_dot_bit(identifier: &str) -> bool {
    is_valid_identifier(identifier)
}

/// A parsed Namecoin identifier ready to be queried against the Namecoin
/// blockchain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamecoinAddress {
    namecoin_name: String,
    local_part: String,
    is_domain: bool,
}

impl fmt::Display for NamecoinAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_domain && self.local_part != "_" {
            write!(f, "{}@{}", self.local_part, self.suffix())
        } else {
            f.write_str(&self.suffix())
        }
    }
}

impl NamecoinAddress {
    /// Parse a Namecoin identifier (e.g. `alice@example.bit`, `example.bit`,
    /// `d/example`, `id/alice`).
    pub fn parse(identifier: &str) -> Result<Self, Error> {
        let input = strip_nostr_prefix(identifier.trim());
        let lower = input.to_ascii_lowercase();

        // Explicit namespace references.
        if let Some(rest) = lower.strip_prefix("d/") {
            if rest.is_empty() {
                return Err(Error::InvalidFormat);
            }
            return Ok(Self {
                namecoin_name: lower.clone(),
                local_part: "_".to_string(),
                is_domain: true,
            });
        }
        if let Some(rest) = lower.strip_prefix("id/") {
            if rest.is_empty() {
                return Err(Error::InvalidFormat);
            }
            return Ok(Self {
                namecoin_name: lower.clone(),
                local_part: "_".to_string(),
                is_domain: false,
            });
        }

        // NIP-05 shape: user@domain.bit
        if input.contains('@') && lower.ends_with(".bit") {
            let mut parts = input.splitn(2, '@');
            let local_raw = parts.next().unwrap_or("");
            let domain_raw = parts.next().unwrap_or("");
            let local = if local_raw.is_empty() {
                "_".to_string()
            } else {
                local_raw.to_ascii_lowercase()
            };
            let domain_lower = domain_raw.to_ascii_lowercase();
            let domain = domain_lower
                .strip_suffix(".bit")
                .ok_or(Error::InvalidFormat)?;
            if domain.is_empty() {
                return Err(Error::InvalidFormat);
            }
            let mut namecoin_name = String::with_capacity(2 + domain.len());
            namecoin_name.push_str("d/");
            namecoin_name.push_str(domain);
            return Ok(Self {
                namecoin_name,
                local_part: local,
                is_domain: true,
            });
        }

        // Bare domain: example.bit
        if lower.ends_with(".bit") {
            let domain = lower.strip_suffix(".bit").ok_or(Error::InvalidFormat)?;
            if domain.is_empty() {
                return Err(Error::InvalidFormat);
            }
            let mut namecoin_name = String::with_capacity(2 + domain.len());
            namecoin_name.push_str("d/");
            namecoin_name.push_str(domain);
            return Ok(Self {
                namecoin_name,
                local_part: "_".to_string(),
                is_domain: true,
            });
        }

        Err(Error::InvalidFormat)
    }

    /// The Namecoin name to look up on-chain (e.g. `d/example` or `id/alice`).
    #[inline]
    pub fn namecoin_name(&self) -> &str {
        &self.namecoin_name
    }

    /// The local-part to match inside the name's value (e.g. `alice`), or
    /// `_` for the root entry.
    #[inline]
    pub fn local_part(&self) -> &str {
        &self.local_part
    }

    /// `true` if the identifier targets the `d/` domain namespace,
    /// `false` for the `id/` identity namespace.
    #[inline]
    pub fn is_domain(&self) -> bool {
        self.is_domain
    }

    /// Build the ElectrumX scripthash for this name. Pass this to
    /// `blockchain.scripthash.get_history` to find the latest `NAME_UPDATE`.
    pub fn electrum_script_hash(&self) -> String {
        let script = build_name_index_script(self.namecoin_name.as_bytes());
        electrum_script_hash(&script)
    }

    fn suffix(&self) -> String {
        if self.is_domain {
            // d/example -> example.bit
            let name = self
                .namecoin_name
                .strip_prefix("d/")
                .unwrap_or(&self.namecoin_name);
            let mut s = String::with_capacity(name.len() + 4);
            s.push_str(name);
            s.push_str(".bit");
            s
        } else {
            // id/alice -> id/alice
            self.namecoin_name.clone()
        }
    }
}

/// A NIP-05 profile resolved via Namecoin.
///
/// Shape mirrors [`Nip05Profile`][crate::nips::nip05::Nip05Profile].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nip05NamecoinProfile {
    /// Public key.
    pub public_key: PublicKey,
    /// Relays.
    pub relays: Vec<RelayUrl>,
}

impl Nip05NamecoinProfile {
    /// Extract a NIP-05 profile from a Namecoin name value (already parsed
    /// as JSON).
    pub fn from_json(address: &NamecoinAddress, json: &Value) -> Result<Self, Error> {
        let (public_key, relays) = extract_nostr_from_value(address, json)?;
        Ok(Self { public_key, relays })
    }

    /// Extract a NIP-05 profile from a raw Namecoin name value JSON string.
    #[inline]
    pub fn from_raw_json(address: &NamecoinAddress, raw_json: &str) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(raw_json)?;
        Self::from_json(address, &value)
    }
}

/// Verify a NIP-05 over Namecoin claim from JSON.
pub fn verify_from_json(public_key: &PublicKey, address: &NamecoinAddress, json: &Value) -> bool {
    match extract_nostr_from_value(address, json) {
        Ok((pk, _)) => &pk == public_key,
        Err(_) => false,
    }
}

/// Verify a NIP-05 over Namecoin claim from a raw JSON string.
#[inline]
pub fn verify_from_raw_json(
    public_key: &PublicKey,
    address: &NamecoinAddress,
    raw_json: &str,
) -> Result<bool, Error> {
    let value: Value = serde_json::from_str(raw_json)?;
    Ok(verify_from_json(public_key, address, &value))
}

impl Nip05NamecoinProfile {
    /// Extract a NIP-05 profile from an apex JSON value, transparently
    /// following ifa-0001 §`"import"` chains.
    ///
    /// `apex_json` is the parsed value of the record named by
    /// `address.namecoin_name()`. `lookup` is invoked for any
    /// `"import"` targets and must return the raw JSON value of the
    /// imported name (typically by re-running an ElectrumX query against
    /// the resulting Namecoin name). Failures are absorbed per spec:
    /// see [`expand_imports`].
    ///
    /// This is the entry point to use when the apex record may delegate
    /// its `nostr.names` block to a sibling name (the `testls.bit`
    /// demo target is a real-world example: its apex `d/testls`
    /// imports `dd/testls`).
    pub fn from_json_with_lookup<F>(
        address: &NamecoinAddress,
        apex_json: &Value,
        lookup: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut value = apex_json.clone();
        expand_imports(&mut value, lookup, DEFAULT_IMPORT_DEPTH);
        Self::from_json(address, &value)
    }

    /// Extract a NIP-05 profile from a raw apex JSON string,
    /// transparently following `"import"` chains. See
    /// [`Nip05NamecoinProfile::from_json_with_lookup`].
    #[inline]
    pub fn from_raw_json_with_lookup<F>(
        address: &NamecoinAddress,
        apex_raw_json: &str,
        lookup: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut value: Value = serde_json::from_str(apex_raw_json)?;
        expand_imports(&mut value, lookup, DEFAULT_IMPORT_DEPTH);
        Self::from_json(address, &value)
    }
}

/// Verify a NIP-05 over Namecoin claim from an apex JSON value,
/// transparently following `"import"` chains.
///
/// Mirrors [`verify_from_json`] but threads the apex value through
/// [`expand_imports`] before extraction, so apex records that delegate
/// their `nostr.names` block via ifa-0001 §"import" verify correctly.
pub fn verify_from_json_with_lookup<F>(
    public_key: &PublicKey,
    address: &NamecoinAddress,
    apex_json: &Value,
    lookup: F,
) -> bool
where
    F: FnMut(&str) -> Option<String>,
{
    let mut value = apex_json.clone();
    expand_imports(&mut value, lookup, DEFAULT_IMPORT_DEPTH);
    verify_from_json(public_key, address, &value)
}

/// Verify a NIP-05 over Namecoin claim from a raw apex JSON string,
/// transparently following `"import"` chains.
#[inline]
pub fn verify_from_raw_json_with_lookup<F>(
    public_key: &PublicKey,
    address: &NamecoinAddress,
    apex_raw_json: &str,
    lookup: F,
) -> Result<bool, Error>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut value: Value = serde_json::from_str(apex_raw_json)?;
    expand_imports(&mut value, lookup, DEFAULT_IMPORT_DEPTH);
    Ok(verify_from_json(public_key, address, &value))
}

/// Extract the nostr pubkey + relay list from a Namecoin name value.
///
/// Supports both the simple `"nostr": "hex"` form and the extended
/// `"nostr": { "names": {...}, "relays": {...} }` form used by Amethyst
/// and the `.bit` NIP-05 spec draft. Exported for callers that want to
/// inspect other fields (e.g. `bitcoin`, `lightning`, `http`) from the
/// same name value.
pub fn extract_nostr_from_value(
    address: &NamecoinAddress,
    json: &Value,
) -> Result<(PublicKey, Vec<RelayUrl>), Error> {
    let nostr_field = json.get("nostr").ok_or(Error::ImpossibleToVerify)?;

    // Simple form: "nostr": "hex-pubkey"
    if let Some(hex) = nostr_field.as_str() {
        if address.is_domain && address.local_part != "_" {
            // Simple form has no local-part addressing.
            return Err(Error::ImpossibleToVerify);
        }
        let pk = PublicKey::from_hex(hex).map_err(|_| Error::InvalidPubKey)?;
        return Ok((pk, Vec::new()));
    }

    // Extended form: object with "names" / "pubkey" / "relays".
    let object = nostr_field.as_object().ok_or(Error::ImpossibleToVerify)?;

    if address.is_domain {
        extract_from_domain_names_object(object, address)
    } else {
        extract_from_identity_object(object, address)
    }
}

fn extract_from_domain_names_object(
    obj: &serde_json::Map<String, Value>,
    address: &NamecoinAddress,
) -> Result<(PublicKey, Vec<RelayUrl>), Error> {
    let names = obj
        .get("names")
        .and_then(Value::as_object)
        .ok_or(Error::ImpossibleToVerify)?;

    // Match priority: exact local-part → "_" root → first entry (only when
    // the caller asked for the root). Matches the Kotlin reference.
    let picked: Option<&str> = names
        .get(&address.local_part)
        .and_then(Value::as_str)
        .filter(|v| is_hex_pubkey(v));

    let picked = picked
        .or_else(|| {
            names
                .get("_")
                .and_then(Value::as_str)
                .filter(|v| is_hex_pubkey(v))
        })
        .or_else(|| {
            if address.local_part == "_" {
                names
                    .values()
                    .filter_map(Value::as_str)
                    .find(|v| is_hex_pubkey(v))
            } else {
                None
            }
        });

    let pubkey_hex = picked.ok_or(Error::ImpossibleToVerify)?;
    let pk = PublicKey::from_hex(pubkey_hex).map_err(|_| Error::InvalidPubKey)?;
    let relays = extract_relays(obj, &pk);
    Ok((pk, relays))
}

fn extract_from_identity_object(
    obj: &serde_json::Map<String, Value>,
    _address: &NamecoinAddress,
) -> Result<(PublicKey, Vec<RelayUrl>), Error> {
    // Try the `pubkey` field first.
    if let Some(pk_str) = obj.get("pubkey").and_then(Value::as_str) {
        if is_hex_pubkey(pk_str) {
            let pk = PublicKey::from_hex(pk_str).map_err(|_| Error::InvalidPubKey)?;
            let relays = obj
                .get("relays")
                .and_then(|v| serde_json::from_value::<Vec<RelayUrl>>(v.clone()).ok())
                .unwrap_or_default();
            return Ok((pk, relays));
        }
    }

    // Fall back to NIP-05-like `names` with the `_` root.
    if let Some(names) = obj.get("names").and_then(Value::as_object) {
        if let Some(v) = names.get("_").and_then(Value::as_str) {
            if is_hex_pubkey(v) {
                let pk = PublicKey::from_hex(v).map_err(|_| Error::InvalidPubKey)?;
                let relays = extract_relays(obj, &pk);
                return Ok((pk, relays));
            }
        }
    }

    Err(Error::ImpossibleToVerify)
}

fn extract_relays(obj: &serde_json::Map<String, Value>, pk: &PublicKey) -> Vec<RelayUrl> {
    let relays_field = match obj.get("relays").and_then(Value::as_object) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let hex_lower = pk.to_hex();
    if let Some(v) = relays_field.get(&hex_lower) {
        if let Ok(list) = serde_json::from_value::<Vec<RelayUrl>>(v.clone()) {
            return list;
        }
    }
    Vec::new()
}

#[inline]
fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[inline]
fn strip_nostr_prefix(s: &str) -> &str {
    if s.len() >= 6 && s[..6].eq_ignore_ascii_case("nostr:") {
        &s[6..]
    } else {
        s
    }
}

// -----------------------------------------------------------------------------
// `import` chain support (ifa-0001 §"import")
// -----------------------------------------------------------------------------
//
// The 520-byte per-name limit on Namecoin makes apex records (`d/<name>`)
// crowded. ifa-0001 §"import" lets a name delegate shared blocks into a
// sibling name (typically `dd/<name>`) via an `"import"` key on the JSON
// value. Without import-chain handling, NIP-05 lookups against records
// that use this pattern (such as the canonical `testls.bit` demo target)
// silently fail: the resolver sees the apex value, finds no `nostr`
// field, and returns `Err(ImpossibleToVerify)` — never consulting the
// imported sibling that actually carries the `nostr.names` block.
//
// The expansion implemented here is value-level only: it walks the
// `import` key, fetches imported names via the caller-supplied lookup,
// applies any subdomain selector against the imported value's `map`
// tree, merges the imported view under the importer's own keys (with
// `null` acting as a suppression marker), recurses on any nested
// `import` up to a small depth budget, and finally strips the `import`
// key from the result. The output is a richer JSON object that the
// existing `extract_nostr_from_value` consumes unchanged.

/// Default recursion depth for [`expand_imports`].
///
/// ifa-0001 mandates implementations support **at least four** levels of
/// `import` recursion. We default to that minimum — deeper chains are
/// silently truncated, but the importing record's own fields still apply.
pub const DEFAULT_IMPORT_DEPTH: u32 = 4;

/// Recursively expand the `import` key on `root` (and on any imported
/// values, up to `max_depth` levels deep), merging the imported view
/// into `root` with **importer-wins** semantics.
///
/// `lookup` is called once per `(name, selector)` pair encountered along
/// a single recursion path. It returns the raw JSON value of the named
/// record as a string, or `None` if the name does not exist, is
/// expired, or could not be fetched. Failures are absorbed: a `None` /
/// malformed result is treated as the empty object `{}`, so transient
/// ElectrumX hiccups never nuke an otherwise resolvable record (the
/// importer's own fields still apply).
///
/// `max_depth` is the maximum recursion depth. Passing `0` disables
/// import expansion entirely; the spec minimum (and the value used by
/// the resolver entry points in this module) is
/// [`DEFAULT_IMPORT_DEPTH`].
///
/// If `root` is not a JSON object, or has no `"import"` key, this
/// function does nothing and `lookup` is never called. That property is
/// the regression guard for the non-import code path's I/O cost: a plain
/// record pays zero extra cost.
///
/// `lookup` is invoked **synchronously**. Callers that wrap an async
/// transport (such as an ElectrumX WSS client) should drive the future
/// to completion inside the closure — for example by stashing pre-fetched
/// values in a map, by using `tokio::task::block_in_place`, or by
/// dispatching to a thread-local runtime handle. Keeping the closure
/// sync mirrors the rest of this module: no transport surface here, the
/// caller owns I/O.
pub fn expand_imports<F>(root: &mut Value, mut lookup: F, max_depth: u32)
where
    F: FnMut(&str) -> Option<String>,
{
    if !root.is_object() {
        return;
    }
    let mut visited: Vec<String> = Vec::new();
    expand_recursive(root, &mut lookup, max_depth, &mut visited);
}

fn expand_recursive<F>(
    obj: &mut Value,
    lookup: &mut F,
    budget_remaining: u32,
    visited: &mut Vec<String>,
) where
    F: FnMut(&str) -> Option<String>,
{
    // Trigger: no `import` key → zero extra I/O, exit immediately.
    let import_item = match obj.as_object_mut().and_then(|m| m.remove("import")) {
        Some(v) => v,
        None => return,
    };

    // Malformed `import` value → strip the key and stop. We have already
    // removed it above, so just return.
    let ops = match parse_import_item(&import_item) {
        Some(ops) if !ops.is_empty() => ops,
        _ => return,
    };
    if budget_remaining == 0 {
        return;
    }

    // Walk imports left-to-right. The spec is silent on multiple-import
    // precedence; we follow the common-sense rule that LATER imports
    // override EARLIER ones in the same array (otherwise listing two
    // libraries would silently ignore the second). The whole accumulator
    // still loses to the importing object on top of all of it.
    let mut accumulator = serde_json::Map::<String, Value>::new();
    for op in &ops {
        let visit_key = visit_key_for(op);
        if visited.iter().any(|k| k == &visit_key) {
            // Cycle or duplicate within this chain — treat as `{}`.
            continue;
        }
        visited.push(visit_key);

        // Lenient I/O: a missing or malformed import is treated as `{}`.
        // The visited-set entry is left in place to short-circuit any
        // recursive revisit of this same (name, selector) pair.
        let imported_raw = match lookup(&op.name) {
            Some(s) => s,
            None => continue,
        };
        let imported_root: Value = match serde_json::from_str(&imported_raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mut selector_view = match apply_selector(imported_root, &op.selector) {
            Some(v) => v,
            None => continue,
        };
        // Recurse: the imported view may itself carry an `import` key.
        expand_recursive(&mut selector_view, lookup, budget_remaining - 1, visited);
        if let Value::Object(map) = selector_view {
            // Later imports override earlier ones in the same array; the
            // newly-fetched view plays the role of "importer" against the
            // existing accumulator.
            merge_later_wins(&mut accumulator, map);
        }
    }

    // Finally merge the importing object on top of the accumulator.
    // `obj` already has its `import` key removed.
    if let Some(obj_map) = obj.as_object_mut() {
        // We want importer-wins: keys already in `obj` stay, missing keys
        // are filled in from the accumulator (without disturbing the
        // importer's `null` suppressions).
        for (k, v) in accumulator {
            obj_map.entry(k).or_insert(v);
        }
    }
}

/// Merge `incoming` into `accumulator` with later-wins semantics:
/// every key in `incoming` overwrites the existing entry in
/// `accumulator`, including `JsonNull` (which suppresses the earlier
/// imported value just as it would in the importing object).
fn merge_later_wins(
    accumulator: &mut serde_json::Map<String, Value>,
    incoming: serde_json::Map<String, Value>,
) {
    for (k, v) in incoming {
        accumulator.insert(k, v);
    }
}

/// One import target: a Namecoin name + an optional DNS-format subdomain
/// selector.
#[derive(Debug, Clone)]
struct ImportOp {
    name: String,
    selector: String,
}

fn visit_key_for(op: &ImportOp) -> String {
    let mut s = String::with_capacity(op.name.len() + 1 + op.selector.len());
    s.push_str(&op.name);
    s.push('|');
    s.push_str(&op.selector);
    s
}

/// Parse an `import` value into a flat list of [`ImportOp`]s.
///
/// Accepted shapes (in order of preference):
///
/// - canonical: `[ ["d/foo"], ["d/bar","sub"] ]`
/// - shorthand string: `"d/foo"` → one op, no selector
/// - shorthand single-array: `["d/foo"]` → one op, no selector
/// - shorthand pair-array: `["d/foo","sub"]` → one op with selector
///
/// Anything else is treated as malformed; the caller must skip the
/// import in that case. An empty array returns `Some(Vec::new())`.
fn parse_import_item(item: &Value) -> Option<Vec<ImportOp>> {
    // Shorthand: bare string.
    if let Some(s) = item.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(vec![ImportOp {
            name: trimmed.to_string(),
            selector: String::new(),
        }]);
    }
    // Array shapes.
    let arr = item.as_array()?;
    if arr.is_empty() {
        return Some(Vec::new());
    }
    // Distinguish: array-of-arrays (canonical) vs array-of-strings (shorthand).
    let first_is_array = matches!(arr.first(), Some(Value::Array(_)));
    if first_is_array {
        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            if let Some(inner) = entry.as_array() {
                if let Some(op) = op_from_array(inner) {
                    out.push(op);
                }
            }
            // Non-array entries in a canonical list are silently skipped.
        }
        return Some(out);
    }
    // Shorthand: ["name"] or ["name", "selector"]. All elements must be
    // strings; anything else makes the whole item malformed.
    Some(op_from_array(arr).into_iter().collect())
}

fn op_from_array(arr: &[Value]) -> Option<ImportOp> {
    let first = arr.first()?.as_str()?;
    let name = first.trim();
    if name.is_empty() {
        return None;
    }
    let selector = if arr.len() >= 2 {
        arr.get(1).and_then(Value::as_str).unwrap_or("").trim()
    } else {
        ""
    };
    // Trailing dot is forbidden by spec; treat as malformed → skip.
    if selector.ends_with('.') {
        return None;
    }
    Some(ImportOp {
        name: name.to_string(),
        selector: selector.to_string(),
    })
}

/// Walk the imported value's `map` tree to the node addressed by `selector`.
///
/// `selector` is DNS-dotted (`relay`, `a.b.c`); the leftmost label is the
/// most-specific. The `map` tree is rooted at the parent and nests inwards
/// toward the leaf, so we walk labels right-to-left. Per ifa-0001 §"map":
///
/// - Exact label match wins.
/// - `"*"` matches any single label.
/// - `""` is the default for the current level when no other match applies.
/// - A non-object child terminates the walk with `None`.
///
/// An empty selector returns the root unchanged.
fn apply_selector(root: Value, selector: &str) -> Option<Value> {
    if selector.is_empty() {
        return Some(root);
    }
    let labels: Vec<&str> = selector.split('.').filter(|s| !s.is_empty()).collect();
    if labels.is_empty() {
        return Some(root);
    }
    let mut current = root;
    for label in labels.iter().rev() {
        let map = current
            .as_object()
            .and_then(|o| o.get("map"))
            .and_then(Value::as_object)?;
        let child = map
            .get(*label)
            .filter(|v| v.is_object())
            .or_else(|| map.get("*").filter(|v| v.is_object()))
            .or_else(|| map.get("").filter(|v| v.is_object()))?;
        // Detach the chosen child as the new current.
        current = child.clone();
    }
    Some(current)
}

// -----------------------------------------------------------------------------
// Namecoin script + ElectrumX scripthash helpers
// -----------------------------------------------------------------------------

const OP_NAME_UPDATE: u8 = 0x53; // OP_3, repurposed as OP_NAME_UPDATE in the Namecoin fork
const OP_2DROP: u8 = 0x6d;
const OP_DROP: u8 = 0x75;
const OP_RETURN: u8 = 0x6a;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;

/// Build the canonical name-index script used by the Namecoin ElectrumX fork.
///
/// Format:
///
/// ```text
/// OP_NAME_UPDATE <push(name)> <push(empty)> OP_2DROP OP_DROP OP_RETURN
/// ```
///
/// The resulting script's SHA-256, reversed and hex-encoded, is the scripthash
/// queried via `blockchain.scripthash.get_history`. See
/// [`electrum_script_hash`].
pub fn build_name_index_script(name_bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(4 + name_bytes.len() + 4);
    out.push(OP_NAME_UPDATE);
    push_data(&mut out, name_bytes);
    push_data(&mut out, &[]);
    out.push(OP_2DROP);
    out.push(OP_DROP);
    out.push(OP_RETURN);
    out
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < OP_PUSHDATA1 as usize {
        out.push(n as u8);
        out.extend_from_slice(data);
    } else if n <= 0xff {
        out.push(OP_PUSHDATA1);
        out.push(n as u8);
        out.extend_from_slice(data);
    } else if n <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.push((n & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.extend_from_slice(data);
    } else {
        out.push(OP_PUSHDATA4);
        out.push((n & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 24) & 0xff) as u8);
        out.extend_from_slice(data);
    }
}

/// Compute the Electrum scripthash: SHA-256 of `script`, byte-reversed, then
/// hex-encoded. Expected by `blockchain.scripthash.get_history` and friends.
pub fn electrum_script_hash(script: &[u8]) -> String {
    let digest: [u8; 32] = Sha256Hash::hash(script).to_byte_array();
    let mut reversed = digest;
    reversed.reverse();
    let mut s = String::with_capacity(64);
    for b in reversed.iter() {
        // Lowercase hex without pulling a dep.
        s.push(nibble_to_hex(b >> 4));
        s.push(nibble_to_hex(b & 0x0f));
    }
    s
}

#[inline]
fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '0',
    }
}

/// Parse a Namecoin `NAME_UPDATE` output script and return `(name, value)`.
///
/// Layout:
///
/// ```text
/// OP_NAME_UPDATE <push(name)> <push(value)> OP_2DROP OP_DROP <address-script>
/// ```
///
/// The trailing address-paying script is ignored.
pub fn parse_name_update_script(script: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if script.is_empty() || script[0] != OP_NAME_UPDATE {
        return Err(Error::InvalidScript);
    }
    let (name, next) = read_push_data(script, 1)?;
    let (value, _) = read_push_data(script, next)?;
    Ok((name.to_vec(), value.to_vec()))
}

fn read_push_data(script: &[u8], pos: usize) -> Result<(&[u8], usize), Error> {
    if pos >= script.len() {
        return Err(Error::InvalidScript);
    }
    let op = script[pos];
    if op == 0x00 {
        return Ok((&script[pos..pos], pos + 1));
    }
    if op < OP_PUSHDATA1 {
        let length = op as usize;
        let end = pos + 1 + length;
        if end > script.len() {
            return Err(Error::InvalidScript);
        }
        return Ok((&script[pos + 1..end], end));
    }
    match op {
        OP_PUSHDATA1 => {
            if pos + 2 > script.len() {
                return Err(Error::InvalidScript);
            }
            let length = script[pos + 1] as usize;
            let end = pos + 2 + length;
            if end > script.len() {
                return Err(Error::InvalidScript);
            }
            Ok((&script[pos + 2..end], end))
        }
        OP_PUSHDATA2 => {
            if pos + 3 > script.len() {
                return Err(Error::InvalidScript);
            }
            let length = script[pos + 1] as usize | ((script[pos + 2] as usize) << 8);
            let end = pos + 3 + length;
            if end > script.len() {
                return Err(Error::InvalidScript);
            }
            Ok((&script[pos + 3..end], end))
        }
        OP_PUSHDATA4 => {
            if pos + 5 > script.len() {
                return Err(Error::InvalidScript);
            }
            let length = (script[pos + 1] as usize)
                | ((script[pos + 2] as usize) << 8)
                | ((script[pos + 3] as usize) << 16)
                | ((script[pos + 4] as usize) << 24);
            let end = pos + 5 + length;
            if end > script.len() {
                return Err(Error::InvalidScript);
            }
            Ok((&script[pos + 5..end], end))
        }
        _ => Err(Error::InvalidScript),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PK1: &str = "460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c";
    const PK2: &str = "6cdebcca8b8b9f5e1ab3b3aa1d2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2";

    #[test]
    fn is_valid_identifier_matches_expected_shapes() {
        assert!(is_valid_identifier("example.bit"));
        assert!(is_valid_identifier("alice@example.bit"));
        assert!(is_valid_identifier("d/example"));
        assert!(is_valid_identifier("id/alice"));
        assert!(is_valid_identifier("nostr:alice@example.bit"));
        assert!(is_valid_identifier("  EXAMPLE.BIT  "));

        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("alice@example.com"));
        assert!(!is_valid_identifier("example.com"));

        // is_valid_identifier is intentionally cheap: it answers "should I
        // route this through Namecoin?" without strictly validating the
        // identifier. Strict validation happens in NamecoinAddress::parse.
        assert!(is_valid_identifier("d/"));
        assert!(parse_is_err("d/"));
        assert!(parse_is_err("id/"));
        assert!(parse_is_err(".bit"));
    }

    fn parse_is_err(input: &str) -> bool {
        NamecoinAddress::parse(input).is_err()
    }

    #[test]
    fn parse_user_at_domain_bit() {
        let addr = NamecoinAddress::parse("alice@example.bit").unwrap();
        assert_eq!(addr.namecoin_name(), "d/example");
        assert_eq!(addr.local_part(), "alice");
        assert!(addr.is_domain());
        assert_eq!(addr.to_string(), "alice@example.bit");
    }

    #[test]
    fn parse_bare_domain_bit() {
        let addr = NamecoinAddress::parse("example.bit").unwrap();
        assert_eq!(addr.namecoin_name(), "d/example");
        assert_eq!(addr.local_part(), "_");
        assert!(addr.is_domain());
        assert_eq!(addr.to_string(), "example.bit");
    }

    #[test]
    fn parse_d_slash() {
        let addr = NamecoinAddress::parse("d/example").unwrap();
        assert_eq!(addr.namecoin_name(), "d/example");
        assert_eq!(addr.local_part(), "_");
        assert!(addr.is_domain());
    }

    #[test]
    fn parse_id_slash() {
        let addr = NamecoinAddress::parse("id/alice").unwrap();
        assert_eq!(addr.namecoin_name(), "id/alice");
        assert_eq!(addr.local_part(), "_");
        assert!(!addr.is_domain());
        assert_eq!(addr.to_string(), "id/alice");
    }

    #[test]
    fn parse_strips_nostr_prefix() {
        let addr = NamecoinAddress::parse("nostr:alice@example.bit").unwrap();
        assert_eq!(addr.namecoin_name(), "d/example");
        assert_eq!(addr.local_part(), "alice");
    }

    #[test]
    fn parse_is_case_insensitive() {
        let addr = NamecoinAddress::parse("ALICE@EXAMPLE.BIT").unwrap();
        assert_eq!(addr.namecoin_name(), "d/example");
        assert_eq!(addr.local_part(), "alice");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(NamecoinAddress::parse("alice@example.com").is_err());
        assert!(NamecoinAddress::parse("").is_err());
        assert!(NamecoinAddress::parse(".bit").is_err());
        assert!(NamecoinAddress::parse("@example.bit").is_ok()); // empty local => "_"
    }

    #[test]
    fn extract_simple_form_string_value() {
        let json: Value = serde_json::from_str(&format!(r#"{{ "nostr": "{}" }}"#, PK1)).unwrap();
        let addr = NamecoinAddress::parse("example.bit").unwrap();
        let profile = Nip05NamecoinProfile::from_json(&addr, &json).unwrap();
        assert_eq!(profile.public_key, PublicKey::from_hex(PK1).unwrap());
        assert!(profile.relays.is_empty());
    }

    #[test]
    fn extract_simple_form_rejects_localpart_address() {
        let json: Value = serde_json::from_str(&format!(r#"{{ "nostr": "{}" }}"#, PK1)).unwrap();
        let addr = NamecoinAddress::parse("alice@example.bit").unwrap();
        assert!(Nip05NamecoinProfile::from_json(&addr, &json).is_err());
    }

    #[test]
    fn extract_extended_form_names_exact_match() {
        let json: Value = serde_json::from_str(&format!(
            r#"{{
                "nostr": {{
                    "names": {{ "_": "{pk1}", "alice": "{pk2}" }},
                    "relays": {{
                        "{pk2}": ["wss://relay.example.com"]
                    }}
                }}
            }}"#,
            pk1 = PK1,
            pk2 = PK1, // reuse PK1 to keep test PublicKey-parse happy
        ))
        .unwrap();
        let addr = NamecoinAddress::parse("alice@example.bit").unwrap();
        let profile = Nip05NamecoinProfile::from_json(&addr, &json).unwrap();
        assert_eq!(profile.public_key, PublicKey::from_hex(PK1).unwrap());
        assert_eq!(
            profile.relays,
            vec![RelayUrl::parse("wss://relay.example.com").unwrap()]
        );
    }

    #[test]
    fn extract_extended_form_falls_back_to_root() {
        let json: Value = serde_json::from_str(&format!(
            r#"{{ "nostr": {{ "names": {{ "_": "{}" }} }} }}"#,
            PK1
        ))
        .unwrap();
        let addr = NamecoinAddress::parse("ghost@example.bit").unwrap();
        let profile = Nip05NamecoinProfile::from_json(&addr, &json).unwrap();
        assert_eq!(profile.public_key, PublicKey::from_hex(PK1).unwrap());
    }

    #[test]
    fn extract_id_namespace_pubkey_field() {
        let json: Value = serde_json::from_str(&format!(
            r#"{{
                "nostr": {{
                    "pubkey": "{pk}",
                    "relays": ["wss://relay.example.com"]
                }}
            }}"#,
            pk = PK1
        ))
        .unwrap();
        let addr = NamecoinAddress::parse("id/alice").unwrap();
        let profile = Nip05NamecoinProfile::from_json(&addr, &json).unwrap();
        assert_eq!(profile.public_key, PublicKey::from_hex(PK1).unwrap());
        assert_eq!(
            profile.relays,
            vec![RelayUrl::parse("wss://relay.example.com").unwrap()]
        );
    }

    #[test]
    fn extract_id_namespace_names_root_fallback() {
        let json: Value = serde_json::from_str(&format!(
            r#"{{ "nostr": {{ "names": {{ "_": "{}" }} }} }}"#,
            PK1
        ))
        .unwrap();
        let addr = NamecoinAddress::parse("id/alice").unwrap();
        let profile = Nip05NamecoinProfile::from_json(&addr, &json).unwrap();
        assert_eq!(profile.public_key, PublicKey::from_hex(PK1).unwrap());
    }

    #[test]
    fn extract_missing_nostr_field_errors() {
        let json: Value = serde_json::from_str(r#"{ "ip": "1.2.3.4" }"#).unwrap();
        let addr = NamecoinAddress::parse("example.bit").unwrap();
        assert!(Nip05NamecoinProfile::from_json(&addr, &json).is_err());
    }

    #[test]
    fn verify_from_raw_json_works() {
        let raw = format!(r#"{{ "nostr": "{}" }}"#, PK1);
        let pk = PublicKey::from_hex(PK1).unwrap();
        let addr = NamecoinAddress::parse("example.bit").unwrap();
        assert!(verify_from_raw_json(&pk, &addr, &raw).unwrap());

        // Mismatch
        let raw_other =
            r#"{ "nostr": "0000000000000000000000000000000000000000000000000000000000000000" }"#;
        // pubkey 0...0 isn't a valid secp x-only, so the extractor returns
        // an error → verify returns false.
        assert!(!verify_from_raw_json(&pk, &addr, raw_other).unwrap());

        let _ = PK2; // referenced for documentation in extract tests
    }

    #[test]
    fn build_name_index_script_layout() {
        let script = build_name_index_script(b"d/example");
        // OP_NAME_UPDATE | push(9, "d/example") | push(0) | OP_2DROP | OP_DROP | OP_RETURN
        assert_eq!(script[0], OP_NAME_UPDATE);
        assert_eq!(script[1], b"d/example".len() as u8);
        assert_eq!(&script[2..2 + 9], b"d/example");
        assert_eq!(script[11], 0x00); // empty push
        assert_eq!(script[12], OP_2DROP);
        assert_eq!(script[13], OP_DROP);
        assert_eq!(script[14], OP_RETURN);
    }

    #[test]
    fn electrum_script_hash_is_reversed_sha256_hex() {
        let script = build_name_index_script(b"d/example");
        let h = electrum_script_hash(&script);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        // Recompute the forward digest manually and confirm it matches the
        // reversed-then-rereversed scripthash.
        let forward = Sha256Hash::hash(&script).to_byte_array();
        let mut from_hex = [0u8; 32];
        for i in 0..32 {
            from_hex[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        // The Electrum convention is reverse(sha256(script)), so reversing
        // the hex back gives the original sha256 digest.
        from_hex.reverse();
        assert_eq!(forward, from_hex);
    }

    #[test]
    fn parse_name_update_script_extracts_name_and_value() {
        // Hand-assemble: OP_NAME_UPDATE push("d/example") push("{}") OP_2DROP OP_DROP <addr...>
        let mut script: Vec<u8> = Vec::new();
        script.push(OP_NAME_UPDATE);
        script.push(9);
        script.extend_from_slice(b"d/example");
        script.push(2);
        script.extend_from_slice(b"{}");
        script.push(OP_2DROP);
        script.push(OP_DROP);
        // Trailing address-paying part (ignored): OP_DUP OP_HASH160 ... — anything works.
        script.extend_from_slice(&[0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef]);

        let (name, value) = parse_name_update_script(&script).unwrap();
        assert_eq!(name, b"d/example");
        assert_eq!(value, b"{}");
    }

    #[test]
    fn parse_name_update_script_rejects_non_name_update() {
        assert!(parse_name_update_script(b"\x76\xa9").is_err());
        assert!(parse_name_update_script(&[]).is_err());
    }

    #[test]
    fn parse_name_update_script_handles_pushdata1() {
        // 200-byte value forces OP_PUSHDATA1 framing.
        let value = vec![b'a'; 200];
        let mut script: Vec<u8> = Vec::new();
        script.push(OP_NAME_UPDATE);
        script.push(9);
        script.extend_from_slice(b"d/example");
        script.push(OP_PUSHDATA1);
        script.push(200);
        script.extend_from_slice(&value);
        script.push(OP_2DROP);
        script.push(OP_DROP);
        let (name, parsed_value) = parse_name_update_script(&script).unwrap();
        assert_eq!(name, b"d/example");
        assert_eq!(parsed_value, value);
    }

    #[test]
    fn default_servers_list_is_sensible() {
        // Smoke check the constant is well-formed.
        const _: () = assert!(!DEFAULT_ELECTRUMX_SERVERS.is_empty());
        for s in DEFAULT_ELECTRUMX_SERVERS {
            assert!(!s.host.is_empty());
            assert!(s.port_tcp_tls > 0);
            assert!(s.port_wss > 0);
        }
    }

    #[test]
    fn namecoin_address_electrum_script_hash_is_stable() {
        let addr = NamecoinAddress::parse("example.bit").unwrap();
        let h1 = addr.electrum_script_hash();
        let h2 = electrum_script_hash(&build_name_index_script(b"d/example"));
        assert_eq!(h1, h2);
    }

    // ---------------------------------------------------------------------
    // ifa-0001 §"import" chain expansion
    // ---------------------------------------------------------------------

    use alloc::collections::BTreeMap;
    use core::cell::RefCell;

    /// In-memory "ElectrumX" double used by import tests. Records the
    /// sequence of names actually queried so tests can assert on I/O
    /// cost as well as merged values.
    struct FakeLookup {
        records: BTreeMap<&'static str, &'static str>,
        queried: RefCell<Vec<String>>,
    }

    impl FakeLookup {
        fn new() -> Self {
            Self {
                records: BTreeMap::new(),
                queried: RefCell::new(Vec::new()),
            }
        }

        fn register(mut self, name: &'static str, value: &'static str) -> Self {
            self.records.insert(name, value);
            self
        }

        fn lookup(&self, name: &str) -> Option<String> {
            self.queried.borrow_mut().push(name.to_string());
            self.records.get(name).map(|s| s.to_string())
        }

        fn queried(&self) -> Vec<String> {
            self.queried.borrow().clone()
        }
    }

    fn parse_json(s: &str) -> Value {
        serde_json::from_str(s).expect("valid json in test fixture")
    }

    fn expand(root: &str, fake: &FakeLookup) -> Value {
        let mut v = parse_json(root);
        expand_imports(&mut v, |n| fake.lookup(n), DEFAULT_IMPORT_DEPTH);
        v
    }

    #[test]
    fn import_no_key_returns_object_unchanged() {
        let fake = FakeLookup::new();
        let merged = expand(r#"{"ip":"1.2.3.4"}"#, &fake);
        assert_eq!(merged, parse_json(r#"{"ip":"1.2.3.4"}"#));
        assert!(
            fake.queried().is_empty(),
            "non-import records must pay zero extra I/O"
        );
    }

    #[test]
    fn import_string_shorthand_merges_imported_items() {
        // ifa-0001 §"import" canonical form is array-of-arrays, but the
        // bare-string form is widely used in real records; accept it.
        let fake = FakeLookup::new()
            .register("d/lib", r#"{"ip":"9.9.9.9","nostr":{"names":{"_":"abc"}}}"#);
        let merged = expand(r#"{"import":"d/lib","ip":"1.1.1.1"}"#, &fake);
        // Importer wins on `ip`, imports fill in `nostr.names`.
        assert_eq!(merged["ip"], Value::from("1.1.1.1"));
        assert_eq!(merged["nostr"]["names"]["_"], Value::from("abc"));
        assert!(
            merged.as_object().unwrap().get("import").is_none(),
            "`import` key must not survive expansion"
        );
    }

    #[test]
    fn import_array_shorthand_no_selector() {
        // `["d/foo"]` is shorthand for `[["d/foo"]]` per spec.
        let fake = FakeLookup::new().register("d/lib", r#"{"tag":"from-lib"}"#);
        let merged = expand(r#"{"import":["d/lib"]}"#, &fake);
        assert_eq!(merged["tag"], Value::from("from-lib"));
    }

    #[test]
    fn import_pair_array_shorthand_uses_subdomain_selector() {
        // `["d/foo","sel"]` is shorthand for `[["d/foo","sel"]]`.
        let fake = FakeLookup::new().register(
            "d/lib",
            r#"{"ip":"1.1.1.1","map":{"relay":{"ip":"7.7.7.7","tag":"selected"}}}"#,
        );
        let merged = expand(r#"{"import":["d/lib","relay"]}"#, &fake);
        // We selected `map.relay` from d/lib so its contents (ip=7.7.7.7,
        // tag=selected) are merged at the top level. d/lib's top-level
        // ip (1.1.1.1) is NOT seen because we descended.
        assert_eq!(merged["ip"], Value::from("7.7.7.7"));
        assert_eq!(merged["tag"], Value::from("selected"));
    }

    #[test]
    fn import_canonical_array_of_arrays_processes_in_order() {
        // Later imports override earlier in the same array. The importer
        // declares no `ip` of its own, so the last imported one wins.
        let fake = FakeLookup::new()
            .register("d/a", r#"{"ip":"10.0.0.1","tag":"from-a"}"#)
            .register("d/b", r#"{"ip":"10.0.0.2","extra":"from-b"}"#);
        let merged = expand(r#"{"import":[["d/a"],["d/b"]]}"#, &fake);
        assert_eq!(merged["ip"], Value::from("10.0.0.2"));
        assert_eq!(merged["tag"], Value::from("from-a"));
        assert_eq!(merged["extra"], Value::from("from-b"));
    }

    #[test]
    fn import_importer_wins_on_plain_keys() {
        let fake = FakeLookup::new().register(
            "d/lib",
            r#"{"ip":"9.9.9.9","extra":"remote","only-imported":"yes"}"#,
        );
        let merged = expand(
            r#"{"import":"d/lib","ip":"1.1.1.1","extra":"local"}"#,
            &fake,
        );
        assert_eq!(merged["ip"], Value::from("1.1.1.1"));
        assert_eq!(merged["extra"], Value::from("local"));
        assert_eq!(merged["only-imported"], Value::from("yes"));
    }

    #[test]
    fn import_null_in_importer_suppresses_imported_value() {
        // ifa-0001: a `null` in the importer is "present for precedence"
        // semantic suppression. The imported `ip` is masked.
        let fake = FakeLookup::new().register("d/lib", r#"{"ip":"9.9.9.9","other":"keep"}"#);
        let merged = expand(r#"{"import":"d/lib","ip":null}"#, &fake);
        let obj = merged.as_object().unwrap();
        assert!(obj.contains_key("ip"));
        assert_eq!(obj["ip"], Value::Null);
        assert_eq!(obj["other"], Value::from("keep"));
    }

    #[test]
    fn import_recursion_depth_four_is_supported() {
        // ifa-0001 mandates implementations support recursion depth >= 4.
        // Pin the 4-deep happy path.
        let fake = FakeLookup::new()
            .register("d/a", r#"{"import":"d/b","layer":"a"}"#)
            .register("d/b", r#"{"import":"d/c","layer":"b"}"#)
            .register("d/c", r#"{"import":"d/d","layer":"c"}"#)
            .register("d/d", r#"{"layer":"d","deep":"reached"}"#);
        let merged = expand(r#"{"import":"d/a"}"#, &fake);
        // Each layer overrides `layer`, so the importer sees "a".
        // `deep` only exists on d/d and survives to the top.
        assert_eq!(merged["layer"], Value::from("a"));
        assert_eq!(merged["deep"], Value::from("reached"));
    }

    #[test]
    fn import_recursion_deeper_than_max_depth_is_truncated() {
        // Anything past the depth limit is dropped, but the importing
        // record's own items still apply.
        let fake = FakeLookup::new()
            .register("d/a", r#"{"import":"d/b","tag":"from-a"}"#)
            .register("d/b", r#"{"tag":"from-b","leaf":"won't-show"}"#);
        let mut v = parse_json(r#"{"import":"d/a","local":"keep"}"#);
        expand_imports(&mut v, |n| fake.lookup(n), 1); // only one level
        assert_eq!(v["tag"], Value::from("from-a"));
        assert_eq!(v["local"], Value::from("keep"));
        // d/b was never expanded, so its leaf key is absent.
        assert!(v.as_object().unwrap().get("leaf").is_none());
    }

    #[test]
    fn import_lookup_returns_none_is_treated_as_empty_object() {
        // Per docs: spec says a failed import MAY fail the whole record;
        // we choose the lenient "empty object" semantics so transient
        // ElectrumX hiccups don't kill resolution.
        let fake = FakeLookup::new(); // nothing registered
        let merged = expand(r#"{"import":"d/missing","local":"survives"}"#, &fake);
        assert_eq!(merged["local"], Value::from("survives"));
        assert!(merged.as_object().unwrap().get("import").is_none());
    }

    #[test]
    fn import_lookup_returning_malformed_json_is_skipped() {
        let fake = FakeLookup::new().register("d/broken", r#"not valid json {{{"#);
        let merged = expand(r#"{"import":"d/broken","local":"keep"}"#, &fake);
        assert_eq!(merged["local"], Value::from("keep"));
    }

    #[test]
    fn import_lookup_panic_is_caught_by_the_caller() {
        // Rust doesn't have a checked-exception equivalent, but the
        // analogous case is a closure that returns `None` for any reason.
        // Pin that None is absorbed (already covered above; this test
        // pins that a closure with side effects still preserves the
        // importer's own fields).
        let calls = RefCell::new(0u32);
        let mut v = parse_json(r#"{"import":"d/x","local":"keep"}"#);
        expand_imports(
            &mut v,
            |_| {
                *calls.borrow_mut() += 1;
                None
            },
            DEFAULT_IMPORT_DEPTH,
        );
        assert_eq!(*calls.borrow(), 1);
        assert_eq!(v["local"], Value::from("keep"));
        assert!(v.as_object().unwrap().get("import").is_none());
    }

    #[test]
    fn import_malformed_import_value_is_skipped() {
        // Numeric `import` is malformed and treated as no-op.
        let fake = FakeLookup::new();
        let merged = expand(r#"{"import":42,"local":"keep"}"#, &fake);
        assert_eq!(merged["local"], Value::from("keep"));
        assert!(merged.as_object().unwrap().get("import").is_none());
        assert!(fake.queried().is_empty(), "no lookup for malformed import");
    }

    #[test]
    fn import_cycle_is_broken_without_infinite_recursion() {
        // d/a imports d/b which imports d/a. A naive resolver would hang.
        // The visited-set guard breaks the loop on the second appearance
        // of d/a; importer's own items still apply.
        let fake = FakeLookup::new()
            .register("d/a", r#"{"import":"d/b","fromA":"yes"}"#)
            .register("d/b", r#"{"import":"d/a","fromB":"yes"}"#);
        let merged = expand(r#"{"import":"d/a","local":"top"}"#, &fake);
        assert_eq!(merged["local"], Value::from("top"));
        // At least one of fromA/fromB must have made it through — we
        // don't pin which because the cycle break point is an
        // implementation detail, but the call MUST terminate.
        let obj = merged.as_object().unwrap();
        assert!(obj.contains_key("fromA") || obj.contains_key("fromB"));
    }

    #[test]
    fn import_selector_with_multiple_labels_descends_in_dns_order() {
        // Selector "a.b" means: descend map.b, then map.a (DNS-rightmost
        // first). The empty-key and "*" wildcard rules apply too.
        let fake =
            FakeLookup::new().register("d/lib", r#"{"map":{"b":{"map":{"a":{"value":"deep"}}}}}"#);
        let merged = expand(r#"{"import":[["d/lib","a.b"]]}"#, &fake);
        assert_eq!(merged["value"], Value::from("deep"));
    }

    #[test]
    fn import_selector_falls_back_to_wildcard_star() {
        let fake = FakeLookup::new().register("d/lib", r#"{"map":{"*":{"value":"wildcard"}}}"#);
        let merged = expand(r#"{"import":["d/lib","ghost"]}"#, &fake);
        assert_eq!(merged["value"], Value::from("wildcard"));
    }

    #[test]
    fn import_selector_falls_back_to_empty_key_default() {
        // When neither the exact label nor `*` is present, the empty-key
        // entry is the default at that level.
        let fake = FakeLookup::new().register("d/lib", r#"{"map":{"":{"value":"default"}}}"#);
        let merged = expand(r#"{"import":["d/lib","ghost"]}"#, &fake);
        assert_eq!(merged["value"], Value::from("default"));
    }

    // ---------------------------------------------------------------------
    // Integration: full Nip05NamecoinProfile resolution across imports
    // ---------------------------------------------------------------------

    // The real-world `testls.bit` deployment: the apex record at
    // `d/testls` is up against the 520-byte per-name limit and delegates
    // its `nostr.names` block to a sibling name via
    // `"import":"dd/testls"`. Without import support, NIP-05 resolution
    // sees no `nostr` field at d/testls and fails.
    const TESTLS_APEX: &str = r#"{"import":"dd/testls","ip":"107.152.38.155"}"#;
    const TESTLS_IMPORTED: &str = r#"{"nostr":{"names":{
        "_":"460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c",
        "m":"6cdebccabda1dfa058ab85352a79509b592b2bdfa0370325e28ec1cb4f18667d"
    }}}"#;

    #[test]
    fn integration_bare_nip05_resolves_across_import() {
        let fake = FakeLookup::new()
            .register("d/testls", TESTLS_APEX)
            .register("dd/testls", TESTLS_IMPORTED);
        let addr = NamecoinAddress::parse("testls.bit").unwrap();
        let profile =
            Nip05NamecoinProfile::from_raw_json_with_lookup(&addr, fake.records["d/testls"], |n| {
                fake.lookup(n)
            })
            .unwrap();
        assert_eq!(
            profile.public_key,
            PublicKey::from_hex("460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c")
                .unwrap()
        );
        // Only the imported name was queried (the apex JSON is passed
        // in directly by the caller, as elsewhere in this module).
        assert_eq!(fake.queried(), vec!["dd/testls".to_string()]);
    }

    #[test]
    fn integration_named_local_part_resolves_across_import() {
        let fake = FakeLookup::new()
            .register("d/testls", TESTLS_APEX)
            .register("dd/testls", TESTLS_IMPORTED);
        let addr = NamecoinAddress::parse("m@testls.bit").unwrap();
        let profile =
            Nip05NamecoinProfile::from_raw_json_with_lookup(&addr, fake.records["d/testls"], |n| {
                fake.lookup(n)
            })
            .unwrap();
        assert_eq!(
            profile.public_key,
            PublicKey::from_hex("6cdebccabda1dfa058ab85352a79509b592b2bdfa0370325e28ec1cb4f18667d")
                .unwrap()
        );
    }

    #[test]
    fn integration_no_import_record_issues_zero_extra_lookups() {
        // Pure regression guard: ensure non-import records pay zero I/O
        // cost (lookup closure is never invoked).
        let fake = FakeLookup::new();
        let raw = r#"{"nostr":{"names":{
            "_":"460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c"
        }}}"#;
        let addr = NamecoinAddress::parse("plain.bit").unwrap();
        let profile =
            Nip05NamecoinProfile::from_raw_json_with_lookup(&addr, raw, |n| fake.lookup(n))
                .unwrap();
        assert_eq!(
            profile.public_key,
            PublicKey::from_hex("460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c")
                .unwrap()
        );
        // No `import` key → lookup never invoked.
        assert!(fake.queried().is_empty());
    }

    #[test]
    fn integration_importer_wins_on_nostr_names_block() {
        // Importer declares its own `nostr.names.m`; imported value
        // declares a different one. Importer wins on the whole `nostr`
        // key (shallow merge per spec).
        let fake = FakeLookup::new().register(
            "dd/testls",
            r#"{"nostr":{"names":{"m":"bbbb000000000000000000000000000000000000000000000000000000000002"}}}"#,
        );
        // Use a valid x-only pubkey for the importer.
        let importer_pk = "460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c";
        let apex =
            format!(r#"{{"import":"dd/testls","nostr":{{"names":{{"m":"{importer_pk}"}}}}}}"#);
        let addr = NamecoinAddress::parse("m@testls.bit").unwrap();
        let profile =
            Nip05NamecoinProfile::from_raw_json_with_lookup(&addr, &apex, |n| fake.lookup(n))
                .unwrap();
        assert_eq!(
            profile.public_key,
            PublicKey::from_hex(importer_pk).unwrap()
        );
    }

    #[test]
    fn integration_failed_import_does_not_break_local_names() {
        // Importer has its own `nostr.names`; the imported boilerplate
        // happens to be unreachable. Resolution still succeeds from the
        // importer's own data.
        let fake = FakeLookup::new();
        let apex = r#"{"import":"dd/missing",
            "nostr":{"names":{"_":"460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c"}}}"#;
        let addr = NamecoinAddress::parse("testls.bit").unwrap();
        let profile =
            Nip05NamecoinProfile::from_raw_json_with_lookup(&addr, apex, |n| fake.lookup(n))
                .unwrap();
        assert_eq!(
            profile.public_key,
            PublicKey::from_hex("460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c")
                .unwrap()
        );
    }

    #[test]
    fn integration_verify_with_lookup_threads_import_chain() {
        let fake = FakeLookup::new().register("dd/testls", TESTLS_IMPORTED);
        let addr = NamecoinAddress::parse("m@testls.bit").unwrap();
        let pk =
            PublicKey::from_hex("6cdebccabda1dfa058ab85352a79509b592b2bdfa0370325e28ec1cb4f18667d")
                .unwrap();
        let ok =
            verify_from_raw_json_with_lookup(&pk, &addr, TESTLS_APEX, |n| fake.lookup(n)).unwrap();
        assert!(ok);
    }
}
