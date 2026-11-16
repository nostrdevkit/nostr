// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-98: HTTP Auth
//!
//! This NIP defines an ephemeral event used to authorize requests to HTTP servers using nostr events.
//! This is useful for HTTP services which are build for Nostr and deal with Nostr user accounts.
//!
//! <https://github.com/nostr-protocol/nips/blob/master/98.md>

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "std")]
use base64::engine::{Engine, general_purpose};
use url::Url;

use super::util::{missing_tag_kind, take_and_parse_from_str, unknown_tag};
use crate::error::{Error, ErrorKind};
#[cfg(feature = "std")]
use crate::event::Event;
#[cfg(all(feature = "std", feature = "rand"))]
use crate::event::{AsyncSignEvent, FinalizeEventAsync};
use crate::event::{EventBuilder, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions};
#[cfg(all(feature = "std", feature = "rand"))]
use crate::key::AsyncGetPublicKey;
#[cfg(feature = "std")]
use crate::key::PublicKey;
#[cfg(feature = "std")]
use crate::types::Timestamp;
pub use crate::util::sha256::Sha256Hash;

#[cfg(feature = "std")]
const AUTH_HEADER_PREFIX: &str = "Nostr";
#[cfg(feature = "std")]
// NIP-98 events are small metadata; 64 KiB leaves headroom while bounding HTTP input.
const MAX_AUTH_EVENT_SIZE: usize = 64 * 1024;
#[cfg(feature = "std")]
const MAX_ENCODED_AUTH_EVENT_SIZE: usize = MAX_AUTH_EVENT_SIZE.div_ceil(3) * 4;
const ABSOLUTE_URL: &str = "u";
const METHOD: &str = "method";
const PAYLOAD: &str = "payload";

#[inline]
fn unknown_method() -> Error {
    Error::with_static_message(ErrorKind::Unsupported, "unknown method")
}

#[inline]
fn missing_tag(tag: RequiredTags) -> Error {
    Error::new(ErrorKind::Missing, format!("missing tag: {tag}"))
}

#[inline]
#[cfg(feature = "std")]
fn authorization_header_missing() -> Error {
    Error::with_static_message(ErrorKind::Missing, "authorization header missing")
}

#[inline]
#[cfg(feature = "std")]
fn malformed_authorization_header() -> Error {
    Error::with_static_message(ErrorKind::Malformed, "malformed authorization header")
}

#[inline]
#[cfg(feature = "std")]
fn wrong_auth_header_kind() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "wrong auth header kind")
}

#[inline]
#[cfg(feature = "std")]
fn payload_hash_mismatch() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "payload hash mismatch")
}

/// [`HttpData`] required tags
#[derive(Debug, PartialEq, Eq)]
pub enum RequiredTags {
    /// `u`
    AbsoluteURL,
    /// `method`
    Method,
    /// `payload`
    Payload,
}

impl fmt::Display for RequiredTags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbsoluteURL => f.write_str("u"),
            Self::Method => f.write_str("method"),
            Self::Payload => f.write_str("payload"),
        }
    }
}

/// HTTP Method
///
/// <https://github.com/nostr-protocol/nips/blob/master/98.md>
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpMethod {
    /// GET
    GET,
    /// POST
    POST,
    /// PUT
    PUT,
    /// PATCH
    PATCH,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl HttpMethod {
    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::PATCH => "PATCH",
        }
    }
}

impl FromStr for HttpMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "GET" => Ok(Self::GET),
            "POST" => Ok(Self::POST),
            "PUT" => Ok(Self::PUT),
            "PATCH" => Ok(Self::PATCH),
            _ => Err(unknown_method()),
        }
    }
}

/// HTTP Data
///
/// <https://github.com/nostr-protocol/nips/blob/master/98.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpData {
    /// Absolute request URL
    pub url: Url,
    /// HTTP method
    pub method: HttpMethod,
    /// SHA256 hash of the request body
    pub payload: Option<Sha256Hash>,
}

/// NIP-98 tags
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip98Tag {
    /// `u` tag
    AbsoluteURL(Url),
    /// `method` tag
    Method(HttpMethod),
    /// `payload` tag
    Payload(Sha256Hash),
}

impl_tag_codec_conversions! {
    Nip98Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            ABSOLUTE_URL => {
                let url: Url = take_and_parse_from_str(&mut iter, "absolute URL")?;
                Ok(Self::AbsoluteURL(url))
            }
            METHOD => {
                let method: HttpMethod = take_and_parse_from_str(&mut iter, "method")?;
                Ok(Self::Method(method))
            }
            PAYLOAD => {
                let payload: Sha256Hash = take_and_parse_from_str(&mut iter, "payload")?;
                Ok(Self::Payload(payload))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::AbsoluteURL(url) => Tag::new(vec![String::from(ABSOLUTE_URL), url.to_string()]),
            Self::Method(method) => Tag::new(vec![String::from(METHOD), method.to_string()]),
            Self::Payload(payload) => Tag::new(vec![String::from(PAYLOAD), payload.to_string()]),
        }
    }
}

impl HttpData {
    /// New [`HttpData`]
    #[inline]
    pub fn new(url: Url, method: HttpMethod) -> Self {
        Self {
            url,
            method,
            payload: None,
        }
    }

    /// Add hex-encoded SHA256 hash of the request body
    #[inline]
    pub fn payload(mut self, payload: Sha256Hash) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Build the base64-encoded HTTP `Authorization` header **value**.
    ///
    /// Return a string with the following format: `Nostr <base64>`.
    #[cfg(all(feature = "std", feature = "rand"))]
    pub async fn to_authorization<T>(self, signer: &T) -> Result<String, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let event: Event = self.finalize_async(signer).await?;
        let encoded: String = general_purpose::STANDARD.encode(event.as_json());
        Ok(format!("{AUTH_HEADER_PREFIX} {encoded}"))
    }
}

impl IntoEventBuilder for HttpData {
    fn into_event_builder(self) -> EventBuilder {
        let tags: Vec<Tag> = self.into();
        EventBuilder::new(Kind::HttpAuth).tags(tags)
    }
}

impl From<HttpData> for Vec<Tag> {
    fn from(data: HttpData) -> Self {
        let HttpData {
            url,
            method,
            payload,
        } = data;

        let mut tags: Vec<Tag> = vec![
            Nip98Tag::AbsoluteURL(url).to_tag(),
            Nip98Tag::Method(method).to_tag(),
        ];
        if let Some(payload) = payload {
            tags.push(Nip98Tag::Payload(payload).to_tag());
        }

        tags
    }
}

impl TryFrom<Vec<Tag>> for HttpData {
    type Error = Error;

    fn try_from(value: Vec<Tag>) -> Result<Self, Self::Error> {
        let mut url: Option<Url> = None;
        let mut method: Option<HttpMethod> = None;
        let mut payload: Option<Sha256Hash> = None;

        for tag in value.into_iter() {
            match Nip98Tag::try_from(tag) {
                Ok(Nip98Tag::AbsoluteURL(value)) => url = Some(value),
                Ok(Nip98Tag::Method(value)) => method = Some(value),
                Ok(Nip98Tag::Payload(value)) => payload = Some(value),
                Err(_) => (),
            }
        }

        Ok(Self {
            url: url.ok_or(missing_tag(RequiredTags::AbsoluteURL))?,
            method: method.ok_or(missing_tag(RequiredTags::Method))?,
            payload,
        })
    }
}

/// Verify authentication header
///
/// Returns the event [`PublicKey`] if the authorization is valid.
///
/// This functions execute the following checks:
/// - Extract the prefix and the base64 event from the header;
/// - Decode the base64 event and check if the kind is correct;
/// - Check if the tags are right;
/// - Check if the auth event is too old
/// - If there is a body, verify if the payload hash matches the body hash;
/// - Verify the event ID and signature (to learn more check [`Event::verify`]).
///
/// <https://github.com/nostr-protocol/nips/blob/master/98.md>
#[cfg(feature = "std")]
pub fn verify_auth_header(
    auth_header: &str,
    url: &Url,
    method: HttpMethod,
    current_time: Timestamp,
    body: Option<&[u8]>,
) -> Result<PublicKey, Error> {
    // Original code at https://github.com/damus-io/notepush/blob/63c5f7e7236f7bfe09f665b5fb4a03b412284d13/src/nip98_auth.rs

    if auth_header.is_empty() {
        return Err(authorization_header_missing());
    }

    let (prefix, base64_encoded_event): (&str, &str) = auth_header
        .split_once(' ')
        .ok_or(malformed_authorization_header())?;

    if prefix != AUTH_HEADER_PREFIX || base64_encoded_event.is_empty() {
        return Err(malformed_authorization_header());
    }

    // Bound attacker-controlled input before Base64 allocates its decoded buffer.
    if base64_encoded_event.len() > MAX_ENCODED_AUTH_EVENT_SIZE {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "authorization event too large",
        ));
    }

    // Decode event
    let decoded_event_json: Vec<u8> = general_purpose::STANDARD
        .decode(base64_encoded_event)
        .map_err(Error::malformed)?;
    // Keep the JSON parser bounded even for non-canonical Base64 representations.
    if decoded_event_json.len() > MAX_AUTH_EVENT_SIZE {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "authorization event too large",
        ));
    }
    let event: Event = Event::from_json(decoded_event_json)?;

    // Check event kind
    if event.kind != Kind::HttpAuth {
        return Err(wrong_auth_header_kind());
    }

    let http_data = HttpData::try_from(event.tags.iter().cloned().collect::<Vec<Tag>>())?;
    let authorized_url: Url = http_data.url;
    let authorized_method: HttpMethod = http_data.method;

    if &authorized_url != url || authorized_method != method {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "authorization does not match request",
        ));
    }

    let time_delta = TimeDelta::subtracting(current_time, event.created_at);
    if (time_delta.negative && time_delta.delta_abs_seconds > 30)
        || (!time_delta.negative && time_delta.delta_abs_seconds > 60)
    {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "authorization is too old",
        ));
    }

    if let Some(body_data) = body {
        // Get payload hash
        let payload: Sha256Hash = match http_data.payload {
            Some(p) => p,
            None => return Err(missing_tag(RequiredTags::Payload)),
        };

        // Hash body data
        let body_hash: Sha256Hash = Sha256Hash::hash(body_data);

        // Check if payload and body hash matches
        if payload != body_hash {
            return Err(payload_hash_mismatch());
        }
    }

    // Verify both the Event ID and the cryptographic signature
    event.verify()?;

    Ok(event.pubkey)
}

#[cfg(feature = "std")]
struct TimeDelta {
    pub delta_abs_seconds: u64,
    pub negative: bool,
}

#[cfg(feature = "std")]
impl TimeDelta {
    /// Safely calculate the difference between two timestamps in seconds
    /// This function is safer against overflows than subtracting the timestamps directly
    pub fn subtracting(t1: Timestamp, t2: Timestamp) -> TimeDelta {
        if t1 > t2 {
            TimeDelta {
                delta_abs_seconds: (t1 - t2).as_secs(),
                negative: false,
            }
        } else {
            TimeDelta {
                delta_abs_seconds: (t2 - t1).as_secs(),
                negative: true,
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_nip98_tag_codec() {
        let url = Nip98Tag::parse(["u", "https://example.com/"]).unwrap();
        assert_eq!(
            url,
            Nip98Tag::AbsoluteURL(Url::parse("https://example.com/").unwrap())
        );
        assert_eq!(
            url.to_tag(),
            Tag::parse(["u", "https://example.com/"]).unwrap()
        );

        let method = Nip98Tag::parse(["method", "GET"]).unwrap();
        assert_eq!(method, Nip98Tag::Method(HttpMethod::GET));
        assert_eq!(method.to_tag(), Tag::parse(["method", "GET"]).unwrap());

        let payload_hash = Sha256Hash::from_str(
            "12f8ff0f5f6f023a4ae796a5f5f6d9030434bf2b9bb7a2f4f0f0f971b3e5d79f",
        )
        .unwrap();
        let payload = Nip98Tag::parse([
            "payload",
            "12f8ff0f5f6f023a4ae796a5f5f6d9030434bf2b9bb7a2f4f0f0f971b3e5d79f",
        ])
        .unwrap();
        assert_eq!(payload, Nip98Tag::Payload(payload_hash));
    }

    #[test]
    fn test_nip98_http_data_round_trip() {
        let payload = Sha256Hash::from_str(
            "12f8ff0f5f6f023a4ae796a5f5f6d9030434bf2b9bb7a2f4f0f0f971b3e5d79f",
        )
        .unwrap();
        let data = HttpData::new(
            Url::parse("https://example.com/").unwrap(),
            HttpMethod::POST,
        )
        .payload(payload);

        let tags: Vec<Tag> = data.clone().into();
        let parsed = HttpData::try_from(tags).unwrap();

        assert_eq!(parsed, data);
    }

    #[test]
    fn empty_auth_header() {
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(
            verify_auth_header("", &url, HttpMethod::GET, Timestamp::now(), None)
                .unwrap_err()
                .kind(),
            ErrorKind::Missing
        );
    }

    #[test]
    fn malformed_auth_header() {
        let url = Url::parse("https://example.com/").unwrap();
        let now = Timestamp::now();
        assert_eq!(
            verify_auth_header("Test Nostr", &url, HttpMethod::GET, now, None)
                .unwrap_err()
                .kind(),
            ErrorKind::Malformed
        );
        assert_eq!(
            verify_auth_header("Nostr", &url, HttpMethod::GET, now, None)
                .unwrap_err()
                .kind(),
            ErrorKind::Malformed
        );
        assert_eq!(verify_auth_header("nostr eyJpZCI6ImZlOTY0ZTc1ODkwMzM2MGYyOGQ4NDI0ZDA5MmRhODQ5NGVkMjA3Y2JhODIzMTEwYmUzYTU3ZGZlNGI1Nzg3MzQiLCJwdWJrZXkiOiI2M2ZlNjMxOGRjNTg1ODNjZmUxNjgxMGY4NmRkMDllMThiZmQ3NmFhYmMyNGEwMDgxY2UyODU2ZjMzMDUwNGVkIiwiY29udGVudCI6IiIsImtpbmQiOjI3MjM1LCJjcmVhdGVkX2F0IjoxNjgyMzI3ODUyLCJ0YWdzIjpbWyJ1IiwiaHR0cHM6Ly9hcGkuc25vcnQuc29jaWFsL2FwaS92MS9uNXNwL2xpc3QiXSxbIm1ldGhvZCIsIkdFVCJdXSwic2lnIjoiNWVkOWQ4ZWM5NThiYzg1NGY5OTdiZGMyNGFjMzM3ZDAwNWFmMzcyMzI0NzQ3ZWZlNGEwMGUyNGY0YzMwNDM3ZmY0ZGQ4MzA4Njg0YmVkNDY3ZDlkNmJlM2U1YTUxN2JiNDNiMTczMmNjN2QzMzk0OWEzYWFmODY3MDVjMjIxODQifQ==", &url, HttpMethod::GET, now, None).unwrap_err().kind(), ErrorKind::Malformed);
    }

    #[test]
    fn oversized_auth_event_is_rejected_before_decoding() {
        let url = Url::parse("https://example.com/").unwrap();
        let encoded = "A".repeat(MAX_ENCODED_AUTH_EVENT_SIZE + 1);
        let header = format!("{AUTH_HEADER_PREFIX} {encoded}");

        let err =
            verify_auth_header(&header, &url, HttpMethod::GET, Timestamp::now(), None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "authorization event too large");
    }

    #[test]
    fn maximum_sized_auth_event_reaches_json_parser() {
        let url = Url::parse("https://example.com/").unwrap();
        let decoded = vec![b' '; MAX_AUTH_EVENT_SIZE];
        let encoded = general_purpose::STANDARD.encode(decoded);
        let header = format!("{AUTH_HEADER_PREFIX} {encoded}");

        let err =
            verify_auth_header(&header, &url, HttpMethod::GET, Timestamp::now(), None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn auth_header_wrong_kind() {
        let url = Url::parse("https://example.com/").unwrap();
        let now = Timestamp::now();
        assert_eq!(verify_auth_header("Nostr eyJpZCI6ImZlOTY0ZTc1ODkwMzM2MGYyOGQ4NDI0ZDA5MmRhODQ5NGVkMjA3Y2JhODIzMTEwYmUzYTU3ZGZlNGI1Nzg3MzQiLCJwdWJrZXkiOiI2M2ZlNjMxOGRjNTg1ODNjZmUxNjgxMGY4NmRkMDllMThiZmQ3NmFhYmMyNGEwMDgxY2UyODU2ZjMzMDUwNGVkIiwiY29udGVudCI6IiIsImtpbmQiOjEsImNyZWF0ZWRfYXQiOjE2ODIzMjc4NTIsInRhZ3MiOltbInUiLCJodHRwczovL2FwaS5zbm9ydC5zb2NpYWwvYXBpL3YxL241c3AvbGlzdCJdLFsibWV0aG9kIiwiR0VUIl1dLCJzaWciOiI1ZWQ5ZDhlYzk1OGJjODU0Zjk5N2JkYzI0YWMzMzdkMDA1YWYzNzIzMjQ3NDdlZmU0YTAwZTI0ZjRjMzA0MzdmZjRkZDgzMDg2ODRiZWQ0NjdkOWQ2YmUzZTVhNTE3YmI0M2IxNzMyY2M3ZDMzOTQ5YTNhYWY4NjcwNWMyMjE4NCJ9", &url, HttpMethod::GET, now, None).unwrap_err().kind(), ErrorKind::Invalid);
    }

    #[test]
    fn auth_header_not_match_request() {
        let url = Url::parse("https://example.com/").unwrap(); // Expected url: https://api.snort.social/api/v1/n5sp/list
        let now = Timestamp::now();
        let method = HttpMethod::POST;
        assert_eq!(
            verify_auth_header("Nostr eyJpZCI6ImZlOTY0ZTc1ODkwMzM2MGYyOGQ4NDI0ZDA5MmRhODQ5NGVkMjA3Y2JhODIzMTEwYmUzYTU3ZGZlNGI1Nzg3MzQiLCJwdWJrZXkiOiI2M2ZlNjMxOGRjNTg1ODNjZmUxNjgxMGY4NmRkMDllMThiZmQ3NmFhYmMyNGEwMDgxY2UyODU2ZjMzMDUwNGVkIiwiY29udGVudCI6IiIsImtpbmQiOjI3MjM1LCJjcmVhdGVkX2F0IjoxNjgyMzI3ODUyLCJ0YWdzIjpbWyJ1IiwiaHR0cHM6Ly9hcGkuc25vcnQuc29jaWFsL2FwaS92MS9uNXNwL2xpc3QiXSxbIm1ldGhvZCIsIkdFVCJdXSwic2lnIjoiNWVkOWQ4ZWM5NThiYzg1NGY5OTdiZGMyNGFjMzM3ZDAwNWFmMzcyMzI0NzQ3ZWZlNGEwMGUyNGY0YzMwNDM3ZmY0ZGQ4MzA4Njg0YmVkNDY3ZDlkNmJlM2U1YTUxN2JiNDNiMTczMmNjN2QzMzk0OWEzYWFmODY3MDVjMjIxODQifQ==", &url, method, now, None).unwrap_err().kind(),
           ErrorKind::Invalid
        );
    }

    #[test]
    fn auth_header_too_old() {
        let url = Url::parse("https://api.snort.social/api/v1/n5sp/list").unwrap();
        let method = HttpMethod::GET;
        let now = Timestamp::from_secs(1777777777);
        assert_eq!(
            verify_auth_header("Nostr eyJpZCI6ImZlOTY0ZTc1ODkwMzM2MGYyOGQ4NDI0ZDA5MmRhODQ5NGVkMjA3Y2JhODIzMTEwYmUzYTU3ZGZlNGI1Nzg3MzQiLCJwdWJrZXkiOiI2M2ZlNjMxOGRjNTg1ODNjZmUxNjgxMGY4NmRkMDllMThiZmQ3NmFhYmMyNGEwMDgxY2UyODU2ZjMzMDUwNGVkIiwiY29udGVudCI6IiIsImtpbmQiOjI3MjM1LCJjcmVhdGVkX2F0IjoxNjgyMzI3ODUyLCJ0YWdzIjpbWyJ1IiwiaHR0cHM6Ly9hcGkuc25vcnQuc29jaWFsL2FwaS92MS9uNXNwL2xpc3QiXSxbIm1ldGhvZCIsIkdFVCJdXSwic2lnIjoiNWVkOWQ4ZWM5NThiYzg1NGY5OTdiZGMyNGFjMzM3ZDAwNWFmMzcyMzI0NzQ3ZWZlNGEwMGUyNGY0YzMwNDM3ZmY0ZGQ4MzA4Njg0YmVkNDY3ZDlkNmJlM2U1YTUxN2JiNDNiMTczMmNjN2QzMzk0OWEzYWFmODY3MDVjMjIxODQifQ==", &url, method, now, None).unwrap_err().kind(),
            ErrorKind::Invalid
        );
    }

    #[test]
    fn valid_auth_header() {
        let url = Url::parse("https://example.com").unwrap();
        let method = HttpMethod::GET;
        let now = Timestamp::from_secs(1742462605);
        let public_key =
            PublicKey::from_hex("aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4")
                .unwrap();
        assert_eq!(verify_auth_header("Nostr eyJpZCI6IjEyYjQ2YmUwMDg5MjI3OWU3YmJhYThlYTg5ODA5ZWNiMWYyYzk5MmY1ZDk0ZWRmMmNkYmQ2Y2JhNmVlMzBjMDMiLCJwdWJrZXkiOiJhYTRmYzg2NjVmNTY5NmUzM2RiN2UxYTU3MmUzYjBmNWIzZDYxNTgzN2IwZjM2MmRjYjFjODA2OGIwOThjN2I0IiwiY3JlYXRlZF9hdCI6MTc0MjQ2MjYwNSwia2luZCI6MjcyMzUsInRhZ3MiOltbInUiLCJodHRwczovL2V4YW1wbGUuY29tLyJdLFsibWV0aG9kIiwiR0VUIl1dLCJjb250ZW50IjoiIiwic2lnIjoiZWEzNGU3NDA3ZGQ2OTFjNDJhYzY3ZjQ3YTMwYjBmMDEwZTFiYWYwMjM3MjhiNzI4OGFlYzA0Zjg3MzMyYmZlYTRhZjJkNDdiNTJiMjhkNGMxMGMwOWY3NmNiZGFhNWZjMTE0OTNiOTlkZTU2NDhmMzlhM2JkYzMwYjQxMTNjNjMifQ==", &url, method, now, None).unwrap(), public_key);
    }
}
