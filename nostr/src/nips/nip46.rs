// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP46: Nostr Connect
//!
//! <https://github.com/nostr-protocol/nips/blob/master/46.md>

use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::str::FromStr;

#[cfg(feature = "rand")]
use rand::Rng;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rand_core::UnwrapErr;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rngs::SysRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::nip44::{AsyncNip44, Nip44};
use super::util::{invalid_uri, unexpected_result, unsupported_method};
use crate::error::{Error, ErrorKind};
use crate::event::{
    AsyncSignEvent, Event, EventBuilder, FinalizeEvent, FinalizeEventAsync, Kind, SignEvent,
    UnsignedEvent,
};
use crate::key::{AsyncGetPublicKey, GetPublicKey, PublicKey};
use crate::types::url::{RelayUrl, Url};
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::util;
use crate::util::{impl_json_methods, parse_json};

/// NIP46 URI Scheme
pub const NOSTR_CONNECT_URI_SCHEME: &str = "nostrconnect";
/// NIP46 bunker URI Scheme
pub const NOSTR_CONNECT_BUNKER_URI_SCHEME: &str = "bunker";

#[inline]
fn invalid_params_length() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "invalid params length")
}

#[inline]
fn invalid_request() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "invalid request")
}

#[inline]
fn not_request() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "not a request")
}

/// NIP46 method
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NostrConnectMethod {
    /// Connect
    Connect,
    /// Get public key
    GetPublicKey,
    /// Sign event
    SignEvent,
    /// Encrypt text (NIP04)
    Nip04Encrypt,
    /// Decrypt (NIP04)
    Nip04Decrypt,
    /// Encrypt text (NIP44)
    Nip44Encrypt,
    /// Decrypt (NIP44)
    Nip44Decrypt,
    /// Ping
    Ping,
}

impl fmt::Display for NostrConnectMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => write!(f, "connect"),
            Self::GetPublicKey => write!(f, "get_public_key"),
            Self::SignEvent => write!(f, "sign_event"),
            Self::Nip04Encrypt => write!(f, "nip04_encrypt"),
            Self::Nip04Decrypt => write!(f, "nip04_decrypt"),
            Self::Nip44Encrypt => write!(f, "nip44_encrypt"),
            Self::Nip44Decrypt => write!(f, "nip44_decrypt"),
            Self::Ping => write!(f, "ping"),
        }
    }
}

impl FromStr for NostrConnectMethod {
    type Err = Error;

    fn from_str(method: &str) -> Result<Self, Self::Err> {
        match method {
            "connect" => Ok(Self::Connect),
            "get_public_key" => Ok(Self::GetPublicKey),
            "sign_event" => Ok(Self::SignEvent),
            "nip04_encrypt" => Ok(Self::Nip04Encrypt),
            "nip04_decrypt" => Ok(Self::Nip04Decrypt),
            "nip44_encrypt" => Ok(Self::Nip44Encrypt),
            "nip44_decrypt" => Ok(Self::Nip44Decrypt),
            "ping" => Ok(Self::Ping),
            other => Err(unsupported_method(other)),
        }
    }
}

impl Serialize for NostrConnectMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NostrConnectMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let method: String = String::deserialize(deserializer)?;
        Self::from_str(&method).map_err(serde::de::Error::custom)
    }
}

/// Nostr Connect Request
#[derive(Clone, PartialEq, Eq)]
pub enum NostrConnectRequest {
    /// Connect
    Connect {
        /// Remote signer public key
        remote_signer_public_key: PublicKey,
        /// Optional secret
        secret: Option<String>,
    },
    /// Get public key
    GetPublicKey,
    /// Sign [`UnsignedEvent`]
    SignEvent(UnsignedEvent),
    /// Encrypt text (NIP04)
    Nip04Encrypt {
        /// Pubkey
        public_key: PublicKey,
        /// Plain text
        text: String,
    },
    /// Decrypt (NIP04)
    Nip04Decrypt {
        /// Pubkey
        public_key: PublicKey,
        /// Ciphertext
        ciphertext: String,
    },
    /// Encrypt text (NIP44)
    Nip44Encrypt {
        /// Pubkey
        public_key: PublicKey,
        /// Plain text
        text: String,
    },
    /// Decrypt (NIP44)
    Nip44Decrypt {
        /// Pubkey
        public_key: PublicKey,
        /// Ciphertext
        ciphertext: String,
    },
    /// Ping
    Ping,
}

impl fmt::Debug for NostrConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect {
                remote_signer_public_key,
                secret,
            } => f
                .debug_struct("Connect")
                .field("remote_signer_public_key", remote_signer_public_key)
                .field("secret", &secret.as_ref().map(|_| "[REDACTED]"))
                .finish(),
            Self::GetPublicKey => f.write_str("GetPublicKey"),
            Self::SignEvent(_) => f.debug_tuple("SignEvent").field(&"[REDACTED]").finish(),
            Self::Nip04Encrypt { public_key, .. } => f
                .debug_struct("Nip04Encrypt")
                .field("public_key", public_key)
                .field("text", &"[REDACTED]")
                .finish(),
            Self::Nip04Decrypt { public_key, .. } => f
                .debug_struct("Nip04Decrypt")
                .field("public_key", public_key)
                .field("ciphertext", &"[REDACTED]")
                .finish(),
            Self::Nip44Encrypt { public_key, .. } => f
                .debug_struct("Nip44Encrypt")
                .field("public_key", public_key)
                .field("text", &"[REDACTED]")
                .finish(),
            Self::Nip44Decrypt { public_key, .. } => f
                .debug_struct("Nip44Decrypt")
                .field("public_key", public_key)
                .field("ciphertext", &"[REDACTED]")
                .finish(),
            Self::Ping => f.write_str("Ping"),
        }
    }
}

impl NostrConnectRequest {
    /// Compose [`NostrConnectRequest`] from message details
    pub fn from_message(method: NostrConnectMethod, params: Vec<String>) -> Result<Self, Error> {
        match method {
            NostrConnectMethod::Connect => {
                let remote_signer_public_key: &String = params.first().ok_or(invalid_request())?;
                let remote_signer_public_key: PublicKey =
                    PublicKey::from_hex(remote_signer_public_key)?;
                let secret: Option<String> = params.get(1).cloned();
                Ok(Self::Connect {
                    remote_signer_public_key,
                    secret,
                })
            }
            NostrConnectMethod::GetPublicKey => Ok(Self::GetPublicKey),
            NostrConnectMethod::SignEvent => {
                let unsigned: &String = params.first().ok_or(invalid_request())?;
                let unsigned_event: UnsignedEvent = UnsignedEvent::from_json(unsigned)?;
                Ok(Self::SignEvent(unsigned_event))
            }
            NostrConnectMethod::Nip04Encrypt => {
                if params.len() != 2 {
                    return Err(invalid_params_length());
                }

                Ok(Self::Nip04Encrypt {
                    public_key: PublicKey::from_hex(&params[0])?,
                    text: params[1].to_owned(),
                })
            }
            NostrConnectMethod::Nip04Decrypt => {
                if params.len() != 2 {
                    return Err(invalid_params_length());
                }

                Ok(Self::Nip04Decrypt {
                    public_key: PublicKey::from_hex(&params[0])?,
                    ciphertext: params[1].to_owned(),
                })
            }
            NostrConnectMethod::Nip44Encrypt => {
                if params.len() != 2 {
                    return Err(invalid_params_length());
                }

                Ok(Self::Nip44Encrypt {
                    public_key: PublicKey::from_hex(&params[0])?,
                    text: params[1].to_owned(),
                })
            }
            NostrConnectMethod::Nip44Decrypt => {
                if params.len() != 2 {
                    return Err(invalid_params_length());
                }

                Ok(Self::Nip44Decrypt {
                    public_key: PublicKey::from_hex(&params[0])?,
                    ciphertext: params[1].to_owned(),
                })
            }
            NostrConnectMethod::Ping => Ok(Self::Ping),
        }
    }

    /// Get req method
    pub fn method(&self) -> NostrConnectMethod {
        match self {
            Self::Connect { .. } => NostrConnectMethod::Connect,
            Self::GetPublicKey => NostrConnectMethod::GetPublicKey,
            Self::SignEvent(_) => NostrConnectMethod::SignEvent,
            Self::Nip04Encrypt { .. } => NostrConnectMethod::Nip04Encrypt,
            Self::Nip04Decrypt { .. } => NostrConnectMethod::Nip04Decrypt,
            Self::Nip44Encrypt { .. } => NostrConnectMethod::Nip44Encrypt,
            Self::Nip44Decrypt { .. } => NostrConnectMethod::Nip44Decrypt,
            Self::Ping => NostrConnectMethod::Ping,
        }
    }

    /// Get req params
    pub fn params(&self) -> Vec<String> {
        match self {
            Self::Connect {
                remote_signer_public_key,
                secret,
            } => {
                let mut params = vec![remote_signer_public_key.to_hex()];
                if let Some(secret) = secret {
                    params.push(secret.to_owned());
                }
                params
            }
            Self::GetPublicKey => Vec::new(),
            Self::SignEvent(event) => vec![event.as_json()],
            Self::Nip04Encrypt { public_key, text } | Self::Nip44Encrypt { public_key, text } => {
                vec![public_key.to_hex(), text.to_owned()]
            }
            Self::Nip04Decrypt {
                public_key,
                ciphertext,
            }
            | Self::Nip44Decrypt {
                public_key,
                ciphertext,
            } => vec![public_key.to_hex(), ciphertext.to_owned()],
            Self::Ping => Vec::new(),
        }
    }
}

/// Response
#[derive(Clone, PartialEq, Eq)]
pub enum ResponseResult {
    /// Connect ACK (returned by signers using the `bunker://` flow or older implementations)
    Ack,
    /// Connect secret echo (returned by signers using the `nostrconnect://` client-initiated flow)
    ///
    /// Per NIP-46, when a `nostrconnect://` URI includes a `secret`, the remote signer must
    /// return that exact secret value as the `result` of the `connect` response.
    /// The client MUST validate this value to prevent connection spoofing.
    ConnectSecret(String),
    /// Get public key
    GetPublicKey(PublicKey),
    /// Sign event
    SignEvent(Box<Event>),
    /// Encrypt text (NIP04)
    Nip04Encrypt {
        /// Cipher text
        ciphertext: String,
    },
    /// Decrypt (NIP04)
    Nip04Decrypt {
        /// Plain text
        plaintext: String,
    },
    /// Encrypt text (NIP44)
    Nip44Encrypt {
        /// Cipher text
        ciphertext: String,
    },
    /// Decrypt (NIP44)
    Nip44Decrypt {
        /// Plain text
        plaintext: String,
    },
    /// Pong
    Pong,
    /// Auth Challenges
    AuthUrl,
    /// Error
    Error,
}

impl fmt::Debug for ResponseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ack => f.write_str("Ack"),
            Self::ConnectSecret(_) => f.debug_tuple("ConnectSecret").field(&"[REDACTED]").finish(),
            Self::GetPublicKey(public_key) => {
                f.debug_tuple("GetPublicKey").field(public_key).finish()
            }
            Self::SignEvent(_) => f.debug_tuple("SignEvent").field(&"[REDACTED]").finish(),
            Self::Nip04Encrypt { .. } => f
                .debug_struct("Nip04Encrypt")
                .field("ciphertext", &"[REDACTED]")
                .finish(),
            Self::Nip04Decrypt { .. } => f
                .debug_struct("Nip04Decrypt")
                .field("plaintext", &"[REDACTED]")
                .finish(),
            Self::Nip44Encrypt { .. } => f
                .debug_struct("Nip44Encrypt")
                .field("ciphertext", &"[REDACTED]")
                .finish(),
            Self::Nip44Decrypt { .. } => f
                .debug_struct("Nip44Decrypt")
                .field("plaintext", &"[REDACTED]")
                .finish(),
            Self::Pong => f.write_str("Pong"),
            Self::AuthUrl => f.write_str("AuthUrl"),
            Self::Error => f.write_str("Error"),
        }
    }
}

/// Nostr Connect Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrConnectResponse {
    /// Response result
    pub result: Option<ResponseResult>,
    /// Response error
    pub error: Option<String>,
}

impl NostrConnectResponse {
    /// New response
    #[inline]
    pub fn new(result: Option<ResponseResult>, error: Option<String>) -> Self {
        Self { result, error }
    }

    /// New response with result
    #[inline]
    pub fn with_result(result: ResponseResult) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }

    /// New response with error
    #[inline]
    pub fn with_error<S>(error: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            result: None,
            error: Some(error.into()),
        }
    }

    /// Parse response
    pub fn parse(
        method: NostrConnectMethod,
        result: Option<String>,
        error: Option<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            result: match result {
                Some(result) => Some(ResponseResult::parse(method, result)?),
                None => None,
            },
            error,
        })
    }

    /// Check if the response is an auth URL
    #[inline]
    pub fn is_auth_url(&self) -> bool {
        match &self.result {
            Some(res) => res.is_auth_url(),
            None => false,
        }
    }
}

impl fmt::Display for ResponseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ack => write!(f, "ack"),
            Self::ConnectSecret(secret) => write!(f, "{secret}"),
            Self::GetPublicKey(public_key) => write!(f, "{public_key}"),
            Self::SignEvent(event) => write!(f, "{}", event.as_json()),
            Self::Nip04Encrypt { ciphertext } | Self::Nip44Encrypt { ciphertext } => {
                write!(f, "{ciphertext}")
            }
            Self::Nip04Decrypt { plaintext } | Self::Nip44Decrypt { plaintext } => {
                write!(f, "{plaintext}")
            }
            Self::Pong => write!(f, "pong"),
            Self::AuthUrl => write!(f, "auth_url"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[allow(missing_docs)]
impl ResponseResult {
    pub fn parse<S>(method: NostrConnectMethod, response: S) -> Result<Self, Error>
    where
        S: Into<String>,
    {
        let response: String = response.into();

        // Check if the response is an Auth URL or an error
        match response.as_str() {
            "auth_url" => return Ok(Self::AuthUrl),
            "error" => return Ok(Self::Error),
            _ => {}
        };

        // Parse response depending on the request method
        match method {
            NostrConnectMethod::Connect => {
                if response == "ack" {
                    Ok(Self::Ack)
                } else {
                    // Per NIP-46, for nostrconnect:// (client-initiated) connections the signer
                    // returns the secret value from the URI as the connect response result.
                    Ok(Self::ConnectSecret(response))
                }
            }
            NostrConnectMethod::GetPublicKey => {
                Ok(Self::GetPublicKey(PublicKey::from_hex(&response)?))
            }
            NostrConnectMethod::SignEvent => {
                Ok(Self::SignEvent(Box::new(Event::from_json(response)?)))
            }
            NostrConnectMethod::Nip04Encrypt => Ok(Self::Nip04Encrypt {
                ciphertext: response,
            }),
            NostrConnectMethod::Nip04Decrypt => Ok(Self::Nip04Decrypt {
                plaintext: response,
            }),
            NostrConnectMethod::Nip44Encrypt => Ok(Self::Nip44Encrypt {
                ciphertext: response,
            }),
            NostrConnectMethod::Nip44Decrypt => Ok(Self::Nip44Decrypt {
                plaintext: response,
            }),
            NostrConnectMethod::Ping => {
                if response == "pong" {
                    Ok(Self::Pong)
                } else {
                    Err(unexpected_result())
                }
            }
        }
    }

    #[inline]
    pub fn is_auth_url(&self) -> bool {
        matches!(self, Self::AuthUrl)
    }

    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }

    #[inline]
    pub fn to_get_public_key(self) -> Result<PublicKey, Error> {
        if let Self::GetPublicKey(val) = self {
            Ok(val)
        } else {
            Err(unexpected_result())
        }
    }

    #[inline]
    pub fn to_sign_event(self) -> Result<Event, Error> {
        if let Self::SignEvent(val) = self {
            Ok(*val)
        } else {
            Err(unexpected_result())
        }
    }

    #[inline]
    pub fn to_nip04_encrypt(self) -> Result<String, Error> {
        if let Self::Nip04Encrypt { ciphertext } = self {
            Ok(ciphertext)
        } else {
            Err(unexpected_result())
        }
    }

    #[inline]
    pub fn to_nip04_decrypt(self) -> Result<String, Error> {
        if let Self::Nip04Decrypt { plaintext } = self {
            Ok(plaintext)
        } else {
            Err(unexpected_result())
        }
    }

    #[inline]
    pub fn to_nip44_encrypt(self) -> Result<String, Error> {
        if let Self::Nip44Encrypt { ciphertext } = self {
            Ok(ciphertext)
        } else {
            Err(unexpected_result())
        }
    }

    #[inline]
    pub fn to_nip44_decrypt(self) -> Result<String, Error> {
        if let Self::Nip44Decrypt { plaintext } = self {
            Ok(plaintext)
        } else {
            Err(unexpected_result())
        }
    }

    #[inline]
    pub fn to_pong(self) -> Result<(), Error> {
        if let Self::Pong = self {
            Ok(())
        } else {
            Err(unexpected_result())
        }
    }
}

/// Nostr Connect Message
///
/// <https://github.com/nostr-protocol/nips/blob/master/46.md>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NostrConnectMessage {
    /// Request
    Request {
        /// Request ID
        id: String,
        /// Request method
        method: NostrConnectMethod,
        /// Request params
        params: Vec<String>,
    },
    /// Response
    Response {
        /// Request id
        id: String,
        /// Result
        result: Option<String>,
        /// Reason, if failed
        error: Option<String>,
    },
}

impl fmt::Debug for NostrConnectMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request { id, method, params } => f
                .debug_struct("Request")
                .field("id", id)
                .field("method", method)
                .field(
                    "params",
                    &format_args!("[REDACTED; {} items]", params.len()),
                )
                .finish(),
            Self::Response { id, result, error } => f
                .debug_struct("Response")
                .field("id", id)
                .field("result", &result.as_ref().map(|_| "[REDACTED]"))
                .field("error", error)
                .finish(),
        }
    }
}

impl fmt::Display for NostrConnectMessage {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl NostrConnectMessage {
    /// Compose [`NostrConnectMessage::Request`] from [`NostrConnectRequest`].
    #[inline]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn request(req: &NostrConnectRequest) -> Self {
        Self::request_with_rng(&mut UnwrapErr(SysRng), req)
    }

    /// Compose [`NostrConnectMessage::Request`] from [`NostrConnectRequest`].
    #[inline]
    #[cfg(feature = "rand")]
    pub fn request_with_rng<R>(rng: &mut R, req: &NostrConnectRequest) -> Self
    where
        R: Rng,
    {
        Self::Request {
            id: rng.next_u32().to_string(),
            method: req.method(),
            params: req.params(),
        }
    }

    /// Compose [`NostrConnectMessage::Response`] from [`NostrConnectResponse`].
    #[inline]
    pub fn response<S>(req_id: S, res: NostrConnectResponse) -> Self
    where
        S: Into<String>,
    {
        Self::Response {
            id: req_id.into(),
            result: res.result.map(|res| res.to_string()),
            error: res.error,
        }
    }

    /// Get [`NostrConnectMessage`] id
    #[inline]
    pub fn id(&self) -> &str {
        match self {
            Self::Request { id, .. } => id,
            Self::Response { id, .. } => id,
        }
    }

    /// Check if the current [`NostrConnectMessage`] is a request.
    #[inline]
    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request { .. })
    }

    /// Check if the current [`NostrConnectMessage`] is a response.
    #[inline]
    pub fn is_response(&self) -> bool {
        matches!(self, Self::Response { .. })
    }

    /// Convert [`NostrConnectMessage::Request`] to [`NostrConnectRequest`].
    #[inline]
    pub fn to_request(self) -> Result<NostrConnectRequest, Error> {
        match self {
            Self::Request { method, params, .. } => {
                NostrConnectRequest::from_message(method, params)
            }
            _ => Err(not_request()),
        }
    }

    /// Convert [`NostrConnectMessage::Response`] to [`NostrConnectResponse`].
    #[inline]
    pub fn to_response(self, method: NostrConnectMethod) -> Result<NostrConnectResponse, Error> {
        match self {
            Self::Response { result, error, .. } => {
                NostrConnectResponse::parse(method, result, error)
            }
            _ => Err(not_request()),
        }
    }
}

impl_json_methods!(NostrConnectMessage);

/// Nostr Connect Metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NostrConnectMetadata {
    /// Human-readable name of the `App`
    pub name: String,
    /// URL of the website requesting the connection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,
    /// Description of the `App`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Array of URLs for icons of the `App`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<Url>>,
}

impl NostrConnectMetadata {
    /// New Nostr Connect Metadata
    #[inline]
    pub fn new<S>(name: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            name: name.into(),
            url: None,
            description: None,
            icons: None,
        }
    }

    /// Set url
    pub fn url(self, url: Url) -> Self {
        Self {
            url: Some(url),
            ..self
        }
    }

    /// Set description
    pub fn description<S>(self, description: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            description: Some(description.into()),
            ..self
        }
    }

    /// Set icons
    pub fn icons(self, icons: Vec<Url>) -> Self {
        Self {
            icons: Some(icons),
            ..self
        }
    }
}

impl_json_methods!(NostrConnectMetadata);

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "use `NostrConnectUri` instead")]
pub type NostrConnectURI = NostrConnectUri;

/// Nostr Connect URI
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum NostrConnectUri {
    /// Direct connection initiated by remote signer
    Bunker {
        /// Remote signer public key
        remote_signer_public_key: PublicKey,
        /// List of relays to use
        relays: Vec<RelayUrl>,
        /// Optional secret
        secret: Option<String>,
    },
    /// Direct connection initiated by the client
    Client {
        /// App Pubkey
        public_key: PublicKey,
        /// URLs of the relays of choice where the `App` is connected and the `Signer` must send and listen for messages.
        relays: Vec<RelayUrl>,
        /// Metadata
        metadata: NostrConnectMetadata,
        /// Secret value that the remote signer must return in the `connect` response.
        ///
        /// Per NIP-46, `secret` is required in `nostrconnect://` URIs to prevent connection spoofing.
        /// The client MUST validate that the signer returns this exact value.
        secret: String,
    },
}

impl fmt::Debug for NostrConnectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bunker {
                remote_signer_public_key,
                relays,
                secret,
            } => f
                .debug_struct("Bunker")
                .field("remote_signer_public_key", remote_signer_public_key)
                .field("relays", relays)
                .field("secret", &secret.as_ref().map(|_| "[REDACTED]"))
                .finish(),
            Self::Client {
                public_key,
                relays,
                metadata,
                ..
            } => f
                .debug_struct("Client")
                .field("public_key", public_key)
                .field("relays", relays)
                .field("metadata", metadata)
                .field("secret", &"[REDACTED]")
                .finish(),
        }
    }
}

impl NostrConnectUri {
    /// Construct a new `nostrconnect://` URI with a randomly generated secret
    ///
    /// Per NIP-46, the `secret` is required in `nostrconnect://` URIs to prevent connection
    /// spoofing. The remote signer must return this secret in the `connect` response.
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn client<I, S>(public_key: PublicKey, relays: I, app_name: S) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
        S: Into<String>,
    {
        let mut rng = UnwrapErr(SysRng);
        let secret: String = util::random_hex_string::<_, 16>(&mut rng);
        Self::client_with_secret(public_key, relays, app_name, secret)
    }

    /// Construct a new `nostrconnect://` URI with a provided secret
    ///
    /// Per NIP-46, the `secret` is required in `nostrconnect://` URIs to prevent connection
    /// spoofing. The remote signer must return this secret in the `connect` response.
    pub fn client_with_secret<I, S, T>(
        public_key: PublicKey,
        relays: I,
        app_name: S,
        secret: T,
    ) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
        S: Into<String>,
        T: Into<String>,
    {
        Self::Client {
            public_key,
            relays: relays.into_iter().collect(),
            metadata: NostrConnectMetadata::new(app_name),
            secret: secret.into(),
        }
    }

    /// Parse Nostr Connect URI
    pub fn parse<S>(uri: S) -> Result<Self, Error>
    where
        S: AsRef<str>,
    {
        let uri: &str = uri.as_ref();
        let uri: Url = Url::parse(uri).map_err(|_| invalid_uri())?;

        match uri.scheme() {
            NOSTR_CONNECT_BUNKER_URI_SCHEME => {
                if let Some(pubkey) = uri.domain() {
                    let public_key = PublicKey::from_hex(pubkey)?;

                    let mut relays: Vec<RelayUrl> = Vec::new();
                    let mut secret: Option<String> = None;

                    for (key, value) in uri.query_pairs() {
                        match key {
                            Cow::Borrowed("relay") => {
                                let value = value.to_string();
                                relays.push(RelayUrl::parse(&value)?);
                            }
                            Cow::Borrowed("secret") => {
                                secret = Some(value.to_string());
                            }
                            _ => (),
                        }
                    }

                    return Ok(Self::Bunker {
                        remote_signer_public_key: public_key,
                        relays,
                        secret,
                    });
                }

                Err(invalid_uri())
            }
            NOSTR_CONNECT_URI_SCHEME => {
                if let Some(pubkey) = uri.domain() {
                    let public_key = PublicKey::from_hex(pubkey)?;

                    let mut relays: Vec<RelayUrl> = Vec::new();
                    let mut metadata: Option<NostrConnectMetadata> = None;
                    let mut secret: Option<String> = None;

                    for (key, value) in uri.query_pairs() {
                        match key {
                            Cow::Borrowed("relay") => {
                                let value = value.to_string();
                                relays.push(RelayUrl::parse(&value)?);
                            }
                            Cow::Borrowed("metadata") => {
                                let value = value.to_string();
                                metadata = Some(parse_json(&value)?);
                            }
                            Cow::Borrowed("secret") => {
                                secret = Some(value.to_string());
                            }
                            _ => (),
                        }
                    }

                    if let (Some(metadata), Some(secret)) = (metadata, secret) {
                        return Ok(Self::Client {
                            public_key,
                            relays,
                            metadata,
                            secret,
                        });
                    }
                }

                Err(invalid_uri())
            }
            _ => Err(invalid_uri()),
        }
    }

    /// Check if is `bunker` URI
    #[inline]
    pub fn is_bunker(&self) -> bool {
        matches!(self, Self::Bunker { .. })
    }

    /// Get remote signer public key (exists only for `bunker` URIs)
    ///
    /// This public key MAY be same as the user one, but not necessarily.
    #[inline]
    pub fn remote_signer_public_key(&self) -> Option<&PublicKey> {
        match self {
            Self::Bunker {
                remote_signer_public_key,
                ..
            } => Some(remote_signer_public_key),
            Self::Client { .. } => None,
        }
    }

    /// Get relays
    #[inline]
    pub fn relays(&self) -> &[RelayUrl] {
        match self {
            Self::Bunker { relays, .. } => relays.as_slice(),
            Self::Client { relays, .. } => relays.as_slice(),
        }
    }

    /// Get secret
    ///
    /// For `bunker://` URIs this is an optional one-time connection secret.
    /// For `nostrconnect://` URIs this is the required anti-spoofing secret that the
    /// remote signer must echo back in the `connect` response.
    #[inline]
    pub fn secret(&self) -> Option<&str> {
        match self {
            Self::Bunker { secret, .. } => secret.as_deref(),
            Self::Client { secret, .. } => Some(secret.as_str()),
        }
    }
}

/// Nostr Connect event builder
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct NostrConnectEventBuilder {
    /// Receiver public key
    pub receiver: PublicKey,
    /// The Nostr Connect message
    pub message: NostrConnectMessage,
}

impl NostrConnectEventBuilder {
    /// Create a new Nostr Connect event builder
    #[inline]
    pub fn new(receiver: PublicKey, message: NostrConnectMessage) -> Self {
        Self { receiver, message }
    }
}

impl<S> FinalizeEvent<S> for NostrConnectEventBuilder
where
    S: GetPublicKey + SignEvent + Nip44,
{
    type Error = Error;

    fn finalize(self, signer: &S) -> Result<Event, Self::Error> {
        let json: String = self.message.as_json();
        let content: String = signer
            .nip44_encrypt(&self.receiver, &json)
            .map_err(Error::crypto)?;
        make_event_builder(content, self.receiver).finalize(signer)
    }
}

impl<S> FinalizeEventAsync<S> for NostrConnectEventBuilder
where
    S: AsyncGetPublicKey + AsyncSignEvent + AsyncNip44,
{
    type Error = Error;

    fn finalize_async<'a>(
        self,
        signer: &'a S,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + 'a>>
    where
        Self: 'a,
        S: 'a,
    {
        Box::pin(async move {
            let json: String = self.message.as_json();
            let content: String = signer
                .nip44_encrypt_async(&self.receiver, &json)
                .await
                .map_err(Error::crypto)?;
            make_event_builder(content, self.receiver)
                .finalize_async(signer)
                .await
        })
    }
}

#[inline]
fn make_event_builder(nip44_encrypted_content: String, receiver: PublicKey) -> EventBuilder {
    EventBuilder::new(Kind::NostrConnect)
        .content(nip44_encrypted_content)
        .tag(receiver)
}

impl FromStr for NostrConnectUri {
    type Err = Error;

    #[inline]
    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        Self::parse(uri)
    }
}

impl fmt::Display for NostrConnectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bunker {
                remote_signer_public_key,
                relays,
                secret,
            } => {
                let mut query: String = String::new();

                for relay_url in relays.iter() {
                    let relay_url = relay_url.to_string();
                    let relay_url = relay_url.strip_suffix('/').unwrap_or(&relay_url);

                    if !query.is_empty() {
                        query.push('&');
                    }

                    query.push_str("relay=");
                    query.push_str(relay_url);
                }

                if let Some(secret) = secret {
                    if !query.is_empty() {
                        query.push('&');
                    }

                    query.push_str("secret=");
                    query.push_str(secret);
                }

                if query.is_empty() {
                    write!(
                        f,
                        "{NOSTR_CONNECT_BUNKER_URI_SCHEME}://{remote_signer_public_key}"
                    )
                } else {
                    write!(
                        f,
                        "{NOSTR_CONNECT_BUNKER_URI_SCHEME}://{remote_signer_public_key}?{query}"
                    )
                }
            }
            Self::Client {
                public_key,
                relays,
                metadata,
                secret,
            } => {
                let mut relays_str: String = String::new();

                for relay_url in relays.iter() {
                    let relay_url: &str = relay_url.as_str_without_trailing_slash();

                    relays_str.push_str("&relay=");
                    relays_str.push_str(relay_url);
                }

                write!(
                    f,
                    "{NOSTR_CONNECT_URI_SCHEME}://{}?metadata={}{relays_str}&secret={secret}",
                    public_key,
                    metadata.as_json()
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_debug_redacts_sensitive_values() {
        let public_key =
            PublicKey::parse("79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3")
                .unwrap();
        let request = NostrConnectRequest::Nip44Encrypt {
            public_key,
            text: String::from("private message"),
        };
        let response = ResponseResult::Nip44Decrypt {
            plaintext: String::from("decrypted message"),
        };
        let message = NostrConnectMessage::Response {
            id: String::from("request-id"),
            result: Some(String::from("connection-secret")),
            error: None,
        };
        let uri = NostrConnectUri::client_with_secret(
            public_key,
            Vec::<RelayUrl>::new(),
            "app",
            "uri-secret",
        );

        let debug = format!("{request:?} {response:?} {message:?} {uri:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private message"));
        assert!(!debug.contains("decrypted message"));
        assert!(!debug.contains("connection-secret"));
        assert!(!debug.contains("uri-secret"));
    }

    #[test]
    fn test_parse_bunker_uri() {
        let uri = "bunker://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss://relay.nsec.app";
        let uri = NostrConnectUri::parse(uri).unwrap();

        let remote_signer_public_key =
            PublicKey::parse("79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.nsec.app").unwrap();
        assert_eq!(uri.relays(), vec![relay_url.clone()]);
        assert_eq!(
            uri,
            NostrConnectUri::Bunker {
                remote_signer_public_key,
                relays: vec![relay_url],
                secret: None
            }
        );
    }

    #[test]
    fn test_parse_client_uri() {
        let uri = r#"nostrconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?metadata={"name":"Example"}&relay=wss://relay.damus.io&secret=mysecret"#;
        let uri = NostrConnectUri::parse(uri).unwrap();

        let pubkey =
            PublicKey::parse("b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let app_name = "Example";
        assert_eq!(
            uri,
            NostrConnectUri::client_with_secret(pubkey, [relay_url], app_name, "mysecret")
        );
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn test_make_client_uri() {
        let pubkey =
            PublicKey::parse("b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let app_name = "Example";
        let uri = NostrConnectUri::client(pubkey, [relay_url], app_name);

        assert!(uri.secret().is_some());
        assert_eq!(uri.secret().unwrap().len(), 32);
    }

    #[test]
    fn test_parse_client_uri_without_secret_fails() {
        // nostrconnect:// URIs without a secret should fail to parse (secret is required per NIP-46)
        let uri = r#"nostrconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?metadata={"name":"Example"}&relay=wss://relay.damus.io"#;
        assert!(NostrConnectUri::parse(uri).is_err());
    }

    #[test]
    fn test_bunker_uri_serialization() {
        let uri = "bunker://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss://relay.nsec.app&secret=abcd";

        let remote_signer_public_key =
            PublicKey::parse("79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.nsec.app").unwrap();
        assert_eq!(
            NostrConnectUri::Bunker {
                remote_signer_public_key,
                relays: vec![relay_url],
                secret: Some(String::from("abcd"))
            }
            .to_string(),
            uri
        );
    }

    #[test]
    fn test_client_uri_serialization() {
        let uri = r#"nostrconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?metadata={"name":"Example"}&relay=wss://relay.damus.io&secret=abcd1234"#;

        let pubkey =
            PublicKey::parse("b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let app_name = "Example";
        assert_eq!(
            NostrConnectUri::client_with_secret(pubkey, [relay_url], app_name, "abcd1234")
                .to_string(),
            uri
        );
    }

    #[test]
    fn test_parse_response_result() {
        let public_key =
            PublicKey::parse("b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4")
                .unwrap();

        let res: ResponseResult =
            ResponseResult::parse(NostrConnectMethod::Connect, "ack").unwrap();
        assert_eq!(res, ResponseResult::Ack);

        let res = ResponseResult::parse(NostrConnectMethod::Ping, "ack");
        assert_eq!(res.unwrap_err().kind(), ErrorKind::Invalid);

        let res: ResponseResult = ResponseResult::parse(
            NostrConnectMethod::GetPublicKey,
            "b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4",
        )
        .unwrap();
        assert_eq!(res, ResponseResult::GetPublicKey(public_key));

        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let event = Event::from_json(json).unwrap();
        let res: ResponseResult =
            ResponseResult::parse(NostrConnectMethod::SignEvent, json).unwrap();
        assert_eq!(res, ResponseResult::SignEvent(Box::new(event)));

        let res: ResponseResult = ResponseResult::parse(NostrConnectMethod::Ping, "pong").unwrap();
        assert_eq!(res, ResponseResult::Pong);
    }

    #[test]
    fn test_message_serialization() {
        // Error
        let message = NostrConnectMessage::response(
            "2581081643",
            NostrConnectResponse::new(
                Some(ResponseResult::Error),
                Some(String::from("Empty response")),
            ),
        );
        let json = r#"{"id":"2581081643","result":"error","error":"Empty response"}"#;
        assert_eq!(message.as_json(), json);

        // Sign event
        let unsigned = UnsignedEvent::from_json(r#"{"created_at":1710854115,"content":"Testing rust-nostr NIP46 signer [bunker]","tags":[],"kind":1,"pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","id":"236ad3390704e1bf435f40143fb3de163723aeaa8f25c3bf12a0ac4d9a4b56a7"}"#).unwrap();
        let json = r#"{"id":"3047714669","method":"sign_event","params":["{\"id\":\"236ad3390704e1bf435f40143fb3de163723aeaa8f25c3bf12a0ac4d9a4b56a7\",\"pubkey\":\"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3\",\"created_at\":1710854115,\"kind\":1,\"tags\":[],\"content\":\"Testing rust-nostr NIP46 signer [bunker]\"}"]}"#;
        let message = NostrConnectMessage::Request {
            id: String::from("3047714669"),
            method: NostrConnectMethod::SignEvent,
            params: vec![unsigned.as_json()],
        };
        assert_eq!(message.as_json(), json);

        let req = message.to_request().unwrap();
        assert_eq!(req, NostrConnectRequest::SignEvent(unsigned));
    }

    #[test]
    fn test_message_deserialization() {
        // Connect
        let json = r#"{"id":"2845841889","method":"connect","params":["79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3"]}"#;
        let message = NostrConnectMessage::from_json(json).unwrap();
        let expected_msg = NostrConnectMessage::Request {
            id: String::from("2845841889"),
            method: NostrConnectMethod::Connect,
            params: vec![String::from(
                "79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3",
            )],
        };
        assert_eq!(message, expected_msg);
        let req = message.to_request().unwrap();
        assert_eq!(
            req,
            NostrConnectRequest::Connect {
                remote_signer_public_key: PublicKey::from_hex(
                    "79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3"
                )
                .unwrap(),
                secret: None,
            }
        );

        // Connect ACK
        let json = r#"{"id":"2581081643","result":"ack","error":null}"#;
        let message = NostrConnectMessage::from_json(json).unwrap();
        assert_eq!(
            message,
            NostrConnectMessage::response(
                "2581081643",
                NostrConnectResponse::new(Some(ResponseResult::Ack), None)
            )
        );

        // Error
        let json = r#"{"id":"2581081643","result":"error","error":"Empty response"}"#;
        let message = NostrConnectMessage::from_json(json).unwrap();
        assert_eq!(
            message,
            NostrConnectMessage::response(
                "2581081643",
                NostrConnectResponse::new(
                    Some(ResponseResult::Error),
                    Some(String::from("Empty response"))
                )
            )
        );

        // Sign event
        let event = Event::from_json(r#"{"created_at":1710854115,"content":"Testing rust-nostr NIP46 signer [bunker]","tags":[],"kind":1,"pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","id":"236ad3390704e1bf435f40143fb3de163723aeaa8f25c3bf12a0ac4d9a4b56a7","sig":"509b8fe51c1e4c4cc55a0b2032b70bfb683f1da6c62e4e5b0da7175eab99b18c67862deaaea80cf31acedb9ad3022ebf54fd0cb6c9d1297a96541848d2035d92"}"#).unwrap();
        let json = r#"{"id":"3047714669","result":"{\"id\":\"236ad3390704e1bf435f40143fb3de163723aeaa8f25c3bf12a0ac4d9a4b56a7\",\"pubkey\":\"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3\",\"created_at\":1710854115,\"kind\":1,\"tags\":[],\"content\":\"Testing rust-nostr NIP46 signer [bunker]\",\"sig\":\"509b8fe51c1e4c4cc55a0b2032b70bfb683f1da6c62e4e5b0da7175eab99b18c67862deaaea80cf31acedb9ad3022ebf54fd0cb6c9d1297a96541848d2035d92\"}","error":null}"#;
        let message = NostrConnectMessage::from_json(json).unwrap();
        assert_eq!(
            message,
            NostrConnectMessage::response(
                "3047714669",
                NostrConnectResponse::new(Some(ResponseResult::SignEvent(Box::new(event))), None),
            )
        );

        // Encryption
        let ciphertext = "ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7s7JqlCMJBAIIjfkpHReBPXeoMCyuClwgbT419jUWU1PwaNl4FEQYKCDKVJz+97Mp3K+Q2YGa77B6gpxB/lr1QgoqpDf7wDVrDmOqGoiPjWDqy8KzLueKDcm9BVP8xeTJIxs=";
        let json = r#"{"id":"3047714669","result":"ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7s7JqlCMJBAIIjfkpHReBPXeoMCyuClwgbT419jUWU1PwaNl4FEQYKCDKVJz+97Mp3K+Q2YGa77B6gpxB/lr1QgoqpDf7wDVrDmOqGoiPjWDqy8KzLueKDcm9BVP8xeTJIxs=","error":null}"#;
        let message = NostrConnectMessage::from_json(json).unwrap();
        assert_eq!(
            message,
            NostrConnectMessage::response(
                "3047714669",
                NostrConnectResponse::new(
                    Some(ResponseResult::Nip44Encrypt {
                        ciphertext: ciphertext.to_string()
                    }),
                    None
                )
            )
        );

        // Decryption
        let plaintext = "Hello world!";
        let json = r#"{"id":"3047714669","result":"Hello world!","error":null}"#;
        let message = NostrConnectMessage::from_json(json).unwrap();
        assert_eq!(
            message,
            NostrConnectMessage::response(
                "3047714669",
                NostrConnectResponse::new(
                    Some(ResponseResult::Nip44Decrypt {
                        plaintext: plaintext.to_string()
                    }),
                    None
                )
            )
        );
    }
}
