//! Implements a Blossom client for interacting with Blossom servers

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use nostr::prelude::*;
use nostr::types::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, LOCATION, RANGE};
#[cfg(not(target_arch = "wasm32"))]
use reqwest::redirect::Policy;
use reqwest::{Response, StatusCode};

use crate::bud01::{BlossomAuthorization, BlossomAuthorizationScope, BlossomAuthorizationVerb};
use crate::bud02::BlobDescriptor;
use crate::error::{Error, ErrorKind};

/// A client for interacting with a Blossom server
///
/// <https://github.com/hzrd149/blossom>
#[derive(Debug, Clone)]
pub struct BlossomClient {
    base_url: Url,
    client: reqwest::Client,
}

impl BlossomClient {
    /// Creates a new `BlossomClient` with the given base URL.
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            client: Self::build_client().unwrap(),
        }
    }

    /// Builds the reqwest client
    fn build_client() -> reqwest::Result<reqwest::Client> {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.redirect(Policy::limited(10));
        builder.build()
    }

    /// Uploads a blob to the Blossom server.
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/02.md>
    pub async fn upload_blob<T>(
        &self,
        data: Vec<u8>,
        content_type: Option<String>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<BlobDescriptor, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url: Url = self.base_url.join("upload")?;

        let hash: Sha256Hash = Sha256Hash::hash(&data);
        let file_hashes: Vec<Sha256Hash> = vec![hash];

        let mut request = self.client.put(url).body(data);
        let mut headers = HeaderMap::new();

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(&ct)?);
        }

        if let Some(signer) = signer {
            let default_auth = self.default_auth(
                BlossomAuthorizationVerb::Upload,
                "Blossom upload authorization",
                BlossomAuthorizationScope::BlobSha256Hashes(file_hashes),
            );
            let final_auth = authorization_options
                .map(|opts| Self::update_authorization_fixture(&default_auth, opts))
                .unwrap_or(default_auth);
            let auth_header = Self::build_auth_header(signer, final_auth).await?;
            headers.insert(AUTHORIZATION, auth_header);
        }

        request = request.headers(headers);

        let response: Response = request.send().await?;

        match response.status() {
            StatusCode::OK => {
                let descriptor: BlobDescriptor = response.json().await?;
                Ok(descriptor)
            }
            _ => Err(Error::response("Failed to upload blob", response)),
        }
    }

    /// Lists blobs uploaded by a specific pubkey.
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/02.md>
    pub async fn list_blobs<T>(
        &self,
        pubkey: &PublicKey,
        since: Option<Timestamp>,
        until: Option<Timestamp>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<Vec<BlobDescriptor>, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let mut url: Url = self.base_url.join("list")?.join(&pubkey.to_hex())?;

        if let Some(since) = since {
            url.query_pairs_mut()
                .append_pair("since", since.to_string().as_str());
        }

        if let Some(until) = until {
            url.query_pairs_mut()
                .append_pair("until", until.to_string().as_str());
        }

        let mut request = self.client.get(url);
        let mut headers = HeaderMap::new();

        if let Some(signer) = signer {
            let default_auth = self.default_auth(
                BlossomAuthorizationVerb::List,
                "Blossom list authorization",
                BlossomAuthorizationScope::ServerUrl(self.base_url.clone()),
            );
            let final_auth = authorization_options
                .map(|opts| Self::update_authorization_fixture(&default_auth, opts))
                .unwrap_or(default_auth);
            let auth_header = Self::build_auth_header(signer, final_auth).await?;
            headers.insert(AUTHORIZATION, auth_header);
        }

        request = request.headers(headers);

        let response: Response = request.send().await?;

        match response.status() {
            StatusCode::OK => {
                let descriptors: Vec<BlobDescriptor> = response.json().await?;
                Ok(descriptors)
            }
            _ => Err(Error::response("Failed to list blobs", response)),
        }
    }

    /// Retrieves a blob from the Blossom server, with optional authorization.
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/01.md>
    pub async fn get_blob<T>(
        &self,
        sha256: Sha256Hash,
        range: Option<String>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<Vec<u8>, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url: Url = self.base_url.join(sha256.to_string().as_str())?;

        let mut request = self.client.get(url);
        let mut headers = HeaderMap::new();

        if let Some(range_value) = range {
            headers.insert(RANGE, HeaderValue::from_str(&range_value)?);
        }

        if let Some(signer) = signer {
            let default_auth = self.default_auth(
                BlossomAuthorizationVerb::Get,
                "Blossom get authorization",
                BlossomAuthorizationScope::BlobSha256Hashes(vec![sha256]),
            );
            let final_auth = authorization_options
                .map(|opts| Self::update_authorization_fixture(&default_auth, opts))
                .unwrap_or(default_auth);
            let auth_header = Self::build_auth_header(signer, final_auth).await?;
            headers.insert(AUTHORIZATION, auth_header);
        }

        request = request.headers(headers.clone());

        #[cfg_attr(target_arch = "wasm32", allow(unused_mut))]
        let mut response: Response = request.send().await?;

        // The trusted origin is the one the request was originally addressed
        // to. Sensitive headers are only ever sent to this origin: as soon as
        // a redirect leaves it (or downgrades to plain HTTP), they are
        // permanently dropped for all the following hops.
        #[cfg(not(target_arch = "wasm32"))]
        let mut trusted_origin: Option<Origin> = Some(self.base_url.origin());

        #[cfg(not(target_arch = "wasm32"))]
        for _ in 0..10 {
            if !response.status().is_redirection() {
                break;
            }

            let location = response.headers().get(LOCATION).ok_or_else(|| {
                Error::with_static_message(
                    ErrorKind::Invalid,
                    "Redirect response missing 'Location' header",
                )
            })?;
            let next_url = response.url().join(location.to_str()?)?;
            if !next_url.as_str().contains(&sha256.to_string()) {
                return Err(Error::with_static_message(
                    ErrorKind::Invalid,
                    "Redirect URL does not contain SHA256",
                ));
            }

            // Drop sensitive headers if the hop leaves the trusted origin or
            // downgrades from HTTPS to plain HTTP. The decision is sticky: a
            // later same-origin hop must not re-attach them.
            let is_trusted =
                trusted_origin.as_ref() == Some(&next_url.origin()) && next_url.scheme() == "https";
            if !is_trusted {
                headers.remove(AUTHORIZATION);
                trusted_origin = None;
            }

            response = self
                .client
                .get(next_url)
                .headers(headers.clone())
                .send()
                .await?;
        }

        if response.status().is_redirection() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Too many blob redirects",
            ));
        }

        match response.status() {
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(response.bytes().await?.to_vec()),
            _ => Err(Error::response("Failed to get blob", response)),
        }
    }

    /// Checks if a blob exists on the Blossom server.
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/01.md>
    pub async fn has_blob<T>(
        &self,
        sha256: Sha256Hash,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<bool, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url: Url = self.base_url.join(sha256.to_string().as_str())?;

        let mut request = self.client.head(url);

        if let Some(signer) = signer {
            let default_auth = self.default_auth(
                BlossomAuthorizationVerb::Get,
                "Blossom get authorization",
                BlossomAuthorizationScope::BlobSha256Hashes(vec![sha256]),
            );

            let final_auth = authorization_options
                .map(|opts| Self::update_authorization_fixture(&default_auth, opts))
                .unwrap_or(default_auth);

            let mut headers = HeaderMap::new();
            let auth_header = Self::build_auth_header(signer, final_auth).await?;
            headers.insert(AUTHORIZATION, auth_header);

            request = request.headers(headers);
        }

        let response: Response = request.send().await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(Error::response("Unexpected HTTP status code", response)),
        }
    }

    /// Deletes a blob from the Blossom server.
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/02.md>
    pub async fn delete_blob<T>(
        &self,
        sha256: Sha256Hash,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: &T,
    ) -> Result<(), Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url: Url = self.base_url.join(sha256.to_string().as_str())?;

        let mut headers = HeaderMap::new();
        let default_auth = self.default_auth(
            BlossomAuthorizationVerb::Delete,
            "Blossom delete authorization",
            BlossomAuthorizationScope::BlobSha256Hashes(vec![sha256]),
        );

        let final_auth = authorization_options
            .map(|opts| Self::update_authorization_fixture(&default_auth, opts))
            .unwrap_or(default_auth);

        let auth_header = Self::build_auth_header(signer, final_auth).await?;
        headers.insert(AUTHORIZATION, auth_header);

        let response: Response = self.client.delete(url).headers(headers).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::response("Failed to delete blob", response))
        }
    }

    /// Returns a default BlossomAuthorization object based on the parameters provided.
    fn default_auth<T>(
        &self,
        action: BlossomAuthorizationVerb,
        default_content: T,
        default_scope: BlossomAuthorizationScope,
    ) -> BlossomAuthorization
    where
        T: Into<String>,
    {
        let expiration_timestamp: Timestamp = Timestamp::now() + Duration::from_secs(300);
        BlossomAuthorization::new(
            default_content.into(),
            expiration_timestamp,
            action,
            default_scope,
        )
    }

    /// Updates a default BlossomAuthorization fixture with the provided options.
    pub fn update_authorization_fixture(
        default: &BlossomAuthorization,
        options: BlossomAuthorizationOptions,
    ) -> BlossomAuthorization {
        BlossomAuthorization {
            content: options.content.unwrap_or(default.content.clone()),
            expiration: options.expiration.unwrap_or(default.expiration),
            action: options.action.unwrap_or(default.action),
            scope: options.scope.unwrap_or(default.scope.clone()),
        }
    }

    /// Helper function to build authorization header.
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/01.md>
    async fn build_auth_header<T>(
        signer: &T,
        authz: BlossomAuthorization,
    ) -> Result<HeaderValue, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let auth_event: Event = authz.finalize_async(signer).await?;
        let encoded_auth: String = general_purpose::STANDARD.encode(auth_event.as_json());
        let value: String = format!("Nostr {}", encoded_auth);
        Ok(HeaderValue::try_from(value)?)
    }
}

/// Options for customizing BlossomAuthorization. All fields are optional.
#[derive(Debug, Clone, Default)]
pub struct BlossomAuthorizationOptions {
    /// A human readable string explaining to the user what the events intended use is
    pub content: Option<String>,
    /// A UNIX timestamp (in seconds) indicating when the authorization should be expired
    pub expiration: Option<Timestamp>,
    /// The type of action authorized by the user
    pub action: Option<BlossomAuthorizationVerb>,
    /// The scope of the authorization
    pub scope: Option<BlossomAuthorizationScope>,
}
