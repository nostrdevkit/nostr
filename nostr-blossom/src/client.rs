//! Implements a Blossom client for interacting with Blossom servers

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use nostr::prelude::*;
use nostr::types::Url;
#[cfg(not(target_arch = "wasm32"))]
use reqwest::header::LOCATION;
use reqwest::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, RANGE};
#[cfg(not(target_arch = "wasm32"))]
use reqwest::redirect::Policy;
use reqwest::{Response, StatusCode};
use serde::Serialize;

use crate::bud01::{BlossomAuthorization, BlossomAuthorizationScope, BlossomAuthorizationVerb};
use crate::bud02::BlobDescriptor;
use crate::bud10::BlossomUri;
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
    pub fn new(mut base_url: Url) -> Self {
        base_url.set_path("/");
        base_url.set_query(None);
        base_url.set_fragment(None);
        Self {
            base_url,
            client: Self::build_client().unwrap(),
        }
    }

    /// Builds the reqwest client
    fn build_client() -> reqwest::Result<reqwest::Client> {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.redirect(Policy::none());
        builder.build()
    }

    /// Uploads a blob to the Blossom server.
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/12.md>
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
        self.upload_blob_with_payment(data, content_type, authorization_options, signer, None)
            .await
    }

    /// Uploads a blob with an optional BUD-07 payment proof.
    pub async fn upload_blob_with_payment<T>(
        &self,
        data: Vec<u8>,
        content_type: Option<String>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
        payment: Option<&BlossomPaymentProof>,
    ) -> Result<BlobDescriptor, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url: Url = self.base_url.join("upload")?;

        let hash: Sha256Hash = Sha256Hash::hash(&data);
        let file_hashes: Vec<Sha256Hash> = vec![hash];

        let data_len = data.len();
        let mut request = self.client.put(url).body(data);
        let mut headers = HeaderMap::new();

        headers.insert(CONTENT_LENGTH, HeaderValue::from(data_len));
        headers.insert("X-SHA-256", HeaderValue::from_str(&hash.to_string())?);

        if let Some(ct) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(&ct)?);
        }
        Self::add_payment_header(&mut headers, payment)?;

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
            StatusCode::OK | StatusCode::CREATED => {
                let descriptor: BlobDescriptor = response.json().await?;
                Ok(descriptor)
            }
            _ => Err(Error::response("Failed to upload blob", response)),
        }
    }

    /// Checks whether the server would accept a blob upload without sending its body.
    ///
    /// This implements the optional BUD-06 `HEAD /upload` preflight endpoint.
    pub async fn upload_requirements<T>(
        &self,
        sha256: Sha256Hash,
        size: u64,
        content_type: Option<&str>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<BlossomPreflight, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        self.preflight(
            "upload",
            sha256,
            size,
            content_type,
            BlossomAuthorizationVerb::Upload,
            authorization_options,
            signer,
        )
        .await
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
        let mut url: Url = self.base_url.join(&format!("list/{}", pubkey.to_hex()))?;

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

    /// Lists one cursor-paginated page of blobs according to BUD-12.
    pub async fn list_blobs_page<T>(
        &self,
        pubkey: &PublicKey,
        options: BlossomListOptions,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
        payment: Option<&BlossomPaymentProof>,
    ) -> Result<Vec<BlobDescriptor>, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let mut url = self.base_url.join(&format!("list/{}", pubkey.to_hex()))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(cursor) = options.cursor {
                query.append_pair("cursor", &cursor.to_string());
            }
            if let Some(limit) = options.limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(since) = options.since {
                query.append_pair("since", &since.to_string());
            }
            if let Some(until) = options.until {
                query.append_pair("until", &until.to_string());
            }
        }

        let mut headers = HeaderMap::new();
        Self::add_payment_header(&mut headers, payment)?;
        self.add_authorization_header(
            &mut headers,
            BlossomAuthorizationVerb::List,
            "Blossom list authorization",
            BlossomAuthorizationScope::ServerUrl(self.base_url.clone()),
            authorization_options,
            signer,
        )
        .await?;
        let response = self.client.get(url).headers(headers).send().await?;
        if response.status() == StatusCode::OK {
            Ok(response.json().await?)
        } else {
            Err(Error::response("Failed to list blobs", response))
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
        self.get_blob_with_payment(sha256, range, authorization_options, signer, None)
            .await
    }

    /// Retrieves a blob with an optional BUD-07 payment proof.
    pub async fn get_blob_with_payment<T>(
        &self,
        sha256: Sha256Hash,
        range: Option<String>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
        payment: Option<&BlossomPaymentProof>,
    ) -> Result<Vec<u8>, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url: Url = self.base_url.join(sha256.to_string().as_str())?;

        let mut request = self.client.get(url);
        let mut headers = HeaderMap::new();

        let verify_hash = range.is_none();
        if let Some(range_value) = range {
            headers.insert(RANGE, HeaderValue::from_str(&range_value)?);
        }
        Self::add_payment_header(&mut headers, payment)?;

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
                if let Some(payment) = payment {
                    headers.remove(format!("X-{}", payment.method).as_str());
                }
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
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => {
                let data = response.bytes().await?.to_vec();
                if verify_hash && Sha256Hash::hash(&data) != sha256 {
                    return Err(Error::with_static_message(
                        ErrorKind::Invalid,
                        "Downloaded blob does not match requested SHA256",
                    ));
                }
                Ok(data)
            }
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
        self.delete_blob_with_payment(sha256, authorization_options, signer, None)
            .await
    }

    /// Deletes a blob with an optional BUD-07 payment proof.
    pub async fn delete_blob_with_payment<T>(
        &self,
        sha256: Sha256Hash,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: &T,
        payment: Option<&BlossomPaymentProof>,
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
        Self::add_payment_header(&mut headers, payment)?;

        let response: Response = self.client.delete(url).headers(headers).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::response("Failed to delete blob", response))
        }
    }

    /// Mirrors an existing blob from its public URL.
    ///
    /// This implements BUD-04. The authorization uses the `upload` verb and the
    /// mirrored blob's hash as required by BUD-11.
    pub async fn mirror_blob<T>(
        &self,
        blob: &BlobDescriptor,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
        payment: Option<&BlossomPaymentProof>,
    ) -> Result<BlobDescriptor, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        #[derive(Serialize)]
        struct MirrorRequest<'a> {
            url: &'a Url,
        }

        let url = self.base_url.join("mirror")?;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            "X-SHA-256",
            HeaderValue::from_str(&blob.sha256.to_string())?,
        );
        headers.insert("X-Content-Length", HeaderValue::from(blob.size));
        headers.insert("X-Content-Type", HeaderValue::from_str(&blob.mime_type)?);
        Self::add_payment_header(&mut headers, payment)?;
        self.add_authorization_header(
            &mut headers,
            BlossomAuthorizationVerb::Upload,
            "Blossom mirror authorization",
            BlossomAuthorizationScope::BlobSha256Hashes(vec![blob.sha256]),
            authorization_options,
            signer,
        )
        .await?;

        let response = self
            .client
            .put(url)
            .headers(headers)
            .json(&MirrorRequest { url: &blob.url })
            .send()
            .await?;
        Self::descriptor_response("Failed to mirror blob", response).await
    }

    /// Uploads to the first BUD-03 server and mirrors to every remaining server.
    ///
    /// Descriptors are returned in server-list order. Processing stops on the
    /// first failed upload or mirror request.
    pub async fn upload_and_mirror<T>(
        servers: &[Url],
        data: Vec<u8>,
        content_type: Option<String>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<Vec<BlobDescriptor>, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let (first, mirrors) = servers.split_first().ok_or_else(|| {
            Error::with_static_message(ErrorKind::Invalid, "A Blossom server list cannot be empty")
        })?;
        let descriptor = Self::new(first.clone())
            .upload_blob(data, content_type, authorization_options.clone(), signer)
            .await?;
        let mut descriptors = Vec::with_capacity(servers.len());
        descriptors.push(descriptor.clone());
        for server in mirrors {
            let mirrored = Self::new(server.clone())
                .mirror_blob(&descriptor, authorization_options.clone(), signer, None)
                .await?;
            descriptors.push(mirrored);
        }
        Ok(descriptors)
    }

    /// Checks whether the server would accept media for optimization.
    pub async fn media_requirements<T>(
        &self,
        sha256: Sha256Hash,
        size: u64,
        content_type: Option<&str>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<BlossomPreflight, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        self.preflight(
            "media",
            sha256,
            size,
            content_type,
            BlossomAuthorizationVerb::Media,
            authorization_options,
            signer,
        )
        .await
    }

    /// Uploads media for server-selected optimization according to BUD-05.
    pub async fn upload_media<T>(
        &self,
        data: Vec<u8>,
        content_type: Option<String>,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
        payment: Option<&BlossomPaymentProof>,
    ) -> Result<BlobDescriptor, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url = self.base_url.join("media")?;
        let sha256 = Sha256Hash::hash(&data);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from(data.len()));
        headers.insert("X-SHA-256", HeaderValue::from_str(&sha256.to_string())?);
        if let Some(content_type) = content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(&content_type)?);
        }
        Self::add_payment_header(&mut headers, payment)?;
        self.add_authorization_header(
            &mut headers,
            BlossomAuthorizationVerb::Media,
            "Blossom media authorization",
            BlossomAuthorizationScope::BlobSha256Hashes(vec![sha256]),
            authorization_options,
            signer,
        )
        .await?;

        let response = self
            .client
            .put(url)
            .headers(headers)
            .body(data)
            .send()
            .await?;
        Self::descriptor_response("Failed to optimize media", response).await
    }

    /// Submits a signed NIP-56 blob report according to BUD-09.
    pub async fn report_blobs(&self, report: &Event) -> Result<(), Error> {
        let has_blob_hash = report
            .tags
            .iter()
            .any(|tag| tag.kind() == "x" && tag.len() > 1);
        if report.kind != Kind::Reporting || !has_blob_hash {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Blob reports must be kind 1984 and contain an x tag",
            ));
        }

        let response = self
            .client
            .put(self.base_url.join("report")?)
            .header(CONTENT_TYPE, "application/json")
            .body(report.as_json())
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::response("Failed to report blob", response))
        }
    }

    /// Resolves a BUD-10 URI using ordered URI, author-list, and fallback servers.
    pub async fn resolve_uri(
        &self,
        uri: &BlossomUri,
        author_servers: impl IntoIterator<Item = Url>,
        fallback_servers: impl IntoIterator<Item = Url>,
    ) -> Result<Vec<u8>, Error> {
        let client = reqwest::Client::new();
        for candidate in uri.candidate_urls(author_servers, fallback_servers) {
            let Ok(response) = client.get(candidate).send().await else {
                continue;
            };
            if !response.status().is_success()
                || !response.url().as_str().contains(&uri.sha256.to_string())
            {
                continue;
            }
            let Ok(data) = response.bytes().await else {
                continue;
            };
            if uri.size.is_none_or(|size| size == data.len() as u64)
                && Sha256Hash::hash(&data) == uri.sha256
            {
                return Ok(data.to_vec());
            }
        }
        Err(Error::with_static_message(
            ErrorKind::Invalid,
            "Blob could not be resolved from any server",
        ))
    }

    async fn preflight<T>(
        &self,
        endpoint: &str,
        sha256: Sha256Hash,
        size: u64,
        content_type: Option<&str>,
        verb: BlossomAuthorizationVerb,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<BlossomPreflight, Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        let url = self.base_url.join(endpoint)?;
        let mut headers = HeaderMap::new();
        headers.insert("X-SHA-256", HeaderValue::from_str(&sha256.to_string())?);
        headers.insert("X-Content-Length", HeaderValue::from(size));
        if let Some(content_type) = content_type {
            headers.insert("X-Content-Type", HeaderValue::from_str(content_type)?);
        }
        self.add_authorization_header(
            &mut headers,
            verb,
            "Blossom upload preflight authorization",
            BlossomAuthorizationScope::BlobSha256Hashes(vec![sha256]),
            authorization_options,
            signer,
        )
        .await?;

        let response = self.client.head(url).headers(headers).send().await?;
        match response.status() {
            StatusCode::OK => Ok(BlossomPreflight::Accepted),
            StatusCode::PAYMENT_REQUIRED => {
                let requests = response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        let method = name.as_str().strip_prefix("x-")?;
                        if method == "reason" {
                            return None;
                        }
                        Some(BlossomPaymentRequest {
                            method: method.to_owned(),
                            request: value.to_str().ok()?.to_owned(),
                        })
                    })
                    .collect::<Vec<_>>();
                if requests.is_empty() || requests.iter().any(|request| !request.is_valid()) {
                    return Err(Error::with_static_message(
                        ErrorKind::Malformed,
                        "Invalid BUD-07 payment challenge",
                    ));
                }
                Ok(BlossomPreflight::PaymentRequired(requests))
            }
            StatusCode::NOT_FOUND => Ok(BlossomPreflight::Unsupported),
            _ => Err(Error::response("Upload preflight failed", response)),
        }
    }

    async fn add_authorization_header<T>(
        &self,
        headers: &mut HeaderMap,
        verb: BlossomAuthorizationVerb,
        content: &'static str,
        scope: BlossomAuthorizationScope,
        authorization_options: Option<BlossomAuthorizationOptions>,
        signer: Option<&T>,
    ) -> Result<(), Error>
    where
        T: AsyncGetPublicKey + AsyncSignEvent,
    {
        if let Some(signer) = signer {
            let default_auth = self.default_auth(verb, content, scope);
            let authorization = authorization_options
                .map(|options| Self::update_authorization_fixture(&default_auth, options))
                .unwrap_or(default_auth);
            headers.insert(
                AUTHORIZATION,
                Self::build_auth_header(signer, authorization).await?,
            );
        }
        Ok(())
    }

    fn add_payment_header(
        headers: &mut HeaderMap,
        payment: Option<&BlossomPaymentProof>,
    ) -> Result<(), Error> {
        if let Some(payment) = payment {
            if !payment.is_valid() {
                return Err(Error::with_static_message(
                    ErrorKind::Malformed,
                    "Invalid BUD-07 payment proof",
                ));
            }
            let name = reqwest::header::HeaderName::from_bytes(
                format!("X-{}", payment.method).as_bytes(),
            )?;
            headers.insert(name, HeaderValue::from_str(&payment.proof)?);
        }
        Ok(())
    }

    async fn descriptor_response(
        error_message: &'static str,
        response: Response,
    ) -> Result<BlobDescriptor, Error> {
        match response.status() {
            StatusCode::OK | StatusCode::CREATED => Ok(response.json().await?),
            _ => Err(Error::response(error_message, response)),
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
            action: default.action,
            scope: default.scope.clone(),
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
        let encoded_auth: String = URL_SAFE_NO_PAD.encode(auth_event.as_json());
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
    #[deprecated = "endpoint actions are fixed by BUD-11 and this field is ignored"]
    pub action: Option<BlossomAuthorizationVerb>,
    /// The scope of the authorization
    #[deprecated = "endpoint hash requirements are fixed by BUD-11 and this field is ignored"]
    pub scope: Option<BlossomAuthorizationScope>,
}

/// BUD-12 list filters and cursor pagination.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlossomListOptions {
    /// Hash of the last blob from the previous page.
    pub cursor: Option<Sha256Hash>,
    /// Maximum number of descriptors to return.
    pub limit: Option<u32>,
    /// Deprecated lower upload-time bound.
    pub since: Option<Timestamp>,
    /// Deprecated upper upload-time bound.
    pub until: Option<Timestamp>,
}

/// Result of a BUD-05 or BUD-06 preflight request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlossomPreflight {
    /// The server indicates that the subsequent upload may proceed.
    Accepted,
    /// The server does not implement the optional preflight endpoint.
    Unsupported,
    /// The server requires one of the advertised payment methods.
    PaymentRequired(Vec<BlossomPaymentRequest>),
}

/// A BUD-07 payment request advertised by a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlossomPaymentRequest {
    /// Payment method suffix from the `X-{method}` header.
    pub method: String,
    /// Encoded payment request supplied by the server.
    pub request: String,
}

impl BlossomPaymentRequest {
    /// Checks the payment method's required transport encoding.
    pub fn is_valid(&self) -> bool {
        match self.method.as_str() {
            "cashu" => self.request.starts_with("creqA"),
            "lightning" => self.request.starts_with("ln") && self.request.is_ascii(),
            _ => !self.method.is_empty() && !self.request.is_empty(),
        }
    }
}

/// A BUD-07 payment proof to attach to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlossomPaymentProof {
    /// Payment method suffix, such as `cashu` or `lightning`.
    pub method: String,
    /// Encoded proof defined by the selected payment method.
    pub proof: String,
}

impl BlossomPaymentProof {
    /// Checks the payment method's required proof encoding.
    pub fn is_valid(&self) -> bool {
        match self.method.as_str() {
            "cashu" => self.proof.starts_with("cashuB"),
            "lightning" => {
                self.proof.len() == 64 && self.proof.bytes().all(|byte| byte.is_ascii_hexdigit())
            }
            _ => !self.method.is_empty() && !self.proof.is_empty(),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, timeout};

    use super::*;

    async fn mock_server(response: &'static str) -> (Url, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("request deadline elapsed")
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = timeout(Duration::from_secs(2), stream.read(&mut buffer))
                    .await
                    .expect("read deadline elapsed")
                    .unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(headers_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&request[..headers_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= headers_end + 4 + content_length {
                        break;
                    }
                }
            }
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (
            Url::parse(&format!("http://{address}/ignored/path")).unwrap(),
            handle,
        )
    }

    #[tokio::test]
    async fn mirror_uses_root_endpoint_and_metadata_headers() {
        let hash = Sha256Hash::hash(b"blob");
        let body = format!(
            r#"{{"url":"https://cdn.example/{hash}.bin","sha256":"{hash}","size":4,"type":"application/octet-stream","uploaded":1}}"#
        );
        let response = Box::leak(
            format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );
        let (base_url, request) = mock_server(response).await;
        let descriptor = BlobDescriptor {
            url: Url::parse(&format!("https://origin.example/{hash}.bin")).unwrap(),
            sha256: hash,
            size: 4,
            mime_type: "application/octet-stream".to_owned(),
            uploaded: Timestamp::from_secs(1),
            nip94: None,
        };

        BlossomClient::new(base_url)
            .mirror_blob(
                &descriptor,
                None,
                None::<&Keys>,
                Some(&BlossomPaymentProof {
                    method: "cashu".to_owned(),
                    proof: "cashuBproof".to_owned(),
                }),
            )
            .await
            .unwrap();

        let request = request.await.unwrap();
        let request_lowercase = request.to_ascii_lowercase();
        assert!(request.starts_with("PUT /mirror HTTP/1.1"));
        assert!(request_lowercase.contains(&format!("x-sha-256: {hash}")));
        assert!(request_lowercase.contains("x-content-length: 4"));
        assert!(request_lowercase.contains("x-cashu: cashubproof"));
        assert!(request.contains(&format!(r#"{{"url":"https://origin.example/{hash}.bin"}}"#)));
    }

    #[tokio::test]
    async fn preflight_returns_payment_challenges() {
        let response = "HTTP/1.1 402 Payment Required\r\nX-Cashu: creqArequest\r\nX-Reason: payment needed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (base_url, request) = mock_server(response).await;
        let hash = Sha256Hash::hash(b"blob");

        let result = BlossomClient::new(base_url)
            .upload_requirements(
                hash,
                4,
                Some("application/octet-stream"),
                None,
                None::<&Keys>,
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            BlossomPreflight::PaymentRequired(vec![BlossomPaymentRequest {
                method: "cashu".to_owned(),
                request: "creqArequest".to_owned(),
            }])
        );
        let request = request.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("head /upload http/1.1"));
        assert!(request.contains(&format!("x-sha-256: {hash}")));
        assert!(request.contains("x-content-length: 4"));
        assert!(request.contains("x-content-type: application/octet-stream"));
    }

    #[tokio::test]
    async fn list_page_sends_cursor_and_limit() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]";
        let (base_url, request) = mock_server(response).await;
        let keys = Keys::generate();
        let cursor = Sha256Hash::hash(b"cursor");

        let page = BlossomClient::new(base_url)
            .list_blobs_page(
                &keys.public_key(),
                BlossomListOptions {
                    cursor: Some(cursor),
                    limit: Some(25),
                    ..Default::default()
                },
                None,
                None::<&Keys>,
                None,
            )
            .await
            .unwrap();

        assert!(page.is_empty());
        let request = request.await.unwrap();
        assert!(request.starts_with(&format!(
            "GET /list/{}?cursor={cursor}&limit=25 HTTP/1.1",
            keys.public_key().to_hex()
        )));
    }

    #[tokio::test]
    async fn rejects_invalid_blob_report_before_request() {
        let event = EventBuilder::new(Kind::TextNote)
            .content("not a report")
            .finalize(&Keys::generate())
            .unwrap();
        let client = BlossomClient::new(Url::parse("http://127.0.0.1:1").unwrap());

        let error = client.report_blobs(&event).await.unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Invalid);
    }

    #[tokio::test]
    async fn rejects_empty_upload_server_list() {
        let error =
            BlossomClient::upload_and_mirror(&[], b"blob".to_vec(), None, None, None::<&Keys>)
                .await
                .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Invalid);
    }

    #[tokio::test]
    async fn uri_resolution_verifies_hash_and_size() {
        let data = "blossom";
        let hash = Sha256Hash::hash(data.as_bytes());
        let response = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{data}",
                data.len()
            )
            .into_boxed_str(),
        );
        let (base_url, request) = mock_server(response).await;
        let mut uri = BlossomUri::new(hash, "bin");
        uri.size = Some(data.len() as u64);

        let resolved = BlossomClient::new(base_url.clone())
            .resolve_uri(&uri, [base_url], [])
            .await
            .unwrap();

        assert_eq!(resolved, data.as_bytes());
        assert!(
            request
                .await
                .unwrap()
                .starts_with(&format!("GET /{hash}.bin HTTP/1.1"))
        );
    }
}
