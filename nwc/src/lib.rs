// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NWC client and zapper backend for Nostr apps

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::large_futures)]
#![warn(rustdoc::bare_urls)]
#![allow(clippy::arc_with_non_send_sync)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use futures_core::Stream;
use nostr::nips::nip47::{
    ListTransactionsRequest, LookupInvoiceRequest, MakeInvoiceRequest, Nip47Ciphers, Nip47Tag,
    NostrWalletConnectUri, Notification, PayInvoiceRequest, PayKeysendRequest, Request, Response,
};
use nostr_sdk::prelude::*;

mod api;
pub mod builder;
pub mod error;
mod future;
pub mod prelude;

pub use self::api::*;
use self::builder::NostrWalletConnectBuilder;
use self::error::Error;

const NOTIFICATIONS_ID: &str = "nwc-notifications";

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use NostrWalletConnect instead")]
pub type NWC = NostrWalletConnect;

#[derive(Debug)]
struct AtomicCipher(AtomicU32);

impl From<Option<Nip47Ciphers>> for AtomicCipher {
    fn from(value: Option<Nip47Ciphers>) -> Self {
        match value {
            Some(cipher) => Self::new(cipher),
            None => Self(AtomicU32::from(0)),
        }
    }
}

impl AtomicCipher {
    /// Create an atomic reference to the given cipher for lock-free shared access.
    #[inline]
    fn new(cipher: Nip47Ciphers) -> Self {
        Self(AtomicU32::from(cipher.as_u32()))
    }

    /// If any cipher is set, returns it; otherwise returns None.
    #[inline]
    fn load(&self) -> Option<Nip47Ciphers> {
        match self.0.load(Ordering::SeqCst) {
            0 => None,
            cipher => Nip47Ciphers::from_u32(cipher),
        }
    }
}

/// Nostr Wallet Connect client
#[derive(Debug, Clone)]
pub struct NostrWalletConnect {
    uri: NostrWalletConnectUri,
    uri_keys: Keys,
    client: Client,
    timeout: Duration,
    cipher: Arc<AtomicCipher>,
    relay_opts: RelayOptions,
    bootstrapped: Arc<AtomicBool>,
    notifications_subscribed: Arc<AtomicBool>,
}

impl NostrWalletConnect {
    /// Construct a new client.
    ///
    /// Use [`NostrWalletConnect::builder`] for customizing the client.
    #[inline]
    pub fn new(uri: NostrWalletConnectUri) -> Self {
        Self::builder(uri).build()
    }

    /// Construct a new Nostr Wallet Connect client builder.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::time::Duration;
    /// use nwc::prelude::*;
    ///
    /// # let uri = NostrWalletConnectUri::parse("nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c&relay=wss%3A%2F%2Frelay.damus.io").unwrap();
    /// let nwc = NostrWalletConnect::builder(uri).timeout(Duration::from_secs(30)).build();
    /// # let _ = nwc;
    /// ```
    #[inline]
    pub fn builder(uri: NostrWalletConnectUri) -> NostrWalletConnectBuilder {
        NostrWalletConnectBuilder::new(uri)
    }

    fn from_builder(builder: NostrWalletConnectBuilder) -> Self {
        let client: Client = match builder.monitor {
            Some(monitor) => Client::builder().monitor(monitor).build(),
            None => Client::default(),
        };

        let uri_keys: Keys = Keys::new(builder.uri.secret.clone());

        Self {
            uri: builder.uri,
            uri_keys,
            client,
            timeout: builder.timeout,
            relay_opts: builder.relay,
            cipher: Arc::new(AtomicCipher::from(builder.cipher)),
            bootstrapped: Arc::new(AtomicBool::new(false)),
            notifications_subscribed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get URI
    #[inline]
    pub fn uri(&self) -> &NostrWalletConnectUri {
        &self.uri
    }

    /// Get the inner nostr client
    #[inline]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get relays status
    #[deprecated(since = "0.45.0", note = "Use the client method instead")]
    pub async fn status(&self) -> HashMap<RelayUrl, RelayStatus> {
        let relays = self.client.relays().await;
        relays.into_iter().map(|(u, r)| (u, r.status())).collect()
    }

    /// Return the NIP-47 cipher to use, caching it if not already known
    ///
    /// Falls back to NIP-04 when the remote wallet does not advertise any
    /// cipher.
    async fn get_cipher(&self) -> Nip47Ciphers {
        let cipher = self.cipher.load();

        match cipher {
            Some(cipher) => cipher,
            None => {
                let cipher = self
                    .get_wallet_cipher()
                    .await
                    .unwrap_or(Nip47Ciphers::NIP04);
                _ = self.cipher.0.compare_exchange(
                    0,
                    cipher.as_u32(),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                cipher
            }
        }
    }

    /// Connect and subscribe
    async fn bootstrap(&self) -> Result<(), Error> {
        // Check if already bootstrapped
        if self.bootstrapped.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Add relays
        for url in self.uri.relays.iter() {
            self.client
                .add_relay(url)
                .opts(self.relay_opts.clone())
                .await?;
        }

        // Connect to relays
        self.client.connect().await;

        // Mark as bootstrapped
        self.bootstrapped.store(true, Ordering::SeqCst);

        Ok(())
    }

    /// Fetch the latest cipher advertised by the wallet, if any.
    async fn get_wallet_cipher(&self) -> Option<Nip47Ciphers> {
        let filter = Filter::new()
            .kind(Kind::WalletConnectInfo)
            .author(self.uri.public_key)
            .limit(1);

        let mut stream = self.client.stream_events(filter).await.ok()?;
        let info_event: Event = stream.next().await.map(|(_, res)| res.ok())??;

        info_event
            .tags
            .iter()
            .find_map(|t| match Nip47Tag::try_from(t).ok()? {
                Nip47Tag::Encryption(et) => Some(et.latest()),
            })
    }

    async fn send_request(&self, req: Request, timeout: Duration) -> Result<Response, Error> {
        // Bootstrap
        self.bootstrap().await?;
        let cipher = self.get_cipher().await;

        tracing::debug!(
            "Sending request '{}' encrypted using '{cipher}'",
            req.as_json()
        );

        // Convert request to event
        let event: Event = req.to_event(&self.uri, cipher)?;

        // Construct the filter to wait for the response
        let filter = Filter::new()
            .author(self.uri.public_key)
            .kind(Kind::WalletConnectResponse)
            .event(event.id);

        // Subscribe to filter and create the stream
        let mut stream = self
            .client
            .stream_events(filter)
            .timeout(timeout)
            .policy(ReqExitPolicy::WaitForEvents(1))
            .await?;

        // Send the request
        self.client.send_event(&event).await?;

        // Wait for the response
        let (_, res) = stream.next().await.ok_or_else(Error::no_response)?;

        // Unwrap event
        let received_event: Event = res?;

        // Verify the response answers this specific request
        verify_response_correlation(&self.uri_keys, &received_event, event.id)?;

        // Parse response
        let response: Response = Response::from_event(&self.uri, &received_event, cipher)?;

        // Return response
        Ok(response)
    }

    /// Pay invoice
    #[inline]
    pub fn pay_invoice(&self, request: PayInvoiceRequest) -> PayInvoice<'_> {
        PayInvoice::new(self, request)
    }

    /// Pay keysend
    #[inline]
    pub fn pay_keysend(&self, request: PayKeysendRequest) -> PayKeysend<'_> {
        PayKeysend::new(self, request)
    }

    /// Create invoice
    #[inline]
    pub fn make_invoice(&self, request: MakeInvoiceRequest) -> MakeInvoice<'_> {
        MakeInvoice::new(self, request)
    }

    /// Lookup invoice
    #[inline]
    pub fn lookup_invoice(&self, request: LookupInvoiceRequest) -> LookupInvoice<'_> {
        LookupInvoice::new(self, request)
    }

    /// List transactions
    #[inline]
    pub fn list_transactions(&self, params: ListTransactionsRequest) -> ListTransactions<'_> {
        ListTransactions::new(self, params)
    }

    /// Get balance (msat)
    #[inline]
    pub fn get_balance(&self) -> GetBalance<'_> {
        GetBalance::new(self)
    }

    /// Get info
    #[inline]
    pub fn get_info(&self) -> GetInfo<'_> {
        GetInfo::new(self)
    }

    /// Subscribe to wallet notifications
    pub async fn subscribe_to_notifications(&self) -> Result<(), Error> {
        if self.notifications_subscribed.load(Ordering::SeqCst) {
            tracing::debug!("Already subscribed to notifications");
            return Ok(());
        }

        tracing::info!("Subscribing to wallet notifications...");

        self.bootstrap().await?;

        let client_keys = Keys::new(self.uri.secret.clone());
        let client_pubkey = client_keys.public_key();

        tracing::debug!("Client pubkey: {}", client_pubkey);
        tracing::debug!("Wallet service pubkey: {}", self.uri.public_key);

        let notification_filter = Filter::new()
            .author(self.uri.public_key)
            .pubkey(client_pubkey)
            .kinds([
                Kind::WalletConnectNotification,
                Kind::WalletConnectNotificationNip44V2,
            ])
            .since(Timestamp::now());

        tracing::debug!("Notification filter: {:?}", notification_filter);

        self.client
            .subscribe(notification_filter)
            .with_id(SubscriptionId::new(NOTIFICATIONS_ID))
            .await?;

        self.notifications_subscribed.store(true, Ordering::SeqCst);

        tracing::info!("Successfully subscribed to notifications");
        Ok(())
    }

    /// Unsubscribe from notifications
    pub async fn unsubscribe_from_notifications(&self) -> Result<(), Error> {
        self.client
            .unsubscribe(&SubscriptionId::new(NOTIFICATIONS_ID))
            .await?;
        self.notifications_subscribed.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Get a new notification stream
    ///
    /// The stream terminates when the client shutdowns.
    pub fn notifications(
        &self,
    ) -> Pin<Box<dyn Stream<Item = Result<Notification, Error>> + Send + '_>> {
        let notifications = self.client.notifications();

        Box::pin(notifications.filter_map(move |notification| async move {
            tracing::trace!("Received a client notification: {:?}", notification);

            if let ClientNotification::Event {
                subscription_id,
                event,
                ..
            } = notification
            {
                tracing::debug!(
                    "Received event: kind={}, author={}, id={}",
                    event.kind,
                    event.pubkey,
                    event.id
                );

                if subscription_id.as_str() != NOTIFICATIONS_ID {
                    tracing::trace!("Ignoring event with subscription id: {}", subscription_id);
                    return None;
                }

                if event.kind != Kind::WalletConnectNotification
                    || event.kind != Kind::WalletConnectNotificationNip44V2
                {
                    tracing::trace!("Ignoring event with kind: {}", event.kind);
                    return None;
                }

                tracing::info!("Processing wallet notification event");

                match Notification::from_event(&self.uri, &event) {
                    Ok(nip47_notification) => {
                        tracing::info!(
                            "Successfully parsed notification: {:?}",
                            nip47_notification.notification_type
                        );
                        return Some(Ok(nip47_notification));
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse notification: {}", e);
                        tracing::debug!("Event content: {}", event.content);
                        return Some(Err(Error::from(e)));
                    }
                }
            }

            None
        }))
    }

    /// Manually reconnect to a specific relay
    ///
    /// This function can be used to force a reconnection to a relay when the automatic reconnection
    /// is disabled via [`RelayOptions::reconnect`].
    ///
    /// If the client is not bootstrapped, it will do nothing.
    #[deprecated(since = "0.45.0", note = "Use the client method instead")]
    pub async fn reconnect_relay<'a, U>(&self, url: U) -> Result<(), Error>
    where
        U: Into<RelayUrlArg<'a>>,
    {
        if !self.bootstrapped.load(Ordering::SeqCst) {
            return Ok(());
        }

        Ok(self.client.connect_relay(url).await?)
    }

    /// Completely shutdown
    #[inline]
    pub async fn shutdown(&self) {
        self.client.shutdown().await
    }
}

/// Check that a NIP-47 response event answers the given request event.
fn verify_response_correlation(
    uri_keys: &Keys,
    response: &Event,
    request_id: EventId,
) -> Result<(), Error> {
    // The request ID is randomly generated for every request, hence requiring the
    // response to reference it prevents replaying stale responses.
    if !response.tags.event_ids().any(|id| id == request_id) {
        return Err(Error::unrelated_response());
    }

    if let Some(pubkey) = response.tags.public_keys().next() {
        if pubkey != uri_keys.public_key() {
            return Err(Error::unrelated_response());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use nostr::nips::nip47::{self, GetBalanceResponse, Method};
    use nostr_sdk::local_relay::MockRelay;

    use super::*;
    use crate::error::ErrorKind;

    const RESPONSE: Response = Response {
        result_type: Method::GetBalance,
        error: None,
        result: Some(nip47::ResponseResult::GetBalance(GetBalanceResponse {
            balance: 0xDEADBEEF,
        })),
    };

    #[test]
    fn test_verify_response_correlation() {
        let wallet_keys = Keys::generate();
        let client_keys = Keys::generate();

        let request_id: EventId = EventId::from_byte_array([0x11; 32]);
        let other_request_id: EventId = EventId::from_byte_array([0x22; 32]);

        let build_response = |e_tag: Option<EventId>, p_tag: Option<PublicKey>| {
            let mut builder = EventBuilder::new(Kind::WalletConnectResponse, "");
            if let Some(id) = e_tag {
                builder = builder.tag(Tag::event(id));
            }
            if let Some(pubkey) = p_tag {
                builder = builder.tag(Tag::public_key(pubkey));
            }
            builder.finalize(&wallet_keys).unwrap()
        };

        // Correlated response: accepted.
        let response = build_response(Some(request_id), Some(client_keys.public_key()));
        assert!(verify_response_correlation(&client_keys, &response, request_id).is_ok());

        // Missing `p` tag: tolerated, wallets only SHOULD include it.
        let response = build_response(Some(request_id), None);
        assert!(verify_response_correlation(&client_keys, &response, request_id).is_ok());

        // Missing `e` tag: rejected.
        let response = build_response(None, Some(client_keys.public_key()));
        let error = verify_response_correlation(&client_keys, &response, request_id).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnrelatedResponse);

        // `e` tag referencing another request: rejected, i.e., a replayed old response.
        let response = build_response(Some(other_request_id), Some(client_keys.public_key()));
        let error = verify_response_correlation(&client_keys, &response, request_id).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnrelatedResponse);

        // `p` tag addressing another client: rejected.
        let response = build_response(Some(request_id), Some(wallet_keys.public_key()));
        let error = verify_response_correlation(&client_keys, &response, request_id).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnrelatedResponse);
    }

    fn create_keys(relay_url: RelayUrl) -> (Keys, Keys, NostrWalletConnectUri) {
        let wallet_keys = Keys::generate();
        let client_keys = Keys::generate();
        let uri = NostrWalletConnectUri::new(
            wallet_keys.public_key(),
            vec![relay_url],
            client_keys.secret_key().clone(),
            None,
        );
        (wallet_keys, client_keys, uri)
    }

    async fn run_wallet(
        wkeys: Keys,
        ckeys: Keys,
        relay_url: RelayUrl,
        advertise_ciphers: Option<Nip47Ciphers>,
        expected_cipher: Nip47Ciphers,
    ) {
        let client = Client::new();
        client.add_relay(relay_url).and_connect().await.unwrap();

        if let Some(ciphers) = advertise_ciphers {
            let event = EventBuilder::new(Kind::WalletConnectInfo, "")
                .tag(Nip47Tag::Encryption(ciphers))
                .finalize(&wkeys)
                .unwrap();
            client.send_event(&event).await.unwrap();
        }

        let mut stream = client
            .stream_events(
                Filter::new()
                    .kind(Kind::WalletConnectRequest)
                    .author(ckeys.public_key())
                    .pubkey(wkeys.public_key()),
            )
            .policy(ReqExitPolicy::WaitForEvents(1))
            .await
            .unwrap();
        let request: Event = stream
            .next()
            .await
            .map(|(_, res)| res.ok())
            .unwrap()
            .unwrap();

        let cipher = request
            .tags
            .iter()
            .find_map(|tag| match Nip47Tag::try_from(tag).ok()? {
                Nip47Tag::Encryption(ciphers) => Some(ciphers),
            })
            .unwrap_or(Nip47Ciphers::NIP04);

        assert_eq!(
            expected_cipher, cipher,
            "expected: {expected_cipher}. Found {cipher}"
        );

        let enc_response = cipher
            .encrypt(wkeys.secret_key(), &ckeys.public_key(), &RESPONSE.as_json())
            .unwrap();
        let response_event = EventBuilder::new(Kind::WalletConnectResponse, enc_response)
            .tag(Tag::public_key(ckeys.public_key()))
            .tag(Tag::event(request.id))
            .finalize(&wkeys)
            .unwrap();
        client.send_event(&response_event).await.unwrap();
    }

    #[tokio::test]
    async fn test_send_request_no_cipher() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await;

        let (wkeys, ckeys, uri) = create_keys(relay_url.clone());

        tokio::spawn(run_wallet(
            wkeys,
            ckeys,
            relay_url,
            None,
            Nip47Ciphers::NIP04,
        ));

        let client = NostrWalletConnectBuilder::new(uri).build();

        // `send_request` should use nip04 because there is no info event.
        let wallet_response = client
            .send_request(Request::get_balance(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(RESPONSE, wallet_response);
    }

    #[tokio::test]
    async fn test_send_request_no_cipher_but_info_single_cipher() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await;

        let (wkeys, ckeys, uri) = create_keys(relay_url.clone());

        tokio::spawn(run_wallet(
            wkeys,
            ckeys,
            relay_url,
            Some(Nip47Ciphers::NIP44V2),
            Nip47Ciphers::NIP44V2,
        ));

        // Wait for the info event
        tokio::time::sleep(Duration::from_secs(1)).await;
        let client = NostrWalletConnectBuilder::new(uri).build();

        // `send_request` should use nip44_v2 because of the info event.
        let wallet_response = client
            .send_request(Request::get_balance(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(RESPONSE, wallet_response);
    }

    #[tokio::test]
    async fn test_send_request_no_cipher_but_info_single_old_cipher() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await;

        let (wkeys, ckeys, uri) = create_keys(relay_url.clone());

        tokio::spawn(run_wallet(
            wkeys,
            ckeys,
            relay_url,
            Some(Nip47Ciphers::NIP04),
            Nip47Ciphers::NIP04,
        ));

        // Wait for the info event
        tokio::time::sleep(Duration::from_secs(1)).await;
        let client = NostrWalletConnectBuilder::new(uri).build();

        // `send_request` should use nip04 because of the info event.
        let wallet_response = client
            .send_request(Request::get_balance(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(RESPONSE, wallet_response);
    }

    #[tokio::test]
    async fn test_send_request_no_cipher_but_info_latest_cipher() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await;

        let (wkeys, ckeys, uri) = create_keys(relay_url.clone());

        tokio::spawn(run_wallet(
            wkeys,
            ckeys,
            relay_url,
            Some(Nip47Ciphers::NIP04.add(Nip47Ciphers::NIP44V2)),
            Nip47Ciphers::NIP44V2,
        ));

        // Wait for the info event
        tokio::time::sleep(Duration::from_secs(1)).await;
        let client = NostrWalletConnectBuilder::new(uri).build();

        // `send_request` should use nip44_v2 because of the info event.
        let wallet_response = client
            .send_request(Request::get_balance(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(RESPONSE, wallet_response);
    }

    #[tokio::test]
    async fn test_send_request_nip04_cipher_no_info() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await;

        let (wkeys, ckeys, uri) = create_keys(relay_url.clone());

        tokio::spawn(run_wallet(
            wkeys,
            ckeys,
            relay_url,
            None,
            Nip47Ciphers::NIP04,
        ));

        // Wait for the info event
        tokio::time::sleep(Duration::from_secs(1)).await;
        let client = NostrWalletConnectBuilder::new(uri).force_nip04().build();

        // `send_request` should use nip04 because of the force.
        let wallet_response = client
            .send_request(Request::get_balance(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(RESPONSE, wallet_response);
    }

    #[tokio::test]
    async fn test_send_request_nip44_cipher_no_info() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await;

        let (wkeys, ckeys, uri) = create_keys(relay_url.clone());

        tokio::spawn(run_wallet(
            wkeys,
            ckeys,
            relay_url,
            None,
            Nip47Ciphers::NIP44V2,
        ));

        // Wait for the info event
        tokio::time::sleep(Duration::from_secs(1)).await;
        let client = NostrWalletConnectBuilder::new(uri).force_nip44_v2().build();

        // `send_request` should use nip44_v2 because of the force.
        let wallet_response = client
            .send_request(Request::get_balance(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(RESPONSE, wallet_response);
    }

    #[tokio::test]
    async fn test_send_request_nip04_cipher_with_info() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await;

        let (wkeys, ckeys, uri) = create_keys(relay_url.clone());

        tokio::spawn(run_wallet(
            wkeys,
            ckeys,
            relay_url,
            Some(Nip47Ciphers::NIP04.add(Nip47Ciphers::NIP44V2)),
            Nip47Ciphers::NIP04,
        ));

        // Wait for the info event
        tokio::time::sleep(Duration::from_secs(1)).await;
        let client = NostrWalletConnectBuilder::new(uri).force_nip04().build();

        // `send_request` should use nip04 because of the force.
        let wallet_response = client
            .send_request(Request::get_balance(), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(RESPONSE, wallet_response);
    }
}
