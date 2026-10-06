// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Client

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use nostr::prelude::*;
use nostr_database::prelude::*;

mod api;
mod builder;
mod gossip;
mod notification;
mod url;

pub use self::api::*;
pub use self::builder::*;
use self::gossip::*;
pub use self::notification::*;
pub use self::url::*;
use crate::error::Error;
use crate::monitor::Monitor;
use crate::pool::{RelayPool, RelayPoolBuilder};
#[cfg(not(target_arch = "wasm32"))]
use crate::proxy::Proxy;
use crate::relay::{
    Relay, RelayCapabilities, RelayLimits, RelayOptions, SleepWhenIdle, SyncOptions,
};
use crate::stream::NotificationStream;

#[derive(Debug)]
struct ClientConfig {
    #[cfg(not(target_arch = "wasm32"))]
    proxy: Option<Proxy>,
    gossip_config: GossipConfig,
    connect_timeout: Duration,
    relay_limits: RelayLimits,
    max_avg_latency: Option<Duration>,
    sleep_when_idle: SleepWhenIdle,
    verify_subscriptions: bool,
    ban_relay_on_mismatch: bool,
}

#[derive(Debug)]
struct InnerClient {
    pool: RelayPool,
    gossip: Option<Gossip>,
    config: ClientConfig,
}

#[derive(Debug)]
struct WeakClient(Weak<InnerClient>);

impl WeakClient {
    /// Upgrade to [`Client`].
    ///
    /// Returns `None` if the all the instances of the [`Client`] has been dropped.
    #[inline]
    fn upgrade(&self) -> Option<Client> {
        Some(Client(self.0.upgrade()?))
    }
}

/// Nostr client
#[derive(Debug, Clone)]
pub struct Client(Arc<InnerClient>);

impl Default for Client {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Construct a new default client
    ///
    /// Use the [`Client::builder`] to configure the client (i.e., set a signer).
    #[inline]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Construct client
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::time::Duration;
    ///
    /// use nostr_sdk::prelude::*;
    ///
    /// let signer = Keys::generate();
    /// let authenticator = SignerAuthenticator::new(signer);
    /// let client: Client = Client::builder().authenticator(authenticator).build();
    /// ```
    #[inline]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    fn from_builder(builder: ClientBuilder) -> Self {
        // Construct relay pool builder
        let pool_builder: RelayPoolBuilder = RelayPoolBuilder {
            websocket_transport: builder.websocket_transport,
            gossip: builder.gossip.clone(),
            admit_policy: builder.admit_policy,
            authenticator: builder.authenticator,
            monitor: builder.monitor,
            database: builder.database,
            max_relays: builder.max_relays,
            notification_channel_size: builder.notification_channel_size,
        };

        // Construct the inner client
        let inner = InnerClient {
            pool: pool_builder.build(),
            gossip: builder.gossip.map(Gossip::new),
            config: ClientConfig {
                #[cfg(not(target_arch = "wasm32"))]
                proxy: builder.proxy,
                gossip_config: builder.gossip_config,
                connect_timeout: builder.connect_timeout,
                relay_limits: builder.relay_limits,
                max_avg_latency: builder.max_avg_latency,
                sleep_when_idle: builder.sleep_when_idle,
                verify_subscriptions: builder.verify_subscriptions,
                ban_relay_on_mismatch: builder.ban_relay_on_mismatch,
            },
        };

        // Construct the client
        let client = Self(Arc::new(inner));

        client.spawn_gossip_background_refresher();

        client
    }

    #[inline]
    fn pool(&self) -> &RelayPool {
        &self.0.pool
    }

    #[inline]
    fn config(&self) -> &ClientConfig {
        &self.0.config
    }

    #[inline]
    fn gossip(&self) -> Option<&Gossip> {
        self.0.gossip.as_ref()
    }

    #[inline]
    fn weak_clone(&self) -> WeakClient {
        WeakClient(Arc::downgrade(&self.0))
    }

    /// Get database
    #[inline]
    pub fn database(&self) -> &Arc<dyn NostrDatabase> {
        self.pool().database()
    }

    /// Get the relay monitor
    #[inline]
    pub fn monitor(&self) -> Option<&Monitor> {
        self.pool().monitor()
    }

    /// Check if the client is shutting down
    #[inline]
    pub fn is_shutdown(&self) -> bool {
        self.pool().is_shutdown()
    }

    /// Explicitly shutdown the client
    ///
    /// This method will shut down the client and all its relays.
    #[inline]
    pub async fn shutdown(&self) {
        self.pool().shutdown().await
    }

    /// Get a new notification stream
    ///
    /// The stream terminates when the client shutdowns.
    ///
    /// Notifications lost when this receiver falls behind are skipped.
    /// Use [`NotificationStream::with_gaps`] to observe such losses.
    ///
    /// <div class="warning">When you call this method, you subscribe to the notifications channel from that precise moment. Anything received by relay/s before that moment is not included in the channel!</div>
    ///
    /// # Examples
    ///
    /// ## Report notification gaps
    ///
    /// ```rust,no_run
    /// # use nostr_sdk::prelude::*;
    /// # async fn example(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    /// // Create the stream before subscribing so it can observe the response.
    /// let mut notifications = client.notifications().with_gaps();
    /// client.subscribe(Filter::new().kind(Kind::TextNote)).await?;
    ///
    /// while let Some(update) = notifications.next().await {
    ///     match update {
    ///         Ok(ClientNotification::Event { event, .. }) => println!("{}", event.id),
    ///         Ok(ClientNotification::Shutdown) => break,
    ///         Ok(_) => {}
    ///         Err(gap) => {
    ///             eprintln!("Skipped {} notifications", gap.skipped);
    ///             // Reacquire any subscription coverage the application requires.
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn notifications(&self) -> NotificationStream<ClientNotification> {
        if self.is_shutdown() {
            return NotificationStream::empty();
        }

        // Subscribe to notifications
        let rx = self.pool().notifications();
        NotificationStream::new(rx, |notification| notification.is_shutdown())
    }

    /// Get relays from the relay pool.
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - Only relays with [`RelayCapabilities::READ`] or [`RelayCapabilities::WRITE`]
    ///   are returned.
    ///
    /// To customize this behavior, the returned [`GetRelays`] can be
    /// configured before awaiting it:
    ///
    /// - [`GetRelays::all`]: return all relays in the pool, regardless of capabilities
    /// - [`GetRelays::with_capabilities`]: return relays matching specific
    ///   [`RelayCapabilities`]
    #[inline]
    pub fn relays(&self) -> GetRelays<'_> {
        GetRelays::new(self)
    }

    /// Get a previously added [`Relay`] by URL.
    ///
    /// It returns the relay **only if it has already been added**
    /// to the client via [`Client::add_relay`].
    ///
    /// - Returns `Ok(None)` if the relay is not found in the pool.
    /// - Returns `Err(_)` if the provided URL cannot be parsed as a relay URL.
    ///
    /// # Example
    ///
    /// ```
    /// # use nostr_sdk::prelude::*;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::default();
    /// // Not added yet
    /// let relay = client.relay("wss://relay.example.com").await?;
    /// assert!(relay.is_none());
    ///
    /// // Add it
    /// client.add_relay("wss://relay.example.com").await?;
    ///
    /// // Now it can be retrieved
    /// let relay = client.relay("wss://relay.example.com").await?;
    /// assert!(relay.is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn relay<'a, U>(&self, url: U) -> Result<Option<Relay>, Error>
    where
        U: Into<RelayUrlArg<'a>>,
    {
        let url: RelayUrlArg<'a> = url.into();
        let url: Cow<RelayUrl> = url.try_as_relay_url()?;
        Ok(self.pool().relay(&url).await)
    }

    fn compose_relay_opts<'a>(&self, _url: &'a RelayUrlArg<'a>) -> RelayOptions {
        let mut opts: RelayOptions = RelayOptions::new();

        // Set proxy
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(proxy) = &self.config().proxy {
            opts = opts.proxy(proxy.clone());
        }

        // Set sleep when idle
        opts = opts.sleep_when_idle(self.config().sleep_when_idle);

        // Set limits
        opts.connect_timeout(self.config().connect_timeout)
            .limits(self.config().relay_limits.clone())
            .max_avg_latency(self.config().max_avg_latency)
            .verify_subscriptions(self.config().verify_subscriptions)
            .ban_relay_on_mismatch(self.config().ban_relay_on_mismatch)
    }

    /// Add relay
    ///
    /// By default, relays added with this method will have both [`RelayCapabilities::READ`] and [`RelayCapabilities::WRITE`] capabilities enabled.
    ///
    /// Returns `true` only when a new relay is actually inserted into the pool.
    /// If the relay already exists, its capabilities are updated and `false` is returned.
    /// If the relay is rejected by the admission policy, this method also returns `false`.
    ///
    /// To add a relay with specific capabilities, use [`AddRelay::capabilities`].
    ///
    /// Connection is **NOT** automatically started with relay!
    #[inline]
    pub fn add_relay<'client, 'url, U>(&'client self, url: U) -> AddRelay<'client, 'url>
    where
        U: Into<RelayUrlArg<'url>>,
    {
        let url: RelayUrlArg<'url> = url.into();
        let opts: RelayOptions = self.compose_relay_opts(&url);
        AddRelay::new(self, url).opts(opts)
    }

    /// Add discovery relay
    ///
    /// If relay already exists, this method automatically add the [`RelayCapabilities::DISCOVERY`] flag to it and return `false`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/65.md>
    #[deprecated(
        since = "0.45.0",
        note = "Use `Client::add_relay(url).capabilities(RelayCapabilities::DISCOVERY)` instead."
    )]
    pub async fn add_discovery_relay<'u, U>(&self, url: U) -> Result<bool, Error>
    where
        U: Into<RelayUrlArg<'u>>,
    {
        self.add_relay(url)
            .capabilities(RelayCapabilities::DISCOVERY)
            .await
    }

    /// Add read relay
    #[deprecated(
        since = "0.45.0",
        note = "Use `Client::add_relay(url).capabilities(RelayCapabilities::READ)` instead."
    )]
    pub async fn add_read_relay<'u, U>(&self, url: U) -> Result<bool, Error>
    where
        U: Into<RelayUrlArg<'u>>,
    {
        self.add_relay(url)
            .capabilities(RelayCapabilities::READ)
            .await
    }

    /// Add write relay
    #[deprecated(
        since = "0.45.0",
        note = "Use `Client::add_relay(url).capabilities(RelayCapabilities::WRITE)` instead."
    )]
    pub async fn add_write_relay<'u, U>(&self, url: U) -> Result<bool, Error>
    where
        U: Into<RelayUrlArg<'u>>,
    {
        self.add_relay(url)
            .capabilities(RelayCapabilities::WRITE)
            .await
    }

    /// Add gossip relay
    #[deprecated(
        since = "0.45.0",
        note = "Use `Client::add_relay(url).capabilities(RelayCapabilities::GOSSIP)` instead."
    )]
    pub async fn add_gossip_relay<'u, U>(&self, url: U) -> Result<bool, Error>
    where
        U: Into<RelayUrlArg<'u>>,
    {
        self.add_relay(url)
            .capabilities(RelayCapabilities::GOSSIP)
            .await
    }

    /// Remove and disconnect relay
    ///
    /// If the relay has [`RelayCapabilities::GOSSIP`], it will not be removed from the pool and its
    /// capabilities will be updated (remove [`RelayCapabilities::READ`],
    /// [`RelayCapabilities::WRITE`] and [`RelayCapabilities::DISCOVERY`] capabilities).
    #[inline]
    pub fn remove_relay<'p, 'u, U>(&'p self, url: U) -> RemoveRelay<'p, 'u>
    where
        U: Into<RelayUrlArg<'u>>,
    {
        RemoveRelay::new(self, url.into())
    }

    /// Force remove and disconnect relay
    ///
    /// Note: this method will remove the relay, also if it's in use for the gossip model or other service!
    #[deprecated(since = "0.45.0", note = "use `remove_relay(url).force()` instead")]
    pub async fn force_remove_relay<'u, U>(&self, url: U) -> Result<(), Error>
    where
        U: Into<RelayUrlArg<'u>>,
    {
        self.remove_relay(url).force().await
    }

    /// Disconnect and remove all relays
    ///
    /// Some relays (i.e., the gossip ones) will not be disconnected and removed unless you
    /// use [`RemoveAllRelays::force()`].
    #[inline]
    pub fn remove_all_relays(&self) -> RemoveAllRelays<'_> {
        RemoveAllRelays::new(self)
    }

    /// Disconnect and force remove all relays
    #[deprecated(
        since = "0.45.0",
        note = "use `remove_all_relays(url).force()` instead"
    )]
    pub async fn force_remove_all_relays(&self) {
        let _ = self.remove_all_relays().force().await;
    }

    /// Connect to a previously added relay.
    ///
    /// Attempts to initiate a connection with a single relay.
    ///
    /// At most **one connection per relay** is allowed at any time.
    /// If the relay is already connected or currently attempting to connect,
    /// this method does nothing.
    ///
    /// If the relay is disconnected, sleeping, or otherwise inactive, a
    /// background task is spawned to initiate a connection.
    ///
    /// For further details, see the documentation of [`Relay::connect`].
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - Doesn't wait that relays connect
    ///
    /// To customize this behavior, the returned [`ConnectRelay`] can be
    /// configured before awaiting it:
    ///
    /// - [`ConnectRelay::and_wait`]: wait for the relay to connect at most for the specified `timeout`
    #[inline]
    pub fn connect_relay<'client, 'url, U>(&'client self, url: U) -> ConnectRelay<'client, 'url>
    where
        U: Into<RelayUrlArg<'url>>,
    {
        let url: RelayUrlArg<'url> = url.into();
        ConnectRelay::new(self, url)
    }

    /// Try to connect to a previously added relay.
    ///
    /// Attempts to initiate a connection with a single relay.
    ///
    /// At most **one connection per relay** is allowed at any time.
    /// If the relay is already connected or currently attempting to connect,
    /// this method does nothing.
    ///
    /// If the initial connection attempt succeeds, a background task is spawned
    /// to maintain the connection and handle future reconnections.
    /// If the initial attempt fails, no background task is spawned and no
    /// automatic retries are scheduled.
    ///
    /// Use [`Client::connect_relay`] if you want to always spawn a background
    /// connection task, regardless of whether the initial attempt succeeds.
    ///
    /// For further details, see the documentation of [`Relay::try_connect`].
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - Connection timeout is set to 15 secs
    ///
    /// To customize this behavior, the returned [`TryConnectRelay`] can be
    /// configured before awaiting it:
    ///
    /// - [`TryConnectRelay::timeout`]: set a maximum timeout
    #[inline]
    pub fn try_connect_relay<'client, 'url, U>(
        &'client self,
        url: U,
    ) -> TryConnectRelay<'client, 'url>
    where
        U: Into<RelayUrlArg<'url>>,
    {
        let url: RelayUrlArg<'url> = url.into();
        TryConnectRelay::new(self, url)
    }

    /// Disconnect relay
    #[inline]
    pub async fn disconnect_relay<'a, U>(&self, url: U) -> Result<(), Error>
    where
        U: Into<RelayUrlArg<'a>>,
    {
        let url: RelayUrlArg<'a> = url.into();
        let url: Cow<RelayUrl> = url.try_as_relay_url()?;
        self.pool().disconnect_relay(&url).await
    }

    /// Connect to relays
    ///
    /// Attempts to initiate a connection with relays.
    ///
    /// At most **one connection per relay** is allowed at any time.
    /// If a relay is already connected or currently attempting to connect,
    /// this method does nothing for that relay.
    ///
    /// If a relay is disconnected, sleeping, or otherwise inactive, a
    /// background task is spawned to initiate a connection.
    ///
    /// For further details, see the documentation of [`Relay::connect`].
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - Doesn't wait that relays connect
    ///
    /// To customize this behavior, the returned [`Connect`] can be
    /// configured before awaiting it:
    ///
    /// - [`Connect::and_wait`]: wait for relays connections at most for the specified `timeout`
    #[inline]
    pub fn connect(&self) -> Connect<'_> {
        Connect::new(self)
    }

    /// Waits for relays connections
    ///
    /// Wait for relays connections at most for the specified `timeout`.
    /// The code continues when the relays are connected or the `timeout` is reached.
    #[deprecated(
        since = "0.45.0",
        note = "use `client.connect().and_wait(timeout).await` instead"
    )]
    pub async fn wait_for_connection(&self, timeout: Duration) {
        self.connect().and_wait(timeout).await;
    }

    /// Try to establish a connection with relays.
    ///
    /// # Overview
    ///
    /// Attempts to initiate a connection with relays.
    ///
    /// At most **one connection per relay** is allowed at any time.
    /// If a relay is already connected or currently attempting to connect,
    /// this method does nothing for that relay.
    ///
    /// If the initial connection attempt succeeds, a background task is spawned
    /// to maintain the connection and handle future reconnections.
    /// If the initial attempt fails, no background task is spawned and no
    /// automatic retries are scheduled.
    ///
    /// Use [`Client::connect`] if you want to always spawn a background
    /// connection task, regardless of whether the initial attempt succeeds.
    ///
    /// For further details, see the documentation of [`Relay::try_connect`].
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - Connection timeout is set to 60 secs
    ///
    /// To customize this behavior, the returned [`TryConnect`] can be
    /// configured before awaiting it:
    ///
    /// - [`TryConnect::timeout`]: set a maximum timeout
    #[inline]
    pub fn try_connect(&self) -> TryConnect<'_> {
        TryConnect::new(self)
    }

    /// Disconnect from all relays
    #[inline]
    pub async fn disconnect(&self) {
        self.pool().disconnect().await
    }

    /// Get subscriptions
    #[inline]
    pub async fn subscriptions(&self) -> HashMap<SubscriptionId, HashMap<RelayUrl, Vec<Filter>>> {
        self.pool().subscriptions().await
    }

    /// Get subscription
    #[inline]
    pub async fn subscription(&self, id: &SubscriptionId) -> HashMap<RelayUrl, Vec<Filter>> {
        self.pool().subscription(id).await
    }

    /// Subscribe to events from relays.
    ///
    /// # Overview
    ///
    /// Creates a long-lived event subscription.
    ///
    /// The subscription remains active until it is explicitly closed or until
    /// auto-close conditions are met.
    ///
    /// For short-lived, request-style event streams, use [`Client::stream_events`] or [`Client::fetch_events`].
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - a random subscription ID is generated
    /// - no auto-close condition are set
    ///
    /// The returned [`Subscribe`] builder can be configured before execution:
    ///
    /// - [`Subscribe::with_id`]: set an explicit subscription ID
    /// - [`Subscribe::close_on`]: configure automatic closing conditions
    ///
    /// # Target Resolution
    ///
    /// The request target determines which relays are queried:
    ///
    /// - [`ReqTarget::auto`]: Sends the subscription to all relays with
    ///   [`RelayCapabilities::READ`]. If gossip is enabled
    ///   ([`ClientBuilder::gossip`]), NIP-65 relays are also included.
    /// - [`ReqTarget::single`] / [`ReqTarget::manual`]: Sends the subscription only to
    ///   the explicitly specified relays.
    ///
    /// # Event Semantics
    ///
    /// - Event signatures are **validated**.
    /// - Events are **verified against the requested filters** if
    ///   [`ClientBuilder::verify_subscriptions`] is enabled.
    /// - Event replacements, deletions, and other stateful event semantics
    ///   depend on the [`NostrDatabase`] implementation in use.
    ///
    /// # Lifetime
    ///
    /// The subscription terminates when:
    ///
    /// - It is explicitly closed,
    /// - Auto-close conditions are met (if configured),
    /// - Or the relay closes it remotely.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The resolved target contains no relays,
    /// - A specified relay does not exist in the pool,
    /// - Target resolution fails.
    ///
    /// # Examples
    ///
    /// ## Automatic target resolution
    ///
    /// ```rust,no_run
    /// # use nostr_sdk::prelude::*;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::default();
    /// # client.add_relay("wss://relay1.example.com").await?;
    /// # client.add_relay("wss://relay2.example.com").await?;
    ///
    /// // Subscribe with a single filter to all relays
    /// let filter = Filter::new().kind(Kind::TextNote).since(Timestamp::now());
    ///
    /// // Subscribe to notifications
    /// let mut notifications = client.notifications();
    ///
    /// // Send REQ
    /// let output = client.subscribe(filter).await?;
    /// println!("Subscription ID: {}", output.id());
    /// println!("Successful relays: {:?}", output.success);
    /// println!("Failed relays: {:?}", output.failed);
    ///
    /// // Handle notifications
    /// while let Some(notification) = notifications.next().await {
    ///     if let ClientNotification::Event { relay_url, subscription_id, event } = notification {
    ///         if output.id() == &subscription_id {
    ///             println!("Received an event from '{relay_url}' relay for the subscription '{subscription_id}': {}", event.as_json());
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Target specific relays
    ///
    /// ```rust,no_run
    /// # use std::collections::HashMap;
    /// # use nostr_sdk::prelude::*;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::default();
    /// # client.add_relay("wss://relay1.example.com").await?;
    /// # client.add_relay("wss://relay2.example.com").await?;
    /// // Subscribe to notifications
    /// let mut notifications = client.notifications();
    ///
    /// // Subscribe with different filters per relay
    /// let mut targets = HashMap::new();
    /// targets.insert(
    ///     "wss://relay1.example.com",
    ///     vec![Filter::new().kind(Kind::TextNote).limit(10)],
    /// );
    /// targets.insert(
    ///     "wss://relay2.example.com",
    ///     vec![Filter::new().kind(Kind::Metadata).limit(5)],
    /// );
    ///
    /// // Send REQ
    /// let output = client.subscribe(targets).await?;
    /// println!("Subscription ID: {}", output.id());
    /// println!("Successful relays: {:?}", output.success);
    /// println!("Failed relays: {:?}", output.failed);
    ///
    /// // Handle notifications
    /// while let Some(notification) = notifications.next().await {
    ///     if let ClientNotification::Event { relay_url, subscription_id, event } = notification {
    ///         if output.id() == &subscription_id {
    ///             println!("Received an event from '{relay_url}' relay for the subscription '{subscription_id}': {}", event.as_json());
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## With custom ID and auto-close
    ///
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use nostr_sdk::prelude::*;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::default();
    /// # client.add_relay("wss://relay1.example.com").await?;
    /// # client.add_relay("wss://relay2.example.com").await?;
    ///
    /// // Subscribe to notifications
    /// let mut notifications = client.notifications();
    ///
    /// let filter = Filter::new().kind(Kind::TextNote).limit(10);
    /// let custom_id = SubscriptionId::generate();
    ///
    /// let auto_close =
    ///     SubscribeAutoCloseOptions::default()
    /// .exit_policy(ReqExitPolicy::WaitForEventsAfterEOSE(10))
    /// .idle_timeout(Some(Duration::from_secs(60)));
    ///
    /// // Send REQ
    /// let output = client
    ///     .subscribe(filter)
    ///     .with_id(custom_id)
    ///     .close_on(auto_close)
    ///     .await?;
    ///
    /// println!("Successful relays: {:?}", output.success);
    /// println!("Failed relays: {:?}", output.failed);
    ///
    /// // Handle notifications
    /// while let Some(notification) = notifications.next().await {
    ///     if let ClientNotification::Event { relay_url, subscription_id, event } = notification {
    ///         if output.id() == &subscription_id {
    ///             println!("Received an event from '{relay_url}' relay for the subscription '{subscription_id}': {}", event.as_json());
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn subscribe<'client, 'url, F>(&'client self, target: F) -> Subscribe<'client, 'url>
    where
        F: Into<ReqTarget<'url>>,
    {
        Subscribe::new(self, target.into())
    }

    /// Unsubscribe from a REQ
    #[inline]
    pub fn unsubscribe<'id>(&self, id: &'id SubscriptionId) -> Unsubscribe<'_, 'id> {
        Unsubscribe::new(self, id)
    }

    /// Unsubscribe from all REQs
    #[inline]
    pub fn unsubscribe_all(&self) -> UnsubscribeAll<'_> {
        UnsubscribeAll::new(self)
    }

    /// Stream events from relays.
    ///
    /// # Overview
    ///
    /// Creates a short-lived event subscription and returns a stream of events.
    ///
    /// For long-lived subscriptions, use [`Client::subscribe`].
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - No timeout is set
    /// - Exit policy is [`ReqExitPolicy::ExitOnEOSE`](crate::relay::ReqExitPolicy::ExitOnEOSE)
    ///
    /// To customize this behavior, the returned [`StreamEvents`] can be
    /// configured before awaiting it:
    ///
    /// - [`StreamEvents::with_id`]: use a specific subscription ID
    /// - [`StreamEvents::timeout`]: set a maximum duration for the stream
    /// - [`StreamEvents::policy`]: control when the stream terminates
    ///
    /// # Target Resolution
    ///
    /// The request target determines which relays are queried:
    ///
    /// - [`ReqTarget::auto`]: Streams events from all relays with
    ///   [`RelayCapabilities::READ`]. If gossip is enabled
    ///   ([`ClientBuilder::gossip`]), NIP-65 relays are also included.
    /// - [`ReqTarget::single`] / [`ReqTarget::manual`]: Streams events only from
    ///   the explicitly specified relays.
    ///
    /// # Event Semantics
    ///
    /// - Events are **deduplicated** across relays by event ID.
    /// - Event signatures are **validated**.
    /// - Events are **verified against the requested filters** if
    ///   [`ClientBuilder::verify_subscriptions`] is enabled.
    /// - Event replacements, deletions, and other stateful event semantics
    ///   depend on the [`NostrDatabase`] implementation in use.
    ///
    /// # Termination
    ///
    /// The stream terminates when:
    ///
    /// - The exit policy condition is met (i.e., EOSE),
    /// - All relay streams terminate,
    /// - Or an optional timeout expires.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The resolved target contains no relays,
    /// - A specified relay does not exist in the pool,
    /// - Target resolution fails.
    ///
    /// Network or relay-specific errors are reported **inside the stream**
    /// as `Err(relay::Error)` items.
    ///
    /// # Examples
    ///
    /// ## Single-filter REQ and custom exit policy
    ///
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use nostr_sdk::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// #   let client = Client::default();
    /// let filter = Filter::new().kind(Kind::TextNote).limit(10);
    ///
    /// let mut stream = client
    ///     .stream_events(filter)
    ///     .timeout(Duration::from_secs(10)) // Custom timeout
    ///     .policy(ReqExitPolicy::WaitForEvents(10)) // Custom policy
    ///     .await?;
    ///
    /// while let Some((url, result)) = stream.next().await {
    ///     let event: Event = result?;
    ///     println!("Received an event from '{url}': {}", event.as_json());
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// ## Streams from the explicitly specified relays
    ///
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use std::collections::HashMap;
    /// # use nostr_sdk::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// #   let client = Client::default();
    /// // Subscribe with different filters per relay
    /// let mut targets = HashMap::new();
    /// targets.insert(
    ///     "wss://relay1.example.com",
    ///     vec![Filter::new().kind(Kind::TextNote).limit(10)],
    /// );
    /// targets.insert(
    ///     "wss://relay2.example.com",
    ///     vec![Filter::new().kind(Kind::Metadata).limit(5)],
    /// );
    ///
    /// let mut stream = client
    ///     .stream_events(targets)
    ///     .timeout(Duration::from_secs(10))
    ///     .await?;
    ///
    /// while let Some((url, result)) = stream.next().await {
    ///     let event: Event = result?;
    ///     println!("Received an event from '{url}': {}", event.as_json());
    /// }
    /// # Ok(()) }
    /// ```
    #[inline]
    pub fn stream_events<'client, 'url, F>(&'client self, target: F) -> StreamEvents<'client, 'url>
    where
        F: Into<ReqTarget<'url>>,
    {
        StreamEvents::new(self, target.into())
    }

    /// Fetch events from relays.
    ///
    /// # Overview
    ///
    /// Creates a short-lived event subscription and returns a list of events.
    /// Compared to [`Client::stream_events`], this buffers events internally and returns them only after the stream terminates.
    ///
    /// For long-lived subscriptions, use [`Client::subscribe`].
    ///
    /// # Configuration
    ///
    /// By default:
    ///
    /// - No timeout is set
    /// - Exit policy is [`ReqExitPolicy::ExitOnEOSE`](crate::relay::ReqExitPolicy::ExitOnEOSE)
    ///
    /// To customize this behavior, the returned [`FetchEvents`] can be
    /// configured before awaiting it:
    ///
    /// - [`FetchEvents::timeout`]: set a maximum duration for the stream
    /// - [`FetchEvents::policy`]: control when the stream terminates
    /// - [`FetchEvents::max_events`]: set the maximum number of events buffered in memory
    ///
    /// # Target Resolution, Event Semantics and Termination
    ///
    /// See [`Client::stream_events`] for details on:
    ///
    /// - Target resolution
    /// - Event semantics
    /// - Stream termination conditions
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The resolved target contains no relays,
    /// - A specified relay does not exist in the pool,
    /// - Target resolution fails.
    ///
    /// # Examples
    ///
    /// ## Single-filter REQ and custom exit policy
    ///
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use nostr_sdk::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// #   let client = Client::default();
    /// let filter = Filter::new().kind(Kind::TextNote).limit(10);
    ///
    /// let events = client
    ///     .fetch_events(filter)
    ///     .timeout(Duration::from_secs(10)) // Custom timeout
    ///     .policy(ReqExitPolicy::WaitForEvents(10)) // Custom policy
    ///     .await?;
    ///
    /// for event in events {
    ///     println!("{}", event.as_json());
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// ## Fetch from the explicitly specified relays
    ///
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use std::collections::HashMap;
    /// # use nostr_sdk::prelude::*;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// #   let client = Client::default();
    /// // Subscribe with different filters per relay
    /// let mut targets = HashMap::new();
    /// targets.insert(
    ///     "wss://relay1.example.com",
    ///     vec![Filter::new().kind(Kind::TextNote).limit(10)],
    /// );
    /// targets.insert(
    ///     "wss://relay2.example.com",
    ///     vec![Filter::new().kind(Kind::Metadata).limit(5)],
    /// );
    ///
    /// let events = client
    ///     .fetch_events(targets)
    ///     .timeout(Duration::from_secs(10))
    ///     .await?;
    ///
    /// for event in events {
    ///     println!("{}", event.as_json());
    /// }
    /// # Ok(()) }
    /// ```
    #[inline]
    pub fn fetch_events<'client, 'url, F>(&'client self, target: F) -> FetchEvents<'client, 'url>
    where
        F: Into<ReqTarget<'url>>,
    {
        FetchEvents::new(self, target.into())
    }

    /// Synchronize events with relays using negentropy.
    ///
    /// # Overview
    ///
    /// Performs a negentropy-based reconciliation between the local database
    /// and one or more relays.
    ///
    /// # Configuration
    ///
    /// The returned [`SyncEvents`] builder can be configured before execution:
    ///
    /// - [`SyncEvents::with`]: explicitly select which relays to synchronize with
    /// - [`SyncEvents::opts`]: configure reconciliation behavior
    ///
    /// If no relays are explicitly specified, the target set is resolved
    /// automatically (see *Target Resolution*).
    ///
    /// # Target Resolution
    ///
    /// The set of relays to synchronize with is determined as follows:
    ///
    /// - If relays are explicitly provided via [`SyncEvents::with`], only those
    ///   relays are used.
    /// - Otherwise, if gossip is enabled ([`ClientBuilder::gossip`]), NIP-65 relays
    ///   are automatically discovered and used as targets.
    /// - Otherwise, all relays in the pool with
    ///   [`RelayCapabilities::READ`] or [`RelayCapabilities::WRITE`] are used.
    ///
    /// Each target relay receives the same filter, scoped to the events relevant
    /// for reconciliation.
    ///
    /// # Reconciliation Semantics
    ///
    /// - Reconciliation is performed using NIP-77 negentropy
    ///   (<https://github.com/nostr-protocol/nips/blob/master/77.md>).
    /// - Event transfer occurs **only** for events determined to be missing
    ///   on either side.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - Target resolution fails,
    /// - A specified relay URL is invalid,
    /// - Database access fails,
    /// - Or reconciliation cannot be initiated.
    ///
    /// Relay-specific failures during event transfer are reported in the
    /// returned [`SyncSummary`].
    #[inline]
    pub fn sync<'url>(&self, filter: Filter) -> SyncEvents<'_, 'url> {
        SyncEvents::new(self, filter)
    }

    /// Sync events with specific relays (negentropy reconciliation)
    ///
    /// <https://github.com/hoytech/negentropy>
    #[deprecated(
        since = "0.45.0",
        note = "use `client.sync(filter).with(urls).await` instead"
    )]
    pub async fn sync_with<'a, I, U>(
        &self,
        urls: I,
        filter: Filter,
        opts: &SyncOptions,
    ) -> Result<Output<SyncSummary>, Error>
    where
        I: IntoIterator<Item = U>,
        U: Into<RelayUrlArg<'a>>,
    {
        self.sync(filter).with(urls).opts(opts.clone()).await
    }

    /// Send a client message to relays.
    ///
    /// # Overview
    ///
    /// Sends a protocol-level [`ClientMessage`] to one or more relays.
    ///
    /// This API is intended for sending raw client messages (e.g. subscription
    /// control, close messages, or other relay commands) and does **not** perform
    /// event persistence, gossip routing, or event-specific processing.
    ///
    /// The operation completes once the message has been dispatched according
    /// to the selected policy and optional waiting behavior.
    ///
    /// # Configuration
    ///
    /// By default:
    /// - broadcast the message to [`RelayCapabilities::READ`] or [`RelayCapabilities::WRITE`] relays
    /// - doesn't wait that the message is sent
    ///
    /// The returned [`SendMessage`] builder can be configured before execution:
    ///
    /// - [`SendMessage::broadcast`]: send the message to all relays with
    ///   [`RelayCapabilities::READ`] or [`RelayCapabilities::WRITE`]
    /// - [`SendMessage::to`]: send the message only to explicitly specified relays
    /// - [`SendMessage::wait_until_sent`]: wait until the message is sent or a
    ///   timeout expires
    ///
    /// # Delivery Semantics
    ///
    /// - Messages are sent once to each resolved relay.
    /// - No retries are performed if delivery fails.
    /// - Message ordering and relay acknowledgment depend on relay behavior.
    ///
    /// If [`SendMessage::wait_until_sent`] is configured, the operation waits
    /// until the message is sent or the timeout expires.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - A specified relay URL is invalid,
    /// - Or a specified relay does not exist in the pool.
    ///
    /// Relay-specific delivery failures are reported in the returned [`Output`].
    #[inline]
    pub fn send_msg<'msg, 'url>(&self, msg: ClientMessage<'msg>) -> SendMessage<'_, 'msg, 'url> {
        SendMessage::new(self, msg)
    }

    /// Send an event to relays.
    ///
    /// # Overview
    ///
    /// Sends an event to one or more relays and returns the event ID on
    /// successful delivery.
    ///
    /// By default, events are routed using the gossip engine (if configured in the [`ClientBuilder`]),
    /// allowing the client to automatically discover appropriate relays and
    /// establish connections as needed.
    ///
    /// The operation completes once delivery attempts have finished according
    /// to the selected routing, acknowledgement policy, and timeouts.
    ///
    /// # Configuration
    ///
    /// The returned [`SendEvent`] builder can be configured before execution:
    ///
    /// - [`SendEvent::broadcast`]: send the event to all relays with
    ///   [`RelayCapabilities::WRITE`]
    /// - [`SendEvent::to`]: send the event only to explicitly specified relays
    /// - [`SendEvent::to_nip17`]: send the event to NIP-17 relays (requires gossip)
    /// - [`SendEvent::to_nip65`]: send the event to NIP-65 relays (requires gossip)
    /// - [`SendEvent::save_into_database`]: control whether the event is saved
    ///   locally before sending
    /// - [`SendEvent::ack_policy`]: control relay `OK` acknowledgement behavior
    /// - [`SendEvent::ok_timeout`]: set a timeout for waiting for `OK` responses
    /// - [`SendEvent::authentication_timeout`]: set a timeout for relay authentication
    ///
    /// # Target Resolution
    ///
    /// The destination relays are resolved as follows:
    ///
    /// - If [`SendEvent::to`] is used, the event is sent only to the specified
    ///   relays.
    /// - If [`SendEvent::broadcast`] is used, the event is sent to all relays in
    ///   the pool with [`RelayCapabilities::WRITE`].
    /// - If [`SendEvent::to_nip17`] or [`SendEvent::to_nip65`] is used, relay
    ///   selection is delegated to the gossip engine.
    /// - If no explicit policy is set:
    ///   - Gossip is used when available,
    ///   - Otherwise, the event is broadcast to all WRITE relays.
    ///
    /// # Persistence
    ///
    /// By default, the event is saved into the local database **before** being
    /// sent to relays.
    ///
    /// This behavior can be disabled via [`SendEvent::save_into_database`].
    ///
    /// # Acknowledgement Policy
    ///
    /// By default, [`AckPolicy::all`] is used, so each selected relay send waits
    /// for an `OK` response.
    ///
    /// You can disable waiting for relay `OK` via [`SendEvent::ack_policy`] with
    /// [`AckPolicy::none`]. In that mode, relay results are reported after
    /// dispatching the `EVENT` message without waiting for relay confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - Gossip-based routing is requested but gossip is not configured,
    /// - A specified relay URL is invalid,
    /// - A specified relay does not exist in the pool,
    /// - The event cannot be saved to the database,
    /// - Or sending cannot be initiated.
    ///
    /// Relay-specific delivery results are reported in the returned [`SendEventOutput`].
    #[inline]
    pub fn send_event<'event, 'url>(&self, event: &'event Event) -> SendEvent<'_, 'event, 'url> {
        SendEvent::new(self, event)
    }

    /// Send event to specific relays
    ///
    /// # Gossip
    ///
    /// If `gossip` is enabled and the [`Event`] is a NIP17/NIP65 relay list,
    /// the gossip data will be updated.
    #[deprecated(
        since = "0.45.0",
        note = "use `client.send_event(event).to(urls).await` instead"
    )]
    pub async fn send_event_to<'a, I, U>(
        &self,
        urls: I,
        event: &Event,
    ) -> Result<SendEventOutput, Error>
    where
        I: IntoIterator<Item = U>,
        U: Into<RelayUrlArg<'a>>,
    {
        self.send_event(event).to(urls).await
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use nostr_gossip_memory::prelude::*;

    use super::*;
    use crate::error::ErrorKind;
    use crate::local_relay::*;
    use crate::relay::RelayStatus;

    #[tokio::test]
    async fn test_shutdown() {
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let client = Client::default();

        client.add_relay(&url).await.unwrap();

        client.connect().await;

        assert!(!client.is_shutdown());

        tokio::time::sleep(Duration::from_secs(1)).await;

        client.shutdown().await;

        // All relays must be removed
        assert!(client.relays().all().await.is_empty());

        // Client must be marked as shutdown
        assert!(client.is_shutdown());

        let err = client.add_relay(url).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::State);
        assert_eq!(err.to_string(), "shutdown");
    }

    #[tokio::test]
    async fn test_shutdown_on_drop() {
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = {
            let client: Client = Client::default();

            client.add_relay(&url).and_connect().await.unwrap();

            assert!(!client.is_shutdown());

            tokio::time::sleep(Duration::from_millis(500)).await;

            let relay = client.relay(&url).await.unwrap().unwrap();

            assert!(relay.status().is_connected());

            relay
        };
        // Client is dropped here

        tokio::time::sleep(Duration::from_secs(1)).await;

        // When the client is dropped, all relays are shutdown
        assert_eq!(relay.status(), RelayStatus::Shutdown);
    }

    #[tokio::test]
    async fn test_shutdown_on_drop_with_weak_clone() {
        let weak: WeakClient = {
            let client: Client = Client::default();

            assert!(!client.is_shutdown());

            // Weak clone
            let weak: WeakClient = client.weak_clone();

            // The client is still alive, so the upgrade must success
            assert!(weak.upgrade().is_some());

            weak
        };
        // Client is dropped here

        // The client is dropped, so the upgrade must fail
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn test_shutdown_on_drop_with_gossip_background_refresher_enabled() {
        let weak: WeakClient = {
            let gossip = NostrGossipMemory::unbounded();
            let client: Client = Client::builder().gossip(gossip).build();

            tokio::time::sleep(Duration::from_secs(1)).await;

            assert!(!client.is_shutdown());
            assert!(client.gossip().unwrap().is_background_refresher_spawned());

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Check number of atomic references for the client
            // Must be 2 because the background refresher is using the client
            assert_eq!(Arc::strong_count(&client.0), 2);

            tokio::time::sleep(Duration::from_secs(4)).await;

            // Now should be just one atomic reference, as the background refresher is sleeping
            assert_eq!(Arc::strong_count(&client.0), 1);

            // Weak clone
            let weak: WeakClient = client.weak_clone();

            // The client is still alive, so the upgrade must success
            assert!(weak.upgrade().is_some());

            weak
        };
        // Client is dropped here

        // The client is dropped, so the upgrade must fail
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn test_terminate_notification_stream_on_shutdown() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let client: Client = Client::default();

        client.add_relay(&url).and_connect().await.unwrap();

        // Shutdown after some time
        let c = client.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;

            c.shutdown().await;
        });

        assert!(!client.is_shutdown());

        let fut = async {
            let mut notifications = client.notifications();

            let mut received = false;

            // The stream must terminate after receiving the shutdown status
            while let Some(n) = notifications.next().await {
                if let ClientNotification::Shutdown = n {
                    received = true;
                }
            }

            // Make sure we received the shutdown status
            assert!(received);
        };
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .unwrap();

        assert!(client.is_shutdown());

        // Try to get a new stream
        let mut notifications = client.notifications();

        let res = tokio::time::timeout(Duration::from_secs(1), notifications.next())
            .await
            .unwrap();

        // Must return None, as it's empty
        assert!(res.is_none());
    }
}
