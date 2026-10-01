//! Relay

use std::cmp;
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_utility::time;
use nostr_database::prelude::*;
use tokio::sync::broadcast;

mod api;
mod builder;
mod capabilities;
mod constants;
mod inner;
mod limits;
mod notification;
mod options;
mod ping;
mod stats;
mod status;

pub use self::api::*;
pub use self::builder::*;
pub use self::capabilities::*;
pub(crate) use self::constants::DEFAULT_FETCH_EVENTS_LIMIT;
use self::inner::InnerRelay;
pub use self::limits::*;
pub use self::notification::*;
pub use self::options::*;
pub use self::stats::*;
pub use self::status::*;
use crate::client::ClientNotification;
use crate::shared::SharedState;
use crate::stream::NotificationStream;

/// Subscription auto-closed reason
#[derive(Debug, Clone, PartialEq, Eq)]
enum SubscriptionAutoClosedReason {
    /// NIP42 authentication failed
    AuthenticationFailed,
    /// Closed
    Closed(String),
    /// Completed
    Completed,
}

#[derive(Debug)]
enum SubscriptionActivity {
    /// Received an event
    ReceivedEvent(Event),
    /// Subscription closed
    Closed(SubscriptionAutoClosedReason),
}

/// Relay
#[derive(Debug)]
pub struct Relay {
    pub(crate) inner: InnerRelay,
    // Keep track of the atomic reference count to know when shutdown the relay.
    atomic_counter: Arc<AtomicUsize>,
}

impl Clone for Relay {
    fn clone(&self) -> Self {
        // Increase the reference count
        self.atomic_counter.fetch_add(1, Ordering::SeqCst);

        // Return a clone of the relay
        Self {
            inner: self.inner.clone(),
            atomic_counter: self.atomic_counter.clone(),
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // Shutdown exactly once when the last client handle is dropped.
        if self.atomic_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.shutdown();
        }
    }
}

impl PartialEq for Relay {
    fn eq(&self, other: &Self) -> bool {
        self.inner.url == other.inner.url
    }
}

impl Eq for Relay {}

impl PartialOrd for Relay {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Relay {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.inner.url.cmp(&other.inner.url)
    }
}

impl Relay {
    #[inline]
    pub(crate) fn new_shared(
        url: RelayUrl,
        state: SharedState,
        capabilities: RelayCapabilities,
        opts: RelayOptions,
    ) -> Self {
        Self {
            inner: InnerRelay::new(url, state, capabilities, opts),
            atomic_counter: Arc::new(AtomicUsize::new(1)),
        }
    }

    /// Construct a new relay.
    ///
    /// Use [`Relay::builder`] for customizing the relay.
    #[inline]
    pub fn new(url: RelayUrl) -> Self {
        Self::builder(url).build()
    }

    /// Construct a new relay builder.
    #[inline]
    pub fn builder(url: RelayUrl) -> RelayBuilder {
        RelayBuilder::new(url)
    }

    fn from_builder(builder: RelayBuilder) -> Self {
        let state: SharedState = SharedState::new(
            builder.database,
            builder.websocket_transport,
            None,
            builder.admit_policy,
            builder.authenticator,
            None,
        );

        Self::new_shared(builder.url, state, builder.capabilities, builder.opts)
    }

    /// Get relay url
    #[inline]
    pub fn url(&self) -> &RelayUrl {
        &self.inner.url
    }

    /// Get proxy
    #[inline]
    #[cfg(not(target_arch = "wasm32"))]
    pub fn proxy(&self) -> Option<SocketAddr> {
        self.inner.proxy()
    }

    /// Get status
    #[inline]
    pub fn status(&self) -> RelayStatus {
        self.inner.status()
    }

    /// Get relay capabilities
    #[inline]
    pub fn capabilities(&self) -> &Arc<AtomicRelayCapabilities> {
        &self.inner.capabilities
    }

    /// Get subscriptions
    #[inline]
    pub async fn subscriptions(&self) -> HashMap<SubscriptionId, Vec<Filter>> {
        self.inner.subscriptions().await
    }

    /// Get filters by [SubscriptionId]
    #[inline]
    pub async fn subscription(&self, id: &SubscriptionId) -> Option<Vec<Filter>> {
        self.inner.subscription(id).await
    }

    /// Get options
    #[inline]
    pub fn opts(&self) -> &RelayOptions {
        &self.inner.opts
    }

    /// Get [`RelayConnectionStats`]
    #[inline]
    pub fn stats(&self) -> &RelayConnectionStats {
        &self.inner.stats
    }

    #[inline]
    pub(super) fn set_notification_sender(
        &mut self,
        notification_sender: broadcast::Sender<ClientNotification>,
    ) {
        self.inner.set_notification_sender(notification_sender);
    }

    /// Get a new notification stream
    ///
    /// The stream terminates when the relay shutdowns or is banned.
    ///
    /// Notifications lost when this receiver falls behind are skipped.
    /// Use [`NotificationStream::with_gaps`] to observe such losses.
    ///
    /// <div class="warning">When you call this method, you subscribe to the notifications channel from that precise moment. Anything received by relay/s before that moment is not included in the channel!</div>
    #[inline]
    pub fn notifications(&self) -> NotificationStream<RelayNotification> {
        // If the relay is permanently unusable, return an empty stream
        let status: RelayStatus = self.status();
        if status.is_banned() || status.is_shutdown() {
            return NotificationStream::empty();
        }

        // Subscribe to notifications
        let rx = self.inner.internal_notification_sender.subscribe();

        NotificationStream::new(
            rx,
            |notification| matches!(notification, RelayNotification::RelayStatus { status } if status.is_banned() || status.is_shutdown()),
        )
    }

    /// Connect to the relay
    ///
    /// # Overview
    ///
    /// If the relay’s status is not [`RelayStatus::Initialized`] or [`RelayStatus::Terminated`],
    /// this method returns immediately without doing anything.
    /// Otherwise, the connection task will be spawned, which will attempt to connect to relay.
    ///
    /// This method returns immediately and doesn't provide any information on if the connection was successful or not.
    ///
    /// # Automatic reconnection
    ///
    /// By default, in case of disconnection, the connection task will automatically attempt to reconnect.
    /// This behavior can be disabled by changing [`RelayOptions::reconnect`] option.
    pub fn connect(&self) {
        // Immediately return if can't connect
        if !self.status().can_connect() {
            return;
        }

        // Update status
        // Change it to pending to avoid issues with the health check (initialized check)
        self.inner.set_status(RelayStatus::Pending, false);

        // Spawn connection task
        self.inner.spawn_connection_task(None);
    }

    /// Waits for relay connection
    ///
    /// Wait for relay connection at most for the specified `timeout`.
    /// The code continues when the relay is connected or the `timeout` is reached.
    pub async fn wait_for_connection(&self, timeout: Duration) {
        let status: RelayStatus = self.status();

        // Immediately returns if the relay is already connected, if it's terminated or banned.
        if status.is_connected()
            || status.is_terminated()
            || status.is_banned()
            || status.is_shutdown()
        {
            return;
        }

        // Subscribe to notifications
        let mut notifications = self.inner.internal_notification_sender.subscribe();

        // Set timeout
        time::timeout(Some(timeout), async {
            while let Ok(notification) = notifications.recv().await {
                // Wait for status change. Break loop when connect.
                if let RelayNotification::RelayStatus { status } = notification {
                    match status {
                        // Waiting for connection
                        RelayStatus::Initialized
                        | RelayStatus::Pending
                        | RelayStatus::Connecting
                        | RelayStatus::Disconnected => {}
                        // Connected or terminated/banned/sleeping/shutdown
                        RelayStatus::Connected
                        | RelayStatus::Terminated
                        | RelayStatus::Banned
                        | RelayStatus::Sleeping
                        | RelayStatus::Shutdown => break,
                    }
                }
            }
        })
        .await;
    }

    /// Try to establish a connection with the relay.
    ///
    /// # Overview
    ///
    /// If the relay’s status is not [`RelayStatus::Initialized`] or [`RelayStatus::Terminated`],
    /// this method returns immediately without doing anything.
    /// Otherwise, attempts to establish a connection without spawning the connection task if it fails.
    /// This means that if the connection fails, no automatic retries are scheduled.
    /// Use [`Relay::connect`] if you want to immediately spawn a connection task,
    /// regardless of whether the initial connection succeeds.
    ///
    /// Returns an error if the connection fails or if the relay has been banned.
    ///
    /// # Automatic reconnection
    ///
    /// By default, in case of disconnection (after a first successful connection),
    /// the connection task will automatically attempt to reconnect.
    /// This behavior can be disabled by changing [`RelayOptions::reconnect`] option.
    pub fn try_connect(&self) -> TryConnect<'_> {
        TryConnect::new(self)
    }

    /// Disconnect from relay and set status to [`RelayStatus::Terminated`].
    #[inline]
    pub fn disconnect(&self) {
        self.inner.disconnect()
    }

    /// Ban relay and set status to [`RelayStatus::Banned`].
    ///
    /// A banned relay can't reconnect again.
    #[inline]
    pub fn ban(&self) {
        self.inner.ban()
    }

    /// Shutdown relay and set the status to [`RelayStatus::Shutdown`].
    #[inline]
    pub fn shutdown(&self) {
        self.inner.shutdown()
    }

    /// Send a message to the relay
    #[inline]
    pub fn send_msg<'msg>(&self, msg: ClientMessage<'msg>) -> SendMessage<'_, 'msg> {
        SendMessage::new(self, msg)
    }

    /// Send event and wait for `OK` relay msg
    #[inline]
    pub fn send_event<'event>(&self, event: &'event Event) -> SendEvent<'_, 'event> {
        SendEvent::new(self, event)
    }

    /// Subscribe to filters
    #[inline]
    pub fn subscribe<F>(&self, filters: F) -> Subscribe<'_>
    where
        F: Into<Vec<Filter>>,
    {
        Subscribe::new(self, filters.into())
    }

    /// Unsubscribe
    ///
    /// Returns `Ok(true)` if the subscription has been unsubscribed.
    #[inline]
    pub fn unsubscribe<'id>(&self, id: &'id SubscriptionId) -> Unsubscribe<'_, 'id> {
        Unsubscribe::new(self, id)
    }

    /// Unsubscribe from all subscriptions
    #[inline]
    pub fn unsubscribe_all(&self) -> UnsubscribeAll<'_> {
        UnsubscribeAll::new(self)
    }

    /// Stream events from relay
    #[inline]
    pub fn stream_events<F>(&self, filters: F) -> StreamEvents<'_>
    where
        F: Into<Vec<Filter>>,
    {
        StreamEvents::new(self, filters.into())
    }

    /// Fetch events
    #[inline]
    pub fn fetch_events<F>(&self, filters: F) -> FetchEvents<'_>
    where
        F: Into<Vec<Filter>>,
    {
        FetchEvents::new(self, filters.into())
    }

    /// Count events.
    ///
    /// A successful zero is returned only for a matching COUNT response.
    /// Timeout, notification loss, closure, or relay rejection return an error.
    pub fn count_events(&self, filter: Filter) -> CountEvents<'_> {
        CountEvents::new(self, filter)
    }

    /// Sync events with relays (negentropy reconciliation)
    #[inline]
    pub fn sync(&self, filter: Filter) -> SyncEvents<'_> {
        SyncEvents::new(self, filter)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use async_utility::time;
    use futures::StreamExt;

    use super::*;
    use crate::error::{Error, ErrorKind};
    use crate::local_relay::*;
    use crate::policy::{AdmitPolicy, AdmitStatus};
    use crate::test_utils::setup_relay;

    #[derive(Debug)]
    struct CustomTestPolicy {
        banned_relays: HashSet<RelayUrl>,
    }

    impl AdmitPolicy for CustomTestPolicy {
        fn admit_connection<'a>(
            &'a self,
            relay_url: &'a RelayUrl,
        ) -> Pin<Box<dyn Future<Output = Result<AdmitStatus, Error>> + Send + 'a>> {
            Box::pin(async move {
                if self.banned_relays.contains(relay_url) {
                    Ok(AdmitStatus::rejected("banned"))
                } else {
                    Ok(AdmitStatus::Success)
                }
            })
        }
    }

    fn new_relay(url: RelayUrl, opts: RelayOptions) -> Relay {
        Relay::builder(url).opts(opts).build()
    }

    async fn setup_subscription_relay() -> (SubscriptionId, Relay, MockRelay) {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        // Sender
        let relay: Relay = setup_relay(url.clone()).await;

        // Subscribe
        let filter = Filter::new().kind(Kind::TextNote);
        let id = relay.subscribe(filter).await.unwrap();

        (id, relay, mock)
    }

    fn check_relay_is_sleeping(relay: &Relay) {
        assert_eq!(relay.status(), RelayStatus::Sleeping);
        assert!(relay.status().can_connect());
        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_status_with_reconnection_enabled() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Connected);

        mock.shutdown();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(relay.status(), RelayStatus::Disconnected);

        assert!(relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_status_with_reconnection_disabled() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default().reconnect(false));

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Connected);

        mock.shutdown();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(relay.status(), RelayStatus::Terminated);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_disconnect() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Connected);

        relay.disconnect();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(relay.status(), RelayStatus::Terminated);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_disconnect_non_connected_relay() {
        let url = RelayUrl::parse("wss://127.0.0.1:666").unwrap();

        let opts = RelayOptions::default()
            .adjust_retry_interval(false)
            .retry_interval(Duration::from_secs(1));
        let relay: Relay = new_relay(url, opts);

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay.connect();

        time::sleep(Duration::from_secs(1)).await;

        assert!(relay.inner.is_running());

        assert_eq!(relay.status(), RelayStatus::Disconnected);

        time::sleep(Duration::from_secs(3)).await;

        relay.disconnect();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(relay.status(), RelayStatus::Terminated);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_connect() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay.connect();

        relay.wait_for_connection(Duration::from_secs(1)).await;

        assert_eq!(relay.status(), RelayStatus::Connected);
        assert!(relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_connect_to_unreachable_relay() {
        let url = RelayUrl::parse("wss://127.0.0.1:666").unwrap();

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay.connect();

        time::sleep(Duration::from_secs(1)).await;

        assert_eq!(relay.status(), RelayStatus::Disconnected);
        assert!(relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_disconnect_unresponsive_relay_that_connect() {
        // Mock relay
        let opts = LocalRelayTestOptions {
            unresponsive_connection: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let mock = MockRelay::run_with_opts(opts).await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay.connect();

        time::sleep(Duration::from_secs(1)).await;

        assert_eq!(relay.status(), RelayStatus::Connecting);

        time::sleep(Duration::from_secs(2)).await;

        assert_eq!(relay.status(), RelayStatus::Connected);

        relay.disconnect();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(relay.status(), RelayStatus::Terminated);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_disconnect_unresponsive_relay_that_not_connect() {
        // Mock relay
        let opts = LocalRelayTestOptions {
            unresponsive_connection: Some(Duration::from_secs(10)),
            ..Default::default()
        };
        let mock = MockRelay::run_with_opts(opts).await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay.connect();

        time::sleep(Duration::from_secs(1)).await;

        assert_eq!(relay.status(), RelayStatus::Connecting);

        relay.disconnect();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(relay.status(), RelayStatus::Terminated);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_disconnect_unresponsive_during_try_connect() {
        // Mock relay
        let opts = LocalRelayTestOptions {
            unresponsive_connection: Some(Duration::from_secs(10)),
            ..Default::default()
        };
        let mock = MockRelay::run_with_opts(opts).await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        // Terminate after 3 secs
        let r = relay.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_secs(3)).await;
            r.disconnect();
        });

        let res = relay.try_connect().timeout(Duration::from_secs(7)).await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Rejected);
        assert_eq!(err.to_string(), "received termination request");

        assert_eq!(relay.status(), RelayStatus::Terminated);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_ban_relay() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Connected);

        relay.ban();

        assert_eq!(relay.status(), RelayStatus::Banned);
        assert!(!relay.inner.is_running());

        // Retry to connect
        let res = relay.try_connect().timeout(Duration::from_secs(2)).await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::State);
        assert_eq!(err.to_string(), "relay banned");

        assert_eq!(relay.status(), RelayStatus::Banned);

        // Try to call disconnect. The status mustn't change.
        relay.disconnect();

        assert_eq!(relay.status(), RelayStatus::Banned);

        // Health check
        let res = relay.inner.ensure_operational();
        let err = res.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::State);
        assert_eq!(err.to_string(), "relay banned");
    }

    #[tokio::test]
    async fn test_shutdown() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Connected);

        relay.shutdown();

        time::sleep(Duration::from_millis(100)).await;

        assert_eq!(relay.status(), RelayStatus::Shutdown);

        assert!(!relay.inner.is_running());

        // Attempt to reconnect: must fail
        let res = relay.try_connect().timeout(Duration::from_secs(3)).await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::State);
        assert_eq!(err.to_string(), "shutdown");
    }

    #[tokio::test]
    async fn test_shutdown_on_drop() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let inner: InnerRelay = {
            let relay: Relay = Relay::new(url);

            relay
                .try_connect()
                .timeout(Duration::from_secs(3))
                .await
                .unwrap();

            assert_eq!(relay.status(), RelayStatus::Connected);

            // Clone the inner relay
            let inner: InnerRelay = relay.inner.clone();

            {
                let r2 = relay.clone();
                tokio::spawn(async move {
                    assert_eq!(r2.atomic_counter.load(Ordering::SeqCst), 2);

                    time::sleep(Duration::from_secs(1)).await;

                    // r2 dropped here
                });
            }

            time::sleep(Duration::from_secs(3)).await;

            assert_eq!(relay.atomic_counter.load(Ordering::SeqCst), 1);

            inner
        }; // relay dropped here

        time::sleep(Duration::from_secs(1)).await;

        assert_eq!(inner.status(), RelayStatus::Shutdown);
        assert!(!inner.is_running());
    }

    #[tokio::test]
    async fn test_wait_for_connection() {
        // Mock relay
        let opts = LocalRelayTestOptions {
            unresponsive_connection: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let mock = MockRelay::run_with_opts(opts).await.unwrap();
        let url = mock.url().await;

        let relay: Relay = new_relay(url, RelayOptions::default());

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay.connect();

        relay.wait_for_connection(Duration::from_millis(500)).await; // This timeout

        assert_eq!(relay.status(), RelayStatus::Connecting);

        relay.wait_for_connection(Duration::from_secs(3)).await;

        assert_eq!(relay.status(), RelayStatus::Connected);
    }

    #[tokio::test]
    async fn test_unsubscribe() {
        let (id, relay, _mock) = setup_subscription_relay().await;

        time::sleep(Duration::from_secs(1)).await;

        assert!(relay.subscription(&id).await.is_some());

        relay.unsubscribe(&id).await.unwrap();

        assert!(relay.subscription(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_unsubscribe_all() {
        let (_id, relay, _mock) = setup_subscription_relay().await;

        time::sleep(Duration::from_secs(1)).await;

        relay.unsubscribe_all().await.unwrap();

        relay.subscriptions().await.is_empty();
    }

    #[tokio::test]
    async fn test_admit_connection() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let mut relay = new_relay(url.clone(), RelayOptions::default());

        relay.inner.state.admit_policy = Some(Arc::new(CustomTestPolicy {
            banned_relays: HashSet::from([url]),
        }));

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay.connect();

        time::sleep(Duration::from_secs(2)).await;

        assert_eq!(relay.status(), RelayStatus::Terminated);
        assert!(!relay.inner.is_running());

        // Retry to connect
        let res = relay.try_connect().timeout(Duration::from_secs(2)).await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Rejected);
        assert_eq!(err.to_string(), "connection rejected: reason=banned");

        assert_eq!(relay.status(), RelayStatus::Terminated);
        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_sleep_when_idle() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        // Relay
        let opts = RelayOptions::default().sleep_when_idle(SleepWhenIdle::Enabled {
            timeout: Duration::from_secs(2),
        });
        let relay = new_relay(url, opts);

        // Connect
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();

        // Check that is connected
        assert_eq!(relay.status(), RelayStatus::Connected);

        // Wait to make sure the relay go in sleep mode (see SLEEP_INTERVAL const)
        time::sleep(Duration::from_secs(3)).await;
        check_relay_is_sleeping(&relay);

        // Test wake up when sending an event
        let event = EventBuilder::new(Kind::TextNote, "text wake-up")
            .finalize(&Keys::generate())
            .unwrap();
        relay.send_event(&event).await.unwrap();
        assert_eq!(relay.status(), RelayStatus::Connected);

        // Check if relay is sleeping
        time::sleep(Duration::from_secs(3)).await;
        check_relay_is_sleeping(&relay);

        // Test wake up when fetch events
        let filter = Filter::new().kind(Kind::TextNote);
        let _ = relay
            .fetch_events(filter)
            .timeout(Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(relay.status(), RelayStatus::Connected);

        // Check if relay is sleeping
        time::sleep(Duration::from_secs(3)).await;
        check_relay_is_sleeping(&relay);

        // Test wake up when sync
        let filter = Filter::new().kind(Kind::TextNote);
        let _ = relay.sync(filter).await.unwrap();
        assert_eq!(relay.status(), RelayStatus::Connected);

        // Check if relay is sleeping
        time::sleep(Duration::from_secs(3)).await;
        check_relay_is_sleeping(&relay);
    }

    #[tokio::test]
    async fn test_sleep_when_idle_with_long_lived_subscription() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        // Relay
        let opts = RelayOptions::default().sleep_when_idle(SleepWhenIdle::Enabled {
            timeout: Duration::from_secs(2),
        });
        let relay = new_relay(url, opts);

        // Connect
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();

        // Check that is connected
        assert_eq!(relay.status(), RelayStatus::Connected);

        let filter = Filter::new().kind(Kind::TextNote);
        relay.subscribe(filter).await.unwrap();

        time::sleep(Duration::from_secs(5)).await;
        assert_eq!(relay.status(), RelayStatus::Connected);
    }

    #[tokio::test]
    async fn test_terminate_notification_stream_on_shutdown() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay = Relay::new(url);

        // Connect
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(relay.status(), RelayStatus::Connected);

        // Shutdown after some time
        let r = relay.clone();
        tokio::spawn(async move {
            time::sleep(Duration::from_secs(3)).await;

            r.shutdown()
        });

        let fut = async {
            let mut notifications = relay.notifications();

            let mut received = false;

            // The stream must terminate after receiving the shutdown status
            while let Some(n) = notifications.next().await {
                if let RelayNotification::RelayStatus {
                    status: RelayStatus::Shutdown,
                } = n
                {
                    received = true;
                }
            }

            // Make sure we received the shutdown status
            assert!(received);
        };
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .unwrap();

        // Try to get a new stream
        let mut notifications = relay.notifications();

        let res = tokio::time::timeout(Duration::from_secs(1), notifications.next())
            .await
            .unwrap();

        // Must return None, as it's empty
        assert!(res.is_none());
    }
}
