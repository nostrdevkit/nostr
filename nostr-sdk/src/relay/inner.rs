use std::borrow::Cow;
use std::cmp;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_utility::{task, time};
use async_wsocket::Message;
use futures::{self, SinkExt, StreamExt};
use nostr::filter::MatchEventOptions;
use nostr::message::MachineReadablePrefix;
use nostr::nips::nip42;
use nostr_database::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
use rand::Rng;
use rand::RngExt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{Mutex, MutexGuard, Notify, RwLock, RwLockWriteGuard, broadcast, oneshot, watch};
use universal_time::Instant;

use super::capabilities::{AtomicRelayCapabilities, RelayCapabilities};
use super::constants::{
    JITTER_RANGE, MAX_RETRY_INTERVAL, MIN_ATTEMPTS, MIN_SUCCESS_RATE, PING_INTERVAL,
    SLEEP_INTERVAL, WEBSOCKET_TX_TIMEOUT,
};
use super::options::{RelayOptions, ReqExitPolicy, SubscribeAutoCloseOptions};
use super::ping::PingTracker;
use super::stats::RelayConnectionStats;
use super::{
    RelayNotification, RelayStatus, SleepWhenIdle, SubscriptionActivity,
    SubscriptionAutoClosedReason,
};
use crate::client::ClientNotification;
use crate::error::Error;
use crate::policy::AdmitStatus;
use crate::relay::status::AtomicRelayStatus;
use crate::shared::SharedState;
use crate::transport::websocket::{WebSocketSink, WebSocketStream};

type ClientMessageJson = String;

// Skip NIP-50 matches since they may create issues and ban non-malicious relays.
const MATCH_EVENT_OPTS: MatchEventOptions = MatchEventOptions::new().nip50(false);

fn queue_auth_challenge(tx: &watch::Sender<Option<String>>, challenge: &str) {
    // NIP-42 invalidates the previous challenge when a relay sends a new one.
    tx.send_replace(Some(challenge.to_owned()));
}

enum HandleClosedMsg {
    MarkAsClosed,
    Remove,
}

struct HandleAutoClosing {
    to_close: bool,
    reason: Option<SubscriptionAutoClosedReason>,
}

struct JsonMessageItem {
    json: ClientMessageJson,
    confirmation: Option<oneshot::Sender<()>>,
}

#[derive(Debug)]
struct RelayChannels {
    nostr: (Sender<JsonMessageItem>, Mutex<Receiver<JsonMessageItem>>),
    ping: Notify,
    terminate: Notify,
}

impl RelayChannels {
    pub fn new() -> Self {
        let (tx_nostr, rx_nostr) = mpsc::channel(1024);

        Self {
            nostr: (tx_nostr, Mutex::new(rx_nostr)),
            ping: Notify::new(),
            terminate: Notify::new(),
        }
    }

    #[inline]
    fn send_client_msg(&self, msg: JsonMessageItem) -> Result<(), Error> {
        self.nostr
            .0
            .try_send(msg)
            .map_err(|_| Error::state_msg("can't send message to the transport dispatcher"))
    }

    #[inline]
    pub async fn rx_nostr(&self) -> MutexGuard<'_, Receiver<JsonMessageItem>> {
        self.nostr.1.lock().await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn ping(&self) {
        self.ping.notify_one()
    }

    pub fn terminate(&self) {
        self.terminate.notify_one()
    }

    fn clear_termination_permit(&self) {
        let mut notified = std::pin::pin!(self.terminate.notified());
        // `enable` consumes a stored permit, if any. The old task no longer
        // waits for it when its replacement is reserved.
        let _ = notified.as_mut().enable();
    }
}

#[derive(Debug)]
struct SubscriptionData {
    pub filters: Vec<Filter>,
    pub subscribed_connection: usize,
    pub is_auto_closing: bool,
    /// Received EOSE msg
    pub received_eose: bool,
    /// Number of received events
    pub received_events: AtomicUsize,
    /// Subscription closed by relay
    pub closed: bool,
}

impl SubscriptionData {
    #[inline]
    fn long_lived(filters: Vec<Filter>, subscribed_connection: usize) -> Self {
        Self {
            filters,
            subscribed_connection,
            is_auto_closing: false,
            received_eose: false,
            received_events: AtomicUsize::new(0),
            closed: false,
        }
    }

    #[inline]
    fn auto_closing(filters: Vec<Filter>) -> Self {
        Self {
            filters,
            subscribed_connection: 0,
            is_auto_closing: true,
            received_eose: false,
            received_events: AtomicUsize::new(0),
            closed: false,
        }
    }
}

// Instead of wrap every field in an `Arc<T>`, which increases the number of atomic operations,
// put all fields that require an `Arc` here.
#[derive(Debug)]
pub(super) struct AtomicPrivateData {
    status: AtomicRelayStatus,
    channels: RelayChannels,
    subscriptions: RwLock<HashMap<SubscriptionId, SubscriptionData>>,
    connection_task: StdMutex<ConnectionTaskOwnership>,
    #[cfg(test)]
    teardown_hook: StdMutex<Option<Arc<TeardownHook>>>,
}

#[derive(Debug, Default)]
struct ConnectionTaskOwnership {
    running: bool,
    restart_requested: bool,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TeardownHook {
    started: Notify,
    entered: Notify,
    release: Notify,
    finished: Notify,
}

#[derive(Debug, Clone)]
pub(crate) struct InnerRelay {
    pub(super) url: RelayUrl,
    pub(super) atomic: Arc<AtomicPrivateData>,
    pub(super) opts: RelayOptions,
    pub(super) capabilities: Arc<AtomicRelayCapabilities>,
    pub(super) stats: RelayConnectionStats,
    pub(super) state: SharedState,
    pub(super) internal_notification_sender: broadcast::Sender<RelayNotification>,
    external_notification_sender: Option<broadcast::Sender<ClientNotification>>,
}

impl InnerRelay {
    pub(super) fn new(
        url: RelayUrl,
        state: SharedState,
        capabilities: RelayCapabilities,
        opts: RelayOptions,
    ) -> Self {
        let (relay_notification_sender, ..) =
            broadcast::channel::<RelayNotification>(opts.notification_channel_size);

        Self {
            url,
            atomic: Arc::new(AtomicPrivateData {
                status: AtomicRelayStatus::default(),
                channels: RelayChannels::new(),
                subscriptions: RwLock::new(HashMap::new()),
                connection_task: StdMutex::new(ConnectionTaskOwnership::default()),
                #[cfg(test)]
                teardown_hook: StdMutex::new(None),
            }),
            capabilities: Arc::new(AtomicRelayCapabilities::new(capabilities)),
            opts,
            stats: RelayConnectionStats::default(),
            state,
            internal_notification_sender: relay_notification_sender,
            external_notification_sender: None,
        }
    }

    #[inline]
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn proxy(&self) -> Option<SocketAddr> {
        self.opts.proxy.as_ref().and_then(|p| p.get_addr(&self.url))
    }

    #[inline]
    #[cfg(target_arch = "wasm32")]
    fn proxy(&self) -> Option<SocketAddr> {
        None
    }

    /// Check if the connection task is running
    #[inline]
    #[cfg(test)]
    pub(super) fn is_running(&self) -> bool {
        self.atomic.connection_task.lock().unwrap().running
    }

    #[inline]
    pub fn status(&self) -> RelayStatus {
        self.atomic.status.load()
    }

    pub(super) fn set_status(&self, status: RelayStatus, log: bool) {
        // Change status
        self.atomic.status.set(status);

        // Log
        if log {
            match status {
                RelayStatus::Initialized => tracing::trace!(url = %self.url, "Relay initialized."),
                RelayStatus::Pending => tracing::trace!(url = %self.url, "Relay is pending."),
                RelayStatus::Connecting => tracing::debug!("Connecting to '{}'", self.url),
                RelayStatus::Connected => tracing::info!("Connected to '{}'", self.url),
                RelayStatus::Disconnected => tracing::info!("Disconnected from '{}'", self.url),
                RelayStatus::Terminated => {
                    tracing::info!("Completely disconnected from '{}'", self.url)
                }
                RelayStatus::Banned => tracing::info!(url = %self.url, "Relay banned."),
                RelayStatus::Sleeping => tracing::info!("Relay '{}' went to sleep.", self.url),
                RelayStatus::Shutdown => tracing::info!("Relay '{}' has been shutdown.", self.url),
            }
        }

        // Send notification
        self.send_notification(RelayNotification::RelayStatus { status }, false);

        // If monitor is enabled, notify status change.
        if let Some(monitor) = &self.state.monitor {
            monitor.notify_status_change(self.url.clone(), status);
        }
    }

    /// Perform checks to ensure that the relay is ready for use.
    pub(super) fn ensure_operational(&self) -> Result<(), Error> {
        // Ensures that the relay is awake.
        self.ensure_awake_for_activity();

        // Get current status
        let status: RelayStatus = self.status();

        // Relay is not ready (never called connect method)
        if status.is_initialized() {
            return Err(Error::not_ready());
        }

        // The relay has been banned
        if status.is_banned() {
            return Err(Error::banned());
        }

        // Sanity-check, to ensure that the relay is not sleeping.
        if status.is_sleeping() {
            return Err(Error::sleeping());
        }

        // This is needed to allow giving the time to the relay to connect,
        // instead of just checking the status.
        //
        // A relay is considered not connected if all the following conditions are met:
        // - the status is different from `RelayStatus::Connected`
        // - the relay has already exceeded the minimum number of attempts
        // - the connection success rate is lower than the minimum success rate
        // - the relay woke up from sleep from more than defaul connection timeout (needed if the relay has just waked up!)
        if !status.is_connected()
            && self.stats.attempts() > MIN_ATTEMPTS
            && self.stats.success_rate() < MIN_SUCCESS_RATE
            && self.stats.woke_up_at() + self.opts.connect_timeout < Timestamp::now()
        {
            return Err(Error::not_connected());
        }

        // Check avg. latency
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Check if max avg latency is set
            if let Some(max) = self.opts.max_avg_latency {
                // ONLY LATER get the latency, to avoid unnecessary calculation
                if let Some(current) = self.stats.latency() {
                    if current > max {
                        return Err(Error::limit_exceeded("maximum latency exceeded"));
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn has_subscription(&self, id: &SubscriptionId) -> bool {
        let subscription = self.atomic.subscriptions.read().await;
        subscription.contains_key(id)
    }

    #[cfg(test)]
    pub(crate) async fn active_subscription_count(&self) -> usize {
        self.atomic.subscriptions.read().await.len()
    }

    /// Returns all long-lived (non-auto-closing) subscriptions
    pub async fn subscriptions(&self) -> HashMap<SubscriptionId, Vec<Filter>> {
        let subscription = self.atomic.subscriptions.read().await;
        subscription
            .iter()
            .filter_map(|(k, v)| (!v.is_auto_closing).then_some((k.clone(), v.filters.clone())))
            .collect()
    }

    pub async fn subscription(&self, id: &SubscriptionId) -> Option<Vec<Filter>> {
        let subscription = self.atomic.subscriptions.read().await;
        subscription.get(id).map(|d| d.filters.clone())
    }

    pub(super) async fn remove_subscription(&self, id: &SubscriptionId) {
        let mut subscriptions = self.atomic.subscriptions.write().await;
        subscriptions.remove(id);
    }

    /// Register a long-lived subscription.
    pub(crate) async fn add_long_lived_subscription(
        &self,
        id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<(), Error> {
        let mut subscriptions = self.atomic.subscriptions.write().await;

        if subscriptions.contains_key(&id) {
            return Err(Error::invalid_msg("subscription ID already exists"));
        }

        subscriptions.insert(
            id,
            SubscriptionData::long_lived(filters, self.stats.success()),
        );

        Ok(())
    }

    /// Register an auto-closing subscription
    pub(crate) async fn add_auto_closing_subscription(
        &self,
        id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<(), Error> {
        let mut subscriptions = self.atomic.subscriptions.write().await;

        if subscriptions.contains_key(&id) {
            return Err(Error::invalid_msg("subscription ID already exists"));
        }

        subscriptions.insert(id, SubscriptionData::auto_closing(filters));

        Ok(())
    }

    pub(crate) async fn update_subscription(
        &self,
        id: &SubscriptionId,
        filters: Vec<Filter>,
        mark_subscribed: bool,
    ) -> Result<(), Error> {
        let mut subscriptions = self.atomic.subscriptions.write().await;
        let data = subscriptions
            .get_mut(id)
            .ok_or_else(|| Error::not_found("subscription not found"))?;
        data.filters = filters;

        if mark_subscribed {
            data.subscribed_connection = self.stats.success();
            data.closed = false;
        }

        Ok(())
    }

    pub(crate) async fn update_auto_closing_subscription(
        &self,
        id: &SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<(), Error> {
        let mut subscriptions = self.atomic.subscriptions.write().await;
        let data = subscriptions
            .get_mut(id)
            .ok_or_else(|| Error::not_found("subscription not found"))?;

        *data = SubscriptionData::auto_closing(filters);

        Ok(())
    }

    /// Mark subscription as closed
    async fn subscription_closed(&self, id: &SubscriptionId) {
        let mut subscriptions = self.atomic.subscriptions.write().await;
        if let Some(data) = subscriptions.get_mut(id) {
            data.closed = true;
        }
    }

    /// Received eose for subscription
    async fn received_eose(&self, id: &SubscriptionId) {
        let mut subscriptions = self.atomic.subscriptions.write().await;
        if let Some(data) = subscriptions.get_mut(id) {
            data.received_eose = true;
        }
    }

    /// Check if it should subscribe for current websocket session
    pub(crate) async fn should_resubscribe(&self, id: &SubscriptionId) -> bool {
        let subscriptions = self.atomic.subscriptions.read().await;
        match subscriptions.get(id) {
            Some(SubscriptionData {
                subscribed_connection,
                closed,
                is_auto_closing: false,
                ..
            }) => {
                // Never subscribed -> SHOULD subscribe
                // Subscription closed by relay -> SHOULD subscribe
                if *closed {
                    return true;
                }

                // A request queued before the first connection is already in the
                // outbound channel. Later connections must restore it once.
                let current_connection = self.stats.success();
                current_connection > 1 && current_connection > *subscribed_connection
            }
            // NOT subscribe if auto-closing subscription or subscription not found
            Some(SubscriptionData {
                is_auto_closing: true,
                ..
            })
            | None => false,
        }
    }

    #[inline]
    pub(crate) fn set_notification_sender(
        &mut self,
        notification_sender: broadcast::Sender<ClientNotification>,
    ) {
        self.external_notification_sender = Some(notification_sender);
    }

    fn send_notification(&self, notification: RelayNotification, external: bool) {
        match (external, &self.external_notification_sender) {
            (true, Some(external_notification_sender)) => {
                // Clone and send internal notification
                let _ = self.internal_notification_sender.send(notification.clone());

                // Convert relay to notification to pool notification
                let notification: Option<ClientNotification> = match notification {
                    RelayNotification::Event {
                        subscription_id,
                        event,
                    } => Some(ClientNotification::Event {
                        relay_url: self.url.clone(),
                        subscription_id,
                        event,
                    }),
                    RelayNotification::Message { message } => Some(ClientNotification::Message {
                        relay_url: self.url.clone(),
                        message,
                    }),
                    RelayNotification::RelayStatus { .. } => None,
                    RelayNotification::Authenticated => None,
                    RelayNotification::AuthenticationFailed => None,
                };

                // Send external notification
                if let Some(notification) = notification {
                    let _ = external_notification_sender.send(notification);
                }
            }
            _ => {
                // Send internal notification
                let _ = self.internal_notification_sender.send(notification);
            }
        }
    }

    pub(super) async fn check_connection_policy(&self) -> Result<AdmitStatus, Error> {
        match &self.state.admit_policy {
            Some(policy) => Ok(policy.admit_connection(&self.url).await?),
            None => Ok(AdmitStatus::Success),
        }
    }

    /// Check if relay should sleep
    async fn should_sleep(&self) -> bool {
        // Check if sleeping is disabled
        let SleepWhenIdle::Enabled { timeout } = self.opts.sleep_when_idle else {
            return false;
        };

        // Get current subscriptions
        let subscriptions = self.atomic.subscriptions.read().await;

        // No sleep if there are active subscriptions
        if !subscriptions.is_empty() {
            return false;
        }

        // See if enough time elapsed since the last activity
        let last_activity: Timestamp = self.stats.last_activity_at();

        // If no activity has been recorded yet, use connection time
        let reference_time: Timestamp = if last_activity == Timestamp::zero() {
            self.stats.connected_at()
        } else {
            last_activity
        };

        // If reference time is still 0, do not sleep; relay has just started.
        if reference_time == Timestamp::zero() {
            return false;
        }

        let idle_duration_secs: u64 = Timestamp::now().as_secs() - reference_time.as_secs();
        let idle_duration: Duration = Duration::from_secs(idle_duration_secs);
        idle_duration >= timeout
    }

    /// Wake up the relay if it's sleeping and update the last activity timestamp.
    #[inline]
    fn ensure_awake_for_activity(&self) {
        // If the sleeping is disabled, immediately return.
        if self.opts.sleep_when_idle.is_disabled() {
            return;
        }

        // Update last activity timestamp
        self.stats.update_activity();

        // If it isn't sleeping, immediately return.
        if !self.status().is_sleeping() {
            return;
        }

        tracing::debug!(url = %self.url, "Waking up sleeping relay.");

        self.request_connect();

        // Update the wake-up timestamp
        self.stats.just_woke_up();
    }

    pub(super) fn reserve_try_connect(&self) -> Result<bool, Error> {
        let mut ownership = self.atomic.connection_task.lock().unwrap();
        let status = self.status();
        if status.is_shutdown() {
            return Err(Error::shutdown());
        }
        if status.is_banned() {
            return Err(Error::banned());
        }
        if !status.can_connect() {
            return Ok(false);
        }
        if ownership.running {
            ownership.restart_requested = true;
            self.set_status(RelayStatus::Pending, false);
            return Err(Error::state_msg(
                "previous connection task is stopping; reconnect queued",
            ));
        }
        self.atomic.channels.clear_termination_permit();
        ownership.running = true;
        self.set_status(RelayStatus::Pending, false);
        Ok(true)
    }

    pub(super) fn spawn_reserved_connection_task(&self, stream: (WebSocketSink, WebSocketStream)) {
        task::spawn(self.clone().connection_task(Some(stream)));
    }

    pub(super) fn finish_reserved_connection_task(&self) {
        if self.status() == RelayStatus::Connecting {
            self.set_status(RelayStatus::Terminated, false);
        }
        self.finish_connection_task();
    }

    pub(super) fn request_connect(&self) {
        let mut ownership = self.atomic.connection_task.lock().unwrap();
        if !self.status().can_connect() {
            return;
        }

        self.set_status(RelayStatus::Pending, false);
        if ownership.running {
            ownership.restart_requested = true;
            return;
        }

        self.atomic.channels.clear_termination_permit();
        ownership.running = true;
        drop(ownership);
        task::spawn(self.clone().connection_task(None));
    }

    /// This **MUST** be called only after connection-task ownership is reserved.
    async fn connection_task(self, mut stream: Option<(WebSocketSink, WebSocketStream)>) {
        let status = self.status();
        if status.is_terminated() || status.is_banned() || status.is_shutdown() {
            self.finish_connection_task();
            return;
        }

        // Lock receiver
        let mut rx_nostr = self.atomic.channels.rx_nostr().await;

        #[cfg(test)]
        if let Some(hook) = self.atomic.teardown_hook.lock().unwrap().as_ref() {
            hook.started.notify_one();
        }

        // Last websocket error
        // Store it to avoid printing every time the same connection error
        let mut last_ws_error = None;

        // Auto-connect loop
        loop {
            // Check if the connection is allowed
            match self.check_connection_policy().await {
                Ok(status) => {
                    // Connection rejected, update status and break the loop.
                    if let AdmitStatus::Rejected { reason } = status {
                        if let Some(reason) = reason {
                            tracing::warn!(reason = %reason, "Connection rejected by admission policy.");
                        }

                        // Set the status to "terminated" and break loop.
                        self.set_status(RelayStatus::Terminated, false);
                        break;
                    }
                }
                Err(e) => tracing::error!(error = %e, "Impossible to check connection policy."),
            }

            // Connect and run message handler
            // The termination requests are handled inside this method!
            self.connect_and_run(stream.take(), &mut rx_nostr, &mut last_ws_error)
                .await;

            // Get status
            let status: RelayStatus = self.status();

            // A connect requested during teardown belongs to a replacement
            // task. Do not turn it into an ordinary delayed retry here.
            if self
                .atomic
                .connection_task
                .lock()
                .unwrap()
                .restart_requested
            {
                break;
            }

            // If the relay is terminated, banned or sleeping, break the loop.
            if status.is_terminated()
                || status.is_banned()
                || status.is_sleeping()
                || status.is_shutdown()
            {
                break;
            }

            // Check if reconnection is enabled
            if self.opts.reconnect {
                // Check if the relay is marked as disconnected. If not, update status.
                // Check if disconnected to avoid a possible double log
                if !status.is_disconnected() {
                    self.set_status(RelayStatus::Disconnected, true);
                }

                // Sleep before retry to connect
                let interval: Duration = self.calculate_retry_interval();
                tracing::debug!(
                    "Reconnecting to '{}' relay in {} secs",
                    self.url,
                    interval.as_secs()
                );

                // Sleep before retry to connect
                // Handle termination to allow exiting immediately if request is received during the sleep.
                tokio::select! {
                    // Sleep
                    _ = time::sleep(interval) => {},
                    // Handle termination notification
                    _ = self.handle_terminate() => break,
                }
            } else {
                // Reconnection disabled, set status to "terminated"
                self.set_status(RelayStatus::Terminated, true);

                // Break loop and exit
                tracing::debug!(url = %self.url, "Reconnection disabled, breaking loop.");
                break;
            }
        }

        drop(rx_nostr);

        #[cfg(test)]
        let hook = self.atomic.teardown_hook.lock().unwrap().take();
        #[cfg(test)]
        if let Some(hook) = hook.as_ref() {
            hook.entered.notify_one();
            hook.release.notified().await;
        }

        self.finish_connection_task();

        #[cfg(test)]
        if let Some(hook) = hook {
            hook.finished.notify_one();
        }

        tracing::debug!(url = %self.url, "Auto connect loop terminated.");
    }

    fn finish_connection_task(&self) {
        let mut ownership = self.atomic.connection_task.lock().unwrap();
        let status = self.status();
        let restart = ownership.restart_requested
            && !status.is_banned()
            && !status.is_shutdown()
            && !status.is_sleeping();

        ownership.restart_requested = false;
        if restart {
            if status.is_terminated() {
                self.set_status(RelayStatus::Pending, false);
            }
            self.atomic.channels.clear_termination_permit();
            // Keep ownership reserved until the replacement task starts.
            drop(ownership);
            task::spawn(self.clone().connection_task(None));
        } else {
            ownership.running = false;
        }
    }

    /// Depending on attempts and success, use default or incremental retry interval
    fn calculate_retry_interval(&self) -> Duration {
        // Check if the incremental interval is enabled
        if self.opts.adjust_retry_interval {
            // Calculate the difference between attempts and success
            let diff: u32 = self.stats.attempts().saturating_sub(self.stats.success()) as u32;

            // Calculate multiplier
            let multiplier: u32 = 1 + (diff / 2);

            // Compute the adaptive retry interval
            let adaptive_interval: Duration = self.opts.retry_interval * multiplier;

            // If the interval is too big, use the min one.
            // If the interval is checked after the jitter, the interval may be the same for all relays!
            let mut interval: Duration = cmp::min(adaptive_interval, MAX_RETRY_INTERVAL);

            // The jitter is added to avoid situations where multiple relays reconnect simultaneously after a failure.
            // This helps prevent synchronized retry storms.
            let jitter: i8 = UnwrapErr(SysRng).random_range(JITTER_RANGE);

            // Apply jitter
            if jitter >= 0 {
                // Positive jitter, add it to the interval.
                interval = interval.saturating_add(Duration::from_secs(jitter as u64));
            } else {
                // Negative jitter, compute `|jitter|` and saturating subtract it from the interval.
                let jitter: u64 = jitter.unsigned_abs() as u64;
                interval = interval.saturating_sub(Duration::from_secs(jitter));
            }

            // Return interval
            return interval;
        }

        // Use default internal
        self.opts.retry_interval
    }

    #[inline]
    async fn handle_terminate(&self) {
        // Wait to be notified
        self.atomic.channels.terminate.notified().await;
    }

    pub(super) async fn _try_connect(
        &self,
        timeout: Duration,
        status_on_failure: RelayStatus,
    ) -> Result<(WebSocketSink, WebSocketStream), Error> {
        {
            let ownership = self.atomic.connection_task.lock().unwrap();
            let status = self.status();
            if ownership.restart_requested
                || status.is_terminated()
                || status.is_banned()
                || status.is_shutdown()
            {
                return Err(Error::state_msg("connection attempt superseded"));
            }
            self.set_status(RelayStatus::Connecting, true);
        }

        // Increase the attempts
        self.stats.new_attempt();

        // Connect futures
        let connect_fut = self
            .state
            .transport
            .connect((&self.url).into(), self.proxy());
        let fut = time::timeout(Some(timeout), connect_fut);

        // Try to connect
        // If during connection the termination request is received, abort the connection and return error.
        // At this stem is NOT required to close the WebSocket connection.
        tokio::select! {
            // Connect
            res = fut => match res {
                Some(Ok((ws_tx, ws_rx))) => {
                    // A disconnect or replacement request may have superseded
                    // this dial while the transport was connecting.
                    let _ownership = self.atomic.connection_task.lock().unwrap();
                    if self.status() != RelayStatus::Connecting {
                        return Err(Error::state_msg("connection attempt superseded"));
                    }
                    self.set_status(RelayStatus::Connected, true);

                    // Increment success stats
                    self.stats.new_success();

                    Ok((ws_tx, ws_rx))
                }
                Some(Err(e)) => {
                    let _ownership = self.atomic.connection_task.lock().unwrap();
                    if self.status() == RelayStatus::Connecting {
                        self.set_status(status_on_failure, false);
                    }

                    // Return error
                    Err(Error::transport(e))
                }
                None => {
                    let _ownership = self.atomic.connection_task.lock().unwrap();
                    if self.status() == RelayStatus::Connecting {
                        self.set_status(status_on_failure, false);
                    }

                    // Return error
                    Err(Error::timeout())
                }
            },
            // Handle termination notification
            _ = self.handle_terminate() => Err(Error::rejected_msg("received termination request")),
        }
    }

    /// Connect and run message handler
    ///
    /// If `stream` arg is passed, no connection attempt will be done.
    async fn connect_and_run(
        &self,
        stream: Option<(WebSocketSink, WebSocketStream)>,
        rx_nostr: &mut MutexGuard<'_, Receiver<JsonMessageItem>>,
        last_ws_error: &mut Option<String>,
    ) {
        match stream {
            // Already have a stream, go to post-connection stage
            Some((ws_tx, ws_rx)) => self.post_connection(ws_tx, ws_rx, rx_nostr).await,
            // No stream is passed, try to connect
            // Set the status to "disconnected" to allow to automatic retries
            None => match self
                ._try_connect(self.opts.connect_timeout, RelayStatus::Disconnected)
                .await
            {
                // Connection success, go to post-connection stage
                Ok((ws_tx, ws_rx)) => self.post_connection(ws_tx, ws_rx, rx_nostr).await,
                // Error during connection
                Err(e) => {
                    // TODO: avoid string allocation. The error is converted to string only to perform the `!=` binary operation.
                    // Check if error should be logged
                    let e: String = e.to_string();
                    let to_log: bool = match &last_ws_error {
                        Some(prev_err) => {
                            // Log only if different from the last one
                            prev_err != &e
                        }
                        None => true,
                    };

                    // Log error and update the last error
                    if to_log {
                        tracing::error!(url = %self.url, error= %e, "Connection failed.");
                        *last_ws_error = Some(e);
                    }
                }
            },
        }
    }

    /// To run after websocket connection.
    /// Run message handlers, pinger and other services
    async fn post_connection(
        &self,
        mut ws_tx: WebSocketSink,
        ws_rx: WebSocketStream,
        rx_nostr: &mut MutexGuard<'_, Receiver<JsonMessageItem>>,
    ) {
        // (Re)subscribe to relay
        if self.capabilities.can_read() {
            if let Err(e) = self.resubscribe().await {
                tracing::error!(url = %self.url, error = %e, "Impossible to subscribe.")
            }
        }

        let ping: PingTracker = PingTracker::default();

        // Retain only the latest valid challenge while asynchronous signing is in progress.
        let (ingester_tx, ingester_rx) = watch::channel(None);

        // Wait that one of the futures terminates/completes
        // Add also termination here, to allow closing the connection in case of termination request.
        tokio::select! {
            // Message sender handler
            res = self.sender_message_handler(&mut ws_tx, rx_nostr, &ping) => match res {
                Ok(()) => tracing::trace!(url = %self.url, "Relay sender exited."),
                Err(e) => tracing::error!(url = %self.url, error = %e, "Relay sender exited with error.")
            },
            // Message receiver handler
            res = self.receiver_message_handler(ws_rx, &ping, ingester_tx) => match res {
                Ok(()) => tracing::trace!(url = %self.url, "Relay receiver exited."),
                Err(e) => tracing::error!(url = %self.url, error = %e, "Relay receiver exited with error.")
            },
            // Ingester: perform actions
            res = self.ingester(ingester_rx) => match res {
                Ok(()) => tracing::trace!(url = %self.url, "Relay ingester exited."),
                Err(e) => tracing::error!(url = %self.url, error = %e, "Relay ingester exited with error.")
            },
            // Monitor when the relay can go to sleep
            _ = self.sleep_when_idle_monitor() => {},
            // Termination handler
            _ = self.handle_terminate() => {},
            // Pinger
            _ = self.pinger() => {}
        }

        // Always try to close the WebSocket connection
        match close_ws(&mut ws_tx).await {
            Ok(..) => tracing::debug!("WebSocket connection closed."),
            Err(e) => tracing::error!(error = %e, "Can't close WebSocket connection."),
        }
    }

    async fn sender_message_handler(
        &self,
        ws_tx: &mut WebSocketSink,
        rx_nostr: &mut MutexGuard<'_, Receiver<JsonMessageItem>>,
        ping: &PingTracker,
    ) -> Result<(), Error> {
        #[cfg(target_arch = "wasm32")]
        let _ping = ping;

        loop {
            tokio::select! {
                // Nostr channel receiver
                Some(JsonMessageItem { json, confirmation }) = rx_nostr.recv() => {
                    // Get messages size
                    let size: usize = json.len();

                    // Log
                    tracing::debug!("Sending '{json}' to '{}' (size: {size} bytes)", self.url);

                    // Compose WebSocket text messages
                    let msg: Message = Message::Text(json);

                    // Send WebSocket messages
                    send_ws_msg(ws_tx, msg).await?;

                    // Send the confirmation
                    if let Some(confirmation) = confirmation {
                        if confirmation.send(()).is_err() {
                            tracing::error!(url = %self.url, "Can't send msg confirmation.");
                        }
                    }

                    // Increase sent bytes
                    self.stats.add_bytes_sent(size);
                }
                // Ping channel receiver
                _ = self.atomic.channels.ping.notified() => {
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        // If the last nonce is NOT 0, check if relay replied.
                        // Return error if relay not replied
                        if ping.last_nonce() != 0 && !ping.replied() {
                            return Err(Error::timeout());
                        }

                        // Generate and save nonce
                        let mut rng = UnwrapErr(SysRng);
                        let nonce: u64 = rng.next_u64();
                        ping.set_last_nonce(nonce);
                        ping.set_replied(false);

                        // Compose ping message
                        let msg = Message::Ping(nonce.to_be_bytes().to_vec());

                        // Send WebSocket message
                        send_ws_msg(ws_tx, msg).await?;

                        // Set ping as just sent
                        ping.just_sent().await;

                        #[cfg(debug_assertions)]
                        tracing::debug!(url = %self.url, nonce = %nonce, "Ping sent.");
                    }
                }
                else => break
            }
        }

        Ok(())
    }

    async fn receiver_message_handler(
        &self,
        mut ws_rx: WebSocketStream,
        ping: &PingTracker,
        ingester_tx: watch::Sender<Option<String>>,
    ) -> Result<(), Error> {
        #[cfg(target_arch = "wasm32")]
        let _ping = ping;

        while let Some(msg) = ws_rx.next().await {
            match msg? {
                Message::Text(json) => self.handle_relay_message(&json, &ingester_tx).await,
                Message::Binary(_) => {
                    tracing::warn!(url = %self.url, "Binary messages aren't supported.");
                }
                #[cfg(not(target_arch = "wasm32"))]
                Message::Pong(bytes) if self.opts.ping && self.state.transport.support_ping() => {
                    match bytes.try_into() {
                        Ok(nonce) => {
                            // Nonce from big-endian bytes
                            let nonce: u64 = u64::from_be_bytes(nonce);

                            // Get last nonce
                            let last_nonce: u64 = ping.last_nonce();

                            // Check if last nonce not matches the received one
                            if last_nonce != nonce {
                                return Err(Error::pong_not_match(last_nonce, nonce));
                            }

                            // Set ping as replied
                            ping.set_replied(true);

                            // Save latency
                            let sent_at = ping.sent_at().await;
                            self.stats.save_latency(sent_at.elapsed());
                        }
                        Err(..) => {
                            return Err(Error::protocol_msg("can't parse pong"));
                        }
                    }
                }
                #[cfg(not(target_arch = "wasm32"))]
                Message::Close(None) => break,
                #[cfg(not(target_arch = "wasm32"))]
                Message::Close(Some(frame)) => {
                    tracing::info!(code = %frame.code, reason = %frame.reason, "Connection closed by peer.");
                    break;
                }
                #[cfg(not(target_arch = "wasm32"))]
                _ => {}
            }
        }

        Ok(())
    }

    async fn ingester(&self, mut rx: watch::Receiver<Option<String>>) -> Result<(), Error> {
        while rx.changed().await.is_ok() {
            let Some(challenge) = rx.borrow_and_update().clone() else {
                continue;
            };

            match self.auth(challenge).await {
                Ok(..) => {
                    self.send_notification(RelayNotification::Authenticated, false);

                    tracing::info!(url = %self.url, "Authenticated to relay.");

                    // TODO: ?
                    if let Err(e) = self.resubscribe().await {
                        tracing::error!(
                            url = %self.url,
                            error = %e,
                            "Impossible to resubscribe."
                        );
                    }
                }
                Err(e) => {
                    self.send_notification(RelayNotification::AuthenticationFailed, false);

                    tracing::error!(
                        url = %self.url,
                        error = %e,
                        "Can't authenticate to relay."
                    );
                }
            }
        }

        Ok(())
    }

    /// Monitor if it's time to put the relay in sleep mode.
    async fn sleep_when_idle_monitor(&self) {
        loop {
            // Sleep
            time::sleep(SLEEP_INTERVAL).await;

            // Check if should go to sleep
            if self.should_sleep().await {
                // Update status
                self.set_status(RelayStatus::Sleeping, true);

                // Break the loop
                break;
            }
        }
    }

    /// Send a signal every [`PING_INTERVAL`] to the other tasks, asking to ping the relay.
    async fn pinger(&self) {
        loop {
            // Check if support ping
            #[cfg(not(target_arch = "wasm32"))]
            if self.opts.ping && self.state.transport.support_ping() {
                // Ping supported, ping!
                self.atomic.channels.ping();
            }

            // Sleep
            time::sleep(PING_INTERVAL).await;
        }
    }

    async fn handle_relay_message(&self, msg: &str, ingester_tx: &watch::Sender<Option<String>>) {
        match self.handle_raw_relay_message(msg).await {
            Ok(Some(message)) => {
                match &message {
                    RelayMessage::Closed {
                        subscription_id,
                        message,
                    } => {
                        // Check machine-readable prefix
                        let res: HandleClosedMsg = match MachineReadablePrefix::parse(message) {
                            Some(MachineReadablePrefix::Duplicate) => HandleClosedMsg::Remove,
                            Some(MachineReadablePrefix::Pow) => HandleClosedMsg::Remove,
                            Some(MachineReadablePrefix::Blocked) => HandleClosedMsg::Remove,
                            Some(MachineReadablePrefix::RateLimited) => {
                                // TODO: add something like MarkAsRateLimited?
                                // TODO: And retry after some time to re-subscribe
                                HandleClosedMsg::MarkAsClosed
                            }
                            Some(MachineReadablePrefix::Invalid) => HandleClosedMsg::Remove,
                            Some(MachineReadablePrefix::Error) => HandleClosedMsg::Remove,
                            Some(MachineReadablePrefix::Unsupported) => HandleClosedMsg::Remove,
                            Some(MachineReadablePrefix::AuthRequired) => {
                                if self.state.is_authenticator_available() {
                                    // Authentication is handled in other parts of code,
                                    // so here just mark as closed for resubscribe.
                                    HandleClosedMsg::MarkAsClosed
                                } else {
                                    HandleClosedMsg::Remove
                                }
                            }
                            Some(MachineReadablePrefix::Restricted) => HandleClosedMsg::Remove,
                            _ => {
                                // Doesn't mach any prefix,
                                // meaning that it probably closed without errors,
                                // so remove it.
                                HandleClosedMsg::Remove
                            }
                        };

                        // TODO: if auto-closing subscription, just remove it.

                        match res {
                            HandleClosedMsg::MarkAsClosed => {
                                self.subscription_closed(subscription_id).await;
                            }
                            HandleClosedMsg::Remove => {
                                tracing::debug!(
                                    url = %self.url,
                                    id = %subscription_id,
                                    "Removing subscription."
                                );

                                self.remove_subscription(subscription_id).await;
                            }
                        }
                    }
                    RelayMessage::EndOfStoredEvents(id) => {
                        self.received_eose(id).await;
                    }
                    RelayMessage::Auth { challenge } if self.state.is_authenticator_available() => {
                        queue_auth_challenge(ingester_tx, challenge);
                    }
                    _ => (),
                }

                // Send notification
                self.send_notification(
                    RelayNotification::Message {
                        message: Box::new(message),
                    },
                    true,
                );
            }
            Ok(None) => (),
            Err(e) => tracing::error!(
                url = %self.url,
                msg = %msg,
                error = %e,
                "Impossible to handle relay message."
            ),
        }
    }

    async fn handle_raw_relay_message(
        &self,
        msg: &str,
    ) -> Result<Option<RelayMessage<'static>>, Error> {
        // Trim the message (removes leading and trailing whitespaces and line breaks).
        let msg: &str = msg.trim();

        // Get message size
        let size: usize = msg.len();

        tracing::debug!("Received '{msg}' from '{}' (size: {size} bytes)", self.url);

        // Update bytes received
        self.stats.add_bytes_received(size);

        // Check message size
        if let Some(max_size) = self.opts.limits.messages.max_size {
            let max_size: usize = max_size as usize;
            if size > max_size {
                return Err(Error::limit_exceeded("relay message too large"));
            }
        }

        // Handle msg
        match RelayMessage::from_json(msg)? {
            RelayMessage::Event {
                subscription_id,
                event,
            } => {
                self.handle_event_msg(subscription_id.into_owned(), event.into_owned())
                    .await
            }
            m => Ok(Some(m)),
        }
    }

    async fn handle_event_msg(
        &self,
        subscription_id: SubscriptionId,
        event: Event,
    ) -> Result<Option<RelayMessage<'static>>, Error> {
        // Check event size
        if let Some(max_size) = self.opts.limits.events.get_max_size(&event.kind) {
            let size: usize = event.as_json().len();
            let max_size: usize = max_size as usize;
            if size > max_size {
                return Err(Error::limit_exceeded("event is too large"));
            }
        }

        // Check tags limit
        if let Some(max_num_tags) = self.opts.limits.events.get_max_num_tags(&event.kind) {
            let size: usize = event.tags.len();
            let max_num_tags: usize = max_num_tags as usize;
            if size > max_num_tags {
                return Err(Error::limit_exceeded("too many tags"));
            }
        }

        // Check if subscription must be verified
        if self.opts.verify_subscriptions || self.opts.ban_relay_on_mismatch {
            // NOTE: here we don't use the `self.subscription(id)` to avoid an unnecessary clone of the filter!

            // Acquire read lock
            let subscriptions = self.atomic.subscriptions.read().await;

            // Check if the subscription id exist and verify if the event matches the subscription filter.
            let SubscriptionData {
                filters,
                received_eose,
                received_events,
                ..
            } = subscriptions
                .get(&subscription_id)
                .ok_or_else(|| Error::not_found("subscription not found"))?;

            // Check filter limit ONLY if EOSE is not received yet and if there is only ONE filter.
            // We can't ensure that limit is respected if there is more than one filter.
            if !received_eose && filters.len() == 1 {
                // SAFETY: we've checked above that exists one filter.
                let filter: &Filter = &filters[0];

                // Check if the filter has a limit
                if let Some(limit) = filter.limit {
                    // Update number of received events
                    let prev: usize = received_events.fetch_add(1, Ordering::SeqCst);
                    let received_events: usize = prev.saturating_add(1);

                    // Check if received more that requested
                    if received_events > limit {
                        // Ban the relay
                        if self.opts.ban_relay_on_mismatch {
                            self.ban();
                        }

                        return Err(Error::limit_exceeded("too many events"));
                    }
                }
            }

            // NIP-01 treats multiple filters in the same REQ as OR: an event is
            // valid for the subscription if it matches at least one filter. Requiring every
            // filter to match would reject valid events and may incorrectly ban the relay.
            if !filters
                .iter()
                .any(|f| f.match_event(&event, MATCH_EVENT_OPTS))
            {
                // Ban the relay
                if self.opts.ban_relay_on_mismatch {
                    self.ban();
                }

                return Err(Error::protocol_msg(
                    "event doesn't match the subscription filter",
                ));
            }
        }

        // Check if the event is expired
        if event.is_expired() {
            return Err(Error::invalid_msg("event expired"));
        }

        // Policies may make security-sensitive decisions from event identity and content.
        self.state.verify_and_cache(&event).await?;

        // Check event admission policy
        if let Some(policy) = &self.state.admit_policy {
            if let AdmitStatus::Rejected { .. } = policy
                .admit_event(&self.url, &subscription_id, &event)
                .await?
            {
                return Ok(None);
            }
        }

        // Check the event status
        match self.state.database().check_id(&event.id).await? {
            // Already saved, continue with code execution
            DatabaseEventStatus::Saved => {}
            // Deleted, immediately return
            DatabaseEventStatus::Deleted => return Ok(None),
            // Not existent, try to save it to the database
            DatabaseEventStatus::NotExistent => {
                // Save into the database
                let send_notification: bool = match self.state.database().save_event(&event).await?
                {
                    SaveEventStatus::Success => true,
                    SaveEventStatus::Rejected(reason) => match reason {
                        RejectedReason::Ephemeral => true,
                        RejectedReason::Duplicate => true,
                        RejectedReason::Deleted => false,
                        RejectedReason::Expired => false,
                        RejectedReason::Replaced => false,
                        RejectedReason::InvalidDelete => false,
                        RejectedReason::Vanished => false,
                        RejectedReason::Other => true,
                    },
                };

                // If the notification should NOT be sent, immediately return.
                if !send_notification {
                    return Ok(None);
                }

                // Send notification
                self.send_notification(
                    RelayNotification::Event {
                        subscription_id: subscription_id.clone(),
                        event: Box::new(event.clone()),
                    },
                    true,
                );
            }
        }

        // Process event for gossip
        if let Some(gossip) = &self.state.gossip {
            gossip.process(&event, Some(&self.url)).await?;
        }

        Ok(Some(RelayMessage::Event {
            subscription_id: Cow::Owned(subscription_id),
            event: Cow::Owned(event),
        }))
    }

    pub fn disconnect(&self) {
        let mut ownership = self.atomic.connection_task.lock().unwrap();
        let status = self.status();

        // Check if it's already terminated, banned or shutdown
        if status.is_terminated() || status.is_banned() || status.is_shutdown() {
            return;
        }

        // Notify termination
        self.atomic.channels.terminate();

        // Update status
        self.set_status(RelayStatus::Terminated, true);
        ownership.restart_requested = false;
    }

    pub fn ban(&self) {
        let mut ownership = self.atomic.connection_task.lock().unwrap();
        let status = self.status();

        // Check if it's already terminated, banned or shutdown
        if status.is_terminated() || status.is_banned() || status.is_shutdown() {
            return;
        }

        // Notify termination
        self.atomic.channels.terminate();

        // Update status
        self.set_status(RelayStatus::Banned, true);
        ownership.restart_requested = false;
    }

    pub(super) fn shutdown(&self) {
        let mut ownership = self.atomic.connection_task.lock().unwrap();
        let status = self.status();

        // Check if it's already terminated, banned or shutdown
        if status.is_terminated() || status.is_banned() || status.is_shutdown() {
            return;
        }

        // Notify termination
        self.atomic.channels.terminate();

        // Update status
        self.set_status(RelayStatus::Shutdown, true);
        ownership.restart_requested = false;
    }

    #[inline]
    pub(super) async fn send_msg(
        &self,
        msg: ClientMessage<'_>,
        wait_until_sent: Option<Duration>,
    ) -> Result<(), Error> {
        // Check if relay is operational
        self.ensure_operational()?;

        // If it can't write, check if there are "write" messages
        if !self.capabilities.can_write() && msg.is_event() {
            return Err(Error::write_disabled());
        }

        // If it can't read, check if there are "read" messages
        if !self.capabilities.can_read() && (msg.is_req() || msg.is_close()) {
            return Err(Error::read_disabled());
        }

        match wait_until_sent {
            Some(timeout) => {
                // Create a channel
                let (tx, rx) = oneshot::channel();

                // Send the item
                self.atomic.channels.send_client_msg(JsonMessageItem {
                    json: msg.as_json(),
                    confirmation: Some(tx),
                })?;

                // Wait for confirmation
                Ok(time::timeout(Some(timeout), rx)
                    .await
                    .ok_or_else(Error::timeout)??)
            }
            None => self.atomic.channels.send_client_msg(JsonMessageItem {
                json: msg.as_json(),
                confirmation: None,
            }),
        }
    }

    async fn auth(&self, challenge: String) -> Result<(), Error> {
        // Check if the relay can authenticate
        if let Some(policy) = &self.state.admit_policy {
            if let AdmitStatus::Rejected { reason } = policy.admit_auth(&self.url).await? {
                return match reason {
                    Some(reason) => Err(Error::rejected(format!(
                        "authentication rejected: {reason}"
                    ))),
                    None => Err(Error::authentication_msg("authentication rejected")),
                };
            }
        }

        let Some(authenticator) = &self.state.authenticator else {
            return Err(Error::state_msg("no authenticator available"));
        };

        // Create the NIP-42 auth event
        let event: Event = authenticator.make_auth_event(&self.url, &challenge).await?;

        // Ensure event is valid
        if !nip42::is_valid_auth_event(&event, &self.url, &challenge) {
            return Err(Error::invalid_msg("invalid auth event"));
        }

        // Subscribe to notifications
        let mut notifications = self.internal_notification_sender.subscribe();

        // Send the AUTH message
        self.send_msg(ClientMessage::Auth(Cow::Borrowed(&event)), None)
            .await?;

        // Wait for OK
        // The event ID is already checked in `wait_for_ok` method
        let (status, message) = self
            .wait_for_ok(&mut notifications, &event.id, Duration::from_secs(10))
            .await?;

        // Check status
        if status {
            Ok(())
        } else {
            Err(Error::relay_msg(message))
        }
    }

    pub(super) async fn wait_for_ok(
        &self,
        notifications: &mut broadcast::Receiver<RelayNotification>,
        id: &EventId,
        timeout: Duration,
    ) -> Result<(bool, String), Error> {
        time::timeout(Some(timeout), async {
            loop {
                match notifications.recv().await.map_err(Error::from)? {
                    RelayNotification::Message { message } => {
                        if let RelayMessage::Ok {
                            event_id,
                            status,
                            message,
                        } = *message
                        {
                            // Check if it can return
                            if id == &event_id {
                                return Ok((status, message.into_owned()));
                            }
                        }
                    }
                    RelayNotification::RelayStatus { status } if status.is_disconnected() => {
                        return Err(Error::not_connected());
                    }
                    _ => (),
                }
            }
        })
        .await
        .ok_or_else(Error::timeout)?
    }

    pub async fn resubscribe(&self) -> Result<(), Error> {
        // TODO: avoid subscriptions clone
        let subscriptions = self.subscriptions().await;
        for (id, filters) in subscriptions.into_iter() {
            if !filters.is_empty() && self.should_resubscribe(&id).await {
                self.update_subscription(&id, filters.clone(), true).await?;

                let msg = ClientMessage::Req {
                    subscription_id: Cow::Borrowed(&id),
                    filters: filters.into_iter().map(Cow::Owned).collect(),
                };

                if let Err(e) = self.send_msg(msg, None).await {
                    self.subscription_closed(&id).await;
                    return Err(e);
                }
            } else {
                tracing::debug!("Skip re-subscription of '{id}'");
            }
        }

        Ok(())
    }

    pub(super) fn spawn_auto_closing_handler(
        &self,
        id: SubscriptionId,
        filters: Vec<Filter>,
        opts: SubscribeAutoCloseOptions,
        notifications: broadcast::Receiver<RelayNotification>,
        activity: Option<Sender<SubscriptionActivity>>,
        cancel_rx: Option<oneshot::Receiver<()>>,
    ) {
        let relay = self.clone(); // <-- FULL RELAY CLONE HERE
        task::spawn(async move {
            // Create a handle auto-closing future
            let handle_fut =
                relay.handle_auto_closing(&id, &filters, opts, notifications, &activity);

            let result: Option<HandleAutoClosing> = match cancel_rx {
                // We have a cancel receiver
                Some(cancel_rx) => {
                    // What that one of the futures terminates
                    tokio::select! {
                        res = handle_fut => res,
                        _ = cancel_rx => Some(HandleAutoClosing {
                            to_close: true,
                            reason: None,
                        }),
                    }
                }
                // No cancel receiver, await directly the handle auto-closing future
                None => handle_fut.await,
            };

            // Check if CLOSE needed
            let to_close: bool = match result {
                Some(HandleAutoClosing { to_close, reason }) => {
                    // Send activity
                    if let Some(reason) = reason {
                        if let Some(activity) = &activity {
                            // TODO: handle error?
                            let _ = activity.send(SubscriptionActivity::Closed(reason)).await;
                        }
                    }

                    to_close
                }
                // Timeout
                None => {
                    tracing::warn!(id = %id, "Timeout reached for subscription, auto-closing.");
                    true
                }
            };

            // Drop activity sender to terminate the receiver activity loop
            drop(activity);

            // Close subscription
            let send_result = if to_close {
                tracing::debug!(id = %id, "Auto-closing subscription.");
                relay
                    .send_msg(ClientMessage::Close(Cow::Borrowed(&id)), None)
                    .await
            } else {
                Ok(())
            };

            // Remove subscription
            relay.remove_subscription(&id).await;

            send_result
        });
    }

    async fn handle_auto_closing(
        &self,
        id: &SubscriptionId,
        filters: &[Filter],
        opts: SubscribeAutoCloseOptions,
        mut notifications: broadcast::Receiver<RelayNotification>,
        activity: &Option<Sender<SubscriptionActivity>>,
    ) -> Option<HandleAutoClosing> {
        time::timeout(opts.timeout, async move {
            let mut wait_for_events_counter: u16 = 0;
            let mut wait_for_events_after_eose_counter: u16 = 0;
            let mut received_eose: bool = false;
            let mut require_resubscription: bool = false;
            let mut last_event: Option<Instant> = None;

            // Listen to notifications with timeout
            // If no notification is received within no-events timeout, `None` is returned.
            while let Ok(notification) =
                time::timeout(opts.idle_timeout, notifications.recv()).await?
            {
                // Check if no-events timeout is reached
                if let (Some(idle_timeout), Some(last_event)) = (opts.idle_timeout, last_event) {
                    if last_event.elapsed() > idle_timeout {
                        // Close the subscription
                        return Some(HandleAutoClosing {
                            to_close: true,
                            reason: None,
                        });
                    }
                }

                match notification {
                    RelayNotification::Message { message, .. } => match *message {
                        RelayMessage::Event {
                            subscription_id,
                            event,
                        } if subscription_id.as_ref() == id => {
                            // Send activity
                            if let Some(activity) = activity {
                                // TODO: handle error?
                                let _ = activity
                                    .send(SubscriptionActivity::ReceivedEvent(event.into_owned()))
                                    .await;
                            }

                            // If no-events timeout is enabled, update instant of last event received
                            if opts.idle_timeout.is_some() {
                                last_event = Some(Instant::now());
                            }

                            // Check exit policy
                            match opts.exit_policy {
                                ReqExitPolicy::WaitForEvents(num) => {
                                    wait_for_events_counter += 1;
                                    if wait_for_events_counter >= num {
                                        break;
                                    }
                                }
                                ReqExitPolicy::WaitForEventsAfterEOSE(num) if received_eose => {
                                    wait_for_events_after_eose_counter += 1;
                                    if wait_for_events_after_eose_counter >= num {
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        RelayMessage::EndOfStoredEvents(subscription_id)
                            if subscription_id.as_ref() == id =>
                        {
                            received_eose = true;
                            if let ReqExitPolicy::ExitOnEOSE
                            | ReqExitPolicy::WaitDurationAfterEOSE(_) = opts.exit_policy
                            {
                                break;
                            }
                        }
                        RelayMessage::Closed {
                            subscription_id,
                            message,
                        } if subscription_id.as_ref() == id => {
                            // Check machine-readable prefix
                            match MachineReadablePrefix::parse(&message) {
                                Some(MachineReadablePrefix::AuthRequired) => {
                                    // Authentication is not enabled, return.
                                    if !self.state.is_authenticator_available() {
                                        return Some(HandleAutoClosing {
                                            to_close: false, // No need to send CLOSE msg
                                            reason: Some(SubscriptionAutoClosedReason::Closed(
                                                message.into_owned(),
                                            )),
                                        });
                                    }

                                    // Needs to re-subscribe
                                    require_resubscription = true;
                                }
                                Some(_) => {
                                    return Some(HandleAutoClosing {
                                        to_close: false, // No need to send CLOSE msg
                                        reason: Some(SubscriptionAutoClosedReason::Closed(
                                            message.into_owned(),
                                        )),
                                    });
                                }
                                // Mark subscription as completed.
                                //
                                // If we are arrived at this point,
                                // means that no error should be occurred,
                                // so the subscription can be marked as completed.
                                //
                                // # Example
                                //
                                // Send a request with `{"ids":["<id>"]}` filter.
                                // In this case, when the relay sends the matching event,
                                // it no longer makes sense to keep the subscription open,
                                // as no more events will ever be served.
                                // Discussion: https://github.com/nostrability/nostrability/issues/167
                                None => {
                                    return Some(HandleAutoClosing {
                                        to_close: false,
                                        reason: Some(SubscriptionAutoClosedReason::Completed),
                                    });
                                }
                            }
                        }
                        _ => (),
                    },
                    RelayNotification::Authenticated if require_resubscription => {
                        // Resend REQ
                        require_resubscription = false;

                        if let Err(e) = self
                            .update_auto_closing_subscription(id, filters.to_vec())
                            .await
                        {
                            return Some(HandleAutoClosing {
                                to_close: false,
                                reason: Some(SubscriptionAutoClosedReason::Closed(e.to_string())),
                            });
                        }

                        let msg = ClientMessage::Req {
                            subscription_id: Cow::Borrowed(id),
                            filters: filters.iter().map(Cow::Borrowed).collect(),
                        };

                        if let Err(e) = self.send_msg(msg, None).await {
                            self.subscription_closed(id).await;

                            return Some(HandleAutoClosing {
                                to_close: false, // REQ wasn't sent, no need to send CLOSE.
                                reason: Some(SubscriptionAutoClosedReason::Closed(e.to_string())),
                            });
                        }
                    }
                    RelayNotification::AuthenticationFailed => {
                        return Some(HandleAutoClosing {
                            to_close: false, // No need to send CLOSE msg
                            reason: Some(SubscriptionAutoClosedReason::AuthenticationFailed),
                        });
                    }
                    RelayNotification::RelayStatus { status } if status.is_disconnected() => {
                        return Some(HandleAutoClosing {
                            to_close: false, // No need to send CLOSE msg
                            reason: None,
                        });
                    }
                    _ => (),
                }
            }

            if let ReqExitPolicy::WaitDurationAfterEOSE(duration) = opts.exit_policy {
                time::timeout(Some(duration), async {
                    while let Ok(notification) = notifications.recv().await {
                        match notification {
                            RelayNotification::Message { message } => {
                                if let RelayMessage::Event {
                                    subscription_id,
                                    event,
                                } = *message
                                {
                                    if subscription_id.as_ref() == id {
                                        // Send activity
                                        if let Some(activity) = activity {
                                            // TODO: handle error?
                                            let _ = activity
                                                .send(SubscriptionActivity::ReceivedEvent(
                                                    event.into_owned(),
                                                ))
                                                .await;
                                        }
                                    }
                                }
                            }
                            RelayNotification::RelayStatus { status }
                                if status.is_disconnected() =>
                            {
                                return Ok(());
                            }
                            _ => (),
                        }
                    }

                    Ok::<(), Error>(())
                })
                .await;
            }

            Some(HandleAutoClosing {
                to_close: true, // Need to send CLOSE msg
                reason: Some(SubscriptionAutoClosedReason::Completed),
            })
        })
        .await?
    }

    // Returns `true` if the subscription has been unsubscribed
    async fn _unsubscribe_long_lived_subscription(
        &self,
        subscriptions: &mut RwLockWriteGuard<'_, HashMap<SubscriptionId, SubscriptionData>>,
        id: Cow<'_, SubscriptionId>,
    ) -> Result<bool, Error> {
        match subscriptions.remove(&id) {
            Some(sub) => {
                // Re-insert if auto-closing
                if sub.is_auto_closing {
                    subscriptions.insert(id.into_owned(), sub);
                    return Ok(false);
                }

                // Send CLOSE message
                self.send_msg(ClientMessage::Close(id), None).await?;

                Ok(true)
            }
            // Not existent subscription
            None => Ok(false),
        }
    }

    pub async fn unsubscribe(&self, id: &SubscriptionId) -> Result<bool, Error> {
        let mut subscriptions = self.atomic.subscriptions.write().await;
        self._unsubscribe_long_lived_subscription(&mut subscriptions, Cow::Borrowed(id))
            .await
    }

    pub async fn unsubscribe_all(&self) -> Result<(), Error> {
        let mut subscriptions = self.atomic.subscriptions.write().await;

        // All IDs
        let ids: Vec<SubscriptionId> = subscriptions.keys().cloned().collect();

        // Unsubscribe
        for id in ids.into_iter() {
            self._unsubscribe_long_lived_subscription(&mut subscriptions, Cow::Owned(id))
                .await?;
        }

        Ok(())
    }
}

/// Send a WebSocket message with timeout set to [WEBSOCKET_TX_TIMEOUT].
async fn send_ws_msg(tx: &mut WebSocketSink, msg: Message) -> Result<(), Error> {
    match time::timeout(Some(WEBSOCKET_TX_TIMEOUT), tx.send(msg)).await {
        Some(res) => Ok(res?),
        None => Err(Error::timeout()),
    }
}

/// Send the close message with timeout set to [WEBSOCKET_TX_TIMEOUT].
async fn close_ws(tx: &mut WebSocketSink) -> Result<(), Error> {
    // TODO: remove timeout from here?
    match time::timeout(Some(WEBSOCKET_TX_TIMEOUT), tx.close()).await {
        Some(res) => Ok(res?),
        None => Err(Error::timeout()),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::error::Error as _;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use nostr::event::{Event, EventBuilder, Kind};
    use nostr::filter::Filter;
    use nostr::key::Keys;
    use nostr::message::SubscriptionId;
    use nostr::types::RelayUrl;

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::error::ErrorKind;
    use crate::local_relay::MockRelay;
    use crate::policy::{AdmitPolicy, AdmitStatus};
    use crate::relay::{Relay, RelayOptions};

    #[tokio::test]
    async fn reconnect_requested_during_task_teardown_is_not_lost() {
        reconnect_during_teardown(true, false).await;
    }

    #[tokio::test]
    async fn explicit_reconnect_during_teardown_works_without_automatic_reconnect() {
        reconnect_during_teardown(false, false).await;
    }

    #[tokio::test]
    async fn queued_reconnect_ignores_stale_termination_permit() {
        reconnect_during_teardown(false, true).await;
    }

    #[tokio::test]
    async fn connect_after_idle_disconnect_ignores_stored_termination() {
        let local = MockRelay::run().await.unwrap();
        let relay = Relay::builder(local.url().await)
            .opts(RelayOptions::default().reconnect(false))
            .build();
        relay.disconnect();
        assert_eq!(relay.status(), RelayStatus::Terminated);

        relay.connect();
        relay.wait_for_connection(Duration::from_secs(2)).await;
        assert_eq!(relay.status(), RelayStatus::Connected);
        assert_eq!(relay.stats().success(), 1);
    }

    async fn reconnect_during_teardown(automatic_reconnect: bool, stale_termination: bool) {
        let local = MockRelay::run().await.unwrap();
        let relay = Relay::builder(local.url().await)
            .opts(RelayOptions::default().reconnect(automatic_reconnect))
            .build();
        let hook = Arc::new(TeardownHook::default());
        *relay.inner.atomic.teardown_hook.lock().unwrap() = Some(hook.clone());
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), hook.started.notified())
            .await
            .unwrap();
        let mut notifications = relay.notifications();
        let keys = Keys::generate();
        let subscription_id = relay
            .subscribe(Filter::new().author(keys.public_key()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notification = notifications
                    .next()
                    .await
                    .expect("notification stream closed before EOSE");
                if matches!(notification, RelayNotification::Message { message } if matches!(*message, RelayMessage::EndOfStoredEvents(ref id) if id.as_ref() == &subscription_id)) {
                    break;
                }
            }
        })
        .await
        .unwrap();

        relay.disconnect();
        tokio::time::timeout(Duration::from_secs(2), hook.entered.notified())
            .await
            .unwrap();
        assert_eq!(relay.status(), RelayStatus::Terminated);
        assert!(relay.inner.is_running());

        if stale_termination {
            // The old task no longer polls the termination Notify at this gate.
            relay.inner.atomic.channels.terminate();
        }

        let ((), ()) = tokio::join!(async { relay.connect() }, async { relay.connect() });
        assert_eq!(relay.status(), RelayStatus::Pending);
        hook.release.notify_one();

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notification = notifications
                    .next()
                    .await
                    .expect("notification stream closed before reconnect");
                if matches!(
                    notification,
                    RelayNotification::RelayStatus {
                        status: RelayStatus::Connected
                    }
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(relay.status(), RelayStatus::Connected);
        assert!(relay.inner.is_running());

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notification = notifications
                    .next()
                    .await
                    .expect("notification stream closed before restored EOSE");
                if matches!(notification, RelayNotification::Message { message } if matches!(*message, RelayMessage::EndOfStoredEvents(ref id) if id.as_ref() == &subscription_id)) {
                    break;
                }
            }
        })
        .await
        .unwrap();

        let event = EventBuilder::new(Kind::TextNote, "after reconnect")
            .finalize(&keys)
            .unwrap();
        local.add_event(event.clone()).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notification = notifications
                    .next()
                    .await
                    .expect("notification stream closed");
                if let RelayNotification::Event {
                    subscription_id: received_id,
                    event,
                } = notification
                {
                    if received_id == subscription_id {
                        break event.id;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(received, event.id);
    }

    #[tokio::test]
    async fn shutdown_cancels_a_queued_reconnect() {
        let local = MockRelay::run().await.unwrap();
        let relay = Relay::new(local.url().await);
        let hook = Arc::new(TeardownHook::default());
        *relay.inner.atomic.teardown_hook.lock().unwrap() = Some(hook.clone());
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), hook.started.notified())
            .await
            .unwrap();

        relay.disconnect();
        tokio::time::timeout(Duration::from_secs(2), hook.entered.notified())
            .await
            .unwrap();
        relay.connect();
        relay.shutdown();
        hook.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), hook.finished.notified())
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Shutdown);
        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn try_connect_reports_when_old_task_still_owns_connection() {
        let local = MockRelay::run().await.unwrap();
        let relay = Relay::new(local.url().await);
        let hook = Arc::new(TeardownHook::default());
        *relay.inner.atomic.teardown_hook.lock().unwrap() = Some(hook.clone());
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), hook.started.notified())
            .await
            .unwrap();

        relay.disconnect();
        tokio::time::timeout(Duration::from_secs(2), hook.entered.notified())
            .await
            .unwrap();

        let success_before = relay.stats().success();
        let mut status_updates = relay.inner.internal_notification_sender.subscribe();
        let error = relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::State);
        assert_eq!(relay.status(), RelayStatus::Pending);
        assert_eq!(relay.stats().success(), success_before);
        loop {
            match status_updates.try_recv() {
                Ok(RelayNotification::RelayStatus {
                    status: RelayStatus::Connected,
                }) => panic!("discarded try_connect socket reported Connected"),
                Ok(_) => {}
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(error) => panic!("unexpected status receiver error: {error}"),
            }
        }
        let mut notifications = relay.notifications();
        hook.release.notify_one();

        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(notification) = notifications.next().await {
                if matches!(
                    notification,
                    RelayNotification::RelayStatus {
                        status: RelayStatus::Connected
                    }
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    #[derive(Debug)]
    struct CountingAdmitPolicy(Arc<AtomicUsize>);

    impl AdmitPolicy for CountingAdmitPolicy {
        fn admit_event<'a>(
            &'a self,
            _relay_url: &'a RelayUrl,
            _subscription_id: &'a SubscriptionId,
            _event: &'a Event,
        ) -> Pin<Box<dyn Future<Output = Result<AdmitStatus, Error>> + Send + 'a>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(AdmitStatus::Success) })
        }
    }

    fn event_with_invalid_signature() -> Event {
        let keys = Keys::generate();
        let mut event = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&keys)
            .unwrap();
        let other_event = EventBuilder::new(Kind::TextNote, "other")
            .finalize(&Keys::generate())
            .unwrap();
        event.sig = other_event.sig;
        event
    }

    #[test]
    fn test_new_auth_challenge_replaces_the_previous_one() {
        let (tx, rx) = watch::channel(None);

        for index in 0..100 {
            queue_auth_challenge(&tx, &index.to_string());
        }

        assert_eq!(rx.borrow().as_deref(), Some("99"));
    }

    #[tokio::test]
    async fn test_invalid_event_does_not_poison_verification_cache() {
        let relay = Relay::new(RelayUrl::parse("wss://relay.example.com").unwrap());
        let event = event_with_invalid_signature();

        assert!(event.verify().is_err());
        for _ in 0..2 {
            assert!(relay.inner.state.verify_and_cache(&event).await.is_err());
        }
    }

    #[tokio::test]
    async fn test_repeated_invalid_event_is_not_saved() {
        let relay = Relay::new(RelayUrl::parse("wss://relay.example.com").unwrap());
        let event = event_with_invalid_signature();
        let subscription_id = SubscriptionId::new("test");

        for _ in 0..2 {
            assert!(
                relay
                    .inner
                    .handle_event_msg(subscription_id.clone(), event.clone())
                    .await
                    .is_err()
            );
        }

        assert_eq!(
            relay
                .inner
                .state
                .database()
                .check_id(&event.id)
                .await
                .unwrap(),
            DatabaseEventStatus::NotExistent
        );
    }

    #[tokio::test]
    async fn test_invalid_event_is_rejected_before_admit_policy() {
        let calls = Arc::new(AtomicUsize::new(0));
        let relay = Relay::builder(RelayUrl::parse("wss://relay.example.com").unwrap())
            .admit_policy(CountingAdmitPolicy(calls.clone()))
            .build();
        let event = event_with_invalid_signature();

        let result = relay
            .inner
            .handle_event_msg(SubscriptionId::new("test"), event)
            .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_invalid_event_with_saved_id_is_rejected() {
        let relay = Relay::new(RelayUrl::parse("wss://relay.example.com").unwrap());
        let valid_event = EventBuilder::new(Kind::TextNote, "valid")
            .finalize(&Keys::generate())
            .unwrap();
        relay
            .inner
            .state
            .database()
            .save_event(&valid_event)
            .await
            .unwrap();

        let mut forged_event = valid_event;
        forged_event.content = String::from("forged");
        assert!(forged_event.verify().is_err());

        let result = relay
            .inner
            .handle_event_msg(SubscriptionId::new("test"), forged_event)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_subscription_verification_accepts_event_matching_any_filter() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&keys)
            .unwrap();

        let filter = Filter::new().kind(Kind::TextNote).since(event.created_at);
        let matching_filter = filter.clone().author(event.pubkey);
        let non_matching_filter = filter.pubkey(event.pubkey);

        assert!(matching_filter.match_event(&event, MATCH_EVENT_OPTS));
        assert!(!non_matching_filter.match_event(&event, MATCH_EVENT_OPTS));

        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let opts = RelayOptions::default()
            .verify_subscriptions(true)
            .ban_relay_on_mismatch(true);
        let relay = Relay::builder(url).opts(opts).build();

        // Manually add the subscription
        let subscription_id = SubscriptionId::new("test");
        relay
            .inner
            .add_long_lived_subscription(
                subscription_id.clone(),
                vec![matching_filter, non_matching_filter],
            )
            .await
            .unwrap();

        // Handle manually the event message
        let message = relay
            .inner
            .handle_event_msg(subscription_id.clone(), event.clone())
            .await
            .unwrap();

        match message {
            Some(RelayMessage::Event {
                subscription_id: received_subscription_id,
                event: received_event,
            }) => {
                assert_eq!(received_subscription_id.as_ref(), &subscription_id);
                assert_eq!(received_event.id, event.id);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_auth_required_closed_remove_subscription_for_resubscribe_without_authenticator() {
        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let relay = Relay::new(url);
        let subscription_id = SubscriptionId::new("test");
        let filter = Filter::new().kind(Kind::TextNote);

        relay
            .inner
            .add_long_lived_subscription(subscription_id.clone(), vec![filter.clone()])
            .await
            .unwrap();

        let (tx, _rx) = watch::channel(None);
        relay
            .inner
            .handle_relay_message(r#"["CLOSED","test","auth-required: you must auth"]"#, &tx)
            .await;

        assert!(relay.inner.subscription(&subscription_id).await.is_none());
    }

    #[tokio::test]
    async fn test_add_long_lived_subscription_rejects_existing_id() {
        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let relay = Relay::new(url);
        let subscription_id = SubscriptionId::new("test");

        relay
            .inner
            .add_long_lived_subscription(
                subscription_id.clone(),
                vec![Filter::new().kind(Kind::TextNote)],
            )
            .await
            .unwrap();

        let err = relay
            .inner
            .add_long_lived_subscription(subscription_id, vec![Filter::new().kind(Kind::Reaction)])
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "subscription ID already exists");
    }

    #[tokio::test]
    async fn test_add_auto_closing_subscription_rejects_existing_id() {
        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let relay = Relay::new(url);
        let subscription_id = SubscriptionId::new("test");

        relay
            .inner
            .add_auto_closing_subscription(
                subscription_id.clone(),
                vec![Filter::new().kind(Kind::TextNote)],
            )
            .await
            .unwrap();

        let err = relay
            .inner
            .add_auto_closing_subscription(
                subscription_id,
                vec![Filter::new().kind(Kind::Reaction)],
            )
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "subscription ID already exists");
    }

    #[tokio::test]
    async fn test_add_long_lived_subscription_rejects_existing_id_across_subscription_types() {
        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let relay = Relay::new(url);
        let subscription_id = SubscriptionId::new("test");

        relay
            .inner
            .add_auto_closing_subscription(
                subscription_id.clone(),
                vec![Filter::new().kind(Kind::TextNote)],
            )
            .await
            .unwrap();

        let err = relay
            .inner
            .add_long_lived_subscription(
                subscription_id.clone(),
                vec![Filter::new().kind(Kind::Reaction)],
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "subscription ID already exists");

        relay.inner.remove_subscription(&subscription_id).await;

        relay
            .inner
            .add_long_lived_subscription(
                subscription_id.clone(),
                vec![Filter::new().kind(Kind::TextNote)],
            )
            .await
            .unwrap();

        let err = relay
            .inner
            .add_auto_closing_subscription(
                subscription_id,
                vec![Filter::new().kind(Kind::Reaction)],
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "subscription ID already exists");
    }

    #[tokio::test]
    async fn test_update_subscription_requires_existing_id() {
        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let relay = Relay::new(url);

        let err = relay
            .inner
            .update_subscription(
                &SubscriptionId::new("test"),
                vec![Filter::new().kind(Kind::TextNote)],
                true,
            )
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "subscription not found");
    }

    #[tokio::test]
    async fn test_update_auto_closing_subscription_resets_previous_state() {
        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let relay = Relay::new(url);
        let subscription_id = SubscriptionId::new("test");
        let first_filter = Filter::new().kind(Kind::TextNote);
        let second_filter = Filter::new().kind(Kind::Reaction);

        relay
            .inner
            .add_auto_closing_subscription(subscription_id.clone(), vec![first_filter])
            .await
            .unwrap();
        relay.inner.subscription_closed(&subscription_id).await;
        relay.inner.received_eose(&subscription_id).await;

        {
            let subscriptions = relay.inner.atomic.subscriptions.read().await;
            let data = subscriptions.get(&subscription_id).unwrap();
            data.received_events.store(1, Ordering::SeqCst);
            assert!(data.closed);
            assert!(data.received_eose);
        }

        relay
            .inner
            .update_auto_closing_subscription(&subscription_id, vec![second_filter.clone()])
            .await
            .unwrap();

        let subscriptions = relay.inner.atomic.subscriptions.read().await;
        let data = subscriptions.get(&subscription_id).unwrap();
        assert!(data.is_auto_closing);
        assert_eq!(data.filters, vec![second_filter]);
        assert!(!data.closed);
        assert!(!data.received_eose);
        assert_eq!(data.received_events.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_auth_required_closed_keeps_subscription_for_resubscribe() {
        let url = RelayUrl::parse("wss://relay.example.com").unwrap();
        let keys = Keys::generate();
        let authenticator = SignerAuthenticator::new(keys);
        let relay = Relay::builder(url).authenticator(authenticator).build();
        let subscription_id = SubscriptionId::new("test");
        let filter = Filter::new().kind(Kind::TextNote);

        relay
            .inner
            .add_long_lived_subscription(subscription_id.clone(), vec![filter.clone()])
            .await
            .unwrap();

        let (tx, _rx) = watch::channel(None);
        relay
            .inner
            .handle_relay_message(r#"["CLOSED","test","auth-required: you must auth"]"#, &tx)
            .await;

        assert!(relay.inner.subscription(&subscription_id).await.is_some());
        assert!(relay.inner.should_resubscribe(&subscription_id).await);

        relay
            .inner
            .update_subscription(&subscription_id, vec![filter], true)
            .await
            .unwrap();

        assert!(!relay.inner.should_resubscribe(&subscription_id).await);
    }

    #[tokio::test]
    async fn ok_waiter_requires_matching_reply_and_preserves_receive_failure() {
        let relay = Relay::new(RelayUrl::parse("wss://relay.example.com").unwrap());

        let wanted = EventId::from_byte_array([0; 32]);
        let other = EventId::from_byte_array([1; 32]);

        let (tx, mut rx) = broadcast::channel(2);

        tx.send(RelayNotification::Message {
            message: Box::new(RelayMessage::Ok {
                event_id: other,
                status: true,
                message: Cow::Borrowed("unrelated"),
            }),
        })
        .unwrap();

        tx.send(RelayNotification::Message {
            message: Box::new(RelayMessage::Ok {
                event_id: wanted,
                status: false,
                message: Cow::Borrowed("rejected"),
            }),
        })
        .unwrap();

        let (accepted, message) = relay
            .inner
            .wait_for_ok(&mut rx, &wanted, Duration::from_secs(1))
            .await
            .unwrap();

        assert!(!accepted);
        assert_eq!(message, "rejected");

        let (_silent_tx, mut silent_rx) = broadcast::channel(2);

        let error = relay
            .inner
            .wait_for_ok(&mut silent_rx, &wanted, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Timeout);

        let (lag_tx, _) = broadcast::channel(2);
        let mut lagged = lag_tx.subscribe();

        for _ in 0..8 {
            lag_tx.send(RelayNotification::Authenticated).unwrap();
        }

        let error = relay
            .inner
            .wait_for_ok(&mut lagged, &wanted, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<broadcast::error::RecvError>())
                .is_some_and(|source| matches!(source, broadcast::error::RecvError::Lagged(_)))
        );

        let (closed_tx, mut closed_rx) = broadcast::channel(2);

        drop(closed_tx);

        let error = relay
            .inner
            .wait_for_ok(&mut closed_rx, &wanted, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<broadcast::error::RecvError>())
                .is_some_and(|source| matches!(source, broadcast::error::RecvError::Closed))
        );
    }
}

#[cfg(bench)]
mod benches {
    use std::sync::LazyLock;

    use test::Bencher;
    use tokio::runtime::Runtime;

    use super::*;

    static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| Runtime::new().unwrap());

    fn relay() -> InnerRelay {
        let url = RelayUrl::parse("ws://localhost:8080").unwrap();
        let state = SharedState::default();
        let opts = RelayOptions::default();
        InnerRelay::new(url, state, opts)
    }

    #[bench]
    fn bench_handle_relay_msg_event(bh: &mut Bencher) {
        let relay = relay();

        let msg = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}]"#;

        bh.iter(|| {
            RUNTIME.block_on(async {
                relay.handle_raw_relay_message(msg).await.unwrap();
            });
        });
    }

    #[bench]
    fn bench_handle_relay_msg_invalid_event(bh: &mut Bencher) {
        let relay = relay();

        let msg = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"fa163f5cfb75d77d9b6269011872ee22b34fb48d23251e9879bb1e4ccbdd8aaaf4b6dc5f5084a65ef42c52fbcde8f3178bac3ba207de827ec513a6aa39fa684c"}]"#;

        bh.iter(|| {
            RUNTIME.block_on(async {
                let _ = relay.handle_raw_relay_message(msg).await;
            });
        });
    }
}
