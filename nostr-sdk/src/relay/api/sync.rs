use std::borrow::Cow;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::future::IntoFuture;

use async_utility::{task, time};
use negentropy::{Id, Negentropy, NegentropyStorageVector};
use nostr::event::EventId;
use nostr::filter::Filter;
use nostr::message::{ClientMessage, RelayMessage, SubscriptionId};
use nostr::types::Timestamp;
use tokio::sync::broadcast;
use universal_time::Instant;

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::constants::{
    NEGENTROPY_BATCH_SIZE_DOWN, NEGENTROPY_FRAME_SIZE_LIMIT, NEGENTROPY_HIGH_WATER_UP,
    NEGENTROPY_LOW_WATER_UP,
};
use crate::relay::{Relay, RelayNotification, SyncOptions};

// A dropped sync future must not keep its request-owned subscription registered.
// Network CLOSE is best effort because the relay may already be disconnected.
struct SyncCleanup<'r> {
    relay: &'r Relay,
    neg_id: SubscriptionId,
    down_id: SubscriptionId,
    armed: bool,
}

impl<'r> SyncCleanup<'r> {
    #[inline]
    fn new(relay: &'r Relay, neg_id: SubscriptionId, down_id: SubscriptionId) -> Self {
        Self {
            relay,
            neg_id,
            down_id,
            armed: true,
        }
    }

    #[inline]
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SyncCleanup<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let relay: Relay = self.relay.clone();
        let neg_id: SubscriptionId = self.neg_id.clone();
        let down_id: SubscriptionId = self.down_id.clone();

        task::spawn(async move {
            relay.inner.remove_subscription(&down_id).await;
            let _ = relay
                .send_msg(ClientMessage::Close(Cow::Owned(down_id)))
                .await;
            let _ = send_neg_close(&relay, &neg_id).await;
        });
    }
}

/// Relay negentropy reconciliation summary
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncSummary {
    /// Events that were stored locally (missing on relay)
    pub local: HashSet<EventId>,
    /// Events that were stored on relay (missing locally)
    pub remote: HashSet<EventId>,
    /// Events that are **successfully** sent to relays during reconciliation
    pub sent: HashSet<EventId>,
    /// Event that are **successfully** received from relay during reconciliation
    pub received: HashSet<EventId>,
    /// Send failures
    pub send_failures: HashMap<EventId, String>,
    // /// Receive failures
    // pub receive: HashMap<EventId, Vec<String>>,
}

/// Reconciliation progress and its terminal result for one relay.
///
/// Progress may be useful after failure. A missing terminal error means the
/// reconciliation loop completed; inspect `summary.send_failures` for individual
/// publication failures. Received events are not evidence of downstream durable
/// admission.
#[derive(Debug)]
pub struct RelaySyncOutcome {
    /// Progress observed before completion or failure.
    pub summary: SyncSummary,
    /// Failure that interrupted reconciliation, if any.
    pub error: Option<Error>,
}

/// Sync events with relay
///
/// <https://github.com/nostr-protocol/nips/blob/master/77.md>
#[must_use = "Does nothing unless you await!"]
pub struct SyncEvents<'relay> {
    relay: &'relay Relay,
    filter: Filter,
    items: Option<Vec<(EventId, Timestamp)>>,
    opts: SyncOptions,
}

impl<'relay> SyncEvents<'relay> {
    #[inline]
    pub(crate) fn new(relay: &'relay Relay, filter: Filter) -> Self {
        Self {
            relay,
            filter,
            items: None,
            opts: SyncOptions::new(),
        }
    }

    /// Set sync items
    ///
    /// When items are provided, negentropy items are NOT fetched from the database.
    #[inline]
    pub fn items<I>(mut self, items: I) -> Self
    where
        I: IntoIterator<Item = (EventId, Timestamp)>,
    {
        self.items = Some(items.into_iter().collect());
        self
    }

    /// Set sync options
    #[inline]
    pub fn opts(mut self, opts: SyncOptions) -> Self {
        self.opts = opts;
        self
    }

    /// Reconcile while retaining partial progress if the operation fails.
    ///
    /// Preflight errors still return `Err` before reconciliation begins.
    pub async fn with_outcomes(self) -> Result<RelaySyncOutcome, Error> {
        self.relay.inner.ensure_operational()?;
        if !self.relay.inner.capabilities.can_read() {
            return Err(Error::read_disabled());
        }

        let items: Vec<(EventId, Timestamp)> = match self.items {
            Some(items) => items,
            None => {
                let database = self.relay.inner.state.database();
                database.negentropy_items(self.filter.clone()).await?
            }
        };

        let mut summary: SyncSummary = SyncSummary::default();
        let error: Option<Error> = sync(self.relay, &self.filter, items, &self.opts, &mut summary)
            .await
            .err();
        Ok(RelaySyncOutcome { summary, error })
    }
}

#[inline]
async fn send_neg_msg(relay: &Relay, id: &SubscriptionId, message: &str) -> Result<(), Error> {
    relay
        .send_msg(ClientMessage::NegMsg {
            subscription_id: Cow::Borrowed(id),
            message: Cow::Borrowed(message),
        })
        .await
}

#[inline]
async fn send_neg_close(relay: &Relay, id: &SubscriptionId) -> Result<(), Error> {
    relay
        .send_msg(ClientMessage::NegClose {
            subscription_id: Cow::Borrowed(id),
        })
        .await
}

#[inline]
fn neg_id_to_event_id(id: Id) -> EventId {
    EventId::from_byte_array(id.to_bytes())
}

#[inline(never)]
async fn handle_neg_msg<I>(
    relay: &Relay,
    subscription_id: &SubscriptionId,
    msg: Option<Vec<u8>>,
    curr_have_ids: I,
    curr_need_ids: I,
    opts: &SyncOptions,
    output: &mut SyncSummary,
    have_ids: &mut Vec<EventId>,
    need_ids: &mut Vec<EventId>,
    sync_done: &mut bool,
) -> Result<(), Error>
where
    I: Iterator<Item = EventId>,
{
    let mut counter: u64 = 0;

    // If event ID wasn't already seen, add to the HAVE IDs
    // Add to HAVE IDs only if `do_up` is true
    for id in curr_have_ids.into_iter() {
        if output.local.insert(id) && opts.do_up() {
            have_ids.push(id);
            counter += 1;
        }
    }

    // If event ID wasn't already seen, add to the NEED IDs
    // Add to NEED IDs only if `do_down` is true
    for id in curr_need_ids.into_iter() {
        if output.remote.insert(id) && opts.do_down() {
            need_ids.push(id);
            counter += 1;
        }
    }

    if let Some(progress) = &opts.progress {
        progress.send_modify(|state| {
            state.total += counter;
        });
    }

    match msg {
        Some(query) => {
            let message: String = faster_hex::hex_string(&query);
            send_neg_msg(relay, subscription_id, &message).await
        }
        None => {
            // Mark sync as done
            *sync_done = true;

            // Send NEG-CLOSE message
            send_neg_close(relay, subscription_id).await
        }
    }
}

#[inline(never)]
async fn upload_neg_events(
    relay: &Relay,
    have_ids: &mut Vec<EventId>,
    in_flight_up: &mut HashSet<EventId>,
    opts: &SyncOptions,
) -> Result<(), Error> {
    // Check if it should skip the upload
    if !opts.do_up() || have_ids.is_empty() || in_flight_up.len() > NEGENTROPY_LOW_WATER_UP {
        return Ok(());
    }

    let mut num_sent = 0;

    while !have_ids.is_empty() && in_flight_up.len() < NEGENTROPY_HIGH_WATER_UP {
        if let Some(id) = have_ids.pop() {
            match relay.inner.state.database().event_by_id(&id).await {
                Ok(Some(event)) => {
                    in_flight_up.insert(id);
                    relay.send_msg(ClientMessage::event(event)).await?;
                    num_sent += 1;
                }
                Ok(None) => {
                    // Event not found
                }
                Err(e) => tracing::error!(
                    url = %relay.url(),
                    error = %e,
                    "Can't upload event."
                ),
            }
        }
    }

    // Update progress
    if let Some(progress) = &opts.progress {
        progress.send_modify(|state| {
            state.current += num_sent;
        });
    }

    if num_sent > 0 {
        tracing::info!(
            "Negentropy UP for '{}': {} events ({} remaining)",
            relay.url(),
            num_sent,
            have_ids.len()
        );
    }

    Ok(())
}

#[inline(never)]
async fn req_neg_events(
    relay: &Relay,
    need_ids: &mut Vec<EventId>,
    in_flight_down: &mut Option<HashSet<EventId>>,
    cleanup: &mut SyncCleanup<'_>,
    opts: &SyncOptions,
) -> Result<(), Error> {
    // Check if it should skip the download
    if !opts.do_down() || need_ids.is_empty() || in_flight_down.is_some() {
        return Ok(());
    }

    // Each batch needs its own ID: a relay may send CLOSED after EOSE, and a
    // late CLOSED from the previous batch must not terminate the next one.
    cleanup.down_id = SubscriptionId::generate();

    let down_sub_id: &SubscriptionId = &cleanup.down_id;

    let capacity: usize = cmp::min(need_ids.len(), NEGENTROPY_BATCH_SIZE_DOWN);
    let mut ids: Vec<EventId> = Vec::with_capacity(capacity);

    while !need_ids.is_empty() && ids.len() < NEGENTROPY_BATCH_SIZE_DOWN {
        if let Some(id) = need_ids.pop() {
            ids.push(id);
        }
    }

    tracing::info!(
        "Negentropy DOWN for '{}': {} events ({} remaining)",
        relay.url(),
        ids.len(),
        need_ids.len()
    );

    // Update progress
    if let Some(progress) = &opts.progress {
        progress.send_modify(|state| {
            state.current += ids.len() as u64;
        });
    }

    let requested_ids: HashSet<EventId> = ids.iter().copied().collect();

    let filter: Filter = Filter::new().ids(ids);
    let msg: ClientMessage = ClientMessage::Req {
        subscription_id: Cow::Borrowed(down_sub_id),
        filters: vec![Cow::Borrowed(&filter)],
    };

    // Register an auto-closing subscription
    relay
        .inner
        .add_auto_closing_subscription(down_sub_id.clone(), vec![filter.clone()])
        .await?;

    // Send msg
    if let Err(e) = relay.send_msg(msg).await {
        // Remove previously added subscription
        relay.inner.remove_subscription(down_sub_id).await;

        // Propagate error
        return Err(e);
    }

    *in_flight_down = Some(requested_ids);

    Ok(())
}

/// Returns `true` if the events was in the `in_flight_up` collection.
#[inline(never)]
fn handle_neg_ok(
    relay: &Relay,
    in_flight_up: &mut HashSet<EventId>,
    event_id: EventId,
    status: bool,
    message: Cow<'_, str>,
    output: &mut SyncSummary,
) -> bool {
    if in_flight_up.remove(&event_id) {
        if status {
            output.sent.insert(event_id);
        } else {
            tracing::error!(
                url = %relay.url(),
                id = %event_id,
                msg = %message,
                "Can't upload event."
            );

            output.send_failures.insert(event_id, message.to_string());
        }

        true
    } else {
        false
    }
}

/// New negentropy protocol
#[inline(never)]
pub(super) async fn sync(
    relay: &Relay,
    filter: &Filter,
    items: Vec<(EventId, Timestamp)>,
    opts: &SyncOptions,
    output: &mut SyncSummary,
) -> Result<(), Error> {
    // Prepare the negentropy client
    let storage: NegentropyStorageVector = prepare_negentropy_storage(items)?;
    let mut negentropy: Negentropy<NegentropyStorageVector> =
        Negentropy::borrowed(&storage, NEGENTROPY_FRAME_SIZE_LIMIT)?;

    // Initiate reconciliation
    let initial_message: Vec<u8> = negentropy.initiate()?;

    // Subscribe
    let mut notifications = relay.inner.internal_notification_sender.subscribe();
    let mut temp_notifications = relay.inner.internal_notification_sender.subscribe();

    // Send the initial negentropy message
    let sub_id: SubscriptionId = SubscriptionId::generate();
    let open_msg: ClientMessage = ClientMessage::NegOpen {
        subscription_id: Cow::Borrowed(&sub_id),
        filter: Cow::Borrowed(filter),
        initial_message: Cow::Owned(faster_hex::hex_string(&initial_message)),
    };
    relay.send_msg(open_msg).await?;

    let mut cleanup: SyncCleanup =
        SyncCleanup::new(relay, sub_id.clone(), SubscriptionId::generate());

    // Check if negentropy is supported
    check_negentropy_support(&sub_id, opts, &mut temp_notifications).await?;

    let mut in_flight_up: HashSet<EventId> = HashSet::new();
    let mut in_flight_down: Option<HashSet<EventId>> = None;
    let mut sync_done: bool = false;
    let mut have_ids: Vec<EventId> = Vec::new();
    let mut need_ids: Vec<EventId> = Vec::new();
    let mut last_relevant_msg: Instant = Instant::now();

    // Start reconciliation
    loop {
        let notification = time::timeout(Some(opts.idle_timeout), notifications.recv())
            .await
            .ok_or(Error::timeout())??;

        if last_relevant_msg.elapsed() > opts.idle_timeout {
            return Err(Error::timeout());
        }

        match notification {
            RelayNotification::Message { message } => {
                let is_relevant: bool = match *message {
                    RelayMessage::NegMsg {
                        subscription_id,
                        message,
                    } => {
                        #[allow(clippy::collapsible_match)]
                        if subscription_id.as_ref() == &sub_id {
                            let mut curr_have_ids: Vec<Id> = Vec::new();
                            let mut curr_need_ids: Vec<Id> = Vec::new();

                            match message.len().checked_div(2) {
                                Some(size) => {
                                    // Parse message
                                    let mut query: Vec<u8> = vec![0; size];
                                    faster_hex::hex_decode(message.as_bytes(), &mut query)?;

                                    // Reconcile
                                    let msg: Option<Vec<u8>> = negentropy.reconcile_with_ids(
                                        &query,
                                        &mut curr_have_ids,
                                        &mut curr_need_ids,
                                    )?;

                                    // Handle the message
                                    handle_neg_msg(
                                        relay,
                                        &subscription_id,
                                        msg,
                                        curr_have_ids.into_iter().map(neg_id_to_event_id),
                                        curr_need_ids.into_iter().map(neg_id_to_event_id),
                                        opts,
                                        output,
                                        &mut have_ids,
                                        &mut need_ids,
                                        &mut sync_done,
                                    )
                                    .await?;
                                }
                                None => {
                                    tracing::warn!("Can't divide negentropy message.")
                                }
                            }

                            // Relevant to this sync
                            true
                        } else {
                            // Not relevant to this sync
                            false
                        }
                    }
                    RelayMessage::NegErr {
                        subscription_id,
                        message,
                    } => {
                        #[allow(clippy::collapsible_match)]
                        if subscription_id.as_ref() == &sub_id {
                            return Err(Error::relay_msg(message.into_owned()));
                        } else {
                            // Not relevant to this sync
                            false
                        }
                    }
                    RelayMessage::Ok {
                        event_id,
                        status,
                        message,
                    } => handle_neg_ok(relay, &mut in_flight_up, event_id, status, message, output),
                    RelayMessage::Event {
                        subscription_id,
                        event,
                    } => {
                        #[allow(clippy::collapsible_match)]
                        if subscription_id.as_ref() == &cleanup.down_id {
                            output.received.insert(event.id);

                            if let Some(in_flight_down) = in_flight_down.as_mut() {
                                in_flight_down.remove(&event.id);
                            }

                            // Relevant to this sync
                            true
                        } else {
                            // Not relevant to this sync
                            false
                        }
                    }
                    RelayMessage::EndOfStoredEvents(subscription_id) => {
                        #[allow(clippy::collapsible_match)]
                        if subscription_id.as_ref() == &cleanup.down_id {
                            in_flight_down = None;

                            // Remove subscription
                            relay.inner.remove_subscription(&cleanup.down_id).await;

                            // Close subscription
                            relay
                                .send_msg(ClientMessage::Close(Cow::Borrowed(&cleanup.down_id)))
                                .await?;

                            // Relevant to this sync
                            true
                        } else {
                            // Not relevant to this sync
                            false
                        }
                    }
                    RelayMessage::Closed {
                        subscription_id,
                        message,
                    } => {
                        #[allow(clippy::collapsible_match)]
                        if subscription_id.as_ref() == &cleanup.down_id && in_flight_down.is_some()
                        {
                            let is_in_flight_down_empty: bool =
                                in_flight_down.as_ref().is_some_and(HashSet::is_empty);

                            // An empty CLOSED can end a finite explicit-ID
                            // batch only after every requested event arrived.
                            if message.is_empty() && is_in_flight_down_empty {
                                in_flight_down = None;
                                true
                            } else {
                                return Err(if message.is_empty() {
                                    Error::relay_msg(String::from(
                                        "download subscription closed before all requested events arrived",
                                    ))
                                } else {
                                    Error::relay_msg(message.into_owned())
                                });
                            }
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                // Send events
                upload_neg_events(relay, &mut have_ids, &mut in_flight_up, opts).await?;

                // Get events
                req_neg_events(
                    relay,
                    &mut need_ids,
                    &mut in_flight_down,
                    &mut cleanup,
                    opts,
                )
                .await?;

                // NOTE: update this after the uploading and requesting of the events, as it may require some time.
                if is_relevant {
                    last_relevant_msg = Instant::now();
                }
            }
            RelayNotification::RelayStatus { status } if status.is_disconnected() => {
                return Err(Error::not_connected());
            }
            _ => (),
        };

        if sync_done
            && have_ids.is_empty()
            && need_ids.is_empty()
            && in_flight_up.is_empty()
            && in_flight_down.is_none()
        {
            break;
        }
    }

    tracing::info!(url = %relay.url(), "Negentropy reconciliation terminated.");

    cleanup.disarm();

    Ok(())
}

fn prepare_negentropy_storage(
    items: Vec<(EventId, Timestamp)>,
) -> Result<NegentropyStorageVector, Error> {
    // Compose negentropy storage
    let mut storage = NegentropyStorageVector::with_capacity(items.len());

    // Add items
    for (id, timestamp) in items.into_iter() {
        let id: Id = Id::from_byte_array(id.to_bytes());
        storage.insert(timestamp.as_secs(), id)?;
    }

    // Seal
    storage.seal()?;

    // Build negentropy client
    Ok(storage)
}

/// Check if negentropy is supported
#[inline(never)]
async fn check_negentropy_support(
    sub_id: &SubscriptionId,
    opts: &SyncOptions,
    temp_notifications: &mut broadcast::Receiver<RelayNotification>,
) -> Result<(), Error> {
    time::timeout(Some(opts.initial_timeout), async {
        loop {
            let notification = temp_notifications.recv().await?;

            if let RelayNotification::Message { message } = notification {
                match *message {
                    RelayMessage::NegMsg {
                        subscription_id, ..
                    } if subscription_id.as_ref() == sub_id => {
                        break;
                    }
                    RelayMessage::NegErr {
                        subscription_id,
                        message,
                    } if subscription_id.as_ref() == sub_id => {
                        return Err(Error::relay_msg(message.into_owned()));
                    }
                    RelayMessage::Notice(message) => {
                        if message == "ERROR: negentropy error: negentropy query missing elements" {
                            // The relay expects the deprecated five-element NEG-OPEN format.
                            return Err(negentropy::Error::UnsupportedProtocolVersion.into());
                        } else if message.contains("bad msg")
                            && (message.contains("unknown cmd")
                                || message.contains("negentropy")
                                || message.contains("NEG-"))
                        {
                            return Err(Error::negentropy_not_supported());
                        } else if message.contains("bad msg: invalid message")
                            && message.contains("NEG-OPEN")
                        {
                            return Err(Error::unknown_negentropy_error());
                        }
                    }
                    _ => (),
                }
            }
        }

        Ok(())
    })
    .await
    .ok_or_else(Error::timeout)?
}

impl<'relay> IntoFuture for SyncEvents<'relay> {
    type Output = Result<SyncSummary, Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let outcome = self.with_outcomes().await?;
            match outcome.error {
                Some(error) => Err(error),
                None => Ok(outcome.summary),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_wsocket::Message;
    use futures::StreamExt;
    use nostr::message::MachineReadablePrefix;
    use nostr_memory::prelude::*;
    use tokio::sync::{Notify, broadcast};
    use tokio::time;

    use super::*;
    use crate::error::{Error, ErrorKind};
    use crate::local_relay::{LocalRelay, MockRelay, QueryPolicy, QueryPolicyResult};
    use crate::relay::{RelayCapabilities, SyncDirection, SyncOptions};
    use crate::transport::websocket::{
        DefaultWebsocketTransport, WebSocketSink, WebSocketStream, WebSocketTransport,
    };

    #[derive(Debug, Clone, Copy)]
    enum ClosedResponse {
        AllEvents,
        MissingEvent,
        Rejected,
    }

    impl ClosedResponse {
        fn is_missing_event(&self) -> bool {
            matches!(self, Self::MissingEvent)
        }
    }

    #[derive(Debug)]
    struct CloseInsteadOfEose {
        response: ClosedResponse,
    }

    impl WebSocketTransport for CloseInsteadOfEose {
        fn support_ping(&self) -> bool {
            true
        }

        fn connect<'a>(
            &'a self,
            url: &'a Url,
            proxy: Option<SocketAddr>,
        ) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
            Box::pin(async move {
                let (sink, stream) = DefaultWebsocketTransport.connect(url, proxy).await?;

                let response: ClosedResponse = self.response;

                let stream = stream.filter_map(move |message| async move {
                    match message {
                        Ok(Message::Text(text)) => match RelayMessage::from_json(&text) {
                            Ok(RelayMessage::EndOfStoredEvents(id)) => {
                                let reason = match response {
                                    ClosedResponse::Rejected => "blocked: reads denied",
                                    _ => "",
                                };
                                Some(Ok(Message::Text(
                                    RelayMessage::closed(id.into_owned(), reason).as_json(),
                                )))
                            }
                            Ok(RelayMessage::Event { .. }) if response.is_missing_event() => None,
                            _ => Some(Ok(Message::Text(text))),
                        },
                        other => Some(other),
                    }
                });
                Ok((sink, Box::pin(stream) as WebSocketStream))
            })
        }
    }

    #[derive(Debug)]
    struct HoldFirstEose {
        first_eose_held: Arc<Notify>,
        release_first_eose: Arc<Notify>,
        first_eose_seen: Arc<AtomicBool>,
    }

    impl WebSocketTransport for HoldFirstEose {
        fn support_ping(&self) -> bool {
            true
        }

        fn connect<'a>(
            &'a self,
            url: &'a Url,
            proxy: Option<SocketAddr>,
        ) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
            Box::pin(async move {
                let (sink, stream) = DefaultWebsocketTransport.connect(url, proxy).await?;

                let first_eose_held: Arc<Notify> = self.first_eose_held.clone();
                let release_first_eose: Arc<Notify> = self.release_first_eose.clone();
                let first_eose_seen: Arc<AtomicBool> = self.first_eose_seen.clone();

                let stream = stream.then(move |message| {
                    let first_eose_held: Arc<Notify> = first_eose_held.clone();
                    let release_first_eose: Arc<Notify> = release_first_eose.clone();
                    let first_eose_seen: Arc<AtomicBool> = first_eose_seen.clone();

                    async move {
                        if let Ok(Message::Text(text)) = &message {
                            if matches!(
                                RelayMessage::from_json(text),
                                Ok(RelayMessage::EndOfStoredEvents(_))
                            ) && !first_eose_seen.swap(true, Ordering::SeqCst)
                            {
                                first_eose_held.notify_one();
                                release_first_eose.notified().await;
                            }
                        }
                        message
                    }
                });
                Ok((sink, Box::pin(stream) as WebSocketStream))
            })
        }
    }

    #[derive(Debug)]
    struct RejectDownloadAfter {
        allowed_batches: usize,
        seen_batches: AtomicUsize,
    }

    impl QueryPolicy for RejectDownloadAfter {
        fn admit_query<'a>(
            &'a self,
            query: &'a mut Filter,
            _addr: &'a SocketAddr,
        ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
            let reject: bool = if query.ids.is_some() {
                let batch_index: usize = self.seen_batches.fetch_add(1, Ordering::SeqCst);
                batch_index >= self.allowed_batches
            } else {
                false
            };

            Box::pin(async move {
                if reject {
                    QueryPolicyResult::reject(MachineReadablePrefix::Blocked, "reads denied")
                } else {
                    QueryPolicyResult::Accept
                }
            })
        }
    }

    #[derive(Debug)]
    struct HoldDownload {
        download_requested: Arc<Notify>,
        release_download: Arc<Notify>,
    }

    impl QueryPolicy for HoldDownload {
        fn admit_query<'a>(
            &'a self,
            query: &'a mut Filter,
            _addr: &'a SocketAddr,
        ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
            Box::pin(async move {
                if query.ids.is_some() {
                    self.download_requested.notify_one();
                    self.release_download.notified().await;
                }
                QueryPolicyResult::Accept
            })
        }
    }

    async fn wait_for_subscription_count(relay: &Relay, expected: usize) {
        time::timeout(Duration::from_secs(2), async {
            while relay.inner.active_subscription_count().await != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn sync_with_closed_response(
        response: ClosedResponse,
    ) -> (Result<SyncSummary, Error>, EventId) {
        let local = LocalRelay::new();
        local.run().await.unwrap();

        let event = EventBuilder::new(Kind::TextNote, "explicit download")
            .finalize(&Keys::generate())
            .unwrap();
        local.add_event(event.clone()).await.unwrap();

        let relay = Relay::builder(local.url().await)
            .websocket_transport(CloseInsteadOfEose { response })
            .build();

        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();

        let filter: Filter = Filter::new().kind(Kind::TextNote);
        let opts: SyncOptions = SyncOptions::new()
            .initial_timeout(Duration::from_secs(2))
            .idle_timeout(Duration::from_secs(2));
        let result = relay.sync(filter).opts(opts).await;

        wait_for_subscription_count(&relay, 0).await;

        relay.shutdown();
        local.shutdown();

        (result, event.id)
    }

    #[tokio::test]
    async fn test_check_negentropy_support_times_out() {
        let (_tx, mut rx) = broadcast::channel(1);
        let sub_id = SubscriptionId::generate();
        let opts = SyncOptions::default().initial_timeout(Duration::from_millis(10));

        let error = check_negentropy_support(&sub_id, &opts, &mut rx)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Timeout);
    }

    #[tokio::test]
    async fn test_check_negentropy_support_fails_when_notifications_close() {
        let (tx, mut rx) = broadcast::channel(1);
        drop(tx);

        let sub_id = SubscriptionId::generate();
        let opts = SyncOptions::default().initial_timeout(Duration::from_secs(1));

        let error = check_negentropy_support(&sub_id, &opts, &mut rx)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Other);
    }

    #[tokio::test]
    async fn test_negentropy_sync() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        // Database
        let database = Arc::new(MemoryDatabase::unbounded());

        // Build events to store in the local database
        let local_events = [
            EventBuilder::new(Kind::TextNote, "Local 1")
                .finalize(&Keys::generate())
                .unwrap(),
            EventBuilder::new(Kind::TextNote, "Local 2")
                .finalize(&Keys::generate())
                .unwrap(),
            EventBuilder::new(Kind::Custom(123), "Local 123")
                .finalize(&Keys::generate())
                .unwrap(),
        ];

        // Save an event to the local database
        for event in local_events.iter() {
            database.save_event(event).await.unwrap();
        }
        assert_eq!(database.count(Filter::new()).await.unwrap(), 3);

        // Relay
        let relay = Relay::builder(url).database(database.clone()).build();

        // Connect
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();

        // Build events to send to the relay
        let relays_events = [
            // Event in common with the local database
            local_events[0].clone(),
            EventBuilder::new(Kind::TextNote, "Test 2")
                .finalize(&Keys::generate())
                .unwrap(),
            EventBuilder::new(Kind::TextNote, "Test 3")
                .finalize(&Keys::generate())
                .unwrap(),
            EventBuilder::new(Kind::Custom(123), "Test 4")
                .finalize(&Keys::generate())
                .unwrap(),
        ];

        // Send events to the relays
        for event in relays_events.iter() {
            relay.send_event(event).await.unwrap();
        }

        // Sync
        let filter = Filter::new().kind(Kind::TextNote);
        let opts = SyncOptions::default().direction(SyncDirection::Both);
        let output = relay.sync(filter).opts(opts).await.unwrap();

        assert_eq!(
            output,
            SyncSummary {
                local: HashSet::from([local_events[1].id]),
                remote: HashSet::from([relays_events[1].id, relays_events[2].id]),
                sent: HashSet::from([local_events[1].id]),
                received: HashSet::from([relays_events[1].id, relays_events[2].id]),
                send_failures: HashMap::new(),
            }
        );
    }

    #[tokio::test]
    async fn empty_closed_after_all_events_completes_download() {
        let (result, event_id) = sync_with_closed_response(ClosedResponse::AllEvents).await;

        assert_eq!(result.unwrap().received, HashSet::from([event_id]));
    }

    #[tokio::test]
    async fn empty_closed_before_all_events_fails_download() {
        let (result, _) = sync_with_closed_response(ClosedResponse::MissingEvent).await;

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("closed before all requested events arrived")
        );
    }

    #[tokio::test]
    async fn closed_with_error_after_all_events_fails_download() {
        let (result, _) = sync_with_closed_response(ClosedResponse::Rejected).await;

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("blocked: reads denied")
        );
    }

    #[tokio::test]
    async fn cancelled_sync_cleans_only_its_subscription() {
        let download_requested = Arc::new(Notify::new());
        let release_download = Arc::new(Notify::new());

        let local: LocalRelay = LocalRelay::builder()
            .query_policy(HoldDownload {
                download_requested: download_requested.clone(),
                release_download: release_download.clone(),
            })
            .build();
        local.run().await.unwrap();

        let url = local.url().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "download")
            .finalize(&keys)
            .unwrap();

        local.add_event(event).await.unwrap();

        let relay = Relay::new(url);
        relay.connect();

        let unrelated_id = relay
            .subscribe(Filter::new().kind(Kind::Metadata))
            .await
            .unwrap();

        let mut notifications = relay.notifications();

        let mut sync_future = Box::pin(
            relay
                .sync(Filter::new().kind(Kind::TextNote))
                .opts(SyncOptions::new().idle_timeout(Duration::from_secs(5)))
                .into_future(),
        );

        time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = download_requested.notified() => (),
                result = &mut sync_future => panic!("sync ended before cancellation: {result:?}"),
            }
        })
        .await
        .unwrap();

        assert_eq!(relay.inner.active_subscription_count().await, 2);

        drop(sync_future);

        wait_for_subscription_count(&relay, 1).await;

        assert!(relay.inner.has_subscription(&unrelated_id).await);

        release_download.notify_one();

        let unrelated_event = EventBuilder::new(Kind::Metadata, "{}")
            .finalize(&keys)
            .unwrap();

        local.add_event(unrelated_event.clone()).await.unwrap();

        time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(RelayNotification::Event {
                    subscription_id,
                    event,
                }) = notifications.next().await
                {
                    if subscription_id == unrelated_id && event.id == unrelated_event.id {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();

        relay.shutdown();
    }

    async fn assert_rejected_download_after(allowed_batches: usize, report_outcomes: bool) {
        let event_count = allowed_batches * NEGENTROPY_BATCH_SIZE_DOWN + 1;

        let local = LocalRelay::builder()
            .query_policy(RejectDownloadAfter {
                allowed_batches,
                seen_batches: AtomicUsize::new(0),
            })
            .build();
        local.run().await.unwrap();

        let url = local.url().await;

        let keys = Keys::generate();
        for index in 0..event_count {
            let event = EventBuilder::new(Kind::TextNote, format!("remote {index}"))
                .finalize(&keys)
                .unwrap();
            local.add_event(event).await.unwrap();
        }

        let relay = Relay::builder(url)
            .database(MemoryDatabase::unbounded())
            .build();

        relay.connect();

        let unrelated_id = SubscriptionId::generate();
        relay
            .subscribe(Filter::new().kind(Kind::Metadata))
            .with_id(unrelated_id.clone())
            .await
            .unwrap();

        let filter: Filter = Filter::new().kind(Kind::TextNote);
        let opts: SyncOptions = SyncOptions::new()
            .initial_timeout(Duration::from_secs(2))
            .idle_timeout(Duration::from_secs(2));
        let err = if report_outcomes {
            let outcome: RelaySyncOutcome =
                relay.sync(filter).opts(opts).with_outcomes().await.unwrap();
            assert_eq!(outcome.summary.remote.len(), event_count);
            assert_eq!(
                outcome.summary.received.len(),
                allowed_batches * NEGENTROPY_BATCH_SIZE_DOWN
            );
            outcome.error.unwrap()
        } else {
            relay.sync(filter).opts(opts).await.unwrap_err()
        };

        assert_eq!(err, Error::relay_msg(String::from("blocked: reads denied")));
        assert_eq!(
            relay
                .inner
                .state
                .database()
                .count(Filter::new().kind(Kind::TextNote))
                .await
                .unwrap(),
            allowed_batches * NEGENTROPY_BATCH_SIZE_DOWN
        );

        wait_for_subscription_count(&relay, 1).await;

        assert!(relay.inner.has_subscription(&unrelated_id).await);

        relay.shutdown();
    }

    #[tokio::test]
    async fn rejected_first_download_batch_fails_sync() {
        assert_rejected_download_after(0, false).await;
    }

    #[tokio::test]
    async fn rejected_later_download_batch_fails_sync() {
        assert_rejected_download_after(1, false).await;
    }

    #[tokio::test]
    async fn sync_outcomes_retain_progress_before_rejection() {
        assert_rejected_download_after(0, true).await;
        assert_rejected_download_after(1, true).await;
    }

    #[tokio::test]
    async fn sync_outcomes_report_success_without_an_error() {
        let local = LocalRelay::new();
        local.run().await.unwrap();
        let relay = Relay::new(local.url().await);
        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();
        let outcome: RelaySyncOutcome = relay.sync(Filter::new()).with_outcomes().await.unwrap();
        assert!(outcome.error.is_none());
        assert_eq!(outcome.summary, SyncSummary::default());
        relay.capabilities().remove(RelayCapabilities::READ);
        let error = relay.sync(Filter::new()).with_outcomes().await.unwrap_err();
        assert_eq!(error, Error::read_disabled());
        relay.shutdown();
        local.shutdown();
    }

    #[tokio::test]
    async fn sync_outcomes_reject_preflight_failure() {
        let relay = Relay::new(RelayUrl::parse("wss://relay.example.com").unwrap());
        let error = relay.sync(Filter::new()).with_outcomes().await.unwrap_err();
        assert_eq!(error, Error::not_ready());
    }

    #[tokio::test]
    async fn waits_for_eose_before_starting_next_download_batch() {
        let first_eose_held = Arc::new(Notify::new());
        let release_first_eose = Arc::new(Notify::new());

        let event_count = NEGENTROPY_BATCH_SIZE_DOWN + 1;

        let local = LocalRelay::new();
        local.run().await.unwrap();

        let keys = Keys::generate();
        for index in 0..event_count {
            let event = EventBuilder::new(Kind::TextNote, format!("remote {index}"))
                .finalize(&keys)
                .unwrap();
            local.add_event(event).await.unwrap();
        }

        let relay = Relay::builder(local.url().await)
            .websocket_transport(HoldFirstEose {
                first_eose_held: first_eose_held.clone(),
                release_first_eose: release_first_eose.clone(),
                first_eose_seen: Arc::new(AtomicBool::new(false)),
            })
            .build();

        relay
            .try_connect()
            .timeout(Duration::from_secs(2))
            .await
            .unwrap();

        let mut notifications = relay.inner.internal_notification_sender.subscribe();

        let mut sync_future = Box::pin(
            relay
                .sync(Filter::new().kind(Kind::TextNote))
                .opts(
                    SyncOptions::new()
                        .initial_timeout(Duration::from_secs(2))
                        .idle_timeout(Duration::from_secs(2)),
                )
                .into_future(),
        );

        time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = first_eose_held.notified() => (),
                result = &mut sync_future => panic!("sync ended before first EOSE: {result:?}"),
            }
        })
        .await
        .unwrap();

        time::timeout(Duration::from_secs(2), async {
            let mut received_events = 0;
            while received_events < NEGENTROPY_BATCH_SIZE_DOWN {
                if let Ok(RelayNotification::Message { message }) = notifications.recv().await {
                    if matches!(*message, RelayMessage::Event { .. }) {
                        received_events += 1;
                    }
                }
            }
        })
        .await
        .unwrap();

        assert!(
            time::timeout(Duration::from_millis(100), &mut sync_future)
                .await
                .is_err()
        );
        assert_eq!(relay.inner.active_subscription_count().await, 1);

        release_first_eose.notify_one();

        let output = time::timeout(Duration::from_secs(2), sync_future)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(output.received.len(), event_count);

        wait_for_subscription_count(&relay, 0).await;

        relay.shutdown();
        local.shutdown();
    }
}
