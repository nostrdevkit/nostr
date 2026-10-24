use std::future::IntoFuture;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{Stream, StreamExt};
use nostr::event::Event;
use nostr::filter::Filter;
use nostr::message::SubscriptionId;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, oneshot};

use super::subscribe::subscribe_auto_closing;
use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::{
    Relay, ReqExitPolicy, SubscribeAutoCloseOptions, SubscriptionActivity,
    SubscriptionAutoClosedReason,
};

type EventStream = Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>;

/// An event or terminal outcome from an auto-closing relay request.
#[derive(Debug)]
pub enum RelayStreamEvent {
    /// An event received from the relay.
    Event(Event),
    /// The request failed before its exit policy was satisfied.
    Error(Error),
    /// The relay completed the request according to its exit policy.
    ///
    /// This doesn't mean that every matching event was received.
    Completed,
    /// The configured event count was reached; more matching events may exist.
    LimitReached,
}

/// Stream events
#[must_use = "Does nothing unless you await!"]
pub struct StreamEvents<'relay> {
    relay: &'relay Relay,
    filters: Vec<Filter>,
    id: Option<SubscriptionId>,
    timeout: Option<Duration>,
    policy: ReqExitPolicy,
}

impl<'relay> StreamEvents<'relay> {
    pub(crate) fn new(relay: &'relay Relay, filters: Vec<Filter>) -> Self {
        Self {
            relay,
            filters,
            id: None,
            timeout: None,
            policy: ReqExitPolicy::ExitOnEOSE,
        }
    }

    /// Set a specific subscription ID
    #[inline]
    pub fn with_id(mut self, id: SubscriptionId) -> Self {
        self.id = Some(id);
        self
    }

    #[inline]
    pub(crate) fn maybe_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set a timeout
    ///
    /// By default, no timeout is configured.
    #[inline]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set request exit policy (default: [`ReqExitPolicy::ExitOnEOSE`]).
    #[inline]
    pub fn policy(mut self, policy: ReqExitPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Stream events together with the terminal outcome of the request.
    ///
    /// Unlike awaiting the builder, the stream ends with a terminal item:
    /// [`RelayStreamEvent::Completed`], [`RelayStreamEvent::LimitReached`],
    /// or [`RelayStreamEvent::Error`] (e.g., timeout, disconnection, notification lag
    /// or a `CLOSED` received before the exit policy was satisfied).
    ///
    /// Dropping the stream cancels the request and closes its subscription.
    pub async fn with_outcomes(
        self,
    ) -> Result<Pin<Box<dyn Stream<Item = RelayStreamEvent> + Send>>, Error> {
        let stream: SubscriptionActivityEventStream = self.into_relay_event_stream(true).await?;
        Ok(Box::pin(stream))
    }

    pub(crate) async fn into_relay_event_stream(
        self,
        report_terminal_errors: bool,
    ) -> Result<SubscriptionActivityEventStream, Error> {
        // Create channels
        let (tx, rx) = mpsc::channel(512);

        // Compose auto-closing options
        let opts: SubscribeAutoCloseOptions = SubscribeAutoCloseOptions::default()
            .exit_policy(self.policy)
            .timeout(self.timeout)
            .report_relay_closed(report_terminal_errors);

        // Get or generate a subscription ID
        let id: SubscriptionId = self.id.unwrap_or_else(SubscriptionId::generate);

        // Subscribe
        let (cancel_tx, cancel_rx) = oneshot::channel();
        subscribe_auto_closing(
            self.relay,
            id,
            self.filters,
            opts,
            Some(tx),
            Some(cancel_rx),
        )
        .await?;

        Ok(SubscriptionActivityEventStream::new(
            rx,
            cancel_tx,
            report_terminal_errors,
        ))
    }
}

impl<'relay> IntoFuture for StreamEvents<'relay> {
    type Output = Result<EventStream, Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let stream = self.into_relay_event_stream(false).await?;

            Ok(Box::pin(stream.filter_map(async |e| match e {
                RelayStreamEvent::Event(event) => Some(Ok(event)),
                RelayStreamEvent::Error(e) => Some(Err(e)),
                RelayStreamEvent::Completed | RelayStreamEvent::LimitReached => None,
            })) as EventStream)
        })
    }
}

pub(crate) struct SubscriptionActivityEventStream {
    rx: mpsc::Receiver<SubscriptionActivity>,
    done: bool,
    cancel: Option<oneshot::Sender<()>>,
    /// Report timeout, disconnection and a missing outcome as errors,
    /// instead of ending the stream quietly.
    report_terminal_errors: bool,
}

impl SubscriptionActivityEventStream {
    fn new(
        rx: mpsc::Receiver<SubscriptionActivity>,
        cancel: oneshot::Sender<()>,
        report_terminal_errors: bool,
    ) -> Self {
        Self {
            rx,
            done: false,
            cancel: Some(cancel),
            report_terminal_errors,
        }
    }

    fn terminate_with_error(&mut self, error: Error) -> Poll<Option<RelayStreamEvent>> {
        self.done = true;

        if self.report_terminal_errors {
            Poll::Ready(Some(RelayStreamEvent::Error(error)))
        } else {
            Poll::Ready(None)
        }
    }
}

impl Drop for SubscriptionActivityEventStream {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

impl Stream for SubscriptionActivityEventStream {
    type Item = RelayStreamEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(activity)) => match activity {
                SubscriptionActivity::ReceivedEvent(event) => {
                    Poll::Ready(Some(RelayStreamEvent::Event(event)))
                }
                SubscriptionActivity::Closed(reason) => match reason {
                    SubscriptionAutoClosedReason::AuthenticationFailed => {
                        self.done = true;
                        Poll::Ready(Some(RelayStreamEvent::Error(Error::authentication_msg(
                            "authentication failed",
                        ))))
                    }
                    SubscriptionAutoClosedReason::Closed(message)
                    | SubscriptionAutoClosedReason::RelayClosed(message) => {
                        self.done = true;
                        Poll::Ready(Some(RelayStreamEvent::Error(Error::relay_msg(message))))
                    }
                    SubscriptionAutoClosedReason::Lagged(skipped) => {
                        self.done = true;
                        Poll::Ready(Some(RelayStreamEvent::Error(
                            RecvError::Lagged(skipped).into(),
                        )))
                    }
                    SubscriptionAutoClosedReason::ReceiverClosed => {
                        self.done = true;
                        Poll::Ready(Some(RelayStreamEvent::Error(RecvError::Closed.into())))
                    }
                    SubscriptionAutoClosedReason::TimedOut => {
                        self.terminate_with_error(Error::timeout())
                    }
                    SubscriptionAutoClosedReason::Disconnected => {
                        self.terminate_with_error(Error::not_connected())
                    }
                    SubscriptionAutoClosedReason::LimitReached => {
                        self.done = true;
                        Poll::Ready(Some(RelayStreamEvent::LimitReached))
                    }
                    SubscriptionAutoClosedReason::Completed => {
                        self.done = true;
                        Poll::Ready(Some(RelayStreamEvent::Completed))
                    }
                },
            },
            // The auto-closing handler always sends a reason before dropping the channel,
            // unless its task was aborted.
            Poll::Ready(None) => {
                self.terminate_with_error(Error::state_msg("stream ended without an outcome"))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::filter::Filter;
    use nostr::key::Keys;
    use nostr::message::{MachineReadablePrefix, SubscriptionId};

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::error::ErrorKind;
    use crate::local_relay::*;
    use crate::relay::{Relay, RelayOptions, ReqExitPolicy};
    use crate::test_utils::{
        setup_nip42_read_local_relay, setup_relay, setup_relay_with_authenticator,
    };

    /// Connect to a mock relay that stores one text note.
    async fn setup_relay_with_one_event() -> (Relay, MockRelay) {
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay = Relay::new(url);
        relay.connect();

        let event = EventBuilder::new(Kind::TextNote, "stored")
            .finalize(&Keys::generate())
            .unwrap();
        relay.send_event(&event).await.unwrap();

        (relay, mock)
    }

    #[tokio::test]
    async fn with_outcomes_ends_with_completion() {
        let (relay, _mock) = setup_relay_with_one_event().await;

        let outcomes: Vec<RelayStreamEvent> = relay
            .stream_events(Filter::new().kind(Kind::TextNote))
            .timeout(Duration::from_secs(2))
            .with_outcomes()
            .await
            .unwrap()
            .collect()
            .await;

        assert!(matches!(
            outcomes.as_slice(),
            [RelayStreamEvent::Event(_), RelayStreamEvent::Completed]
        ));
    }

    #[tokio::test]
    async fn with_outcomes_reports_timeout_after_partial_events() {
        let (relay, _mock) = setup_relay_with_one_event().await;

        let outcomes: Vec<RelayStreamEvent> = relay
            .stream_events(Filter::new().kind(Kind::TextNote))
            .policy(ReqExitPolicy::WaitDurationAfterEOSE(Duration::from_secs(1)))
            .timeout(Duration::from_millis(100))
            .with_outcomes()
            .await
            .unwrap()
            .collect()
            .await;

        assert!(matches!(
            outcomes.as_slice(),
            [RelayStreamEvent::Event(_), RelayStreamEvent::Error(e)] if e.kind() == ErrorKind::Timeout
        ));
    }

    #[tokio::test]
    async fn reporting_stream_preserves_limit_and_receiver_failure() {
        let (tx, rx) = mpsc::channel(2);
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let mut stream = SubscriptionActivityEventStream::new(rx, cancel_tx, true);

        tx.send(SubscriptionActivity::Closed(
            SubscriptionAutoClosedReason::LimitReached,
        ))
        .await
        .unwrap();
        assert!(matches!(
            stream.next().await,
            Some(RelayStreamEvent::LimitReached)
        ));
        assert!(stream.next().await.is_none());

        let (tx, rx) = mpsc::channel(2);
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let mut stream = SubscriptionActivityEventStream::new(rx, cancel_tx, true);
        tx.send(SubscriptionActivity::Closed(
            SubscriptionAutoClosedReason::Lagged(6),
        ))
        .await
        .unwrap();
        assert!(matches!(
            stream.next().await,
            Some(RelayStreamEvent::Error(error)) if error.to_string().contains("lagged")
        ));
        assert!(stream.next().await.is_none());

        let (tx, rx) = mpsc::channel(2);
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let mut stream = SubscriptionActivityEventStream::new(rx, cancel_tx, true);
        tx.send(SubscriptionActivity::Closed(
            SubscriptionAutoClosedReason::ReceiverClosed,
        ))
        .await
        .unwrap();
        assert!(matches!(
            stream.next().await,
            Some(RelayStreamEvent::Error(error)) if error.to_string().contains("closed")
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn legacy_stream_ends_quietly_on_timeout_and_disconnect() {
        for reason in [
            SubscriptionAutoClosedReason::TimedOut,
            SubscriptionAutoClosedReason::Disconnected,
        ] {
            let (tx, rx) = mpsc::channel(1);
            let (cancel_tx, _cancel_rx) = oneshot::channel();
            let mut stream = SubscriptionActivityEventStream::new(rx, cancel_tx, false);
            tx.send(SubscriptionActivity::Closed(reason)).await.unwrap();
            assert!(stream.next().await.is_none());
        }
    }

    #[tokio::test]
    async fn stream_without_outcome_is_reported_only_when_requested() {
        let (tx, rx) = mpsc::channel(1);
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let mut stream = SubscriptionActivityEventStream::new(rx, cancel_tx, true);
        drop(tx);
        assert!(matches!(
            stream.next().await,
            Some(RelayStreamEvent::Error(error)) if error.kind() == ErrorKind::State
        ));
        assert!(stream.next().await.is_none());

        let (tx, rx) = mpsc::channel(1);
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let mut stream = SubscriptionActivityEventStream::new(rx, cancel_tx, false);
        drop(tx);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn reporting_stream_does_not_complete_on_early_relay_closed() {
        let (tx, rx) = mpsc::channel(1);
        let (cancel_tx, _cancel_rx) = oneshot::channel();
        let mut stream = SubscriptionActivityEventStream::new(rx, cancel_tx, true);
        tx.send(SubscriptionActivity::Closed(
            SubscriptionAutoClosedReason::RelayClosed("temporarily unavailable".to_owned()),
        ))
        .await
        .unwrap();
        assert!(matches!(
            stream.next().await,
            Some(RelayStreamEvent::Error(error)) if error.to_string().contains("temporarily unavailable")
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_terminates_on_drop() {
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay = Relay::new(url);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        let filter = Filter::new().kind(Kind::TextNote).limit(1);
        let id = SubscriptionId::generate();

        let stream = relay
            .stream_events(filter)
            .with_id(id.clone())
            .policy(ReqExitPolicy::WaitForEvents(1))
            .await
            .unwrap();

        // Check if relay has the stream subscription
        let exists: bool = relay.subscription(&id).await.is_some();
        assert!(exists);

        // Drop the stream
        // This must terminate the stream and close the subscription
        drop(stream);

        // Wait a bit
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Now the subscription must not exist anymore
        let exists: bool = relay.subscription(&id).await.is_some();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_stream_with_subscription_verification_single_filter() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&keys)
            .unwrap();

        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        mock.add_event(event.clone()).await.unwrap();

        let opts = RelayOptions::default()
            .verify_subscriptions(true)
            .ban_relay_on_mismatch(true);
        let relay = Relay::builder(url).opts(opts).build();

        relay.connect();

        let filter = Filter::new().author(event.pubkey).kind(Kind::TextNote);

        let mut stream = relay
            .stream_events(filter)
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        let streamed_event = stream
            .next()
            .await
            .expect("Received None instead of the event")
            .unwrap();
        assert_eq!(streamed_event.id, event.id);
    }

    #[tokio::test]
    async fn test_stream_with_subscription_verification_multiple_filters() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "test")
            .finalize(&keys)
            .unwrap();

        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        mock.add_event(event.clone()).await.unwrap();

        let opts = RelayOptions::default()
            .verify_subscriptions(true)
            .ban_relay_on_mismatch(true);
        let relay = Relay::builder(url).opts(opts).build();

        relay.connect();

        let matching_filter = Filter::new().author(event.pubkey).kind(Kind::TextNote);
        let non_matching_filter = Filter::new().author(event.pubkey).kind(Kind::Repost);

        let mut stream = relay
            .stream_events([matching_filter, non_matching_filter])
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        let streamed_event = stream
            .next()
            .await
            .expect("Received None instead of the event")
            .unwrap();
        assert_eq!(streamed_event.id, event.id);
    }

    #[tokio::test]
    async fn test_stream_events_dont_resubscribes_after_auth_required_closed_without_authenticator()
    {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(event.clone()).await.unwrap();

        let url = local.url().await;
        let relay: Relay = setup_relay(url).await;

        let filter: Filter = Filter::new().kind(Kind::TextNote).limit(3);

        let mut stream = relay
            .stream_events(filter.clone())
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        let err = stream
            .next()
            .await
            .expect("stream ended before error was received")
            .unwrap_err();

        assert_eq!(
            MachineReadablePrefix::parse(&err.to_string()).unwrap(),
            MachineReadablePrefix::AuthRequired
        );
    }

    #[tokio::test]
    async fn test_stream_events_resubscribes_after_auth_required_closed() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let authenticator = SignerAuthenticator::new(keys);
        let relay = setup_relay_with_authenticator(local.url().await, authenticator).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let mut stream = relay
            .stream_events(filter)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        let event = stream
            .next()
            .await
            .expect("stream ended before event was received")
            .unwrap();
        assert_eq!(event.id, expected.id);
    }

    #[tokio::test]
    async fn test_stream_events_keeps_auto_closing_subscription_after_auth_required_resubscribe() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let authenticator = SignerAuthenticator::new(keys);
        let relay = setup_relay_with_authenticator(local.url().await, authenticator).await;

        let id = SubscriptionId::new("auto-closing-auth-required");
        let mut stream = relay
            .stream_events(Filter::new().kind(Kind::TextNote).limit(1))
            .with_id(id.clone())
            .policy(ReqExitPolicy::WaitDurationAfterEOSE(Duration::from_secs(2)))
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        let event = stream
            .next()
            .await
            .expect("stream ended before event was received")
            .unwrap();
        assert_eq!(event.id, expected.id);

        assert!(relay.inner.has_subscription(&id).await);
    }
}
