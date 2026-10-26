use std::collections::BTreeSet;
use std::future::IntoFuture;
use std::time::Duration;

use futures::StreamExt;
use nostr::event::Event;
use nostr::filter::Filter;

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::constants::DEFAULT_FETCH_EVENTS_LIMIT;
use crate::relay::{Relay, ReqExitPolicy};

/// Fetch events
#[must_use = "Does nothing unless you await!"]
pub struct FetchEvents<'relay> {
    relay: &'relay Relay,
    filters: Vec<Filter>,
    timeout: Option<Duration>,
    policy: ReqExitPolicy,
    max_events: usize,
}

impl<'relay> FetchEvents<'relay> {
    pub(crate) fn new(relay: &'relay Relay, filters: Vec<Filter>) -> Self {
        Self {
            relay,
            filters,
            timeout: None,
            policy: ReqExitPolicy::ExitOnEOSE,
            max_events: DEFAULT_FETCH_EVENTS_LIMIT,
        }
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

    /// Set the maximum number of unique events to buffer (default: 10,000).
    #[inline]
    pub fn max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }
}

impl<'relay> IntoFuture for FetchEvents<'relay> {
    type Output = Result<BTreeSet<Event>, Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Lookup ID: EVENT_ORD_IMPL
            let mut events: BTreeSet<Event> = BTreeSet::new();

            // Stream events
            let mut stream = self
                .relay
                .stream_events(self.filters)
                .maybe_timeout(self.timeout)
                .policy(self.policy)
                .await?;

            while let Some(res) = stream.next().await {
                // Get event from the result
                let event: Event = res?;

                if events.len() >= self.max_events && !events.contains(&event) {
                    return Err(Error::limit_exceeded("too many fetched events"));
                }

                events.insert(event);
            }

            Ok(events)
        })
    }
}

#[cfg(test)]
mod tests {
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::key::Keys;
    use nostr::message::MachineReadablePrefix;
    use nostr::nips::nip01::Metadata;

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::local_relay::*;
    use crate::relay::{RelayOptions, RelayStatus, ReqExitPolicy};
    use crate::test_utils::{
        setup_nip42_read_local_relay, setup_relay, setup_relay_with_authenticator,
    };

    /// Setup public (without NIP42 auth) relay with N events to test event fetching
    ///
    /// **Adds ONLY text notes**
    async fn setup_event_fetching_relay(num_events: usize) -> (Relay, MockRelay) {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay = Relay::new(url);
        relay.connect();

        // Signer
        let keys = Keys::generate();

        // Send some events
        for i in 0..num_events {
            let event = EventBuilder::new(Kind::TextNote, i.to_string())
                .finalize(&keys)
                .unwrap();
            relay.send_event(&event).await.unwrap();
        }

        (relay, mock)
    }

    #[tokio::test]
    async fn fetch_events_keeps_partial_events_when_request_times_out() {
        let (relay, _mock) = setup_event_fetching_relay(1).await;
        let events = relay
            .fetch_events(Filter::new().kind(Kind::TextNote))
            .policy(ReqExitPolicy::WaitDurationAfterEOSE(Duration::from_secs(1)))
            .timeout(Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_events_ban_relay() {
        // Mock relay
        let opts = LocalRelayTestOptions {
            unresponsive_connection: None,
            send_random_events: true,
        };
        let mock = MockRelay::run_with_opts(opts).await.unwrap();
        let url = mock.url().await;

        let relay = Relay::builder(url)
            .opts(
                RelayOptions::default()
                    .verify_subscriptions(true)
                    .ban_relay_on_mismatch(true),
            )
            .build();

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Connected);

        let filter = Filter::new().kind(Kind::Metadata);
        relay
            .fetch_events(filter)
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Banned);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_fetch_events_dont_resubscribes_after_auth_required_closed_without_authenticator()
    {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(event.clone()).await.unwrap();

        let url = local.url().await;
        let relay: Relay = setup_relay(url).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(3);

        // Unauthenticated fetch (MUST return error)
        let err = relay
            .fetch_events(filter.clone())
            .timeout(Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(
            MachineReadablePrefix::parse(&err.to_string()).unwrap(),
            MachineReadablePrefix::AuthRequired
        );
    }

    #[tokio::test]
    async fn test_fetch_events_resubscribes_after_auth_required_closed() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let authenticator = SignerAuthenticator::new(keys);
        let relay: Relay = setup_relay_with_authenticator(local.url().await, authenticator).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let events = relay
            .fetch_events(filter)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events.first().map(|event| event.id), Some(expected.id));
    }

    #[tokio::test]
    async fn test_fetch_events_exit_on_eose() {
        let (relay, _mock) = setup_event_fetching_relay(5).await;

        // Exit on EOSE
        let events = relay
            .fetch_events(Filter::new().kind(Kind::TextNote))
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(events.len(), 5);

        // Exit on EOSE
        let events = relay
            .fetch_events(Filter::new().kind(Kind::TextNote).limit(3))
            .timeout(Duration::from_secs(5))
            .policy(ReqExitPolicy::ExitOnEOSE)
            .await
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[tokio::test]
    async fn test_fetch_events_enforces_buffer_limit() {
        let (relay, _mock) = setup_event_fetching_relay(5).await;

        let err = relay
            .fetch_events(Filter::new().kind(Kind::TextNote))
            .max_events(3)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), crate::error::ErrorKind::LimitExceeded);
    }

    #[tokio::test]
    async fn test_fetch_events_wait_for_events() {
        let (relay, _mock) = setup_event_fetching_relay(5).await;

        let events = relay
            .fetch_events(Filter::new().kind(Kind::TextNote))
            .timeout(Duration::from_secs(15))
            .policy(ReqExitPolicy::WaitForEvents(2))
            .await
            .unwrap();
        assert_eq!(events.len(), 2); // Requested all text notes but exit after receive 2

        // Task to send additional event
        let r = relay.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Signer
            let keys = Keys::generate();

            // Build and send event
            let event = Metadata::new().name("Test").finalize(&keys).unwrap();
            r.send_event(&event).await.unwrap();
        });

        let events = relay
            .fetch_events(Filter::new().kind(Kind::Metadata))
            .timeout(Duration::from_secs(5))
            .policy(ReqExitPolicy::WaitForEvents(1))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_events_wait_for_events_after_eose() {
        let (relay, _mock) = setup_event_fetching_relay(10).await;

        // Task to send additional events
        let r = relay.clone();
        tokio::spawn(async move {
            // Signer
            let keys = Keys::generate();

            // Send more events
            for _ in 0..2 {
                // Sleep
                tokio::time::sleep(Duration::from_secs(2)).await;

                // Build and send event
                let event = EventBuilder::new(Kind::TextNote, "Additional")
                    .finalize(&keys)
                    .unwrap();
                r.send_event(&event).await.unwrap();
            }
        });

        let events = relay
            .fetch_events(Filter::new().kind(Kind::TextNote).limit(3))
            .timeout(Duration::from_secs(15))
            .policy(ReqExitPolicy::WaitForEventsAfterEOSE(2))
            .await
            .unwrap();
        assert_eq!(events.len(), 5); // 3 events received until EOSE + 2 new events
    }

    #[tokio::test]
    async fn test_fetch_events_wait_for_duration_after_eose() {
        let (relay, _mock) = setup_event_fetching_relay(5).await;

        // Task to send additional events
        let r = relay.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Signer
            let keys = Keys::generate();

            // Send more events
            for _ in 0..2 {
                // Build and send event
                let event = EventBuilder::new(Kind::TextNote, "Additional")
                    .finalize(&keys)
                    .unwrap();
                r.send_event(&event).await.unwrap();

                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let events = relay
            .fetch_events(Filter::new().kind(Kind::TextNote))
            .timeout(Duration::from_secs(15))
            .policy(ReqExitPolicy::WaitDurationAfterEOSE(Duration::from_secs(3)))
            .await
            .unwrap();
        assert_eq!(events.len(), 6); // 5 events received until EOSE + 1 new events
    }
}
