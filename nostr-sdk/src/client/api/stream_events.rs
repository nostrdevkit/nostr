use std::collections::HashMap;
use std::future::IntoFuture;
use std::pin::Pin;
use std::time::Duration;

use futures::{Stream, StreamExt};
use nostr::event::Event;
use nostr::filter::Filter;
use nostr::message::SubscriptionId;
use nostr::types::url::RelayUrl;

use super::req_target::ReqTarget;
use super::util::build_targets;
use crate::client::Client;
use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::{RelayStreamEvent, ReqExitPolicy};

type EventStream = Pin<Box<dyn Stream<Item = (RelayUrl, Result<Event, Error>)> + Send>>;
type OutcomeStream = Pin<Box<dyn Stream<Item = (RelayUrl, RelayStreamEvent)> + Send>>;

/// Stream events
#[must_use = "Does nothing unless you await!"]
pub struct StreamEvents<'client, 'url> {
    // --------------------------------------------------
    // WHEN ADDING NEW OPTIONS HERE,
    // REMEMBER TO UPDATE THE "Configuration" SECTION in
    // Client::stream_events DOC.
    // --------------------------------------------------
    client: &'client Client,
    target: ReqTarget<'url>,
    id: Option<SubscriptionId>,
    timeout: Option<Duration>,
    policy: ReqExitPolicy,
}

impl<'client, 'url> StreamEvents<'client, 'url> {
    pub(crate) fn new(client: &'client Client, target: ReqTarget<'url>) -> Self {
        Self {
            client,
            target,
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

    /// Stream events together with the terminal outcome of each selected relay.
    ///
    /// See [`relay::StreamEvents::with_outcomes`](crate::relay::StreamEvents::with_outcomes)
    /// for the outcomes of a single relay.
    /// A relay failure doesn't stop the other relays.
    ///
    /// Dropping the stream cancels the outstanding requests.
    pub async fn with_outcomes(self) -> Result<OutcomeStream, Error> {
        self.into_outcome_stream(true).await
    }

    async fn into_outcome_stream(
        self,
        report_terminal_errors: bool,
    ) -> Result<OutcomeStream, Error> {
        // Build targets
        let targets: HashMap<RelayUrl, Vec<Filter>> =
            build_targets(self.client, self.target).await?;

        // Make the stream
        let stream = self
            .client
            .pool()
            .stream_events(
                targets,
                self.id,
                self.timeout,
                self.policy,
                report_terminal_errors,
            )
            .await?;

        Ok(Box::pin(stream))
    }
}

impl<'client, 'url> IntoFuture for StreamEvents<'client, 'url>
where
    'url: 'client,
{
    type Output = Result<EventStream, Error>;
    type IntoFuture = BoxedFuture<'client, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let stream: OutcomeStream = self.into_outcome_stream(false).await?;

            Ok(Box::pin(stream.filter_map(|(url, item)| async move {
                match item {
                    RelayStreamEvent::Event(event) => Some((url, Ok(event))),
                    RelayStreamEvent::Error(error) => Some((url, Err(error))),
                    RelayStreamEvent::Completed | RelayStreamEvent::LimitReached => None,
                }
            })) as EventStream)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::SocketAddr;
    use std::time::Duration;

    use futures::StreamExt;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::filter::Filter;
    use nostr::key::Keys;
    use nostr::message::{MachineReadablePrefix, SubscriptionId};

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::local_relay::*;
    use crate::test_utils::{
        setup_client, setup_client_with_authenticator, setup_nip42_read_local_relay,
    };

    #[derive(Debug)]
    struct RejectQuery;

    impl QueryPolicy for RejectQuery {
        fn admit_query<'a>(
            &'a self,
            _query: &'a mut Filter,
            _addr: &'a SocketAddr,
        ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
            Box::pin(async {
                QueryPolicyResult::reject(MachineReadablePrefix::Blocked, "query rejected")
            })
        }
    }

    #[tokio::test]
    async fn with_outcomes_reports_each_relay_outcome() {
        let healthy = LocalRelay::builder().build();
        healthy.run().await.unwrap();
        let failing = LocalRelay::builder().query_policy(RejectQuery).build();
        failing.run().await.unwrap();

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "healthy event")
            .finalize(&keys)
            .unwrap();
        healthy.add_event(expected.clone()).await.unwrap();

        let healthy_url = healthy.url().await;
        let failing_url = failing.url().await;
        let client = Client::new();
        client.add_relay(&healthy_url).and_connect().await.unwrap();
        client.add_relay(&failing_url).and_connect().await.unwrap();

        let stream = client
            .stream_events(Filter::new().author(keys.public_key()))
            .timeout(Duration::from_secs(2))
            .with_outcomes()
            .await
            .unwrap();
        let outcomes: Vec<(RelayUrl, RelayStreamEvent)> =
            tokio::time::timeout(Duration::from_secs(3), stream.collect())
                .await
                .unwrap();

        // The healthy relay sends its event and completes, the failing one rejects the query.
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes.iter().any(|(url, outcome)| *url == healthy_url
            && matches!(outcome, RelayStreamEvent::Event(event) if event.id == expected.id)));
        assert!(
            outcomes.iter().any(|(url, outcome)| *url == healthy_url
                && matches!(outcome, RelayStreamEvent::Completed))
        );
        assert!(outcomes.iter().any(|(url, outcome)| *url == failing_url
            && matches!(outcome, RelayStreamEvent::Error(error) if error.to_string().contains("query rejected"))));

        let stream = client
            .stream_events(Filter::new().author(keys.public_key()))
            .policy(ReqExitPolicy::WaitForEvents(1))
            .timeout(Duration::from_secs(2))
            .with_outcomes()
            .await
            .unwrap();
        let outcomes: Vec<(RelayUrl, RelayStreamEvent)> =
            tokio::time::timeout(Duration::from_secs(3), stream.collect())
                .await
                .unwrap();

        assert!(outcomes.iter().any(|(url, outcome)| *url == healthy_url
            && matches!(outcome, RelayStreamEvent::LimitReached)));
    }

    #[tokio::test]
    async fn test_stream_terminates_on_drop() {
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let client = Client::default();

        client.add_relay(&url).and_connect().await.unwrap();

        let filter = Filter::new().kind(Kind::TextNote).limit(1);
        let id = SubscriptionId::generate();

        let stream = client
            .stream_events(filter)
            .with_id(id.clone())
            .policy(ReqExitPolicy::WaitForEvents(1))
            .await
            .unwrap();

        let relay = client.relay(&url).await.unwrap().unwrap();

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
    async fn test_client_stream_events_dont_resubscribes_after_auth_required_closed_without_authenticator()
     {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let client = setup_client(local.url().await).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let mut stream = client
            .stream_events(filter)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        let (_url, res) = stream
            .next()
            .await
            .expect("stream ended before error was received");
        let err = res.unwrap_err();

        assert_eq!(
            MachineReadablePrefix::parse(&err.to_string()).unwrap(),
            MachineReadablePrefix::AuthRequired
        );
    }

    #[tokio::test]
    async fn test_client_stream_events_resubscribes_after_auth_required_closed() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let authenticator = SignerAuthenticator::new(keys);
        let client = setup_client_with_authenticator(local.url().await, authenticator).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let mut stream = client
            .stream_events(filter)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        let (_url, event) = stream
            .next()
            .await
            .expect("stream ended before event was received");
        assert_eq!(event.unwrap().id, expected.id);
    }
}
