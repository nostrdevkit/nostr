use std::collections::BTreeSet;
use std::future::IntoFuture;
use std::time::Duration;

use futures::StreamExt;
use nostr::event::Event;

use super::req_target::ReqTarget;
use super::stream_events::StreamEvents;
use crate::client::{Client, Error};
use crate::future::BoxedFuture;
use crate::relay::{DEFAULT_FETCH_EVENTS_LIMIT, ReqExitPolicy};

/// Fetch events
#[must_use = "Does nothing unless you await!"]
pub struct FetchEvents<'client, 'url> {
    // --------------------------------------------------
    // WHEN ADDING NEW OPTIONS HERE,
    // REMEMBER TO UPDATE THE "Configuration" SECTION in
    // Client::fetch_events DOC.
    // --------------------------------------------------
    client: &'client Client,
    target: ReqTarget<'url>,
    timeout: Option<Duration>,
    policy: ReqExitPolicy,
    max_events: usize,
}

impl<'client, 'url> FetchEvents<'client, 'url> {
    pub(crate) fn new(client: &'client Client, target: ReqTarget<'url>) -> Self {
        Self {
            client,
            target,
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

impl<'client, 'url> IntoFuture for FetchEvents<'client, 'url>
where
    'url: 'client,
{
    type Output = Result<BTreeSet<Event>, Error>;
    type IntoFuture = BoxedFuture<'client, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Stream events
            let mut stream: StreamEvents<'client, 'url> =
                self.client.stream_events(self.target).policy(self.policy);

            // Set timeout
            if let Some(timeout) = self.timeout {
                stream = stream.timeout(timeout);
            }

            // Execute stream
            let mut stream = stream.await?;

            // Lookup ID: EVENT_ORD_IMPL
            let mut events: BTreeSet<Event> = BTreeSet::new();

            // Collect events
            while let Some((url, result)) = stream.next().await {
                // NOTE: not propagate the error here! A single error by any of the relays would stop the entire fetching process.
                match result {
                    Ok(event) => {
                        if events.len() >= self.max_events && !events.contains(&event) {
                            // TODO: break the stream instead of returnin an error?
                            return Err(Error::limit_exceeded("too many fetched events"));
                        }

                        events.insert(event);
                    }
                    Err(e) => {
                        tracing::error!(url = %url, error = %e, "Failed to handle streamed event");
                    }
                }
            }

            Ok(events)
        })
    }
}

#[allow(deprecated)]
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::filter::Filter;
    use nostr::key::Keys;

    use crate::authenticator::SignerAuthenticator;
    use crate::error::ErrorKind;
    use crate::local_relay::LocalRelay;
    use crate::test_utils::{
        setup_client, setup_client_with_authenticator, setup_nip42_read_local_relay,
    };

    #[tokio::test]
    async fn test_client_fetch_events_dont_resubscribes_after_auth_required_closed_without_authenticator()
     {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote)
            .content("Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let client = setup_client(local.url().await).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let events = client
            .fetch_events(filter)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(events.len(), 0);
    }

    #[tokio::test]
    async fn test_client_fetch_events_resubscribes_after_auth_required_closed() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote)
            .content("Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let authenticator = SignerAuthenticator::new(keys);
        let client = setup_client_with_authenticator(local.url().await, authenticator).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let events = client
            .fetch_events(filter)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events.first().map(|event| event.id), Some(expected.id));
    }

    #[tokio::test]
    async fn test_client_fetch_events_enforces_buffer_limit() {
        let local = LocalRelay::new();
        local.run().await.unwrap();
        let keys = Keys::generate();

        for i in 0..5 {
            let event = EventBuilder::new(Kind::TextNote)
                .content(i.to_string())
                .finalize(&keys)
                .unwrap();
            local.add_event(event).await.unwrap();
        }

        let client = setup_client(local.url().await).await;
        let err = client
            .fetch_events(Filter::new().kind(Kind::TextNote))
            .max_events(3)
            .timeout(Duration::from_secs(5))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::LimitExceeded);
    }
}
