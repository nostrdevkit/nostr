use std::collections::HashMap;
use std::future::IntoFuture;

use nostr::filter::Filter;
use nostr::message::SubscriptionId;
use nostr::types::RelayUrl;

use super::output::Output;
use super::req_target::ReqTarget;
use super::util::build_targets;
use crate::client::{Client, Error};
use crate::future::BoxedFuture;
use crate::relay::SubscribeAutoCloseOptions;

/// Subscribe to events
#[must_use = "Does nothing unless you await!"]
pub struct Subscribe<'client, 'url> {
    client: &'client Client,
    target: ReqTarget<'url>,
    id: Option<SubscriptionId>,
    auto_close: Option<SubscribeAutoCloseOptions>,
}

impl<'client, 'url> Subscribe<'client, 'url> {
    #[inline]
    pub(crate) fn new(client: &'client Client, target: ReqTarget<'url>) -> Self {
        Self {
            client,
            target,
            id: None,
            auto_close: None,
        }
    }

    /// Set a specific subscription ID
    #[inline]
    pub fn with_id(mut self, id: SubscriptionId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set auto-close conditions
    #[inline]
    pub fn close_on(mut self, opts: SubscribeAutoCloseOptions) -> Self {
        self.auto_close = Some(opts);
        self
    }
}

impl<'client, 'url> IntoFuture for Subscribe<'client, 'url>
where
    'url: 'client,
{
    type Output = Result<Output<SubscriptionId>, Error>;
    type IntoFuture = BoxedFuture<'client, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Build targets
            let targets: HashMap<RelayUrl, Vec<Filter>> =
                build_targets(self.client, self.target).await?;

            self.client
                .pool()
                .subscribe(targets, self.id, self.auto_close)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;
    use std::{future, slice};

    use futures::StreamExt;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::filter::Filter;
    use nostr::key::Keys;
    use nostr::message::{RelayMessage, SubscriptionId};
    use nostr::types::RelayUrl;

    use crate::authenticator::SignerAuthenticator;
    use crate::client::ClientNotification;
    use crate::local_relay::MockRelay;
    use crate::relay::SubscriptionData;
    use crate::test_utils::{
        setup_client, setup_client_with_authenticator, setup_nip42_read_local_relay,
    };

    #[tokio::test]
    async fn test_client_subscription_returns_data_registered_on_each_relay() {
        let mock = MockRelay::run().await.unwrap();
        let url: RelayUrl = mock.url().await;
        let client = setup_client(url.clone()).await;
        let filter: Filter = Filter::new().kind(Kind::TextNote);
        let id: SubscriptionId = SubscriptionId::new("client-subscription-data");

        let notifications = client.notifications();

        client
            .subscribe(filter.clone())
            .with_id(id.clone())
            .await
            .unwrap();

        let eose = notifications.any(|notification| {
            future::ready(matches!(notification, ClientNotification::Message { ref message, .. }
                if matches!(message.as_ref(), RelayMessage::EndOfStoredEvents { subscription_id: received, .. } if received.as_ref() == &id)))
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(5), eose)
                .await
                .unwrap()
        );

        let subscription: HashMap<RelayUrl, SubscriptionData> = client.subscription(&id).await;
        let data: &SubscriptionData = subscription.get(&url).unwrap();
        assert_eq!(data.filters(), slice::from_ref(&filter));
        assert!(data.received_eose());
        assert!(!data.is_closed());

        let subscriptions = client.subscriptions().await;
        assert_eq!(subscriptions[&id][&url].filters(), [filter]);
    }

    #[tokio::test]
    async fn test_client_subscribe_dont_resubscribes_after_auth_required_closed_without_authenticator()
     {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(event).await.unwrap();

        let client = setup_client(local.url().await).await;
        let id = SubscriptionId::new("client-auth-required-subscribe");

        let output = client
            .subscribe(Filter::new().kind(Kind::TextNote).limit(1))
            .with_id(id.clone())
            .await
            .unwrap();
        assert!(output.failed.is_empty());

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(!client.subscriptions().await.contains_key(&id));
    }

    #[tokio::test]
    async fn test_client_subscribe_resubscribes_after_auth_required_closed() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let authenticator = SignerAuthenticator::new(keys);
        let client = setup_client_with_authenticator(local.url().await, authenticator).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let id = SubscriptionId::new("client-auth-required-subscribe");

        let mut notifications = client.notifications();

        let output = client.subscribe(filter).with_id(id.clone()).await.unwrap();
        assert!(output.failed.is_empty());

        let received = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(notification) = notifications.next().await {
                if let ClientNotification::Event {
                    subscription_id,
                    event,
                    ..
                } = notification
                {
                    if subscription_id == id {
                        return event;
                    }
                }
            }

            panic!("notifications ended before event was received");
        })
        .await
        .unwrap();

        assert_eq!(received.id, expected.id);
    }
}
