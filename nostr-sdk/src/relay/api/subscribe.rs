use std::borrow::Cow;
use std::future::IntoFuture;

use nostr::filter::Filter;
use nostr::message::{ClientMessage, SubscriptionId};
use tokio::sync::{mpsc, oneshot};

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::{Relay, SubscribeAutoCloseOptions, SubscriptionActivity};

/// Subscribe to events
#[must_use = "Does nothing unless you await!"]
pub struct Subscribe<'relay> {
    relay: &'relay Relay,
    filters: Vec<Filter>,
    id: Option<SubscriptionId>,
    auto_close: Option<SubscribeAutoCloseOptions>,
}

impl<'relay> Subscribe<'relay> {
    #[inline]
    pub(crate) fn new(relay: &'relay Relay, filters: Vec<Filter>) -> Self {
        Self {
            relay,
            filters,
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

pub(super) async fn subscribe_auto_closing(
    relay: &Relay,
    id: SubscriptionId,
    filters: Vec<Filter>,
    opts: SubscribeAutoCloseOptions,
    activity: Option<mpsc::Sender<SubscriptionActivity>>,
    cancel: Option<oneshot::Receiver<()>>,
) -> Result<(), Error> {
    // Check if filters are empty
    if filters.is_empty() {
        return Err(Error::invalid_msg("filters cannot be empty"));
    }

    // Compose REQ message
    let msg: ClientMessage = ClientMessage::Req {
        subscription_id: Cow::Borrowed(&id),
        filters: filters.iter().map(Cow::Borrowed).collect(),
    };

    // Subscribe to notifications
    let notifications = relay.inner.internal_notification_sender.subscribe();

    // Register the auto-closing subscription
    relay
        .inner
        .add_auto_closing_subscription(id.clone(), filters.clone())
        .await?;

    // Send REQ message
    if let Err(e) = relay.send_msg(msg).await {
        // Remove previously added subscription
        relay.inner.remove_subscription(&id).await;

        // Propagate error
        return Err(e);
    }

    // Spawn auto-closing handler
    relay
        .inner
        .spawn_auto_closing_handler(id, filters, opts, notifications, activity, cancel);

    // Return
    Ok(())
}

async fn subscribe_long_lived(
    relay: &Relay,
    id: SubscriptionId,
    filters: Vec<Filter>,
) -> Result<(), Error> {
    // Check if filters are empty
    if filters.is_empty() {
        return Err(Error::invalid_msg("filters cannot be empty"));
    }

    // No auto-close subscription: add subscription filter before sending the
    // REQ, so an immediate CLOSED can still mark the subscription for retry.
    relay
        .inner
        .add_long_lived_subscription(id.clone(), filters.clone())
        .await?;

    // Compose REQ message
    let msg: ClientMessage = ClientMessage::Req {
        subscription_id: Cow::Borrowed(&id),
        filters: filters.iter().map(Cow::Borrowed).collect(),
    };

    // Send REQ message
    if let Err(e) = relay.send_msg(msg).await {
        // Remove previously added subscription
        relay.inner.remove_subscription(&id).await;

        // Propagate error
        return Err(e);
    }

    // Return
    Ok(())
}

impl<'relay> IntoFuture for Subscribe<'relay> {
    type Output = Result<SubscriptionId, Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Get or generate subscription ID
            let id: SubscriptionId = self.id.unwrap_or_else(SubscriptionId::generate);

            // Check if the auto-close condition is set
            match self.auto_close {
                Some(opts) => {
                    subscribe_auto_closing(self.relay, id.clone(), self.filters, opts, None, None)
                        .await?
                }
                None => subscribe_long_lived(self.relay, id.clone(), self.filters).await?,
            }

            // Return subscription ID
            Ok(id)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_utility::time;
    use futures::StreamExt;
    use nostr::event::{Event, EventBuilder, EventId, FinalizeEvent, Kind};
    use nostr::filter::Filter;
    use nostr::key::Keys;
    use nostr::message::SubscriptionId;

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::error::ErrorKind;
    use crate::local_relay::*;
    use crate::relay::{RelayNotification, RelayOptions, RelayStatus, ReqExitPolicy};
    use crate::test_utils::{
        setup_nip42_read_local_relay, setup_relay, setup_relay_with_authenticator,
    };

    #[tokio::test]
    async fn test_subscribe_ban_relay() {
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

        let filter = Filter::new().kind(Kind::Metadata).limit(3);
        relay.subscribe(filter).await.unwrap();

        // Keep up the test
        time::sleep(Duration::from_secs(5)).await;

        assert_eq!(relay.status(), RelayStatus::Banned);

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_subscribe_ephemeral_event() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        // Sender
        let relay1: Relay = Relay::new(url.clone());
        relay1.connect();
        relay1
            .try_connect()
            .timeout(Duration::from_millis(500))
            .await
            .unwrap();

        // Fetcher
        let relay2 = Relay::new(url.clone());
        relay2
            .try_connect()
            .timeout(Duration::from_millis(500))
            .await
            .unwrap();

        // Signer
        let keys = Keys::generate();

        // Event
        let kind = Kind::Custom(22_222); // Ephemeral kind
        let event: Event = EventBuilder::new(kind, "").finalize(&keys).unwrap();

        let event_id: EventId = event.id;

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            relay1.send_event(&event).await.unwrap();
        });

        // Subscribe
        let filter = Filter::new().kind(kind);
        let sub_id = relay2.subscribe(filter).await.unwrap();

        // Listen for notifications
        let fut = async {
            let mut notifications = relay2.notifications();

            let mut received: bool = false;

            while let Some(notification) = notifications.next().await {
                if let RelayNotification::Event {
                    subscription_id,
                    event,
                } = notification
                {
                    if subscription_id == sub_id {
                        if event.id == event_id {
                            received = true;
                            break;
                        } else {
                            panic!("Unexpected event");
                        }
                    } else {
                        panic!("Unexpected subscription ID");
                    }
                }
            }

            if !received {
                panic!("No event received");
            }
        };

        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_subscribe_rejects_existing_id_without_overwriting_filters() {
        let mock = MockRelay::run().await.unwrap();
        let relay = Relay::new(mock.url().await);
        relay
            .try_connect()
            .timeout(Duration::from_millis(500))
            .await
            .unwrap();

        let id = SubscriptionId::new("duplicate-subscription");
        let first_filter = Filter::new().kind(Kind::TextNote);
        let second_filter = Filter::new().kind(Kind::Reaction);

        relay
            .subscribe(first_filter.clone())
            .with_id(id.clone())
            .await
            .unwrap();

        let err = relay
            .subscribe(second_filter)
            .with_id(id.clone())
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "subscription ID already exists");
        assert_eq!(
            relay.subscription(&id).await.unwrap().filters(),
            [first_filter]
        );
    }

    #[tokio::test]
    async fn test_subscribe_auto_closing_rejects_existing_id_without_overwriting_filters() {
        let mock = MockRelay::run().await.unwrap();
        let relay = Relay::new(mock.url().await);
        relay
            .try_connect()
            .timeout(Duration::from_millis(500))
            .await
            .unwrap();

        let id = SubscriptionId::new("duplicate-auto-closing-subscription");
        let first_filter = Filter::new().kind(Kind::TextNote);
        let second_filter = Filter::new().kind(Kind::Reaction);
        let close_opts = SubscribeAutoCloseOptions::default()
            .exit_policy(ReqExitPolicy::WaitDurationAfterEOSE(Duration::from_secs(5)));

        relay
            .subscribe(first_filter.clone())
            .with_id(id.clone())
            .close_on(close_opts)
            .await
            .unwrap();

        let err = relay
            .subscribe(second_filter)
            .with_id(id.clone())
            .close_on(close_opts)
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(err.to_string(), "subscription ID already exists");
        assert_eq!(
            relay.subscription(&id).await.unwrap().filters(),
            [first_filter]
        );
    }

    #[tokio::test]
    async fn test_subscribe_auto_closing_is_removed_after_timeout() {
        let mock = MockRelay::run().await.unwrap();
        let relay = Relay::new(mock.url().await);
        relay
            .try_connect()
            .timeout(Duration::from_millis(500))
            .await
            .unwrap();

        // No stored event matches, so only the timeout can end the subscription.
        let id = SubscriptionId::new("auto-closing-timeout");
        let close_opts = SubscribeAutoCloseOptions::default()
            .exit_policy(ReqExitPolicy::WaitForEvents(1))
            .timeout(Some(Duration::from_millis(100)));

        relay
            .subscribe(Filter::new().kind(Kind::TextNote))
            .with_id(id.clone())
            .close_on(close_opts)
            .await
            .unwrap();

        time::timeout(Some(Duration::from_secs(2)), async {
            while relay.subscription(&id).await.is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_subscribe_dont_resubscribes_after_auth_required_closed_without_authenticator() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let relay = setup_relay(local.url().await).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let id = SubscriptionId::new("auth-required-subscribe");

        relay.subscribe(filter).with_id(id.clone()).await.unwrap();

        // sleep a bit
        time::sleep(Duration::from_secs(2)).await;

        // The subscription mustn't exist as we haven't an authenticator
        assert!(!relay.inner.has_subscription(&id).await);
    }

    #[tokio::test]
    async fn test_subscribe_resubscribes_after_auth_required_closed() {
        let local = setup_nip42_read_local_relay().await;

        let keys = Keys::generate();
        let expected = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        local.add_event(expected.clone()).await.unwrap();

        let authenticator = SignerAuthenticator::new(keys);
        let relay = setup_relay_with_authenticator(local.url().await, authenticator).await;

        let filter = Filter::new().kind(Kind::TextNote).limit(1);

        let id = SubscriptionId::new("auth-required-subscribe");

        let mut notifications = relay.notifications();

        relay.subscribe(filter).with_id(id.clone()).await.unwrap();

        // sleep a bit
        time::sleep(Duration::from_secs(2)).await;

        // The subscription must exist as we have an authenticator
        assert!(relay.inner.has_subscription(&id).await);

        let received = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(notification) = notifications.next().await {
                if let RelayNotification::Event {
                    subscription_id,
                    event,
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
        assert!(!relay.inner.should_resubscribe(&id).await);
    }
}
