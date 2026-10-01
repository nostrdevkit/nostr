use std::borrow::Cow;
use std::future::IntoFuture;
use std::time::Duration;

use async_utility::time;
use nostr::filter::Filter;
use nostr::message::{ClientMessage, RelayMessage, SubscriptionId};
use tokio::sync::broadcast;

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::{Relay, RelayNotification};

/// Count events.
///
/// A successful zero is returned only for a matching COUNT response.
/// Timeout, notification loss, closure, or relay rejection return an error.
#[must_use = "Does nothing unless you await!"]
pub struct CountEvents<'relay> {
    relay: &'relay Relay,
    filter: Filter,
    timeout: Option<Duration>,
}

impl<'relay> CountEvents<'relay> {
    pub(crate) fn new(relay: &'relay Relay, filter: Filter) -> Self {
        Self {
            relay,
            filter,
            timeout: None,
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
}

impl<'relay> IntoFuture for CountEvents<'relay> {
    type Output = Result<usize, Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let id: SubscriptionId = SubscriptionId::generate();

            let mut notifications = self.relay.inner.internal_notification_sender.subscribe();

            let msg = ClientMessage::Count {
                subscription_id: Cow::Borrowed(&id),
                filter: Cow::Owned(self.filter),
            };
            self.relay.send_msg(msg).await?;

            let fut = time::timeout(self.timeout, receive_count_reply(&mut notifications, &id));
            let result: Result<usize, Error> = fut.await.unwrap_or_else(|| Err(Error::timeout()));

            // Unsubscribe
            let close_result: Result<(), Error> =
                self.relay.send_msg(ClientMessage::close(id)).await;

            match result {
                Ok(count) => {
                    close_result?;
                    Ok(count)
                }
                Err(error) => Err(error),
            }
        })
    }
}

async fn receive_count_reply(
    notifications: &mut broadcast::Receiver<RelayNotification>,
    id: &SubscriptionId,
) -> Result<usize, Error> {
    loop {
        match notifications.recv().await.map_err(Error::from)? {
            RelayNotification::Message { message } => match *message {
                RelayMessage::Count {
                    subscription_id,
                    count,
                } if subscription_id.as_ref() == id => return Ok(count),
                RelayMessage::Closed {
                    subscription_id,
                    message,
                } if subscription_id.as_ref() == id => {
                    return Err(Error::relay_msg(message.into_owned()));
                }
                _ => {}
            },
            RelayNotification::RelayStatus { status } if status.is_disconnected() => {
                return Err(Error::not_connected());
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::pin::Pin;

    use nostr::message::MachineReadablePrefix;

    use super::*;
    use crate::error::ErrorKind;
    use crate::local_relay::*;
    use crate::relay::RelayStatus;
    use crate::test_utils::setup_relay;

    #[derive(Debug)]
    struct RejectCount;

    impl QueryPolicy for RejectCount {
        fn admit_query<'a>(
            &'a self,
            _query: &'a mut Filter,
            _addr: &'a SocketAddr,
        ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
            Box::pin(async {
                QueryPolicyResult::reject(MachineReadablePrefix::Blocked, "count rejected")
            })
        }
    }

    #[derive(Debug)]
    struct SilentCount;

    impl QueryPolicy for SilentCount {
        fn admit_query<'a>(
            &'a self,
            _query: &'a mut Filter,
            _addr: &'a SocketAddr,
        ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn count_requires_a_matching_response() {
        let (tx, mut notifications) = broadcast::channel(4);
        let id = SubscriptionId::new("expected-count");
        let other_id = SubscriptionId::new("other-count");

        tx.send(RelayNotification::Authenticated).unwrap();

        tx.send(RelayNotification::Message {
            message: Box::new(RelayMessage::Count {
                subscription_id: Cow::Owned(other_id),
                count: 99,
            }),
        })
        .unwrap();
        tx.send(RelayNotification::Message {
            message: Box::new(RelayMessage::Count {
                subscription_id: Cow::Owned(id.clone()),
                count: 0,
            }),
        })
        .unwrap();

        assert_eq!(
            receive_count_reply(&mut notifications, &id).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn count_receive_loss_and_closure_are_errors() {
        let id = SubscriptionId::new("missing-count");
        let (tx, mut notifications) = broadcast::channel(2);
        for _ in 0..8 {
            tx.send(RelayNotification::Authenticated).unwrap();
        }
        let error = receive_count_reply(&mut notifications, &id)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Other);
        assert!(error.to_string().contains("lagged"));

        let (tx, mut notifications) = broadcast::channel(2);
        drop(tx);
        let error = receive_count_reply(&mut notifications, &id)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Other);
        assert!(error.to_string().contains("closed"));
    }

    #[tokio::test]
    async fn count_disconnect_is_reported_before_timeout() {
        let id = SubscriptionId::new("interrupted-count");
        let (tx, mut notifications) = broadcast::channel(2);
        tx.send(RelayNotification::RelayStatus {
            status: RelayStatus::Disconnected,
        })
        .unwrap();

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            receive_count_reply(&mut notifications, &id),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::State);
        assert!(error.to_string().contains("not connected"));
    }

    #[tokio::test]
    async fn count_with_no_matches_returns_zero() {
        let local = LocalRelay::builder().build();
        local.run().await.unwrap();

        let url = local.url().await;
        let relay = setup_relay(url).await;

        assert_eq!(
            relay
                .count_events(Filter::new())
                .timeout(Duration::from_secs(2))
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn count_without_count_reply_reports_rejection() {
        let local = LocalRelay::builder().query_policy(RejectCount).build();
        local.run().await.unwrap();

        let url = local.url().await;
        let relay = setup_relay(url).await;

        let error = relay
            .count_events(Filter::new())
            .timeout(Duration::from_secs(2))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Rejected);
        assert!(error.to_string().contains("count rejected"));
    }

    #[tokio::test]
    async fn count_without_a_reply_times_out() {
        let local = LocalRelay::builder().query_policy(SilentCount).build();
        local.run().await.unwrap();

        let url = local.url().await;
        let relay = setup_relay(url).await;

        let error = relay
            .count_events(Filter::new())
            .timeout(Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Timeout);
        assert_eq!(relay.status(), RelayStatus::Connected);
        relay.shutdown();
        local.shutdown();
    }
}
