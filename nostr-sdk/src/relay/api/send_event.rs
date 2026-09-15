use std::borrow::Cow;
use std::future::IntoFuture;
use std::ops::Deref;
use std::time::Duration;

use async_utility::time;
use nostr::event::{Event, EventId};
use nostr::message::{ClientMessage, MachineReadablePrefix};
use tokio::sync::broadcast;

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::{Relay, RelayNotification};

/// Output returned when sending an event to a single relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySendEventOutput {
    event_id: EventId,
    status: EventSendStatus,
}

impl RelaySendEventOutput {
    #[inline]
    fn new(event_id: EventId, status: EventSendStatus) -> Self {
        Self { event_id, status }
    }

    /// Get the event ID.
    #[inline]
    #[must_use]
    pub fn id(&self) -> &EventId {
        &self.event_id
    }

    /// Get the per-relay send status.
    #[inline]
    #[must_use]
    pub fn status(&self) -> &EventSendStatus {
        &self.status
    }

    /// Split into event ID and per-relay send status.
    #[inline]
    #[must_use]
    pub fn into_parts(self) -> (EventId, EventSendStatus) {
        (self.event_id, self.status)
    }
}

impl Deref for RelaySendEventOutput {
    type Target = EventId;

    fn deref(&self) -> &Self::Target {
        &self.event_id
    }
}

/// Per-relay success status for an event send operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventSendStatus {
    /// The event was sent without waiting for a relay `OK` acknowledgement.
    Sent,
    /// The relay returned an `OK true` acknowledgement.
    Ack(EventSendAcknowledgement),
}

/// Relay acknowledgement for a successful event send.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventSendAcknowledgement {
    message: Option<String>,
}

impl EventSendAcknowledgement {
    #[inline]
    fn new(message: String) -> Self {
        Self {
            message: if message.is_empty() {
                None
            } else {
                Some(message)
            },
        }
    }

    /// Return the relay `OK true` message, if available.
    #[inline]
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl EventSendStatus {
    #[inline]
    fn ack(message: String) -> Self {
        Self::Ack(EventSendAcknowledgement::new(message))
    }

    /// Return `true` if the relay returned an `OK true` acknowledgement.
    #[inline]
    #[must_use]
    pub fn is_ack(&self) -> bool {
        matches!(self, Self::Ack(..))
    }

    /// Return the relay `OK true` message, if available.
    #[inline]
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Ack(ack) => ack.message(),
            Self::Sent => None,
        }
    }
}

/// Send event to relay
#[must_use = "Does nothing unless you await!"]
pub struct SendEvent<'relay, 'event> {
    relay: &'relay Relay,
    event: &'event Event,
    wait_for_ok: bool,
    wait_for_ok_timeout: Duration,
    wait_for_authentication_timeout: Duration,
}

impl<'relay, 'event> SendEvent<'relay, 'event> {
    pub(crate) fn new(relay: &'relay Relay, event: &'event Event) -> Self {
        Self {
            relay,
            event,
            wait_for_ok: true,
            wait_for_ok_timeout: Duration::from_secs(10),
            wait_for_authentication_timeout: Duration::from_secs(10),
        }
    }

    /// Wait for OK confirmation by the relay (default: true)
    #[inline]
    pub fn wait_for_ok(mut self, enable: bool) -> Self {
        self.wait_for_ok = enable;
        self
    }

    /// Timeout for waiting for the `OK` message from relay (default: 10 sec)
    #[inline]
    pub fn ok_timeout(mut self, timeout: Duration) -> Self {
        self.wait_for_ok_timeout = timeout;
        self
    }

    /// Timeout for waiting that relay authenticates (default: 10 sec)
    #[inline]
    pub fn authentication_timeout(mut self, timeout: Duration) -> Self {
        self.wait_for_authentication_timeout = timeout;
        self
    }

    async fn send(
        &self,
        notifications: &mut broadcast::Receiver<RelayNotification>,
        event: &Event,
    ) -> Result<(bool, String), Error> {
        // Send the EVENT message
        self.relay
            .send_msg(ClientMessage::Event(Cow::Borrowed(event)))
            .await?;

        // Check if we can skip the OK confirmation
        if !self.wait_for_ok {
            return Ok((true, String::new()));
        }

        // Wait for OK
        self.relay
            .inner
            .wait_for_ok(notifications, &event.id, self.wait_for_ok_timeout)
            .await
    }
}

async fn wait_for_authentication(
    notifications: &mut broadcast::Receiver<RelayNotification>,
    timeout: Duration,
) -> Result<(), Error> {
    time::timeout(Some(timeout), async {
        while let Ok(notification) = notifications.recv().await {
            match notification {
                RelayNotification::Authenticated => {
                    return Ok(());
                }
                RelayNotification::AuthenticationFailed => {
                    return Err(Error::authentication_msg("authentication failed"));
                }
                RelayNotification::RelayStatus { status } if status.is_disconnected() => {
                    return Err(Error::not_connected());
                }
                _ => (),
            }
        }

        Err(Error::state_msg("premature exit"))
    })
    .await
    .ok_or_else(Error::timeout)?
}

impl<'relay, 'event> IntoFuture for SendEvent<'relay, 'event>
where
    'event: 'relay,
{
    type Output = Result<RelaySendEventOutput, Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Health, write permission and number of messages checks are executed in `batch_msg` method.

            // Subscribe to notifications
            let mut notifications = self.relay.inner.internal_notification_sender.subscribe();

            // Send event
            let (status, message) = self.send(&mut notifications, self.event).await?;

            // Check status
            if status {
                let status: EventSendStatus = if self.wait_for_ok {
                    EventSendStatus::ack(message)
                } else {
                    EventSendStatus::Sent
                };

                return Ok(RelaySendEventOutput::new(self.event.id, status));
            }

            // If auth required, wait for authentication and resend it
            if let Some(MachineReadablePrefix::AuthRequired) =
                MachineReadablePrefix::parse(&message)
            {
                // Check if NIP42 authenticator is available
                if self.relay.inner.state.is_authenticator_available() {
                    // Wait that relay authenticate
                    wait_for_authentication(
                        &mut notifications,
                        self.wait_for_authentication_timeout,
                    )
                    .await?;

                    // Try to resend event
                    let (status, message) = self.send(&mut notifications, self.event).await?;

                    // Check status
                    return if status {
                        Ok(RelaySendEventOutput::new(
                            self.event.id,
                            EventSendStatus::ack(message),
                        ))
                    } else {
                        Err(Error::relay_msg(message))
                    };
                }
            }

            Err(Error::relay_msg(message))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nostr::prelude::*;

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::local_relay::*;

    #[tokio::test]
    async fn test_ok_msg() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = Relay::new(url);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        // Make an event
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();

        // Send the event
        let output = relay.send_event(&event).await.unwrap();
        assert_eq!(output.id(), &event.id);
        assert!(output.status().is_ack());
        assert_eq!(output.status().message(), None);

        // Resend the same event
        let output = relay.send_event(&event).await.unwrap();
        assert_eq!(output.id(), &event.id);
        assert!(output.status().is_ack());
        assert_eq!(
            output.status().message(),
            Some("duplicate: already have this event")
        );
    }

    #[tokio::test]
    async fn test_without_ok_msg() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = Relay::new(url);

        relay
            .try_connect()
            .timeout(Duration::from_secs(3))
            .await
            .unwrap();

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();
        let output = relay.send_event(&event).wait_for_ok(false).await.unwrap();

        assert_eq!(output.id(), &event.id);
        assert_eq!(output.status(), &EventSendStatus::Sent);
        assert_eq!(output.status().message(), None);
    }

    #[tokio::test]
    async fn test_nip42_send_event_without_authenticator() {
        // Mock relay
        let opts = LocalRelayBuilderNip42 {
            mode: LocalRelayBuilderNip42Mode::Write,
            relay_url: None,
        };
        let mock = LocalRelay::builder().nip42(opts).build();
        mock.run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = Relay::new(url);

        relay.connect();

        // Signer and event
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();

        // Auth disabled, so must fails as is unauthenticated
        let err = relay.send_event(&event).await.unwrap_err();
        assert_eq!(
            MachineReadablePrefix::parse(&err.to_string()).unwrap(),
            MachineReadablePrefix::AuthRequired
        );
    }

    #[tokio::test]
    async fn test_nip42_send_event_with_authenticator() {
        // Mock relay
        let opts = LocalRelayBuilderNip42 {
            mode: LocalRelayBuilderNip42Mode::Write,
            relay_url: None,
        };
        let mock = LocalRelay::builder().nip42(opts).build();
        mock.run().await.unwrap();
        let url = mock.url().await;

        // Signer
        let keys = Keys::generate();

        let authenticator = SignerAuthenticator::new(keys.clone());
        let relay: Relay = Relay::builder(url).authenticator(authenticator).build();

        relay.connect();

        let event = EventBuilder::new(Kind::TextNote, "Test")
            .finalize(&keys)
            .unwrap();

        // Send as authenticated
        assert!(relay.send_event(&event).await.is_ok());
    }
}
