use nostr::event::Event;
use nostr::message::{RelayMessage, SubscriptionId};
use nostr::types::RelayUrl;

/// Nostr client notification
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClientNotification {
    /// Received a new [`Event`] from a relay.
    ///
    /// This notification is sent only the **first time** the [`Event`] is seen.
    /// Events sent by this client are not included.
    /// This is useful when you only need to process new incoming events
    /// and avoid handling the same events multiple times.
    ///
    /// If you require notifications for all messages, including previously sent or received events,
    /// consider using the [`ClientNotification::Message`] variant instead.
    Event {
        /// The URL of the relay from which the event was received.
        relay_url: RelayUrl,
        /// Subscription ID
        subscription_id: SubscriptionId,
        /// The received event.
        event: Box<Event>,
    },
    /// Received a [`RelayMessage`].
    ///
    /// This notification is sent **every time** a [`RelayMessage`] is received,
    /// regardless of whether it has been received before.
    ///
    /// May includes messages wrapping events that were sent by this client.
    Message {
        /// The URL of the relay from which the message was received.
        relay_url: RelayUrl,
        /// The received relay message.
        message: Box<RelayMessage<'static>>,
    },
    /// Shutdown
    ///
    /// This notification variant is sent after [`Client::shutdown`](super::Client::shutdown) method is called and all connections have been closed.
    Shutdown,
}

impl ClientNotification {
    #[inline]
    pub(super) fn is_shutdown(&self) -> bool {
        matches!(self, Self::Shutdown)
    }
}
