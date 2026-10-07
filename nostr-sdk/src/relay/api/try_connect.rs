use std::future::IntoFuture;
use std::time::Duration;

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::Relay;

/// Try to connect relay
#[must_use = "Does nothing unless you await!"]
pub struct TryConnect<'relay> {
    relay: &'relay Relay,
    timeout: Duration,
}

impl<'relay> TryConnect<'relay> {
    #[inline]
    pub(crate) fn new(relay: &'relay Relay) -> Self {
        Self {
            relay,
            timeout: Duration::from_secs(15),
        }
    }

    /// Timeout (default: 15 sec)
    #[inline]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl<'relay> IntoFuture for TryConnect<'relay> {
    type Output = Result<(), Error>;
    type IntoFuture = BoxedFuture<'relay, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.relay.inner.try_connect(self.timeout))
    }
}

#[cfg(test)]
mod tests {
    use async_utility::time;
    use nostr::types::RelayUrl;

    use super::*;
    use crate::error::ErrorKind;
    use crate::local_relay::*;
    use crate::relay::RelayStatus;

    #[tokio::test]
    async fn test_try_connect() {
        // Mock relay
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let relay: Relay = Relay::new(url);

        assert_eq!(relay.status(), RelayStatus::Initialized);

        relay
            .try_connect()
            .timeout(Duration::from_millis(500))
            .await
            .unwrap();

        assert_eq!(relay.status(), RelayStatus::Connected);

        time::sleep(Duration::from_millis(500)).await;

        assert!(relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_try_connect_to_unreachable_relay() {
        let url = RelayUrl::parse("wss://127.0.0.1:666").unwrap();

        let relay: Relay = Relay::new(url);

        assert_eq!(relay.status(), RelayStatus::Initialized);

        let res = relay.try_connect().timeout(Duration::from_secs(2)).await;
        assert_eq!(res.unwrap_err().kind(), ErrorKind::Transport);

        assert_eq!(relay.status(), RelayStatus::Idle);

        // Connection failed; the persistent task waits for another request.
        assert!(relay.inner.is_running());
    }
}
