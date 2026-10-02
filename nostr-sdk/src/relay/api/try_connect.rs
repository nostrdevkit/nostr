use std::future::IntoFuture;
use std::time::Duration;

use crate::error::Error;
use crate::future::BoxedFuture;
use crate::policy::AdmitStatus;
use crate::relay::{Relay, RelayStatus};
use crate::transport::websocket::{WebSocketSink, WebSocketStream};

/// Try to connect relay
#[must_use = "Does nothing unless you await!"]
pub struct TryConnect<'relay> {
    relay: &'relay Relay,
    timeout: Duration,
}

struct ReservedConnection<'relay> {
    relay: &'relay Relay,
    transferred: bool,
}

impl Drop for ReservedConnection<'_> {
    fn drop(&mut self) {
        if !self.transferred {
            self.relay.inner.finish_reserved_connection_task();
        }
    }
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
        Box::pin(async move {
            let status: RelayStatus = self.relay.status();

            if status.is_shutdown() {
                return Err(Error::shutdown());
            }

            if status.is_banned() {
                return Err(Error::banned());
            }

            // Check if relay can't connect
            if !status.can_connect() {
                return Ok(());
            }

            // Check connection policy
            if let AdmitStatus::Rejected { reason } =
                self.relay.inner.check_connection_policy().await?
            {
                // Set status to "terminated"
                self.relay.inner.set_status(RelayStatus::Terminated, false);

                // Return error
                return Err(Error::connection_rejected(reason));
            }

            // Reserve the relay before dialing. Otherwise a retiring task can
            // still own it after the handshake publishes Connected.
            if !self.relay.inner.reserve_try_connect()? {
                return Ok(());
            }
            let mut reservation = ReservedConnection {
                relay: self.relay,
                transferred: false,
            };

            // Try to connect
            // This will set the status to "terminated" if the connection fails
            let stream: (WebSocketSink, WebSocketStream) = self
                .relay
                .inner
                ._try_connect(self.timeout, RelayStatus::Terminated)
                .await?;

            self.relay.inner.spawn_reserved_connection_task(stream);
            reservation.transferred = true;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_utility::time;
    use nostr::types::{RelayUrl, Url};
    use tokio::sync::Notify;

    use super::*;
    use crate::error::ErrorKind;
    use crate::local_relay::*;
    use crate::policy::AdmitPolicy;
    use crate::transport::websocket::WebSocketTransport;

    #[derive(Debug, Clone, Default)]
    struct FirstConnectionGate {
        blocked: Arc<AtomicBool>,
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl AdmitPolicy for FirstConnectionGate {
        fn admit_connection<'a>(
            &'a self,
            _url: &'a RelayUrl,
        ) -> BoxedFuture<'a, Result<AdmitStatus, Error>> {
            Box::pin(async move {
                if !self.blocked.swap(true, Ordering::SeqCst) {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                Ok(AdmitStatus::Success)
            })
        }
    }

    #[tokio::test]
    async fn try_connect_rechecks_state_after_connection_policy() {
        for status in [
            RelayStatus::Shutdown,
            RelayStatus::Banned,
            RelayStatus::Connected,
        ] {
            let mock = MockRelay::run().await.unwrap();
            let gate = FirstConnectionGate::default();
            let relay = Relay::builder(mock.url().await)
                .admit_policy(gate.clone())
                .build();
            let mut attempt = relay.try_connect().into_future();
            tokio::time::timeout(Duration::from_secs(2), async {
                tokio::select! {
                    _ = gate.entered.notified() => (),
                    result = &mut attempt => panic!("attempt ended before policy release: {result:?}"),
                }
            }).await.unwrap();

            match status {
                RelayStatus::Shutdown => relay.shutdown(),
                RelayStatus::Banned => relay.ban(),
                RelayStatus::Connected => relay
                    .try_connect()
                    .timeout(Duration::from_secs(2))
                    .await
                    .unwrap(),
                _ => unreachable!(),
            }
            gate.release.notify_one();
            let result = attempt.await;
            assert_eq!(relay.status(), status);
            if status.is_connected() {
                result.unwrap();
                assert_eq!(relay.stats().success(), 1);
                assert!(relay.inner.is_running());
            } else {
                assert!(result.is_err());
                assert_eq!(relay.stats().attempts(), 0);
                assert!(!relay.inner.is_running());
            }
            relay.shutdown();
            mock.shutdown();
        }
    }

    #[derive(Debug, Clone, Default)]
    struct PendingTransport {
        entered: Arc<Notify>,
    }

    impl WebSocketTransport for PendingTransport {
        fn support_ping(&self) -> bool {
            false
        }

        fn connect<'a>(
            &'a self,
            _url: &'a Url,
            _proxy: Option<SocketAddr>,
        ) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
            Box::pin(async move {
                self.entered.notify_one();
                std::future::pending().await
            })
        }
    }

    #[tokio::test]
    async fn cancelled_and_timed_out_dials_release_connection_ownership() {
        let transport = PendingTransport::default();
        let relay = Relay::builder("wss://relay.example.com".parse().unwrap())
            .websocket_transport(transport.clone())
            .build();
        let mut attempt = relay.try_connect().into_future();
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                _ = transport.entered.notified() => (),
                result = &mut attempt => panic!("dial ended before cancellation: {result:?}"),
            }
        })
        .await
        .unwrap();
        assert_eq!(relay.status(), RelayStatus::Connecting);
        assert!(relay.inner.is_running());
        drop(attempt);
        assert_eq!(relay.status(), RelayStatus::Terminated);
        assert!(!relay.inner.is_running());

        let error = relay
            .try_connect()
            .timeout(Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Timeout);
        assert_eq!(relay.stats().attempts(), 2);
        assert_eq!(relay.status(), RelayStatus::Terminated);
        assert!(!relay.inner.is_running());
    }

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

        assert_eq!(relay.status(), RelayStatus::Terminated);

        // Connection failed, the connection task is not running
        assert!(!relay.inner.is_running());
    }
}
