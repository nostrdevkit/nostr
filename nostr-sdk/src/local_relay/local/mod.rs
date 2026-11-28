// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nostr::event::Event;
use nostr::filter::Filter;
use nostr::types::RelayUrl;
use nostr_database::SaveEventStatus;
use tokio::io::{AsyncRead, AsyncWrite};

mod inner;
mod session;
mod util;

use self::inner::InnerLocalRelay;
use super::builder::LocalRelayBuilder;
use crate::client::{Output, RelayUrlArg, SyncSummary};
use crate::error::Error;
use crate::relay::SyncOptions;

/// A local nostr relay
///
/// This is automatically shutdown when all instances/clones are dropped!
///
/// If a session falls behind the bounded live event buffer, its active live
/// subscriptions receive `CLOSED`. Clients can resubscribe to recover stored
/// events; ephemeral events and events only passed to [`Self::notify_event`]
/// cannot be recovered from the relay database.
#[derive(Debug)]
pub struct LocalRelay {
    inner: InnerLocalRelay,
    // Keep track of the atomic reference count to know when shutdown the relay.
    atomic_counter: Arc<AtomicUsize>,
}

impl Clone for LocalRelay {
    fn clone(&self) -> Self {
        self.atomic_counter.fetch_add(1, Ordering::SeqCst);

        Self {
            inner: self.inner.clone(),
            atomic_counter: self.atomic_counter.clone(),
        }
    }
}

impl Drop for LocalRelay {
    fn drop(&mut self) {
        // Shutdown exactly once when the last handle is dropped.
        if self.atomic_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.shutdown();
        }
    }
}

impl Default for LocalRelay {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl LocalRelay {
    /// Create a new local relay with the default configuration.
    ///
    /// Use [`LocalRelay::builder`] for customizing it!
    #[inline]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create a new local relay builder
    #[inline]
    pub fn builder() -> LocalRelayBuilder {
        LocalRelayBuilder::default()
    }

    #[inline]
    pub(super) fn from_builder(builder: LocalRelayBuilder) -> Self {
        Self {
            inner: InnerLocalRelay::new(builder),
            atomic_counter: Arc::new(AtomicUsize::new(1)),
        }
    }

    /// Run the local relay
    #[inline]
    pub async fn run(&self) -> Result<(), Error> {
        self.inner.run().await?;
        Ok(())
    }

    /// Get url
    #[inline]
    pub async fn url(&self) -> RelayUrl {
        self.inner.url().await
    }

    /// Returns the remaining connection capacity before the limit is reached.
    #[inline]
    pub fn connections_left(&self) -> usize {
        self.inner.connections_limit.available_permits()
    }

    /// Sync events with other relay(s).
    #[inline]
    pub async fn sync_with<'a, I, U>(
        &self,
        urls: I,
        filter: Filter,
        opts: SyncOptions,
    ) -> Result<Output<SyncSummary>, Error>
    where
        I: IntoIterator<Item = U>,
        U: Into<RelayUrlArg<'a>>,
    {
        self.inner.sync_with(urls, filter, opts).await
    }

    /// Send event to subscribers
    ///
    /// Return `true` if the event is successfully sent.
    ///
    /// This method doesn't save the event into the database!
    /// It's intended to be used ONLY when the database is shared with other apps (i.e. with the nostr-sdk `Client`).
    pub fn notify_event(&self, event: Event) -> bool {
        if event.verify().is_err() {
            return false;
        }

        self.inner.notify_event(event)
    }

    /// Save the event to the database and, if success, notify the subscribers.
    pub async fn add_event(&self, event: Event) -> Result<SaveEventStatus, Error> {
        event.verify()?;

        let status = self.inner.save_event(&event).await?;

        if status.is_success() {
            self.inner.notify_event(event);
        }

        Ok(status)
    }

    /// Shutdown relay
    #[inline]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Pass an already upgraded stream
    pub async fn take_connection<S>(&self, stream: S, addr: SocketAddr) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.inner.handle_upgraded_connection(stream, addr).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time;

    use super::*;

    // NOTE: keep here only the LocalRelay tests that needs access to private inner values of LocalRelay,
    // the other generic ones should be in the super::tests module.

    #[tokio::test]
    async fn test_shutdown() {
        let relay = LocalRelay::new();

        assert!(!relay.inner.is_running());

        relay.run().await.unwrap();

        time::sleep(Duration::from_secs(1)).await;

        assert!(relay.inner.is_running());

        relay.shutdown();

        time::sleep(Duration::from_millis(100)).await;

        assert!(!relay.inner.is_running());
    }

    #[tokio::test]
    async fn test_shutdown_on_drop() {
        let inner: InnerLocalRelay = {
            let relay: LocalRelay = LocalRelay::new();

            assert!(!relay.inner.is_running());

            relay.run().await.unwrap();

            time::sleep(Duration::from_secs(1)).await;

            assert!(relay.inner.is_running());

            // Clone the inner relay
            let inner: InnerLocalRelay = relay.inner.clone();

            {
                let r2: LocalRelay = relay.clone();
                tokio::spawn(async move {
                    assert_eq!(r2.atomic_counter.load(Ordering::SeqCst), 2);

                    time::sleep(Duration::from_secs(1)).await;

                    // r2 dropped here
                });
            }

            time::sleep(Duration::from_secs(2)).await;

            assert_eq!(relay.atomic_counter.load(Ordering::SeqCst), 1);

            inner
        }; // relay dropped here

        time::sleep(Duration::from_secs(1)).await;

        assert!(!inner.is_running());
    }
}
