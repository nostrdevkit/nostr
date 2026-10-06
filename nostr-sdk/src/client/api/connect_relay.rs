use std::borrow::Cow;
use std::future::IntoFuture;
use std::time::Duration;

use nostr::types::RelayUrl;

use crate::client::{Client, RelayUrlArg};
use crate::error::Error;
use crate::future::BoxedFuture;

/// Connect one relay
#[must_use = "Does nothing unless you await!"]
pub struct ConnectRelay<'client, 'url> {
    // --------------------------------------------------
    // WHEN ADDING NEW OPTIONS HERE,
    // REMEMBER TO UPDATE THE "Configuration" SECTION in
    // Client::connect_relay DOC.
    // --------------------------------------------------
    client: &'client Client,
    url: RelayUrlArg<'url>,
    wait: Option<Duration>,
}

impl<'client, 'url> ConnectRelay<'client, 'url> {
    #[inline]
    pub(crate) fn new(client: &'client Client, url: RelayUrlArg<'url>) -> Self {
        Self {
            client,
            url,
            wait: None,
        }
    }

    /// Waits for the relay to connect.
    ///
    /// Wait for the relay to connect at most for the specified `timeout`.
    /// The code continues when the relay is connected or the `timeout` is reached.
    #[inline]
    pub fn and_wait(mut self, timeout: Duration) -> Self {
        self.wait = Some(timeout);
        self
    }
}

impl<'client, 'url> IntoFuture for ConnectRelay<'client, 'url>
where
    'url: 'client,
{
    type Output = Result<(), Error>;
    type IntoFuture = BoxedFuture<'client, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let url: Cow<RelayUrl> = self.url.try_as_relay_url()?;
            self.client.pool().connect_relay(&url, self.wait).await?;
            Ok(())
        })
    }
}
