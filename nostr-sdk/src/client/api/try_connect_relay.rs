use std::borrow::Cow;
use std::future::IntoFuture;
use std::time::Duration;

use nostr::types::RelayUrl;

use crate::client::{Client, RelayUrlArg};
use crate::error::Error;
use crate::future::BoxedFuture;

/// Try to connect one relay.
#[must_use = "Does nothing unless you await!"]
pub struct TryConnectRelay<'client, 'url> {
    // --------------------------------------------------
    // WHEN ADDING NEW OPTIONS HERE,
    // REMEMBER TO UPDATE THE "Configuration" SECTION in
    // Client::try_connect_relay DOC.
    // --------------------------------------------------
    client: &'client Client,
    url: RelayUrlArg<'url>,
    timeout: Duration,
}

impl<'client, 'url> TryConnectRelay<'client, 'url> {
    #[inline]
    pub(crate) fn new(client: &'client Client, url: RelayUrlArg<'url>) -> Self {
        Self {
            client,
            url,
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

impl<'client, 'url> IntoFuture for TryConnectRelay<'client, 'url>
where
    'url: 'client,
{
    type Output = Result<(), Error>;
    type IntoFuture = BoxedFuture<'client, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let url: Cow<RelayUrl> = self.url.try_as_relay_url()?;
            self.client
                .pool()
                .try_connect_relay(&url, self.timeout)
                .await?;
            Ok(())
        })
    }
}
