//! Nostr Connect client builder

use std::sync::Arc;
use std::time::Duration;

use nostr::key::Keys;
use nostr::nips::nip46::NostrConnectUri;
use nostr_sdk::client::Client;

use crate::client::{AuthUrlHandler, NostrConnect};
use crate::error::Error;

/// Default timeout
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Nostr Connect builder
#[derive(Debug, Clone)]
pub struct NostrConnectBuilder {
    pub(crate) uri: NostrConnectUri,
    pub(crate) client_keys: Keys,
    // Requests timeout.
    pub(crate) timeout: Duration,
    // An optional custom client, constructed externally
    pub(crate) client: Option<Client>,
    pub(crate) auth_url_handler: Option<Arc<dyn AuthUrlHandler>>,
}

impl NostrConnectBuilder {
    /// Construct a new Nostr Wallet Connect client builder.
    pub fn new(uri: NostrConnectUri, client_keys: Keys) -> Self {
        Self {
            uri,
            client_keys,
            timeout: DEFAULT_TIMEOUT,
            client: None,
            auth_url_handler: None,
        }
    }

    /// Set default requests timeout (default: 10 secs)
    #[inline]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set a custom client
    #[inline]
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Set an `auth_url` handler
    ///
    /// ```rust
    /// use std::future::Future;
    /// use std::pin::Pin;
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// use nostr_connect::prelude::*;
    ///
    /// #[derive(Debug, Clone)]
    /// struct MyAuthUrlHandler;
    ///
    /// impl AuthUrlHandler for MyAuthUrlHandler {
    ///     fn on_auth_url(&self, auth_url: Url) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
    ///         Box::pin(async move {
    ///             webbrowser::open(auth_url.as_str()).map_err(Error::other)?;
    ///             Ok(())
    ///         })
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let uri = NostrConnectUri::parse("bunker://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss://relay.nsec.app")?;
    ///     let client_keys = Keys::generate();
    ///
    ///     let connect: NostrConnect = NostrConnect::builder(uri, client_keys).auth_url_handler(Arc::new(MyAuthUrlHandler)).build()?;
    ///
    ///     // ...
    ///
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn auth_url_handler(mut self, auth_url_handler: Arc<dyn AuthUrlHandler>) -> Self {
        self.auth_url_handler = Some(auth_url_handler);
        self
    }

    /// Build [`NostrConnect`] client.
    #[inline]
    pub fn build(self) -> Result<NostrConnect, Error> {
        NostrConnect::from_builder(self)
    }
}
