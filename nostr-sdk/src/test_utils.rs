use std::time::Duration;

use nostr::types::RelayUrl;

use crate::authenticator::Authenticator;
use crate::client::Client;
use crate::local_relay::*;
use crate::relay::Relay;

pub(crate) async fn setup_nip42_read_local_relay() -> LocalRelay {
    let local = LocalRelay::builder()
        .nip42(LocalRelayBuilderNip42::read())
        .build();
    local.run().await.unwrap();
    local
}

pub(crate) async fn setup_relay(url: RelayUrl) -> Relay {
    let relay = Relay::new(url);

    relay
        .try_connect()
        .timeout(Duration::from_secs(3))
        .await
        .unwrap();

    relay
}

pub(crate) async fn setup_relay_with_authenticator<A>(url: RelayUrl, authenticator: A) -> Relay
where
    A: Authenticator + 'static,
{
    let relay = Relay::builder(url).authenticator(authenticator).build();

    relay
        .try_connect()
        .timeout(Duration::from_secs(3))
        .await
        .unwrap();

    relay
}

pub(crate) async fn setup_client(url: RelayUrl) -> Client {
    let client = Client::new();

    client.add_relay(&url).await.unwrap();
    client
        .try_connect_relay(url)
        .timeout(Duration::from_secs(3))
        .await
        .unwrap();

    client
}

pub(crate) async fn setup_client_with_authenticator<A>(url: RelayUrl, authenticator: A) -> Client
where
    A: Authenticator + 'static,
{
    let client = Client::builder().authenticator(authenticator).build();

    client.add_relay(&url).await.unwrap();
    client
        .try_connect_relay(url)
        .timeout(Duration::from_secs(3))
        .await
        .unwrap();

    client
}
