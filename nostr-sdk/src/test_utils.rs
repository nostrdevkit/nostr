use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_wsocket::Message;
use futures::{Sink, SinkExt, StreamExt};
use nostr::event::EventId;
use nostr::message::{RelayMessage, SubscriptionId};
use nostr::types::{RelayUrl, Url};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time;

use crate::authenticator::Authenticator;
use crate::client::Client;
use crate::error::Error;
use crate::future::BoxedFuture;
use crate::local_relay::*;
use crate::policy::{AdmitPolicy, AdmitStatus};
use crate::relay::{Relay, RelayBuilder, RelayNotification, RelayOptions, RelayStatus};
use crate::stream::NotificationStream;
use crate::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};

pub(crate) type DialReply = oneshot::Sender<Result<(WebSocketSink, WebSocketStream), Error>>;
pub(crate) type PolicyReply = oneshot::Sender<Result<AdmitStatus, Error>>;

pub(crate) const TEST_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn start_try_connect(relay: &Relay, timeout: Duration) -> JoinHandle<Result<(), Error>> {
    let relay = relay.clone();
    tokio::spawn(async move { relay.try_connect().timeout(timeout).await })
}

pub(crate) async fn wait_until<F>(description: &str, mut condition: F)
where
    F: FnMut() -> bool,
{
    time::timeout(TEST_TIMEOUT, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {description}"));
}

pub(crate) async fn wait_for_status(relay: &Relay, status: RelayStatus) {
    wait_until(&format!("relay status {status}"), || {
        relay.status() == status
    })
    .await;
}

async fn wait_for_notification<F>(
    notifications: &mut NotificationStream<RelayNotification>,
    description: &str,
    mut matches: F,
) where
    F: FnMut(&RelayNotification) -> bool,
{
    time::timeout(TEST_TIMEOUT, async {
        while let Some(notification) = notifications.next().await {
            if matches(&notification) {
                return;
            }
        }

        panic!("notification stream closed while waiting for {description}");
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {description}"));
}

pub(crate) async fn wait_for_eose(
    notifications: &mut NotificationStream<RelayNotification>,
    subscription: &SubscriptionId,
) {
    wait_for_notification(notifications, "subscription EOSE", |notification| {
        matches!(notification, RelayNotification::Message { message }
            if matches!(message.as_ref(), RelayMessage::EndOfStoredEvents(id)
                if id.as_ref() == subscription))
    })
    .await;
}

pub(crate) async fn wait_for_subscription_event(
    notifications: &mut NotificationStream<RelayNotification>,
    subscription: &SubscriptionId,
    event_id: &EventId,
) {
    wait_for_notification(notifications, "subscription event", |notification| {
        matches!(notification, RelayNotification::Event { subscription_id, event }
            if subscription_id == subscription && event.id == *event_id)
    })
    .await;
}

#[derive(Debug)]
pub(crate) struct ControlledConnectionPolicy(Sender<PolicyReply>);

impl ControlledConnectionPolicy {
    pub(crate) fn new() -> (Self, PolicyController) {
        let (sender, receiver) = mpsc::channel(8);
        (Self(sender), PolicyController { receiver })
    }
}

impl AdmitPolicy for ControlledConnectionPolicy {
    fn admit_connection<'a>(
        &'a self,
        _url: &'a RelayUrl,
    ) -> BoxedFuture<'a, Result<AdmitStatus, Error>> {
        Box::pin(async move {
            let (reply, result) = oneshot::channel();
            self.0.send(reply).await.expect("policy controller dropped");
            result.await.expect("policy reply dropped without a result")
        })
    }
}

pub(crate) struct PolicyController {
    receiver: Receiver<PolicyReply>,
}

impl PolicyController {
    pub(crate) async fn next_check(&mut self) -> PolicyReply {
        time::timeout(TEST_TIMEOUT, self.receiver.recv())
            .await
            .expect("timed out waiting for a connection policy check")
            .expect("connection policy dropped before checking")
    }

    pub(crate) fn assert_no_pending_checks(&mut self) {
        assert!(
            matches!(
                self.receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ),
            "expected no pending connection policy checks"
        );
    }
}

#[derive(Debug)]
struct ControlledWebSocketTransport(Sender<DialReply>);

impl WebSocketTransport for ControlledWebSocketTransport {
    fn support_ping(&self) -> bool {
        false
    }

    fn connect<'a>(
        &'a self,
        _url: &'a Url,
        _proxy: Option<SocketAddr>,
    ) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
        Box::pin(async move {
            let (reply, result) = oneshot::channel();
            self.0.send(reply).await.expect("dial controller dropped");
            result.await.expect("dial reply dropped without a result")
        })
    }
}

pub(crate) struct DialController {
    receiver: Receiver<DialReply>,
}

impl DialController {
    pub(crate) async fn next_dial(&mut self) -> DialReply {
        time::timeout(TEST_TIMEOUT, self.receiver.recv())
            .await
            .expect("timed out waiting for a transport dial")
            .expect("transport dropped before dialing")
    }

    pub(crate) fn assert_no_pending_dials(&mut self) {
        assert!(
            matches!(
                self.receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ),
            "expected no pending transport dials"
        );
    }
}

/// Keeps the relay separate from the controller that completes its transport attempts.
pub(crate) struct ControlledRelay {
    pub(crate) relay: Relay,
    pub(crate) transport: DialController,
}

impl ControlledRelay {
    pub(crate) fn new() -> Self {
        Self::with_opts(RelayOptions::default())
    }

    pub(crate) fn with_opts(opts: RelayOptions) -> Self {
        let builder =
            Relay::builder(RelayUrl::parse("wss://relay.example.com").unwrap()).opts(opts);
        Self::with_builder(builder)
    }

    pub(crate) fn with_policy(policy: ControlledConnectionPolicy) -> Self {
        let builder = Relay::builder(RelayUrl::parse("wss://relay.example.com").unwrap())
            .admit_policy(policy);
        Self::with_builder(builder)
    }

    fn with_builder(builder: RelayBuilder) -> Self {
        let (requests, receiver) = mpsc::channel(8);
        let relay = builder
            .websocket_transport(ControlledWebSocketTransport(requests))
            .build();

        Self {
            relay,
            transport: DialController { receiver },
        }
    }
}

/// Pauses WebSocket closing until the test releases it.
pub(crate) struct CloseGate {
    closing: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
}

impl CloseGate {
    pub(crate) async fn wait_until_closing(&mut self) {
        time::timeout(TEST_TIMEOUT, &mut self.closing)
            .await
            .expect("timed out waiting for WebSocket closing to start")
            .expect("WebSocket dropped before closing");
    }

    pub(crate) fn release(self) {
        self.release
            .send(())
            .expect("WebSocket close was cancelled");
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.release.is_closed()
    }
}

struct ClosingSink {
    inner: WebSocketSink,
    entered: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
}

impl Sink<Message> for ClosingSink {
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.inner.as_mut().poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Error> {
        self.inner.as_mut().start_send(message)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }

        if Pin::new(&mut self.release).poll(cx).is_pending() {
            return Poll::Pending;
        }

        self.inner.as_mut().poll_close(cx)
    }
}

/// Accepts outgoing messages without producing any incoming messages.
pub(crate) fn fake_connection() -> (WebSocketSink, WebSocketStream) {
    (
        Box::pin(futures::sink::drain().sink_map_err(|error| match error {})),
        Box::pin(futures::stream::pending()),
    )
}

pub(crate) fn connection_gate_close(
    connection: (WebSocketSink, WebSocketStream),
) -> ((WebSocketSink, WebSocketStream), CloseGate) {
    let (entered, closing) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (inner, stream) = connection;

    (
        (
            Box::pin(ClosingSink {
                inner,
                entered: Some(entered),
                release: released,
            }),
            stream,
        ),
        CloseGate { closing, release },
    )
}

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
