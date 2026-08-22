// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_utility::futures_util::stream::SplitSink;
use async_utility::futures_util::{SinkExt, StreamExt};
use async_wsocket::native;
use async_wsocket::native::{Message, Role, WebSocketConfig, WebSocketStream};
use negentropy::{Id, Negentropy, NegentropyStorageVector};
use nostr::filter::{MatchEventOptions, SingleLetterTag};
use nostr::message::MachineReadablePrefix;
use nostr::prelude::*;
use nostr_memory::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Notify, OnceCell, OwnedSemaphorePermit, Semaphore, broadcast};

use super::super::builder::{
    DEFAULT_MAX_PENDING_HANDSHAKES, LocalRelayBuilder, LocalRelayBuilderMode,
    LocalRelayBuilderNip42, LocalRelayTestOptions, QueryPolicy, QueryPolicyResult, RateLimit,
    WritePolicy, WritePolicyResult,
};
use super::session::{NegentropySubscription, Nip42Session, RateLimiterResponse, Session, Tokens};
use super::util;
use crate::client::{Client, ClientNotification, Output, RelayUrlArg, SyncSummary};
use crate::error::{Error, ErrorKind};
use crate::relay::SyncOptions;

type WsTx<S> = SplitSink<WebSocketStream<S>, Message>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GiftWrapQueryAccess {
    Allowed,
    AuthRequired,
    Forbidden,
}

#[derive(Debug, Clone)]
pub(super) struct InnerLocalRelay {
    ip: IpAddr,
    addr: OnceCell<SocketAddr>,
    database: Arc<dyn NostrDatabase>,
    shutdown: Arc<Notify>,
    /// Channel to notify new event received
    ///
    /// Every session will listen and check own subscriptions
    new_event: broadcast::Sender<Event>,
    mode: LocalRelayBuilderMode,
    rate_limit: RateLimit,
    queries_per_minute: u32,
    auth_events_per_minute: u32,
    messages_per_minute: u32,
    pending_handshakes_limit: Arc<Semaphore>,
    connections_limit: Arc<Semaphore>,
    max_websocket_message_size: usize,
    max_event_size: usize,
    websocket_handshake_timeout: Duration,
    max_subid_length: usize,
    max_filters_per_req: usize,
    max_filter_limit: usize,
    max_subscription_bytes: usize,
    max_negentropy_subscriptions: usize,
    max_negentropy_items: usize,
    auth_dm: bool,
    min_pow: Option<u8>, // TODO: use AtomicU8 to allow to change it?
    kinds_blacklist: HashSet<Kind>,
    write_policy: Option<Arc<dyn WritePolicy>>,
    query_policy: Option<Arc<dyn QueryPolicy>>,
    nip42: Option<LocalRelayBuilderNip42>,
    test: LocalRelayTestOptions,
    running: Arc<AtomicBool>,
}

impl InnerLocalRelay {
    pub fn new(builder: LocalRelayBuilder) -> Self {
        // Get IP
        let ip: IpAddr = builder.addr.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        // Compose local address
        let addr: OnceCell<SocketAddr> = match builder.port {
            Some(port) => OnceCell::from(SocketAddr::new(ip, port)),
            None => OnceCell::new(),
        };

        // Channels
        let (new_event, ..) = broadcast::channel(1024);

        let database: Arc<dyn NostrDatabase> = builder.database.unwrap_or_else(|| {
            let max: NonZeroUsize = NonZeroUsize::new(75_000).unwrap();
            Arc::new(MemoryDatabase::bounded(max))
        });

        // Compose relay
        Self {
            ip,
            addr,
            database,
            shutdown: Arc::new(Notify::new()),
            new_event,
            mode: builder.mode,
            rate_limit: builder.rate_limit,
            queries_per_minute: builder.queries_per_minute,
            auth_events_per_minute: builder.auth_events_per_minute,
            messages_per_minute: builder.messages_per_minute,
            pending_handshakes_limit: Arc::new(Semaphore::new(DEFAULT_MAX_PENDING_HANDSHAKES)),
            connections_limit: Arc::new(Semaphore::new(
                builder.max_connections.unwrap_or(Semaphore::MAX_PERMITS),
            )),
            max_websocket_message_size: builder.max_websocket_message_size,
            max_event_size: builder.max_event_size,
            websocket_handshake_timeout: builder.websocket_handshake_timeout,
            max_subid_length: builder.max_subid_length,
            max_filters_per_req: builder.max_filters_per_req,
            max_filter_limit: builder.max_filter_limit,
            max_subscription_bytes: builder.max_subscription_bytes,
            max_negentropy_subscriptions: builder.max_negentropy_subscriptions,
            max_negentropy_items: builder.max_negentropy_items,
            auth_dm: builder.auth_dm,
            min_pow: builder.min_pow,
            kinds_blacklist: builder.kinds_blacklist,
            write_policy: builder.write_policy,
            query_policy: builder.query_policy,
            nip42: builder.nip42,
            test: builder.test,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn addr(&self) -> &SocketAddr {
        self.addr
            .get_or_init(|| async {
                let port: u16 = util::find_available_port(self.ip).await;
                SocketAddr::new(self.ip, port)
            })
            .await
    }

    #[inline]
    pub(super) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Start socket to listen for new websocket connections
    ///
    /// Returns `true` if the relay has started, `false` if it's already running.
    pub async fn run(&self) -> Result<bool, Error> {
        if self.is_running() {
            return Ok(false);
        }

        // Get the address
        let addr: &SocketAddr = self.addr().await;

        // Start listener
        let listener: TcpListener = TcpListener::bind(&addr).await?;

        let r: Self = self.clone();
        tokio::spawn(async move {
            r.running.store(true, Ordering::SeqCst);

            loop {
                tokio::select! {
                    output = listener.accept() => {
                        match output {
                            Ok((stream, addr)) => {
                                // Acquire before spawning so excess sockets cannot create tasks.
                                let permit = match r.pending_handshakes_limit.clone().try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(e) => {
                                        tracing::warn!("Rejecting connection from {addr}: {e}");
                                        continue;
                                    }
                                };
                                let r1: Self = r.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = r1.handle_connection(stream, addr, permit).await {
                                        tracing::warn!("{e}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!("Can't accept incoming connection: {e}");
                            }
                        }
                    }
                    _ = r.shutdown.notified() => break,
                }
            }

            r.running.store(false, Ordering::SeqCst);

            tracing::info!("Local relay listener loop terminated.");
        });

        Ok(true)
    }

    #[inline]
    pub async fn url(&self) -> RelayUrl {
        let addr: &SocketAddr = self.addr().await;
        let addr: String = format!("ws://{addr}");
        // SAFETY: must be a valid address
        RelayUrl::parse(&addr).unwrap()
    }

    pub(super) async fn sync_with<'a, I, U>(
        &self,
        urls: I,
        filter: Filter,
        opts: SyncOptions,
    ) -> Result<Output<SyncSummary>, Error>
    where
        I: IntoIterator<Item = U>,
        U: Into<RelayUrlArg<'a>>,
    {
        // Construct a new pool
        let client: Client = Client::default();

        // Add relays to client
        for url in urls {
            client.add_relay(url).await?;
        }

        // Connect
        client.connect().await;

        // Subscribe to notifications
        let mut notifications = client.notifications();

        // Create a notification future
        let fut = async {
            while let Some(notification) = notifications.next().await {
                // Notify about new events received by the sync
                if let ClientNotification::Event { event, .. } = notification {
                    self.notify_event(*event);
                }
            }
        };

        // Start sync and wait for the result
        tokio::select! {
            result = client.sync(filter).opts(opts) => {
                // Shutdown client
                client.shutdown().await;

                // Return reconciliation output
                Ok(result?)
            },
            _ = fut => Err(Error::with_static_message(ErrorKind::Other, "notifications exited before sync completed"))
        }
    }

    #[inline]
    pub(super) fn notify_event(&self, event: Event) -> bool {
        self.new_event.send(event).is_ok()
    }

    #[inline]
    pub(super) async fn save_event(&self, event: &Event) -> Result<SaveEventStatus, Error> {
        Ok(self.database.save_event(event).await?)
    }

    #[inline]
    pub fn shutdown(&self) {
        // There are at least 2 waiters
        self.shutdown.notify_waiters()
    }

    /// Handle already upgraded HTTP request
    pub(crate) async fn handle_upgraded_connection<S>(
        &self,
        stream: S,
        addr: SocketAddr,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let permit = self.connections_limit.clone().try_acquire_owned()?;

        if let Some(unresponsive_connection) = self.test.unresponsive_connection {
            tokio::time::sleep(unresponsive_connection).await;
        }

        let ws_stream =
            WebSocketStream::from_raw_socket(stream, Role::Server, Some(self.websocket_config()))
                .await;

        self.handle_websocket(ws_stream, addr, permit).await?;

        Ok(())
    }

    /// Pass bare [TcpStream] for handling
    async fn handle_connection<S>(
        self,
        raw_stream: S,
        addr: SocketAddr,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(unresponsive_connection) = self.test.unresponsive_connection {
            tokio::time::sleep(unresponsive_connection).await;
        }

        // Bound clients that open TCP but never complete the WebSocket handshake.
        let ws_stream = tokio::time::timeout(
            self.websocket_handshake_timeout,
            native::accept_async_with_config(raw_stream, Some(self.websocket_config())),
        )
        .await
        .map_err(|_| {
            Error::with_static_message(ErrorKind::Transport, "WebSocket handshake timed out")
        })?
        .map_err(Error::transport)?;

        // The pre-handshake socket is no longer consuming admission resources.
        drop(permit);

        // An established connection only consumes a permit when explicitly configured.
        let permit = self.connections_limit.clone().try_acquire_owned()?;

        self.handle_websocket(ws_stream, addr, permit).await?;

        Ok(())
    }

    /// Handle websocket connection
    async fn handle_websocket<S>(
        &self,
        ws_stream: WebSocketStream<S>,
        addr: SocketAddr,
        _permit: OwnedSemaphorePermit,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tracing::debug!("WebSocket connection established: {addr}");

        let mut new_event = self.new_event.subscribe();

        let (mut tx, mut rx) = ws_stream.split();

        let mut session: Session = Session {
            subscriptions: HashMap::new(),
            subscription_bytes: 0,
            negentropy_subscription: HashMap::new(),
            nip42: Nip42Session::default(),
            write_tokens: Tokens::new(self.rate_limit.notes_per_minute),
            query_tokens: Tokens::new(self.queries_per_minute),
            negentropy_tokens: Tokens::new(self.queries_per_minute),
            auth_tokens: Tokens::new(self.auth_events_per_minute),
            message_tokens: Tokens::new(self.messages_per_minute),
        };

        loop {
            tokio::select! {
                msg = rx.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            // Charge every frame type so non-text traffic cannot bypass the limit.
                            if let RateLimiterResponse::Limited =
                                session.check_message_rate_limit(self.messages_per_minute)
                            {
                                return Err(Error::limit_exceeded("too many client messages"));
                            }

                            match msg {
                                Message::Text(json) => {
                                    tracing::trace!("Received {json}");
                                    let message_size = json.len();
                                    match ClientMessage::from_json(json.as_bytes()) {
                                        Ok(msg) => {
                                            self.handle_client_msg(
                                                &mut session,
                                                &mut tx,
                                                msg,
                                                &addr,
                                                message_size,
                                            )
                                                .await?;
                                        }
                                        Err(e) => {
                                            tracing::debug!("Can't parse client message: {e}");
                                            send_msg(
                                                &mut tx,
                                                RelayMessage::Notice(Cow::Borrowed(
                                                    "invalid client message",
                                                )),
                                            )
                                            .await?;
                                        }
                                    }
                                }
                                Message::Binary(..) => {
                                    let msg =
                                        RelayMessage::Notice(Cow::Borrowed("binary messages are not processed by this relay"));
                                    if let Err(e) = send_msg(&mut tx, msg).await {
                                        tracing::error!("Can't send msg to client: {e}");
                                    }
                                }
                                Message::Ping(..) => {}
                                Message::Pong(..) => {}
                                Message::Close(..) => {}
                                Message::Frame(..) => {}
                            }
                        }
                        Some(Err(e)) => tracing::error!("Can't handle websocket msg: {e}"),
                        None => break,
                    }
                }
                event = new_event.recv() => {
                    if let Ok(event) = event {
                         // Iter subscriptions
                        'sub_iter: for (subscription_id, subscription) in session.subscriptions.iter() {
                            for filter in subscription.filters.iter() {
                                // Check if event matches filter
                                if filter.match_event(&event, MatchEventOptions::new()) {
                                    send_msg(&mut tx, RelayMessage::Event{
                                        subscription_id: Cow::Borrowed(subscription_id),
                                        event: Cow::Borrowed(&event)
                                    }).await?;

                                    // Found a match, stop iterating the filters and continue with the next subscription
                                    continue 'sub_iter;
                                }
                            }

                        }
                    }
                }
                _ = self.shutdown.notified() => break,
            }
        }

        tracing::debug!("WebSocket connection terminated for {addr}");

        Ok(())
    }

    fn websocket_config(&self) -> WebSocketConfig {
        WebSocketConfig::default()
            .max_message_size(Some(self.max_websocket_message_size))
            .max_frame_size(Some(self.max_websocket_message_size))
    }

    async fn handle_client_msg<S>(
        &self,
        session: &mut Session<'_>,
        ws_tx: &mut WsTx<S>,
        msg: ClientMessage<'_>,
        addr: &SocketAddr,
        message_size: usize,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match msg {
            ClientMessage::Event(event) => {
                // Check rate limit
                if let RateLimiterResponse::Limited =
                    session.check_rate_limit(self.rate_limit.notes_per_minute)
                {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: slow down",
                                MachineReadablePrefix::RateLimited
                            )),
                        },
                    )
                    .await;
                }

                // Check the event size. The `-10` for `["EVENT",]`
                if (message_size - 10) > self.max_event_size {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: event size ({} bytes) exceeds maximum allowed size ({} bytes)",
                                MachineReadablePrefix::Blocked,
                                message_size - 10,
                                self.max_event_size
                            )),
                        },
                    )
                    .await;
                }

                // Reject the event if it's a blacklisted kind
                if self.kinds_blacklist.contains(&event.kind) {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: kind `{}` is not accepted by this relay",
                                MachineReadablePrefix::Blocked,
                                event.kind.as_u16()
                            )),
                        },
                    )
                    .await;
                }

                if !event.verify_id() {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: invalid event ID",
                                MachineReadablePrefix::Invalid
                            )),
                        },
                    )
                    .await;
                }

                // Check POW
                if let Some(difficulty) = self.min_pow {
                    let target_difficulty = event
                        .tags
                        .iter()
                        .find_map(|t| match Nip13Tag::try_from(t).ok()? {
                            Nip13Tag::Nonce { difficulty, .. } => Some(difficulty),
                        })
                        .unwrap_or_default();

                    if target_difficulty < difficulty || !event.id.check_pow(difficulty) {
                        return send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: false,
                                message: Cow::Owned(format!(
                                    "{}: required a difficulty >= {difficulty}",
                                    MachineReadablePrefix::Pow
                                )),
                            },
                        )
                        .await;
                    }
                }

                // Check if the event is expired
                if event.is_expired() {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: event is expired",
                                MachineReadablePrefix::Blocked
                            )),
                        },
                    )
                    .await;
                }

                // Reject repost of a protected event
                if matches!(event.kind, Kind::Repost | Kind::GenericRepost)
                    && Event::from_json(&event.content).is_ok_and(|e| e.is_protected())
                {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: repost of a protected event",
                                MachineReadablePrefix::Blocked
                            )),
                        },
                    )
                    .await;
                }

                if event.kind == Kind::GiftWrap {
                    let mut pkeys = event.tags.public_keys();
                    // Ensure exactly one recipient public key: the first
                    // `next()` must return Some (key exists), and the second
                    // must return None (no extra keys).
                    if pkeys.next().is_none() || pkeys.next().is_some() {
                        return send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: false,
                                message: Cow::Owned(format!(
                                    "{}: GiftWrap must contain exactly one recipient public key",
                                    MachineReadablePrefix::Blocked,
                                )),
                            },
                        )
                        .await;
                    }
                }

                if !event.verify_signature() {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: invalid event signature",
                                MachineReadablePrefix::Invalid
                            )),
                        },
                    )
                    .await;
                }

                // Check if it's configured to require NIP42 authentication for writing
                let require_nip42_auth: bool = match &self.nip42 {
                    Some(nip42) => nip42.mode.is_write(),
                    None => false,
                };

                // Check if it's a protected event
                let is_protected: bool = event.is_protected();

                // Check if authentication is required
                if (require_nip42_auth || is_protected) && !session.nip42.is_authenticated() {
                    // Generate and send AUTH challenge
                    send_msg(
                        ws_tx,
                        RelayMessage::Auth {
                            challenge: Cow::Owned(session.nip42.generate_challenge()),
                        },
                    )
                    .await?;

                    // Return error
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: you must auth",
                                MachineReadablePrefix::AuthRequired
                            )),
                        },
                    )
                    .await;
                }

                if is_protected {
                    if let Some(authenticated_public_key) = &session.nip42.public_key {
                        // Block if the event author not matches the authenticated public key
                        if event.pubkey != *authenticated_public_key {
                            return send_msg(
                                ws_tx,
                                RelayMessage::Ok {
                                    event_id: event.id,
                                    status: false,
                                    message: Cow::Owned(format!(
                                        "{}: this event may only be published by its author",
                                        MachineReadablePrefix::Blocked
                                    )),
                                },
                            )
                            .await;
                        }
                    }
                }

                // Check mode
                if let LocalRelayBuilderMode::PublicKey(pk) = self.mode {
                    let authored: bool = event.pubkey == pk;
                    let tagged: bool = event.tags.public_keys().any(|p| p == pk);

                    if !authored && !tagged {
                        return send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: false,
                                message: Cow::Owned(format!(
                                    "{}: event not related to owner of this relay",
                                    MachineReadablePrefix::Blocked
                                )),
                            },
                        )
                        .await;
                    }
                }

                // Check write policy
                if let Some(policy) = self.write_policy.as_ref() {
                    if let WritePolicyResult::Reject {
                        prefix,
                        message,
                        status,
                    } = policy.admit_event(&event, addr).await
                    {
                        return send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status,
                                message: Cow::Owned(format!("{prefix}: {message}")),
                            },
                        )
                        .await;
                    }
                }

                // Check if event already exists only after all write authorization checks.
                let event_status = self.database.check_id(&event.id).await?;
                match event_status {
                    DatabaseEventStatus::Saved => {
                        return send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: true,
                                message: Cow::Owned(format!(
                                    "{}: already have this event",
                                    MachineReadablePrefix::Duplicate
                                )),
                            },
                        )
                        .await;
                    }
                    DatabaseEventStatus::Deleted => {
                        return send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: false,
                                message: Cow::Owned(format!(
                                    "{}: this event is deleted",
                                    MachineReadablePrefix::Blocked
                                )),
                            },
                        )
                        .await;
                    }
                    DatabaseEventStatus::NotExistent => {}
                }

                if event.kind.is_ephemeral() {
                    let event_id = event.id;

                    // Broadcast to channel
                    self.new_event.send(event.into_owned())?;

                    // Send OK message
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id,
                            status: true,
                            message: Cow::Owned(String::new()),
                        },
                    )
                    .await;
                }

                let msg: RelayMessage = match self.database.save_event(&event).await {
                    Ok(status) => {
                        // TODO: match status
                        if status.is_success() {
                            let event_id = event.id;

                            // Broadcast to channel
                            self.new_event.send(event.into_owned())?;

                            // Reply to client
                            RelayMessage::Ok {
                                event_id,
                                status: true,
                                message: Cow::Owned(String::new()),
                            }
                        } else {
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: false,
                                message: Cow::Owned(format!(
                                    "{}: unknown",
                                    MachineReadablePrefix::Error
                                )),
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Can't save event into database: {e}");
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: database error",
                                MachineReadablePrefix::Error
                            )),
                        }
                    }
                };

                send_msg(ws_tx, msg).await
            }
            ClientMessage::Req {
                subscription_id,
                filters,
            } => {
                self.handle_req(
                    session,
                    ws_tx,
                    addr,
                    subscription_id,
                    filters.into_iter().map(|f| f.into_owned()).collect(),
                    message_size,
                )
                .await
            }
            ClientMessage::Count {
                subscription_id,
                filter,
            } => {
                if let RateLimiterResponse::Limited =
                    session.check_query_rate_limit(self.queries_per_minute)
                {
                    return send_query_rate_limit_error(ws_tx, subscription_id).await;
                }

                if self.requires_read_auth(session) {
                    return send_auth_and_close(
                        ws_tx,
                        subscription_id,
                        session.nip42.generate_challenge(),
                    )
                    .await;
                }

                let mut filter = filter.into_owned();
                if let Some(policy) = self.query_policy.as_ref() {
                    if let QueryPolicyResult::Reject { prefix, message } =
                        policy.admit_query(&mut filter, addr).await
                    {
                        return send_msg(
                            ws_tx,
                            RelayMessage::Closed {
                                subscription_id,
                                message: Cow::Owned(format!("{prefix}: {message}")),
                            },
                        )
                        .await;
                    }
                }

                // A policy may broaden the filter, so authorize the mutated form.
                match self.gift_wrap_query_access(session, [&filter]) {
                    GiftWrapQueryAccess::Allowed => {}
                    GiftWrapQueryAccess::AuthRequired => {
                        return send_auth_and_close(
                            ws_tx,
                            subscription_id,
                            session.nip42.generate_challenge(),
                        )
                        .await;
                    }
                    GiftWrapQueryAccess::Forbidden => {
                        return send_gift_wrap_error(ws_tx, subscription_id).await;
                    }
                }

                let count: usize = self.database.count(filter).await?;
                send_msg(
                    ws_tx,
                    RelayMessage::Count {
                        subscription_id,
                        count,
                    },
                )
                .await
            }
            ClientMessage::Close(subscription_id) => {
                session.remove_subscription(&subscription_id);
                Ok(())
            }
            ClientMessage::Auth(event) => {
                // Charge before signature verification so malformed attempts consume quota too.
                if let RateLimiterResponse::Limited =
                    session.check_auth_rate_limit(self.auth_events_per_minute)
                {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Ok {
                            event_id: event.id,
                            status: false,
                            message: Cow::Owned(format!(
                                "{}: too many authentication attempts",
                                MachineReadablePrefix::RateLimited
                            )),
                        },
                    )
                    .await;
                }

                match session.nip42.check_challenge(&event, &self.url().await) {
                    Ok(()) => {
                        send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: true,
                                message: Cow::Owned(String::new()),
                            },
                        )
                        .await
                    }
                    Err(e) => {
                        send_msg(
                            ws_tx,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: false,
                                message: Cow::Owned(format!(
                                    "{}: {e}",
                                    MachineReadablePrefix::AuthRequired
                                )),
                            },
                        )
                        .await
                    }
                }
            }
            ClientMessage::NegOpen {
                subscription_id,
                filter,
                initial_message,
            } => {
                if let RateLimiterResponse::Limited =
                    session.check_query_rate_limit(self.queries_per_minute)
                {
                    return send_negentropy_rate_limit_error(ws_tx, subscription_id).await;
                }

                if self.subscription_id_exceeds_limit(&subscription_id) {
                    return send_msg(
                        ws_tx,
                        RelayMessage::NegErr {
                            subscription_id,
                            message: Cow::Owned(format!(
                                "{}: subscription ID exceeds max length {}",
                                MachineReadablePrefix::Blocked,
                                self.max_subid_length
                            )),
                        },
                    )
                    .await;
                }

                // Reopening an existing ID replaces state and does not consume another slot.
                if session.negentropy_subscription.len() >= self.max_negentropy_subscriptions
                    && !session
                        .negentropy_subscription
                        .contains_key(&subscription_id)
                {
                    return send_msg(
                        ws_tx,
                        RelayMessage::NegErr {
                            subscription_id,
                            message: Cow::Owned(format!(
                                "{}: too many negentropy subscriptions",
                                MachineReadablePrefix::RateLimited
                            )),
                        },
                    )
                    .await;
                }

                if self.requires_read_auth(session) {
                    return send_auth_and_neg_err(
                        ws_tx,
                        subscription_id,
                        session.nip42.generate_challenge(),
                    )
                    .await;
                }

                let mut filter = filter.into_owned();
                if let Some(policy) = self.query_policy.as_ref() {
                    if let QueryPolicyResult::Reject { prefix, message } =
                        policy.admit_query(&mut filter, addr).await
                    {
                        return send_msg(
                            ws_tx,
                            RelayMessage::NegErr {
                                subscription_id,
                                message: Cow::Owned(format!("{prefix}: {message}")),
                            },
                        )
                        .await;
                    }
                }

                // A policy may broaden the filter, so authorize the mutated form.
                match self.gift_wrap_query_access(session, [&filter]) {
                    GiftWrapQueryAccess::Allowed => {}
                    GiftWrapQueryAccess::AuthRequired => {
                        return send_auth_and_neg_err(
                            ws_tx,
                            subscription_id,
                            session.nip42.generate_challenge(),
                        )
                        .await;
                    }
                    GiftWrapQueryAccess::Forbidden => {
                        return send_gift_wrap_neg_err(ws_tx, subscription_id).await;
                    }
                }

                // Decode the initial message before any database work so a
                // malformed payload is rejected with a subscription-scoped
                // error before consuming query resources.
                let Some(initial_message) = decode_negentropy_message(&initial_message) else {
                    return send_invalid_negentropy_msg_err(ws_tx, subscription_id).await;
                };

                // Reopening the same ID replaces its index, so exclude its old budget.
                let retained_items: usize = session
                    .negentropy_subscription
                    .iter()
                    .filter(|(id, _)| id.as_str() != subscription_id.as_str())
                    .fold(0usize, |total, (_, subscription)| {
                        total.saturating_add(subscription.items)
                    });
                let remaining_items = self.max_negentropy_items.saturating_sub(retained_items);
                // One sentinel item distinguishes an exact fit from a truncated oversized query.
                let query_limit = remaining_items.saturating_add(1);
                filter.limit = Some(
                    filter
                        .limit
                        .map_or(query_limit, |limit| limit.min(query_limit)),
                );

                // Query database
                let items = self.database.negentropy_items(filter).await?;

                if items.len() > remaining_items {
                    return send_msg(
                        ws_tx,
                        RelayMessage::NegErr {
                            subscription_id,
                            message: Cow::Owned(format!(
                                "{}: too many negentropy items",
                                MachineReadablePrefix::RateLimited
                            )),
                        },
                    )
                    .await;
                }

                let item_count = items.len();

                tracing::debug!(
                    id = %subscription_id,
                    "Found {} items for negentropy reconciliation.",
                    items.len()
                );

                // Construct negentropy storage, add items and seal
                let mut storage = NegentropyStorageVector::with_capacity(items.len());
                for (id, timestamp) in items.into_iter() {
                    let id: Id = Id::from_byte_array(id.to_bytes());
                    storage.insert(timestamp.as_secs(), id)?;
                }
                storage.seal()?;

                // Construct negentropy client
                let mut negentropy = Negentropy::owned(storage, 60_000)?;

                // Reconcile
                // The payload is client-controlled: a reconciliation failure
                // must terminate only this subscription, not the connection.
                let message: Vec<u8> = match negentropy.reconcile(&initial_message) {
                    Ok(message) => message,
                    Err(e) => {
                        tracing::debug!(id = %subscription_id, "Negentropy reconciliation failed: {e}");
                        return send_invalid_negentropy_msg_err(ws_tx, subscription_id).await;
                    }
                };

                // Reply
                send_msg(
                    ws_tx,
                    RelayMessage::NegMsg {
                        subscription_id: Cow::Borrowed(&subscription_id),
                        message: Cow::Owned(faster_hex::hex_string(&message)),
                    },
                )
                .await?;

                // Update subscriptions
                session.negentropy_subscription.insert(
                    subscription_id.into_owned(),
                    NegentropySubscription {
                        state: negentropy,
                        items: item_count,
                    },
                );
                Ok(())
            }
            ClientMessage::NegMsg {
                subscription_id,
                message,
            } => {
                if let RateLimiterResponse::Limited =
                    session.check_negentropy_rate_limit(self.queries_per_minute)
                {
                    return send_negentropy_rate_limit_error(ws_tx, subscription_id).await;
                }

                let Some(buf) = decode_negentropy_message(&message) else {
                    // The failed round trip leaves the reconciliation state
                    // unusable, so drop the subscription but keep the socket.
                    session.negentropy_subscription.remove(&subscription_id);
                    return send_invalid_negentropy_msg_err(ws_tx, subscription_id).await;
                };

                match session.negentropy_subscription.get_mut(&subscription_id) {
                    Some(subscription) => {
                        // Reconcile
                        // The payload is client-controlled: a reconciliation
                        // failure must terminate only this subscription.
                        let message: Vec<u8> = match subscription.state.reconcile(&buf) {
                            Ok(message) => message,
                            Err(e) => {
                                tracing::debug!(id = %subscription_id, "Negentropy reconciliation failed: {e}");
                                session.negentropy_subscription.remove(&subscription_id);
                                return send_invalid_negentropy_msg_err(ws_tx, subscription_id)
                                    .await;
                            }
                        };

                        // Reply
                        send_msg(
                            ws_tx,
                            RelayMessage::NegMsg {
                                subscription_id,
                                message: Cow::Owned(faster_hex::hex_string(&message)),
                            },
                        )
                        .await
                    }
                    None => {
                        send_msg(
                            ws_tx,
                            RelayMessage::NegErr {
                                subscription_id,
                                message: Cow::Owned(format!(
                                    "{}: subscription not found",
                                    MachineReadablePrefix::Error
                                )),
                            },
                        )
                        .await
                    }
                }
            }
            ClientMessage::NegClose { subscription_id } => {
                session.negentropy_subscription.remove(&subscription_id);
                Ok(())
            }
        }
    }

    async fn handle_req<S>(
        &self,
        session: &mut Session<'_>,
        ws_tx: &mut WsTx<S>,
        addr: &SocketAddr,
        subscription_id: Cow<'_, SubscriptionId>,
        mut filters: Vec<Filter>,
        request_size: usize,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.subscription_id_exceeds_limit(&subscription_id) {
            return send_msg(
                ws_tx,
                RelayMessage::Closed {
                    subscription_id,
                    message: Cow::Owned(format!(
                        "{}: subscription ID exceeds max length {}",
                        MachineReadablePrefix::Blocked,
                        self.max_subid_length
                    )),
                },
            )
            .await;
        }

        if let RateLimiterResponse::Limited =
            session.check_query_rate_limit(self.queries_per_minute)
        {
            return send_query_rate_limit_error(ws_tx, subscription_id).await;
        }

        // Check number of subscriptions
        if session.subscriptions.len() >= self.rate_limit.max_reqs
            && !session.subscriptions.contains_key(&subscription_id)
        {
            return send_msg(
                ws_tx,
                RelayMessage::Closed {
                    subscription_id,
                    message: Cow::Owned(format!(
                        "{}: too many REQs",
                        MachineReadablePrefix::RateLimited
                    )),
                },
            )
            .await;
        }

        // Bound retained filter state before policy and database work.
        if filters.len() > self.max_filters_per_req {
            return send_msg(
                ws_tx,
                RelayMessage::Closed {
                    subscription_id,
                    message: Cow::Owned(format!(
                        "{}: too many filters",
                        MachineReadablePrefix::Blocked
                    )),
                },
            )
            .await;
        }

        if !session.subscription_fits(
            subscription_id.as_ref(),
            request_size,
            self.max_subscription_bytes,
        ) {
            return send_msg(
                ws_tx,
                RelayMessage::Closed {
                    subscription_id,
                    message: Cow::Owned(format!(
                        "{}: active subscriptions exceed max size {} bytes",
                        MachineReadablePrefix::RateLimited,
                        self.max_subscription_bytes
                    )),
                },
            )
            .await;
        }

        // Check NIP42
        // TODO: check if public key allowed
        if self.requires_read_auth(session) {
            return send_auth_and_close(ws_tx, subscription_id, session.nip42.generate_challenge())
                .await;
        }

        // Check query policy
        if let Some(policy) = self.query_policy.as_ref() {
            for filter in filters.iter_mut() {
                if let QueryPolicyResult::Reject { prefix, message } =
                    policy.admit_query(filter, addr).await
                {
                    return send_msg(
                        ws_tx,
                        RelayMessage::Closed {
                            subscription_id,
                            message: Cow::Owned(format!("{prefix}: {message}",)),
                        },
                    )
                    .await;
                }
            }
        }

        // Policies may broaden filters, so authorize their final mutated forms.
        match self.gift_wrap_query_access(session, &filters) {
            GiftWrapQueryAccess::Allowed => {}
            GiftWrapQueryAccess::AuthRequired => {
                return send_auth_and_close(
                    ws_tx,
                    subscription_id,
                    session.nip42.generate_challenge(),
                )
                .await;
            }
            GiftWrapQueryAccess::Forbidden => {
                return send_gift_wrap_error(ws_tx, subscription_id).await;
            }
        }

        for filter in filters.iter_mut() {
            match filter.limit {
                Some(filter_limit) => {
                    // If the limit is greater than the max limit, use the max limit
                    if filter_limit > self.max_filter_limit {
                        filter.limit = Some(self.max_filter_limit)
                    }
                }
                // No limit set, if the filter has IDs, set the limit to the number of IDs, otherwise to the default limit.
                None => match filter.ids.as_ref() {
                    Some(ids) => {
                        if ids.len() > self.max_filter_limit {
                            return send_msg(
                                ws_tx,
                                RelayMessage::Closed {
                                    subscription_id,
                                    message: Cow::Owned(format!(
                                        "{}: requested too many event IDs",
                                        MachineReadablePrefix::Blocked
                                    )),
                                },
                            )
                            .await;
                        }

                        filter.limit = Some(ids.len());
                    }
                    None => filter.limit = Some(self.max_filter_limit),
                },
            }
        }

        // Check if subscription has IDs
        let ids_len: Option<usize> = filters
            .iter()
            .map(|f| f.ids.as_ref().map(|ids| ids.len()))
            .sum();

        // Query database
        let events: BTreeSet<Event> = if self.test.send_random_events {
            let mut events: BTreeSet<Event> = BTreeSet::new();

            let keys = Keys::generate();

            for _ in 0..500 {
                events.insert(EventBuilder::new(Kind::TextNote, "Test").finalize(&keys)?);
            }

            events
        } else {
            let mut events: BTreeSet<Event> = BTreeSet::new();

            for filter in filters.iter() {
                let res = self.database.query(filter.clone()).await?;
                events.extend(res);
            }

            events
        };

        let events_len: usize = events.len();

        tracing::debug!("Found {events_len} events for subscription '{subscription_id}'",);

        let now = Timestamp::now();
        for event in events {
            if event.is_expired_at(now) {
                continue;
            }
            send_msg(
                ws_tx,
                RelayMessage::Event {
                    subscription_id: Cow::Borrowed(subscription_id.as_ref()),
                    event: Cow::Owned(event),
                },
            )
            .await?;
        }

        send_msg(
            ws_tx,
            RelayMessage::EndOfStoredEvents(Cow::Borrowed(subscription_id.as_ref())),
        )
        .await?;

        match ids_len {
            // Requested IDs len is the same as the query output, close the subscription.
            Some(ids_len) if ids_len == events_len => {
                send_msg(
                    ws_tx,
                    RelayMessage::Closed {
                        subscription_id,
                        message: Cow::Borrowed(""),
                    },
                )
                .await?;
            }
            // The stored events are all served, but miss some: save the subscription.
            _ => {
                // Save the subscription
                session.insert_subscription(
                    subscription_id.clone().into_owned(),
                    filters,
                    request_size,
                );
            }
        }

        Ok(())
    }

    fn requires_read_auth(&self, session: &Session<'_>) -> bool {
        self.nip42
            .as_ref()
            .is_some_and(|nip42| nip42.mode.is_read())
            && !session.nip42.is_authenticated()
    }

    fn subscription_id_exceeds_limit(&self, subscription_id: &SubscriptionId) -> bool {
        // Bound retained and echoed UTF-8 bytes, not the number of Unicode scalar values.
        subscription_id.as_str().len() > self.max_subid_length
    }

    fn gift_wrap_query_access<'a, I>(
        &self,
        session: &Session<'_>,
        filters: I,
    ) -> GiftWrapQueryAccess
    where
        I: IntoIterator<Item = &'a Filter>,
    {
        if !self.auth_dm {
            return GiftWrapQueryAccess::Allowed;
        }

        // A missing kind constraint is a wildcard and can therefore select gift wraps.
        let gift_wrap_filters = filters.into_iter().filter(|filter| {
            filter
                .kinds
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&Kind::GiftWrap))
        });
        let Some(public_key) = session.nip42.public_key else {
            return if gift_wrap_filters.count() > 0 {
                GiftWrapQueryAccess::AuthRequired
            } else {
                GiftWrapQueryAccess::Allowed
            };
        };

        let public_key = public_key.to_hex();
        for filter in gift_wrap_filters {
            let Some(public_keys) = filter.generic_tags.get(&SingleLetterTag::LOWERCASE_P) else {
                return GiftWrapQueryAccess::Forbidden;
            };
            if public_keys.len() != 1 || !public_keys.contains(&public_key) {
                return GiftWrapQueryAccess::Forbidden;
            }
        }

        GiftWrapQueryAccess::Allowed
    }
}

#[inline]
async fn send_msg<S>(tx: &mut WsTx<S>, msg: RelayMessage<'_>) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tx.send(Message::Text(msg.as_json().into()))
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    Ok(())
}

async fn send_query_rate_limit_error<S>(
    tx: &mut WsTx<S>,
    subscription_id: Cow<'_, SubscriptionId>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_msg(
        tx,
        RelayMessage::Closed {
            subscription_id,
            message: Cow::Owned(format!(
                "{}: too many queries",
                MachineReadablePrefix::RateLimited
            )),
        },
    )
    .await
}

async fn send_negentropy_rate_limit_error<S>(
    tx: &mut WsTx<S>,
    subscription_id: Cow<'_, SubscriptionId>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_msg(
        tx,
        RelayMessage::NegErr {
            subscription_id,
            message: Cow::Owned(format!(
                "{}: too many queries",
                MachineReadablePrefix::RateLimited
            )),
        },
    )
    .await
}

async fn send_auth_and_close<S>(
    tx: &mut WsTx<S>,
    subscription_id: Cow<'_, SubscriptionId>,
    challenge: String,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Generate and send AUTH challenge
    send_msg(
        tx,
        RelayMessage::Auth {
            challenge: Cow::Owned(challenge),
        },
    )
    .await?;

    // Return error
    send_msg(
        tx,
        RelayMessage::Closed {
            subscription_id,
            message: Cow::Owned(format!(
                "{}: you must auth",
                MachineReadablePrefix::AuthRequired
            )),
        },
    )
    .await
}

async fn send_auth_and_neg_err<S>(
    tx: &mut WsTx<S>,
    subscription_id: Cow<'_, SubscriptionId>,
    challenge: String,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_msg(
        tx,
        RelayMessage::Auth {
            challenge: Cow::Owned(challenge),
        },
    )
    .await?;

    send_msg(
        tx,
        RelayMessage::NegErr {
            subscription_id,
            message: Cow::Owned(format!(
                "{}: you must auth",
                MachineReadablePrefix::AuthRequired
            )),
        },
    )
    .await
}

/// Send gift wrap error, when a user ask for someone else DMs
#[inline]
async fn send_gift_wrap_error<S>(
    tx: &mut WsTx<S>,
    subscription_id: Cow<'_, SubscriptionId>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_msg(
        tx,
        RelayMessage::Closed {
            subscription_id,
            message: Cow::Owned(format!(
                "{}: you cannot request another user's gift wrap",
                MachineReadablePrefix::Error
            )),
        },
    )
    .await
}

#[inline]
async fn send_gift_wrap_neg_err<S>(
    tx: &mut WsTx<S>,
    subscription_id: Cow<'_, SubscriptionId>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_msg(
        tx,
        RelayMessage::NegErr {
            subscription_id,
            message: Cow::Owned(format!(
                "{}: you cannot request another user's gift wrap",
                MachineReadablePrefix::Error
            )),
        },
    )
    .await
}

/// Decode a hex-encoded negentropy payload.
///
/// `faster_hex::hex_decode` requires a caller-sized output buffer, so
/// odd-length input must be rejected explicitly before halving the length.
fn decode_negentropy_message(message: &str) -> Option<Vec<u8>> {
    let size: usize = message.len().checked_div(2)?;

    let mut buf: Vec<u8> = vec![0u8; size];
    faster_hex::hex_decode(message.as_bytes(), &mut buf).ok()?;

    Some(buf)
}

#[inline]
async fn send_invalid_negentropy_msg_err<S>(
    tx: &mut WsTx<S>,
    subscription_id: Cow<'_, SubscriptionId>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_msg(
        tx,
        RelayMessage::NegErr {
            subscription_id,
            message: Cow::Owned(format!(
                "{}: invalid negentropy message",
                MachineReadablePrefix::Error
            )),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct RejectWrites;

    impl WritePolicy for RejectWrites {
        fn admit_event<'a>(
            &'a self,
            _event: &'a Event,
            _addr: &'a SocketAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = WritePolicyResult> + Send + 'a>>
        {
            Box::pin(async {
                WritePolicyResult::reject(MachineReadablePrefix::Blocked, "write rejected")
            })
        }
    }

    #[derive(Debug)]
    struct ReplaceWithGiftWrap;

    impl QueryPolicy for ReplaceWithGiftWrap {
        fn admit_query<'a>(
            &'a self,
            query: &'a mut Filter,
            _addr: &'a SocketAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = QueryPolicyResult> + Send + 'a>>
        {
            Box::pin(async move {
                *query = Filter::new().kind(Kind::GiftWrap);
                QueryPolicyResult::Accept
            })
        }
    }

    fn session(public_key: Option<PublicKey>) -> Session<'static> {
        Session {
            subscriptions: HashMap::new(),
            subscription_bytes: 0,
            negentropy_subscription: HashMap::new(),
            nip42: Nip42Session {
                public_key,
                challenges: HashSet::new(),
            },
            write_tokens: Tokens::new(1),
            query_tokens: Tokens::new(1),
            negentropy_tokens: Tokens::new(1),
            auth_tokens: Tokens::new(1),
            message_tokens: Tokens::new(1),
        }
    }

    #[test]
    fn local_relay_defaults_bound_connection_resources() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default());
        let config = relay.websocket_config();

        assert_eq!(relay.pending_handshakes_limit.available_permits(), 128);
        assert_eq!(
            relay.connections_limit.available_permits(),
            Semaphore::MAX_PERMITS
        );
        assert_eq!(relay.queries_per_minute, 1_200);
        assert_eq!(relay.auth_events_per_minute, 30);
        assert_eq!(relay.messages_per_minute, 6_000);
        assert_eq!(relay.max_filters_per_req, 20);
        assert_eq!(relay.max_filter_limit, 500);
        assert_eq!(relay.max_subscription_bytes, 1024 * 1024);
        assert_eq!(relay.max_negentropy_items, 50_000);
        assert_eq!(config.max_message_size, Some(5 * 1024 * 1024));
        assert_eq!(config.max_frame_size, Some(5 * 1024 * 1024));
        assert_eq!(relay.websocket_handshake_timeout.as_secs(), 10);
    }

    #[test]
    fn local_relay_connection_limits_are_configurable() {
        let relay = InnerLocalRelay::new(
            LocalRelayBuilder::default()
                .max_connections(4)
                .max_websocket_message_size(1024)
                .websocket_handshake_timeout(Duration::from_secs(2)),
        );
        let config = relay.websocket_config();

        assert_eq!(relay.pending_handshakes_limit.available_permits(), 128);
        assert_eq!(relay.connections_limit.available_permits(), 4);
        assert_eq!(config.max_message_size, Some(1024));
        assert_eq!(config.max_frame_size, Some(1024));
        assert_eq!(relay.websocket_handshake_timeout.as_secs(), 2);
    }

    #[test]
    fn subscription_budget_tracks_replacement_and_removal() {
        let mut session = session(None);
        let id = SubscriptionId::new("test");

        session.insert_subscription(id.clone(), vec![Filter::new()], 7);
        assert_eq!(session.subscription_bytes, 7);
        assert!(session.subscription_fits(&id, 10, 10));

        session.insert_subscription(id.clone(), vec![Filter::new()], 10);
        assert_eq!(session.subscription_bytes, 10);

        session.remove_subscription(&id);
        assert_eq!(session.subscription_bytes, 0);
    }

    #[tokio::test]
    async fn write_policy_is_applied_before_duplicate_lookup() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().write_policy(RejectWrites));
        let event = EventBuilder::new(Kind::TextNote, "already stored")
            .finalize(&Keys::generate())
            .unwrap();
        relay.database.save_event(&event).await.unwrap();

        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let server = WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (mut server_tx, _) = server.split();
        let mut session = session(None);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let message_size = event.as_json().len() + 10;
        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Event(Cow::Owned(event)),
                &addr,
                message_size,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::Ok {
                status: false,
                message,
                ..
            } if message == "blocked: write rejected"
        ));
    }

    #[tokio::test]
    async fn gift_wrap_access_is_checked_after_query_policy_mutation() {
        let relay = InnerLocalRelay::new(
            LocalRelayBuilder::default()
                .auth_dm(true)
                .query_policy(ReplaceWithGiftWrap),
        );
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let server = WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (mut server_tx, _) = server.split();
        let mut session = session(None);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Count {
                    subscription_id: Cow::Owned(SubscriptionId::new("gift-wrap")),
                    filter: Cow::Owned(Filter::new().kind(Kind::TextNote)),
                },
                &addr,
                0,
            )
            .await
            .unwrap();

        let auth = client.next().await.unwrap().unwrap();
        let closed = client.next().await.unwrap().unwrap();
        assert!(matches!(
            auth,
            Message::Text(json)
                if matches!(
                    RelayMessage::from_json(json.as_bytes()).unwrap(),
                    RelayMessage::Auth { .. }
                )
        ));
        assert!(matches!(
            closed,
            Message::Text(json)
                if matches!(
                    RelayMessage::from_json(json.as_bytes()).unwrap(),
                    RelayMessage::Closed { message, .. }
                        if message.starts_with("auth-required:")
                )
        ));
    }

    #[tokio::test]
    async fn oversized_active_subscription_is_rejected() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().max_subscription_bytes(10));
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let server = WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (mut server_tx, _) = server.split();
        let mut session = session(None);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Req {
                    subscription_id: Cow::Owned(SubscriptionId::new("oversized")),
                    filters: vec![Cow::Owned(Filter::new())],
                },
                &addr,
                11,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == "oversized"
                && message == "rate-limited: active subscriptions exceed max size 10 bytes"
        ));
        assert!(session.subscriptions.is_empty());
        assert_eq!(session.subscription_bytes, 0);
    }

    #[tokio::test]
    async fn excessive_req_filters_are_rejected() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().max_filters_per_req(1));
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let server = WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (mut server_tx, _) = server.split();
        let mut session = session(None);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Req {
                    subscription_id: Cow::Owned(SubscriptionId::new("filters")),
                    filters: vec![Cow::Owned(Filter::new()), Cow::Owned(Filter::new())],
                },
                &addr,
                4,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == "filters"
                && message == "blocked: too many filters"
        ));
    }

    #[tokio::test]
    async fn zero_query_rate_rejects_query_starts() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().queries_per_minute(0));
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let server = WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (mut server_tx, _) = server.split();
        let mut session = session(None);
        session.query_tokens = Tokens::new(0);
        session.negentropy_tokens = Tokens::new(0);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Req {
                    subscription_id: Cow::Owned(SubscriptionId::new("limited")),
                    filters: vec![Cow::Owned(Filter::new())],
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == "limited"
                && message == "rate-limited: too many queries"
        ));

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::NegMsg {
                    subscription_id: Cow::Owned(SubscriptionId::new("limited-neg-msg")),
                    message: Cow::Borrowed("6100"),
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "limited-neg-msg"
                && message == "rate-limited: too many queries"
        ));

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Count {
                    subscription_id: Cow::Owned(SubscriptionId::new("limited-count")),
                    filter: Cow::Owned(Filter::new()),
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == "limited-count"
                && message == "rate-limited: too many queries"
        ));

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::NegOpen {
                    subscription_id: Cow::Owned(SubscriptionId::new("limited-neg")),
                    filter: Cow::Owned(Filter::new()),
                    initial_message: Cow::Borrowed(""),
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "limited-neg"
                && message == "rate-limited: too many queries"
        ));
    }

    #[tokio::test]
    async fn negentropy_continuations_do_not_consume_query_start_allowance() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().queries_per_minute(1));
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let server = WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (mut server_tx, _) = server.split();
        let mut session = session(None);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::NegMsg {
                    subscription_id: Cow::Owned(SubscriptionId::new("neg")),
                    message: Cow::Borrowed("6100"),
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "neg"
                && message == "error: subscription not found"
        ));
        assert_eq!(session.query_tokens.count, 1);
        assert_eq!(session.negentropy_tokens.count, 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::NegMsg {
                    subscription_id: Cow::Owned(SubscriptionId::new("limited-neg")),
                    message: Cow::Borrowed("6100"),
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "limited-neg"
                && message == "rate-limited: too many queries"
        ));
        assert_eq!(session.query_tokens.count, 1);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Req {
                    subscription_id: Cow::Owned(SubscriptionId::new("allowed")),
                    filters: vec![Cow::Owned(Filter::new())],
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::EndOfStoredEvents(subscription_id)
                if subscription_id.as_str() == "allowed"
        ));
        assert_eq!(session.query_tokens.count, 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Count {
                    subscription_id: Cow::Owned(SubscriptionId::new("limited")),
                    filter: Cow::Owned(Filter::new()),
                },
                &addr,
                2,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        let Message::Text(response) = response else {
            panic!("unexpected WebSocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(response.as_bytes()).unwrap(),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == "limited"
                && message == "rate-limited: too many queries"
        ));
    }

    #[tokio::test]
    async fn zero_auth_rate_rejects_before_event_verification() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().auth_events_per_minute(0));
        let event = EventBuilder::new(Kind::TextNote, "not an auth event")
            .finalize(&Keys::generate())
            .unwrap();
        let (server_stream, client_stream) = tokio::io::duplex(16 * 1024);
        let server = WebSocketStream::from_raw_socket(server_stream, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(client_stream, Role::Client, None).await;
        let (mut server_tx, _) = server.split();
        let mut session = session(None);
        session.auth_tokens = Tokens::new(0);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        relay
            .handle_client_msg(
                &mut session,
                &mut server_tx,
                ClientMessage::Auth(Cow::Owned(event)),
                &addr,
                0,
            )
            .await
            .unwrap();

        let response = client.next().await.unwrap().unwrap();
        assert!(matches!(
            response,
            Message::Text(json)
                if matches!(
                    RelayMessage::from_json(json.as_bytes()).unwrap(),
                    RelayMessage::Ok { status: false, message, .. }
                        if message == "rate-limited: too many authentication attempts"
                )
        ));
    }

    #[test]
    fn gift_wrap_auth_restricts_filters_without_kinds() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().auth_dm(true));
        let filter = Filter::new();

        assert_eq!(
            relay.gift_wrap_query_access(&session(None), [&filter]),
            GiftWrapQueryAccess::AuthRequired
        );
    }

    #[test]
    fn gift_wrap_auth_only_allows_the_authenticated_public_key() {
        let relay = InnerLocalRelay::new(LocalRelayBuilder::default().auth_dm(true));
        let public_key = Keys::generate().public_key();
        let other_public_key = Keys::generate().public_key();

        let own_filter = Filter::new().kind(Kind::GiftWrap).pubkey(public_key);
        assert_eq!(
            relay.gift_wrap_query_access(&session(Some(public_key)), [&own_filter]),
            GiftWrapQueryAccess::Allowed
        );

        let other_filter = Filter::new().kind(Kind::GiftWrap).pubkey(other_public_key);
        assert_eq!(
            relay.gift_wrap_query_access(&session(Some(public_key)), [&other_filter]),
            GiftWrapQueryAccess::Forbidden
        );
    }
}
