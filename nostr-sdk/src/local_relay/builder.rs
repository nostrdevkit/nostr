// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use nostr::message::MachineReadablePrefix;
use nostr_database::prelude::*;

use super::local::LocalRelay;

pub(super) const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 128;
pub(super) const DEFAULT_MAX_FILTERS_PER_REQ: usize = 20;
pub(super) const DEFAULT_MAX_EVENT_SIZE: usize = 64 * 1024;
pub(super) const DEFAULT_MAX_NEGENTROPY_ITEMS: usize = 50_000;
pub(super) const DEFAULT_MAX_SUBSCRIPTION_BYTES: usize = 1024 * 1024;
pub(super) const DEFAULT_MAX_WEBSOCKET_MESSAGE_SIZE: usize = 5 * 1024 * 1024;
pub(super) const DEFAULT_WEBSOCKET_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const DEFAULT_QUERIES_PER_MINUTE: u32 = 1_200;
pub(super) const DEFAULT_AUTH_EVENTS_PER_MINUTE: u32 = 30;
pub(super) const DEFAULT_MESSAGES_PER_MINUTE: u32 = 6_000;

/// Rate limit
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Max active REQs
    pub max_reqs: usize,
    /// Max events per minutes
    pub notes_per_minute: u32,
    //pub whitelist: Option<Vec<String>>,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            max_reqs: 500,
            notes_per_minute: 60,
        }
    }
}

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use `LocalRelayBuilderMode` instead")]
pub type RelayBuilderMode = LocalRelayBuilderMode;

/// Mode
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalRelayBuilderMode {
    /// Generic mode
    #[default]
    Generic,
    /// Accept only events that are authored by or contains a specific public key
    ///
    /// All other events are rejected
    PublicKey(PublicKey),
}

/// Write policy result
pub enum WritePolicyResult {
    /// Continue processing the event without taking any action.
    Accept,
    /// Stop processing the event and reply with a OK message with a status.
    Reject {
        /// The message prefix
        prefix: MachineReadablePrefix,
        /// The rejection message to be sent.
        message: Cow<'static, str>,
        /// Indicates whether the operation was successful.
        status: bool,
    },
}

impl WritePolicyResult {
    /// Stops processing and send a success message.
    #[inline]
    pub fn ok_msg<S>(prefix: MachineReadablePrefix, msg: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self::Reject {
            message: msg.into(),
            status: true,
            prefix,
        }
    }

    /// Stops processing and send a rejection message.
    #[inline]
    pub fn reject<S>(prefix: MachineReadablePrefix, msg: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self::Reject {
            message: msg.into(),
            status: false,
            prefix,
        }
    }

    /// Check if is [WritePolicyResult::Accept]
    #[inline]
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accept)
    }

    /// Check if is [WritePolicyResult::Reject]
    #[inline]
    pub fn is_reject(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }
}

/// Query policy result
pub enum QueryPolicyResult {
    /// Accept the query
    Accept,
    /// Reject the query
    Reject {
        /// The reject message prefix.
        prefix: MachineReadablePrefix,
        /// The reject message.
        message: Cow<'static, str>,
    },
}

impl QueryPolicyResult {
    /// Reject the query
    #[inline]
    pub fn reject<S>(prefix: MachineReadablePrefix, msg: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        Self::Reject {
            prefix,
            message: msg.into(),
        }
    }

    /// Check if is [QueryPolicyResult::Accept]
    #[inline]
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accept)
    }

    /// Check if is [QueryPolicyResult::Reject]
    #[inline]
    pub fn is_reject(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }
}

/// Custom policy for accepting events into the relay database
pub trait WritePolicy: fmt::Debug + Send + Sync {
    /// Check if the policy should accept an event
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        addr: &'a SocketAddr,
    ) -> Pin<Box<dyn Future<Output = WritePolicyResult> + Send + 'a>>;
}

/// Filters REQ's to the internal relay database
pub trait QueryPolicy: fmt::Debug + Send + Sync {
    /// Check if the policy should accept a query
    fn admit_query<'a>(
        &'a self,
        query: &'a mut Filter,
        addr: &'a SocketAddr,
    ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>>;
}

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use `LocalRelayTestOptions` instead")]
pub type RelayTestOptions = LocalRelayTestOptions;

/// Testing options
#[derive(Debug, Clone, Default)]
pub struct LocalRelayTestOptions {
    /// Simulate unresponsive connection
    pub unresponsive_connection: Option<Duration>,
    /// Send random events to the clients
    pub send_random_events: bool,
}

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use `LocalRelayBuilderNip42Mode` instead")]
pub type RelayBuilderNip42Mode = LocalRelayBuilderNip42Mode;

/// NIP42 mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalRelayBuilderNip42Mode {
    /// Require authentication for writing
    Write,
    /// Require authentication for reading
    Read,
    /// Always require authentication
    #[default]
    Both,
}

impl LocalRelayBuilderNip42Mode {
    /// Check if is [`LocalRelayBuilderNip42Mode::Read`] or [`LocalRelayBuilderNip42Mode::Both`]
    #[inline]
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Read | Self::Both)
    }

    /// Check if is [`LocalRelayBuilderNip42Mode::Write`] or [`LocalRelayBuilderNip42Mode::Both`]
    #[inline]
    pub fn is_write(&self) -> bool {
        matches!(self, Self::Write | Self::Both)
    }
}

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use `LocalRelayBuilderNip42` instead")]
pub type RelayBuilderNip42 = LocalRelayBuilderNip42;

/// NIP42 options
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalRelayBuilderNip42 {
    /// Mode
    pub mode: LocalRelayBuilderNip42Mode,
    // /// Allowed public keys
    // pub allowed: HashSet<PublicKey>,
}

impl LocalRelayBuilderNip42 {
    /// Creates a new instance configured for write-only.
    #[inline]
    pub fn write() -> Self {
        Self {
            mode: LocalRelayBuilderNip42Mode::Write,
        }
    }

    /// Creates a new instance configured for read-only.
    #[inline]
    pub fn read() -> Self {
        Self {
            mode: LocalRelayBuilderNip42Mode::Read,
        }
    }

    /// Creates a new instance configured for both read and write.
    #[inline]
    pub fn read_and_write() -> Self {
        Self {
            mode: LocalRelayBuilderNip42Mode::Both,
        }
    }
}

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use `LocalRelayBuilder` instead")]
pub type RelayBuilder = LocalRelayBuilder;

/// Local relay builder
#[derive(Debug, Clone)]
pub struct LocalRelayBuilder {
    /// IP address
    pub(crate) addr: Option<IpAddr>,
    /// Port
    pub(crate) port: Option<u16>,
    /// Database
    pub(crate) database: Option<Arc<dyn NostrDatabase>>,
    /// Mode
    pub(crate) mode: LocalRelayBuilderMode,
    /// Rate limit
    pub(crate) rate_limit: RateLimit,
    /// Query-start messages per minute per connection
    pub(crate) queries_per_minute: u32,
    /// Authentication events per minute per connection
    pub(crate) auth_events_per_minute: u32,
    /// Text messages per minute per connection
    pub(crate) messages_per_minute: u32,
    /// NIP42 options
    pub(crate) nip42: Option<LocalRelayBuilderNip42>,
    /// Max connections allowed
    pub(crate) max_connections: Option<usize>,
    /// Max WebSocket message size
    pub(crate) max_websocket_message_size: usize,
    /// Max event size in bytes
    pub(crate) max_event_size: usize,
    /// WebSocket handshake timeout
    pub(crate) websocket_handshake_timeout: Duration,
    /// Max subscription ID length in UTF-8 bytes
    pub(crate) max_subid_length: usize,
    /// Max filters in one REQ
    pub(crate) max_filters_per_req: usize,
    /// Maximum records that can be returned per filter
    pub(crate) max_filter_limit: usize,
    /// Max total bytes retained by active subscriptions per connection
    pub(crate) max_subscription_bytes: usize,
    /// Max active negentropy subscriptions per connection
    pub(crate) max_negentropy_subscriptions: usize,
    /// Max total negentropy items retained per connection
    pub(crate) max_negentropy_items: usize,
    /// Enables NIP-42 authentication for kind 1059 (GiftWrap), ensuring the
    /// authenticated pubkey is the only "p" tag
    pub(crate) auth_dm: bool,
    /// Min POW difficulty
    pub(crate) min_pow: Option<u8>,
    /// Kinds blacklist
    pub(crate) kinds_blacklist: HashSet<Kind>,
    /// Write policy
    pub(crate) write_policy: Option<Arc<dyn WritePolicy>>,
    /// Query policy
    pub(crate) query_policy: Option<Arc<dyn QueryPolicy>>,
    /// Test options
    pub(crate) test: LocalRelayTestOptions,
}

impl Default for LocalRelayBuilder {
    fn default() -> Self {
        // The list of kinds originates from a commit message by Alex Gleason:
        // <https://gitlab.com/soapbox-pub/ditto-relay/-/commit/ddce82c040e78cc37d3a56b8a7f0448daddf3df2>
        const BLACKLISTED_KINDS: [Kind; 5] = [
            Kind::Seal,           // Only valid inside a gift-wrap event; meaningless on its own.
            Kind::ZapRequest,     // Sent directly to the LNURL callback server, never to relays.
            Kind::Authentication, // Carried exclusively inside `["AUTH", ...]` frames.
            Kind::BlossomAuth, // An HTTP Authorization header artifact, not an independent event.
            Kind::HttpAuth,    // An HTTP Authorization header artifact, not an independent event.
        ];

        Self {
            addr: None,
            port: None,
            database: None,
            mode: LocalRelayBuilderMode::default(),
            rate_limit: RateLimit::default(),
            queries_per_minute: DEFAULT_QUERIES_PER_MINUTE,
            auth_events_per_minute: DEFAULT_AUTH_EVENTS_PER_MINUTE,
            messages_per_minute: DEFAULT_MESSAGES_PER_MINUTE,
            nip42: None,
            max_connections: None,
            max_websocket_message_size: DEFAULT_MAX_WEBSOCKET_MESSAGE_SIZE,
            max_event_size: DEFAULT_MAX_EVENT_SIZE,
            websocket_handshake_timeout: DEFAULT_WEBSOCKET_HANDSHAKE_TIMEOUT,
            max_subid_length: 250,
            max_filters_per_req: DEFAULT_MAX_FILTERS_PER_REQ,
            max_filter_limit: 500,
            max_subscription_bytes: DEFAULT_MAX_SUBSCRIPTION_BYTES,
            max_negentropy_subscriptions: 10,
            max_negentropy_items: DEFAULT_MAX_NEGENTROPY_ITEMS,
            auth_dm: false,
            min_pow: None,
            kinds_blacklist: HashSet::from(BLACKLISTED_KINDS),
            write_policy: None,
            query_policy: None,
            test: LocalRelayTestOptions::default(),
        }
    }
}

impl LocalRelayBuilder {
    /// Set IP address
    #[inline]
    pub fn addr(mut self, ip: IpAddr) -> Self {
        self.addr = Some(ip);
        self
    }

    /// Set port
    #[inline]
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set database
    #[inline]
    pub fn database<D>(mut self, database: D) -> Self
    where
        D: IntoNostrDatabase,
    {
        self.database = Some(database.into_nostr_database());
        self
    }

    /// Set mode
    #[inline]
    pub fn mode(mut self, mode: LocalRelayBuilderMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set rate limit
    #[inline]
    pub fn rate_limit(mut self, limit: RateLimit) -> Self {
        self.rate_limit = limit;
        self
    }

    /// Sets the maximum query messages per minute for each connection.
    ///
    /// `REQ`, `COUNT`, and `NEG-OPEN` messages share one query-start allowance.
    /// NIP-77 `NEG-MSG` continuation frames use a separate allowance with the
    /// same capacity, so reconciliation traffic cannot exhaust the query-start
    /// allowance. Every frame is also covered by the connection-wide
    /// [`LocalRelayBuilder::messages_per_minute`] limit.
    ///
    /// Defaults to 1,200 for each allowance.
    #[inline]
    pub fn queries_per_minute(mut self, max: u32) -> Self {
        self.queries_per_minute = max;
        self
    }

    /// Sets the maximum NIP-42 authentication events per minute for each connection.
    /// Defaults to 30.
    #[inline]
    pub fn auth_events_per_minute(mut self, max: u32) -> Self {
        self.auth_events_per_minute = max;
        self
    }

    /// Sets the maximum WebSocket messages per minute for each connection.
    ///
    /// Defaults to 6,000. This coarse connection-wide catch-all aggregates all
    /// activity sharing a WebSocket and bounds malformed and non-text frames,
    /// while operation-specific limits remain the primary controls for valid
    /// protocol messages.
    #[inline]
    pub fn messages_per_minute(mut self, max: u32) -> Self {
        self.messages_per_minute = max;
        self
    }

    /// Require NIP42 authentication
    #[inline]
    pub fn nip42(mut self, opts: LocalRelayBuilderNip42) -> Self {
        self.nip42 = Some(opts);
        self
    }

    /// Set number of max connections allowed. By default, connections are unlimited.
    #[inline]
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Set the maximum WebSocket message size in bytes. Defaults to 5 MiB.
    #[inline]
    pub fn max_websocket_message_size(mut self, max: usize) -> Self {
        self.max_websocket_message_size = max;
        self
    }

    /// Sets the maximum accepted event size in bytes. Defaults to 64KB.
    #[inline]
    pub fn max_event_size(mut self, max: usize) -> Self {
        self.max_event_size = max;
        self
    }

    /// Set the WebSocket handshake timeout. Defaults to 10 seconds.
    #[inline]
    pub fn websocket_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.websocket_handshake_timeout = timeout;
        self
    }

    /// Sets the maximum subscription ID length in UTF-8 bytes. Defaults to 250.
    #[inline]
    pub fn max_subid_length(mut self, max: usize) -> Self {
        self.max_subid_length = max;
        self
    }

    /// Sets the maximum number of filters allowed in a REQ. Defaults to 20.
    #[inline]
    pub fn max_filters_per_req(mut self, max: usize) -> Self {
        self.max_filters_per_req = max;
        self
    }

    /// Sets the maximum limit for the filter. Defaults to 500.
    #[inline]
    pub fn max_filter_limit(mut self, max: usize) -> Self {
        self.max_filter_limit = max;
        self
    }

    /// Sets the maximum total bytes retained by active subscriptions per connection.
    /// Defaults to 1 MiB.
    #[inline]
    pub fn max_subscription_bytes(mut self, max: usize) -> Self {
        self.max_subscription_bytes = max;
        self
    }

    /// Sets the maximum number of active negentropy subscriptions per connection.
    /// Defaults to 10.
    #[inline]
    pub fn max_negentropy_subscriptions(mut self, max: usize) -> Self {
        self.max_negentropy_subscriptions = max;
        self
    }

    /// Sets the maximum total number of negentropy items retained per connection.
    /// Defaults to 50,000.
    #[inline]
    pub fn max_negentropy_items(mut self, max: usize) -> Self {
        self.max_negentropy_items = max;
        self
    }

    /// This is a no-op
    #[deprecated(note = "Use max_filters_per_req instead")]
    pub fn max_query_results(self, _max: usize) -> Self {
        self
    }

    /// Sets the maximum limit for the filter. Defaults to 500.
    #[deprecated(note = "Use max_filter_limit instead")]
    pub fn default_filter_limit(self, limit: usize) -> Self {
        self.max_filter_limit(limit)
    }

    /// If enabled, NIP-42 will be used for DMs, returning GiftWrap events for
    /// the mentioned public key only.
    #[inline]
    pub fn auth_dm(mut self, enable: bool) -> Self {
        self.auth_dm = enable;
        self
    }

    /// Sets the minimum Proof of Work difficulty.
    ///
    /// Only values `> 0` are accepted!
    #[inline]
    pub fn min_pow(mut self, difficulty: u8) -> Self {
        if difficulty > 0 {
            self.min_pow = Some(difficulty);
        }
        self
    }

    /// Reject events matching the given kinds
    #[inline]
    pub fn blacklist_kinds(mut self, kinds: &[Kind]) -> Self {
        self.kinds_blacklist.extend(kinds);
        self
    }

    /// Set a **write** policy plugin
    #[inline]
    pub fn write_policy<T>(mut self, policy: T) -> Self
    where
        T: WritePolicy + 'static,
    {
        self.write_policy = Some(Arc::new(policy));
        self
    }

    /// Set a **query** policy plugin
    #[inline]
    pub fn query_policy<T>(mut self, policy: T) -> Self
    where
        T: QueryPolicy + 'static,
    {
        self.query_policy = Some(Arc::new(policy));
        self
    }

    /// Testing options
    #[inline]
    pub(crate) fn test(mut self, test: LocalRelayTestOptions) -> Self {
        self.test = test;
        self
    }

    /// Build local relay
    #[inline]
    pub fn build(self) -> LocalRelay {
        LocalRelay::from_builder(self)
    }
}
