use std::collections::{BTreeSet, HashSet};
use std::future::IntoFuture;
use std::iter;
use std::time::Duration;

use nostr::event::{Event, EventId, Kind};
use nostr::key::PublicKey;
use nostr::types::RelayUrl;
use nostr_gossip::{BestRelaySelection, GossipListKind};

use crate::client::gossip::Gossip;
use crate::client::url::RelayUrlArg;
use crate::client::{Client, Output};
use crate::error::Error;
use crate::future::BoxedFuture;
use crate::relay::{EventSendStatus, RelayCapabilities};

/// Output returned when sending an event.
pub type SendEventOutput = Output<EventId, EventSendStatus, String>;

enum OverwritePolicy<'url> {
    // All WRITE relays
    Broadcast,
    // To specific relays
    To(Vec<RelayUrlArg<'url>>),
    // To NIP-17 relays
    ToNip17,
    // To NIP-65 relays
    ToNip65,
}

// /// Error returned when building an invalid [`AckPolicy`].
// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub enum AckPolicyError {
//     /// `AtLeast` ratio must satisfy `0.0 < ratio <= 1.0`.
//     InvalidAtLeastRatio,
// }
//
// impl std::error::Error for AckPolicyError {}
//
// impl fmt::Display for AckPolicyError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             Self::InvalidAtLeastRatio => {
//                 f.write_str("invalid ack policy ratio: expected 0.0 < ratio <= 1.0")
//             }
//         }
//     }
// }

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum InnerAckPolicy {
    All,
    None,
    // FirstSuccess,
    // // 0.0 < p <= 1.0
    // AtLeast(f64),
}

/// Policy for relay `OK` acknowledgements when sending events.
///
/// This policy controls whether each relay send waits for an `OK` response
/// after dispatching the `EVENT` message.
#[derive(Debug, Clone)]
pub struct AckPolicy(InnerAckPolicy);

impl Default for AckPolicy {
    /// Wait for relay `OK` acknowledgements ([`AckPolicy::all`]).
    #[inline]
    fn default() -> Self {
        Self::all()
    }
}

impl AckPolicy {
    /// Wait for relay `OK` acknowledgement from each selected relay (default).
    #[inline]
    pub const fn all() -> Self {
        Self(InnerAckPolicy::All)
    }

    /// Do not wait for relay `OK` acknowledgements.
    ///
    /// The operation still sends to all selected relays, but each relay result
    /// is reported immediately after dispatch.
    #[inline]
    pub const fn none() -> Self {
        Self(InnerAckPolicy::None)
    }

    // /// Return as soon as the first relay succeeds.
    // #[inline]
    // pub const fn first_success() -> Self {
    //     Self(InnerAckPolicy::FirstSuccess)
    // }
    //
    // /// Return once at least `ratio` of selected relays succeeds.
    // ///
    // /// The ratio is expressed in `(0.0, 1.0]` space (e.g. `0.6` = 60%).
    // ///
    // /// Returns [`AckPolicyError::InvalidAtLeastRatio`] when `ratio` is not
    // /// finite or outside `0.0 < ratio <= 1.0`.
    // #[inline]
    // pub fn at_least(ratio: f64) -> Result<Self, AckPolicyError> {
    //     if !ratio.is_finite() || ratio <= 0.0 || ratio > 1.0 {
    //         return Err(AckPolicyError::InvalidAtLeastRatio);
    //     }
    //
    //     Ok(Self(InnerAckPolicy::AtLeast(ratio)))
    // }

    #[inline]
    pub(crate) fn into_inner(self) -> InnerAckPolicy {
        self.0
    }
}

/// Send event
#[must_use = "Does nothing unless you await!"]
pub struct SendEvent<'client, 'event, 'url> {
    // --------------------------------------------------
    // WHEN ADDING NEW OPTIONS HERE,
    // REMEMBER TO UPDATE THE "Configuration" SECTION in
    // Client::send_event DOC.
    // --------------------------------------------------
    client: &'client Client,
    event: &'event Event,
    policy: Option<OverwritePolicy<'url>>,
    ack_policy: AckPolicy,
    save_into_database: bool,
    wait_for_ok_timeout: Duration,
    wait_for_authentication_timeout: Duration,
}

impl<'client, 'event, 'url> SendEvent<'client, 'event, 'url> {
    pub(crate) fn new(client: &'client Client, event: &'event Event) -> Self {
        Self {
            client,
            event,
            policy: None,
            ack_policy: AckPolicy::default(),
            save_into_database: true,
            wait_for_ok_timeout: Duration::from_secs(10),
            wait_for_authentication_timeout: Duration::from_secs(10),
        }
    }

    /// Send event to all relays with [`RelayCapabilities::WRITE`] capability.
    ///
    /// This overwrites the following methods:
    /// - [`SendEvent::to`]
    /// - [`SendEvent::to_nip17`]
    /// - [`SendEvent::to_nip65`]
    #[inline]
    pub fn broadcast(mut self) -> Self {
        self.policy = Some(OverwritePolicy::Broadcast);
        self
    }

    /// Send event to specific relays
    ///
    /// This overwrites the following methods:
    /// - [`SendEvent::broadcast`]
    /// - [`SendEvent::to_nip17`]
    /// - [`SendEvent::to_nip65`]
    pub fn to<I, T>(mut self, urls: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<RelayUrlArg<'url>>,
    {
        self.policy = Some(OverwritePolicy::To(
            urls.into_iter().map(Into::into).collect(),
        ));
        self
    }

    /// Send event to NIP-17 relays
    ///
    /// This overwrites the following methods:
    /// - [`SendEvent::to`]
    /// - [`SendEvent::broadcast`]
    /// - [`SendEvent::to_nip65`]
    ///
    /// Returns an error if gossip is not configured.
    #[inline]
    pub fn to_nip17(mut self) -> Self {
        self.policy = Some(OverwritePolicy::ToNip17);
        self
    }

    /// Send event to NIP-65 relays
    ///
    /// This overwrites the following methods:
    /// - [`SendEvent::to`]
    /// - [`SendEvent::broadcast`]
    /// - [`SendEvent::to_nip17`]
    ///
    /// Returns an error if gossip is not configured.
    #[inline]
    pub fn to_nip65(mut self) -> Self {
        self.policy = Some(OverwritePolicy::ToNip65);
        self
    }

    /// Save the event into the database (default: true)
    ///
    /// If `true`, the event is immediately saved into the database.
    #[inline]
    pub fn save_into_database(mut self, enabled: bool) -> Self {
        self.save_into_database = enabled;
        self
    }

    /// Set how relay `OK` acknowledgements are handled.
    ///
    /// Default is [`AckPolicy::all`].
    #[inline]
    pub fn ack_policy(mut self, policy: AckPolicy) -> Self {
        self.ack_policy = policy;
        self
    }

    /// Timeout for waiting for relay `OK` (default: 10 sec).
    ///
    /// Used only when waiting for relay `OK` is enabled.
    #[inline]
    pub fn ok_timeout(mut self, timeout: Duration) -> Self {
        self.wait_for_ok_timeout = timeout;
        self
    }

    /// Timeout for waiting for relay authentication (default: 10 sec).
    ///
    /// Used only when waiting for relay `OK` is enabled.
    #[inline]
    pub fn authentication_timeout(mut self, timeout: Duration) -> Self {
        self.wait_for_authentication_timeout = timeout;
        self
    }
}

async fn gossip_prepare_urls(
    client: &Client,
    gossip: &Gossip,
    event: &Event,
    is_nip17: bool,
) -> Result<HashSet<RelayUrl>, Error> {
    let is_contact_list: bool = event.kind == Kind::ContactList;
    let is_gift_wrap: bool = event.kind == Kind::GiftWrap;

    // Get involved public keys and check what are up to date in the gossip graph and which ones require an update.
    let (public_keys, gossip_kinds): (BTreeSet<PublicKey>, &[GossipListKind]) = if is_gift_wrap {
        let kind: GossipListKind = if is_nip17 {
            GossipListKind::Nip17
        } else {
            GossipListKind::Nip65
        };

        // Get only p tags since the author of a gift wrap is randomized
        let public_keys: BTreeSet<PublicKey> = event.tags.public_keys().collect();

        (public_keys, &[kind])
    } else if is_contact_list {
        // Contact list, update only author
        (BTreeSet::from([event.pubkey]), &[GossipListKind::Nip65])
    } else {
        // Get all public keys involved in the event: author + p tags
        let public_keys: BTreeSet<PublicKey> = event
            .tags
            .public_keys()
            .chain(iter::once(event.pubkey))
            .collect();
        (public_keys, &[GossipListKind::Nip65])
    };

    // Ensure public keys are up to date
    client
        .ensure_gossip_public_keys_fresh(gossip, public_keys, gossip_kinds)
        .await?;

    // Check if NIP17 or NIP65
    if is_nip17 && is_gift_wrap {
        // Get NIP17 relays
        // Get only for relays for p tags since gift wraps are signed with random key (random author)
        let relays = gossip
            .resolver()
            .get_relays(
                event.tags.public_keys(),
                BestRelaySelection::PrivateMessage {
                    limit: client.config().gossip_config.limits.nip17_relays,
                },
                client.config().gossip_config.allowed,
            )
            .await?;

        // Clients SHOULD publish kind 14 events to the 10050-listed relays.
        // If that is not found, that indicates the user is not ready to receive messages under this NIP and clients shouldn't try.
        //
        // <https://github.com/nostr-protocol/nips/blob/6e7a618e7f873bb91e743caacc3b09edab7796a0/17.md>
        if relays.is_empty() {
            return Err(Error::not_found(
                "Private message relays not found. The user is not ready to receive private messages.",
            ));
        }

        // Add outbox and inbox relays
        for url in relays.iter().cloned() {
            client
                .add_relay(url)
                .capabilities(RelayCapabilities::GOSSIP)
                .and_connect()
                .await?;
        }

        Ok(relays)
    } else {
        // Get OUTBOX, HINTS and MOST_RECEIVED relays for the author
        let mut relays: HashSet<RelayUrl> = gossip
            .store()
            .get_best_relays(
                &event.pubkey,
                BestRelaySelection::All {
                    read: 0, // No read relays
                    write: client.config().gossip_config.limits.write_relays_per_user,
                    hints: client.config().gossip_config.limits.hint_relays_per_user,
                    most_received: client
                        .config()
                        .gossip_config
                        .limits
                        .most_used_relays_per_user,
                },
                client.config().gossip_config.allowed,
            )
            .await?;

        // Extend with INBOX, HINTS and MOST_RECEIVED relays for the tags
        if !is_contact_list {
            let inbox_hints_most_recv: HashSet<RelayUrl> = gossip
                .resolver()
                .get_relays(
                    event.tags.public_keys(),
                    BestRelaySelection::All {
                        read: client.config().gossip_config.limits.read_relays_per_user,
                        write: 0, // No write relays
                        hints: client.config().gossip_config.limits.hint_relays_per_user,
                        most_received: client
                            .config()
                            .gossip_config
                            .limits
                            .most_used_relays_per_user,
                    },
                    client.config().gossip_config.allowed,
                )
                .await?;

            relays.extend(inbox_hints_most_recv);
        }

        // Add OUTBOX and INBOX relays
        for url in relays.iter().cloned() {
            client
                .add_relay(url)
                .capabilities(RelayCapabilities::GOSSIP)
                .and_connect()
                .await?;
        }

        // Get WRITE relays
        let write_relays: HashSet<RelayUrl> = client.pool().write_relay_urls().await;

        // Extend relays with WRITE ones
        relays.extend(write_relays);

        // Return all relays
        Ok(relays)
    }
}

impl<'client, 'event, 'url> IntoFuture for SendEvent<'client, 'event, 'url>
where
    'event: 'client,
    'url: 'client,
{
    type Output = Result<SendEventOutput, Error>;
    type IntoFuture = BoxedFuture<'client, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Caller-supplied events may be externally signed; validate before local side effects.
            self.event.verify()?;

            // Save event into database
            if self.save_into_database {
                self.client.database().save_event(self.event).await?;
            }

            // Process event for gossip, independently of the policy
            if let Some(gossip) = self.client.gossip() {
                gossip.store().process(self.event, None).await?;
            }

            let urls: HashSet<RelayUrl> = match (self.policy, self.client.gossip()) {
                // No overwrite policy or send to NIP-65 and gossip available: send to NIP-65 relays
                (None | Some(OverwritePolicy::ToNip65), Some(gossip)) => {
                    gossip_prepare_urls(self.client, gossip, self.event, false).await?
                }
                // Send to NIP-17 and gossip available: send to NIP-17 relays
                (Some(OverwritePolicy::ToNip17), Some(gossip)) => {
                    gossip_prepare_urls(self.client, gossip, self.event, true).await?
                }
                // Send to gossip, but gossip is not available: error
                (Some(OverwritePolicy::ToNip17 | OverwritePolicy::ToNip65), None) => {
                    return Err(Error::gossip_not_configured());
                }
                // Send to specific relays
                (Some(OverwritePolicy::To(list)), _) => {
                    let mut urls: HashSet<RelayUrl> = HashSet::with_capacity(list.len());

                    for url in list {
                        urls.insert(url.try_into_relay_url()?.into_owned());
                    }

                    urls
                }
                // - Broadcast policy,
                // - Or, no overwrite policy and no gossip available
                // -> Send to all WRITE relays
                (Some(OverwritePolicy::Broadcast), _) | (None, None) => {
                    self.client.pool().write_relay_urls().await
                }
            };

            self.client
                .pool()
                .send_event(
                    urls,
                    self.event,
                    self.ack_policy.into_inner(),
                    self.wait_for_ok_timeout,
                    self.wait_for_authentication_timeout,
                )
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nostr::nips::nip17::InboxRelayList;
    use nostr::nips::nip65::RelayList;
    use nostr::prelude::*;
    use nostr_database::DatabaseEventStatus;
    use nostr_gossip::GossipAllowedRelays;
    use nostr_gossip_memory::store::NostrGossipMemory;

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::client::{GossipConfig, GossipRelayLimits};
    use crate::error::ErrorKind;
    use crate::local_relay::*;
    use crate::test_utils::{setup_client, setup_client_with_authenticator};

    #[tokio::test]
    async fn auth_gated_clients_keep_independent_signers_across_removal_and_reconnect() {
        let local = LocalRelay::builder()
            .nip42(LocalRelayBuilderNip42::write())
            .build();
        local.run().await.unwrap();
        let url = local.url().await;

        let first_keys = Keys::generate();
        let second_keys = Keys::generate();
        let first = setup_client_with_authenticator(
            url.clone(),
            SignerAuthenticator::new(first_keys.clone()),
        )
        .await;
        let second = setup_client_with_authenticator(
            url.clone(),
            SignerAuthenticator::new(second_keys.clone()),
        )
        .await;
        let unauthenticated = setup_client(url.clone()).await;

        for (client, keys, content) in [
            (&first, &first_keys, "first account"),
            (&second, &second_keys, "second account"),
        ] {
            let event = EventBuilder::new(Kind::TextNote, content)
                .tag(Tag::protected())
                .finalize(keys)
                .unwrap();
            let output = client
                .send_event(&event)
                .ok_timeout(Duration::from_secs(2))
                .authentication_timeout(Duration::from_secs(2))
                .await
                .unwrap();
            assert!(output.failed.is_empty());
            assert!(output.success.get(&url).unwrap().is_ack());
        }

        let unauthenticated_event = EventBuilder::new(Kind::TextNote, "no signer")
            .tag(Tag::protected())
            .finalize(&Keys::generate())
            .unwrap();
        let output = unauthenticated
            .send_event(&unauthenticated_event)
            .ok_timeout(Duration::from_secs(2))
            .await
            .unwrap();
        assert!(output.success.is_empty());
        assert!(output.failed.contains_key(&url));

        first.remove_relay(&url).force().await.unwrap();
        second.disconnect().await;
        second.connect().and_wait(Duration::from_secs(3)).await;
        assert_eq!(
            second.relay(&url).await.unwrap().unwrap().status(),
            crate::relay::RelayStatus::Connected
        );
        let event = EventBuilder::new(Kind::TextNote, "second account after reconnect")
            .tag(Tag::protected())
            .finalize(&second_keys)
            .unwrap();
        let output = second
            .send_event(&event)
            .ok_timeout(Duration::from_secs(2))
            .authentication_timeout(Duration::from_secs(2))
            .await
            .unwrap();
        assert!(output.failed.is_empty(), "{:?}", output.failed);
        assert!(output.success.get(&url).unwrap().is_ack());
    }

    #[tokio::test]
    async fn unverified_event_is_rejected_before_sending() {
        let client = Client::default();
        let keys = Keys::generate();
        let mut event = EventBuilder::new(Kind::TextNote, "original")
            .finalize(&keys)
            .unwrap();
        event.content = String::from("forged");

        let err = client.send_event(&event).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol);
        assert_eq!(
            client.database().check_id(&event.id).await.unwrap(),
            DatabaseEventStatus::NotExistent
        );
    }

    #[tokio::test]
    async fn test_send_event() {
        let mock1 = MockRelay::run().await.unwrap();
        let url1 = mock1.url().await;
        let mock2 = MockRelay::run().await.unwrap();
        let url2 = mock2.url().await;
        let mock3 = MockRelay::run().await.unwrap();
        let url3 = mock3.url().await;

        let client: Client = Client::default();

        // Add 2 READ and WRITE relays
        client.add_relay(&url1).await.unwrap();
        client.add_relay(&url2).await.unwrap();

        // Add a READ-only relay
        client
            .add_relay(&url3)
            .capabilities(RelayCapabilities::READ)
            .await
            .unwrap();

        client.connect().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Broadcast test")
            .finalize(&keys)
            .unwrap();

        // Send event (broadcast to all WRITE relays by default)
        let output = client.send_event(&event).await.unwrap();

        assert_eq!(output.success.len(), 2);
        assert!(output.success.contains_key(&url1));
        assert!(output.success.contains_key(&url2));
        assert!(!output.success.contains_key(&url3));
        assert!(output.failed.is_empty());
        assert_eq!(output.value, event.id);
    }

    #[tokio::test]
    async fn test_send_event_to() {
        let mock1 = MockRelay::run().await.unwrap();
        let url1 = mock1.url().await;
        let mock2 = MockRelay::run().await.unwrap();
        let url2 = mock2.url().await;

        let client = Client::default();
        client.add_relay(&url1).await.unwrap();
        client.add_relay(&url2).await.unwrap();
        client.connect().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Targeted test")
            .finalize(&keys)
            .unwrap();

        // Send only to relay 1
        let output = client.send_event(&event).to([&url1]).await.unwrap();

        assert_eq!(output.success.len(), 1);
        assert!(output.success.contains_key(&url1));
        assert!(!output.success.contains_key(&url2));
        assert!(output.failed.is_empty());
        assert_eq!(output.value, event.id);
    }

    #[tokio::test]
    async fn test_send_event_broadcast() {
        let mock1 = MockRelay::run().await.unwrap();
        let url1 = mock1.url().await;
        let mock2 = MockRelay::run().await.unwrap();
        let url2 = mock2.url().await;
        let mock3 = MockRelay::run().await.unwrap();
        let url3 = mock3.url().await;

        // Configure client with gossip
        let gossip: NostrGossipMemory = NostrGossipMemory::unbounded();
        let client: Client = Client::builder().gossip(gossip).build();

        // Add 2 READ and WRITE relays
        client.add_relay(&url1).await.unwrap();
        client.add_relay(&url2).await.unwrap();

        // Add a READ-only relay
        client
            .add_relay(&url3)
            .capabilities(RelayCapabilities::READ)
            .await
            .unwrap();

        client.connect().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Force to all test")
            .finalize(&keys)
            .unwrap();

        // Force send to all WRITE instead of using gossip
        let output = client.send_event(&event).broadcast().await.unwrap();

        assert_eq!(output.success.len(), 2);
        assert!(output.success.contains_key(&url1));
        assert!(output.success.contains_key(&url2));
        assert!(!output.success.contains_key(&url3));
        assert!(output.failed.is_empty());
        assert_eq!(output.value, event.id);
    }

    #[tokio::test]
    async fn test_send_event_with_auto_gossip() {
        // Setup Outbox Relay (where the user wants to receive/send events)
        let outbox_mock = MockRelay::run().await.unwrap();
        let outbox_url = outbox_mock.url().await;

        // Setup Discovery Relay (where NIP-65 lists are stored)
        let discovery_mock = MockRelay::run().await.unwrap();
        let discovery_url = discovery_mock.url().await;

        // Setup a generic "Public" Relay
        let public_mock = MockRelay::run().await.unwrap();
        let public_url = public_mock.url().await;

        // Setup User A keys and their Relay List (NIP-65) pointing to the Outbox Relay
        let keys_a = Keys::generate();
        let relay_list = RelayList::new([(outbox_url.clone(), None)])
            .finalize(&keys_a)
            .unwrap();
        let res = discovery_mock.add_event(relay_list).await.unwrap();
        assert!(res.is_success());

        // Configure Client with Gossip
        let gossip = NostrGossipMemory::unbounded();
        let config = GossipConfig::default()
            .limits(GossipRelayLimits {
                read_relays_per_user: 2,
                write_relays_per_user: 2,
                hint_relays_per_user: 1,
                most_used_relays_per_user: 0, // Disable the most used, as it would be the discovery one
                nip17_relays: 3,
            })
            .allowed(GossipAllowedRelays {
                onion: true,
                local: true,
                without_tls: true,
            });
        let client = Client::builder()
            .gossip(gossip)
            .gossip_config(config)
            .build();

        // The client only knows about the Discovery and Public relays initially
        client
            .add_relay(&discovery_url)
            .capabilities(RelayCapabilities::DISCOVERY)
            .await
            .unwrap();
        client.add_relay(&public_url).await.unwrap();
        client.connect().await;

        // Verify that the client doesn't have the outbox relay
        assert!(client.relay(&outbox_url).await.unwrap().is_none());

        // Verify capabilities
        let relay = client.relay(&discovery_url).await.unwrap().unwrap();
        assert_eq!(relay.capabilities().load(), RelayCapabilities::DISCOVERY);

        // Now, send a Text Note from User A.
        // The gossip engine should:
        // - See the author is User A
        // - Fetch User A's relay list from Discovery/Public relays (or local cache)
        // - Identify 'outbox_url' as the target
        // - Automatically connect to 'outbox_url'
        // - Send the event to the outbox and public relay
        let event = EventBuilder::new(Kind::TextNote, "Gossip test")
            .finalize(&keys_a)
            .unwrap();

        // Send event using default config (must be sent to gossip)
        let output = client.send_event(&event).await.unwrap();

        // Verify output
        assert_eq!(output.success.len(), 2);
        assert!(output.success.contains_key(&outbox_url));
        assert!(output.success.contains_key(&public_url));
        assert!(!output.success.contains_key(&discovery_url));
        assert!(output.failed.is_empty());
        assert_eq!(output.value, event.id);

        // Verify the client now has the outbox relay in its pool with GOSSIP capability
        let outbox_relay = client.relay(&outbox_url).await.unwrap().unwrap();
        assert_eq!(
            outbox_relay.capabilities().load(),
            RelayCapabilities::GOSSIP
        );
    }

    #[tokio::test]
    async fn test_send_event_to_nip65_without_gossip() {
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let client: Client = Client::default();
        client.add_relay(&url).await.unwrap();
        client.connect().await;

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Broadcast test")
            .finalize(&keys)
            .unwrap();

        // Send event
        let err = client.send_event(&event).to_nip65().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::State);
        assert_eq!(err.to_string(), "gossip not configured");
    }

    #[tokio::test]
    async fn test_send_event_to_nip17() {
        let inbox_mock = MockRelay::run().await.unwrap();
        let inbox_url = inbox_mock.url().await;

        // Setup Discovery Relay (where NIP-17 lists are stored)
        let discovery_mock = MockRelay::run().await.unwrap();
        let discovery_url = discovery_mock.url().await;

        // Setup a generic "Public" Relay
        let public_mock = MockRelay::run().await.unwrap();
        let public_url = public_mock.url().await;

        // Setup Bob keys and NIP-17 list pointing to the Inbox Relay
        let bob_keys = Keys::generate();
        let relay_list = InboxRelayList::new([inbox_url.clone()])
            .finalize(&bob_keys)
            .unwrap();
        let res = discovery_mock.add_event(relay_list).await.unwrap();
        assert!(res.is_success());

        // Configure Client with Gossip
        let gossip = NostrGossipMemory::unbounded();
        let config = GossipConfig::default().allowed(GossipAllowedRelays {
            onion: true,
            local: true,
            without_tls: true,
        });
        let client = Client::builder()
            .gossip(gossip)
            .gossip_config(config)
            .build();

        // The client only knows about the Discovery and Public relays initially
        client
            .add_relay(&discovery_url)
            .capabilities(RelayCapabilities::DISCOVERY)
            .await
            .unwrap();
        client.add_relay(&public_url).await.unwrap();
        client.connect().await;

        // Verify that the client doesn't have the inbox relay
        assert!(client.relay(&inbox_url).await.unwrap().is_none());

        // Sends an event to the inbox relay
        // NOTE: this is not a NIP-17 event, as the nip59 feature is required, so we are sending a fake gift wrap tagging the recipient
        let event = EventBuilder::new(Kind::GiftWrap, "payload")
            .tag(Tag::public_key(bob_keys.public_key()))
            .finalize(&Keys::generate())
            .unwrap();
        let output = client.send_event(&event).to_nip17().await.unwrap();

        // Should be sent ONLY to Bob's discovered inbox
        assert_eq!(output.success.len(), 1);
        assert!(output.success.contains_key(&inbox_url));
        assert!(!output.success.contains_key(&public_url));
        assert!(!output.success.contains_key(&discovery_url));
        assert!(output.failed.is_empty());
        assert_eq!(output.value, event.id);

        // Verify the client now has the outbox relay in its pool with GOSSIP capability
        let inbox_relay = client.relay(&inbox_url).await.unwrap().unwrap();
        assert_eq!(inbox_relay.capabilities().load(), RelayCapabilities::GOSSIP);
    }

    #[tokio::test]
    async fn test_send_event_to_nip17_without_gossip() {
        let mock = MockRelay::run().await.unwrap();
        let url = mock.url().await;

        let client: Client = Client::default();
        client.add_relay(&url).await.unwrap();
        client.connect().await;

        // NOTE: this is not a NIP-17 event, as the nip59 feature is required, so we are sending a fake gift wrap tagging the recipient
        let bob_keys = Keys::generate();
        let event = EventBuilder::new(Kind::GiftWrap, "payload")
            .tag(Tag::public_key(bob_keys.public_key()))
            .finalize(&Keys::generate())
            .unwrap();

        // Send event
        let err = client.send_event(&event).to_nip17().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::State);
        assert_eq!(err.to_string(), "gossip not configured");
    }
}
