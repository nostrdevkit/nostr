//! Gossip in-memory storage.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;

use indexmap::IndexMap;
use lru::LruCache;
use nostr::event::{Event, Kind};
use nostr::key::PublicKey;
use nostr::nips::nip01::Nip01Tag;
use nostr::nips::nip17;
use nostr::nips::nip65::{self, RelayMetadata};
use nostr::types::{RelayUrl, Timestamp};
use nostr_gossip::error::Error;
use nostr_gossip::flags::GossipFlags;
use nostr_gossip::{
    BestRelaySelection, GossipAllowedRelays, GossipListKind, GossipPublicKeyStatus, NostrGossip,
    OutdatedPublicKey,
};
use tokio::sync::RwLock;

use crate::constant::{MAX_NIP17_SIZE, MAX_NIP65_SIZE, TTL_OUTDATED};

#[derive(Default)]
struct PkRelayData {
    bitflags: GossipFlags,
    received_events: u64,
    last_received_event: Option<Timestamp>,
}

struct PkData {
    last_nip17_update: Option<Timestamp>,
    last_nip65_update: Option<Timestamp>,
    relays: IndexMap<RelayUrl, PkRelayData>,
}

impl Default for PkData {
    fn default() -> Self {
        Self {
            last_nip17_update: None,
            last_nip65_update: None,
            relays: IndexMap::new(),
        }
    }
}

/// Gossip in-memory storage.
#[derive(Debug)]
pub struct NostrGossipMemory {
    public_keys: RwLock<LruCache<PublicKey, PkData>>,
}

impl NostrGossipMemory {
    /// Creates an unbounded cache for testing or non-production use.
    ///
    /// Prefer [`NostrGossipMemory::bounded`] for production code to avoid
    /// unbounded memory growth.
    pub fn unbounded() -> Self {
        Self {
            public_keys: RwLock::new(LruCache::unbounded()),
        }
    }

    /// Construct a new **bounded** instance
    pub fn bounded(limit: NonZeroUsize) -> Self {
        Self {
            public_keys: RwLock::new(LruCache::new(limit)),
        }
    }

    async fn process_event(&self, event: &Event, relay_url: Option<&RelayUrl>) {
        let mut public_keys = self.public_keys.write().await;

        match &event.kind {
            // Extract NIP-65 relays
            Kind::RelayList => {
                let pk_data: &mut PkData =
                    public_keys.get_or_insert_mut(event.pubkey, PkData::default);

                for (relay_url, metadata) in nip65::extract_relay_list(event).take(MAX_NIP65_SIZE) {
                    // New bitflag for the relay
                    let bitflag: GossipFlags = match metadata {
                        Some(RelayMetadata::Read) => GossipFlags::READ,
                        Some(RelayMetadata::Write) => GossipFlags::WRITE,
                        None => {
                            let mut f = GossipFlags::READ;
                            f.add(GossipFlags::WRITE);
                            f
                        }
                    };

                    // Create a mask for READ and WRITE flags
                    let mut read_write_mask: GossipFlags = GossipFlags::READ;
                    read_write_mask.add(GossipFlags::WRITE);

                    match pk_data.relays.get_mut(&relay_url) {
                        Some(relay_data) => {
                            // Update the bitflag: remove the previous READ and WRITE values and apply the new bitflag (preserves any other flag)
                            relay_data.bitflags.remove(read_write_mask);
                            relay_data.bitflags.add(bitflag);
                        }
                        None => {
                            let mut relay_data = PkRelayData::default();
                            relay_data.bitflags.add(bitflag);

                            pk_data.relays.insert(relay_url.clone(), relay_data);
                        }
                    }
                }
            }
            // Extract NIP-17 relays
            Kind::InboxRelays => {
                let pk_data: &mut PkData =
                    public_keys.get_or_insert_mut(event.pubkey, PkData::default);

                for relay_url in nip17::extract_relay_list(event).take(MAX_NIP17_SIZE) {
                    match pk_data.relays.get_mut(&relay_url) {
                        Some(relay_data) => {
                            relay_data.bitflags.add(GossipFlags::PRIVATE_MESSAGE);
                        }
                        None => {
                            let mut relay_data = PkRelayData::default();
                            relay_data.bitflags.add(GossipFlags::PRIVATE_MESSAGE);

                            pk_data.relays.insert(relay_url, relay_data);
                        }
                    }
                }
            }
            // Extract hints
            _ => {
                for tag in event.tags.iter().filter_map(|t| {
                    if t.kind() != "p" {
                        return None;
                    }

                    Nip01Tag::try_from(t).ok()
                }) {
                    if let Nip01Tag::PublicKey {
                        public_key,
                        relay_hint: Some(relay_hint),
                    } = tag
                    {
                        let pk_data: &mut PkData =
                            public_keys.get_or_insert_mut(public_key, PkData::default);
                        update_relay_per_user(pk_data, relay_hint, GossipFlags::HINT);
                    }
                }
            }
        }

        if let Some(relay_url) = relay_url {
            let pk_data: &mut PkData = public_keys.get_or_insert_mut(event.pubkey, PkData::default);
            update_relay_per_user(pk_data, relay_url.clone(), GossipFlags::RECEIVED);
        }
    }

    async fn get_status(
        &self,
        public_key: &PublicKey,
        list: GossipListKind,
    ) -> GossipPublicKeyStatus {
        let public_keys = self.public_keys.read().await;

        match public_keys.peek(public_key) {
            Some(pk_data) => {
                let now: Timestamp = Timestamp::now();

                match (list, pk_data.last_nip17_update, pk_data.last_nip65_update) {
                    (GossipListKind::Nip17, Some(last), _) => {
                        if last + TTL_OUTDATED < now {
                            GossipPublicKeyStatus::Outdated { created_at: None }
                        } else {
                            GossipPublicKeyStatus::Updated
                        }
                    }
                    (GossipListKind::Nip65, _, Some(last)) => {
                        if last + TTL_OUTDATED < now {
                            GossipPublicKeyStatus::Outdated { created_at: None }
                        } else {
                            GossipPublicKeyStatus::Updated
                        }
                    }
                    (_, _, _) => GossipPublicKeyStatus::Missing,
                }
            }
            None => GossipPublicKeyStatus::Missing,
        }
    }

    async fn _update_fetch_attempt(&self, public_key: &PublicKey, list: GossipListKind) {
        let mut public_keys = self.public_keys.write().await;

        let pk_data: &mut PkData = public_keys.get_or_insert_mut(*public_key, PkData::default);

        let now: Timestamp = Timestamp::now();

        match list {
            GossipListKind::Nip17 => pk_data.last_nip17_update = Some(now),
            GossipListKind::Nip65 => pk_data.last_nip65_update = Some(now),
        };
    }

    async fn collect_outdated_public_keys(
        &self,
        list: GossipListKind,
        limit: NonZeroUsize,
    ) -> BTreeSet<OutdatedPublicKey> {
        let public_keys = self.public_keys.read().await;
        let now: Timestamp = Timestamp::now();

        let mut outdated: BTreeSet<OutdatedPublicKey> = BTreeSet::new();

        for (public_key, pk_data) in public_keys.iter() {
            let last_checked_at: Option<Timestamp> = match list {
                GossipListKind::Nip17 => pk_data.last_nip17_update,
                GossipListKind::Nip65 => pk_data.last_nip65_update,
            };

            if let Some(last_checked_at) = last_checked_at {
                if last_checked_at + TTL_OUTDATED < now {
                    let pk = OutdatedPublicKey::new(*public_key, last_checked_at);
                    outdated.insert(pk);
                }
            }
        }

        outdated.into_iter().take(limit.get()).collect()
    }

    async fn _get_best_relays(
        &self,
        public_key: &PublicKey,
        selection: BestRelaySelection,
        allowed: GossipAllowedRelays,
    ) -> HashSet<RelayUrl> {
        let public_keys = self.public_keys.read().await;

        let mut relays: HashSet<RelayUrl> = HashSet::new();

        match selection {
            BestRelaySelection::All {
                read,
                write,
                hints,
                most_received,
            } => {
                // Get read relays
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::READ,
                    allowed,
                    read,
                ));

                // Get write relays
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::WRITE,
                    allowed,
                    write,
                ));

                // Get hint relays
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::HINT,
                    allowed,
                    hints,
                ));

                // Get most received relays
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::RECEIVED,
                    allowed,
                    most_received,
                ));
            }
            BestRelaySelection::Read { limit } => {
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::READ,
                    allowed,
                    limit,
                ));
            }
            BestRelaySelection::Write { limit } => {
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::WRITE,
                    allowed,
                    limit,
                ));
            }
            BestRelaySelection::PrivateMessage { limit } => {
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::PRIVATE_MESSAGE,
                    allowed,
                    limit,
                ));
            }
            BestRelaySelection::Hints { limit } => {
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::HINT,
                    allowed,
                    limit,
                ));
            }
            BestRelaySelection::MostReceived { limit } => {
                relays.extend(self.get_relays_by_flag(
                    &public_keys,
                    public_key,
                    GossipFlags::RECEIVED,
                    allowed,
                    limit,
                ));
            }
        }

        relays
    }

    fn get_relays_by_flag(
        &self,
        tx: &LruCache<PublicKey, PkData>,
        public_key: &PublicKey,
        flag: GossipFlags,
        allowed: GossipAllowedRelays,
        limit: u8,
    ) -> impl Iterator<Item = RelayUrl> + '_ {
        let mut relays: Vec<(RelayUrl, u64, Option<Timestamp>)> = Vec::new();

        if let Some(pk_data) = tx.peek(public_key) {
            for (relay_url, relay_data) in pk_data.relays.iter() {
                // Check if the relay is allowed by the allowed relays filter
                if !allowed.is_allowed(relay_url) {
                    continue;
                }

                // Check if the relay has the specified flag
                if relay_data.bitflags.has(flag) {
                    relays.push((
                        relay_url.clone(),
                        relay_data.received_events,
                        relay_data.last_received_event,
                    ));
                }
            }
        }

        // Sort by received_events DESC, then by last_received_event DESC
        relays.sort_by(|a, b| match b.1.cmp(&a.1) {
            Ordering::Equal => b.2.cmp(&a.2),
            other => other,
        });

        // Take only the requested limit and extract relay URLs
        relays
            .into_iter()
            .take(limit as usize)
            .map(|(url, _, _)| url)
    }
}

/// Add relay per user or update the received events and bitflags.
fn update_relay_per_user(pk_data: &mut PkData, relay_url: RelayUrl, flags: GossipFlags) {
    match pk_data.relays.get_mut(&relay_url) {
        Some(relay_data) => {
            relay_data.bitflags.add(flags);
            relay_data.received_events = relay_data.received_events.saturating_add(1);
            relay_data.last_received_event = Some(Timestamp::now());
        }
        None => {
            let mut relay_data = PkRelayData::default();

            relay_data.bitflags.add(flags);
            relay_data.received_events = relay_data.received_events.saturating_add(1);
            relay_data.last_received_event = Some(Timestamp::now());

            pk_data.relays.insert(relay_url, relay_data);
        }
    }
}

impl NostrGossip for NostrGossipMemory {
    fn process<'a>(
        &'a self,
        event: &'a Event,
        relay_url: Option<&'a RelayUrl>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            self.process_event(event, relay_url).await;
            Ok(())
        })
    }

    fn status<'a>(
        &'a self,
        public_key: &'a PublicKey,
        list: GossipListKind,
    ) -> Pin<Box<dyn Future<Output = Result<GossipPublicKeyStatus, Error>> + Send + 'a>> {
        Box::pin(async move { Ok(self.get_status(public_key, list).await) })
    }

    fn update_fetch_attempt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        list: GossipListKind,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            self._update_fetch_attempt(public_key, list).await;
            Ok(())
        })
    }

    fn outdated_public_keys(
        &self,
        list: GossipListKind,
        limit: NonZeroUsize,
    ) -> Pin<Box<dyn Future<Output = Result<BTreeSet<OutdatedPublicKey>, Error>> + Send + '_>> {
        Box::pin(async move { Ok(self.collect_outdated_public_keys(list, limit).await) })
    }

    fn get_best_relays<'a>(
        &'a self,
        public_key: &'a PublicKey,
        selection: BestRelaySelection,
        allowed: GossipAllowedRelays,
    ) -> Pin<Box<dyn Future<Output = Result<HashSet<RelayUrl>, Error>> + Send + 'a>> {
        Box::pin(async move { Ok(self._get_best_relays(public_key, selection, allowed).await) })
    }
}

#[cfg(test)]
mod tests {
    use nostr_gossip_test_suite::gossip_unit_tests;

    use super::*;

    async fn setup() -> NostrGossipMemory {
        NostrGossipMemory::unbounded()
    }

    gossip_unit_tests!(NostrGossipMemory, setup);
}
