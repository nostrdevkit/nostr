use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nostr::prelude::*;
use nostr_gossip::prelude::*;

use super::{
    BrokenDownFilters, Gossip, GossipFilterPattern, GossipSemaphorePermit, find_filter_pattern,
};
use crate::client::{Client, Error, Output, SyncSummary};
use crate::relay::{
    RelayCapabilities, RelayStreamEvent, ReqExitPolicy, SyncDirection, SyncOptions,
};

impl Client {
    async fn compute_gossip_update_candidates(
        &self,
        gossip: &Arc<dyn NostrGossip>,
        public_keys: BTreeSet<PublicKey>,
        gossip_kinds: &[GossipListKind],
    ) -> Result<BTreeSet<PublicKey>, Error> {
        let mut update: BTreeSet<PublicKey> = BTreeSet::new();

        for public_key in public_keys {
            'gossip_kind_loop: for gossip_kind in gossip_kinds {
                // Check the status
                match gossip.status(&public_key, *gossip_kind).await? {
                    // Nothing to do as it's already updated
                    GossipPublicKeyStatus::Updated => {}
                    // Missing or outdated
                    GossipPublicKeyStatus::Missing | GossipPublicKeyStatus::Outdated { .. } => {
                        // Add the public key to the update set
                        update.insert(public_key);

                        // Break the gossip kind loop as we already know that the pk needs an update
                        break 'gossip_kind_loop;
                    }
                }
            }
        }

        Ok(update)
    }

    /// Refresh gossip data for the specified keys and list kinds.
    pub(super) async fn sync_gossip_public_keys(
        &self,
        gossip: &Gossip,
        public_keys: BTreeSet<PublicKey>,
        gossip_kinds: &[GossipListKind],
    ) -> Result<(), Error> {
        if public_keys.is_empty() {
            return Ok(());
        }

        let outdated_public_keys_first_check: BTreeSet<PublicKey> = self
            .compute_gossip_update_candidates(gossip.store(), public_keys, gossip_kinds)
            .await?;

        if outdated_public_keys_first_check.is_empty() {
            tracing::debug!(kind = ?gossip_kinds, "Gossip data is up to date.");
            return Ok(());
        }

        let sync_id: u64 = gossip.resolver().next_sync_id();

        tracing::debug!(
            sync_id,
            public_keys = outdated_public_keys_first_check.len(),
            "Acquiring gossip permits..."
        );

        let _permit: GossipSemaphorePermit = gossip
            .semaphore()
            .acquire(outdated_public_keys_first_check.clone())
            .await;

        tracing::debug!(
            sync_id,
            kind = ?gossip_kinds,
            "Acquired gossip permits. Start syncing..."
        );

        let outdated_public_keys: BTreeSet<PublicKey> = self
            .compute_gossip_update_candidates(
                gossip.store(),
                outdated_public_keys_first_check,
                gossip_kinds,
            )
            .await?;

        if outdated_public_keys.is_empty() {
            tracing::debug!(
                sync_id = %sync_id,
                kind = ?gossip_kinds,
                "Gossip sync skipped: data updated by another process while acquiring permits."
            );
            return Ok(());
        }

        let (output, stored_events) = self
            .sync_gossip_public_keys_with_negentropy(
                sync_id,
                gossip.store(),
                gossip_kinds,
                outdated_public_keys.clone(),
            )
            .await?;

        let mut missing_public_keys: BTreeSet<PublicKey> = outdated_public_keys;

        for event in stored_events.iter() {
            missing_public_keys.remove(&event.pubkey);
        }

        let has_success: bool = !output.success.is_empty();
        let has_failed: bool = !output.failed.is_empty();

        // At least one negentropy sync failed, so try a standard REQ fallback for those relays.
        if has_failed {
            tracing::debug!(
                sync_id,
                relays = ?output.failed,
                "Gossip sync failed for some relays."
            );

            self.fetch_newer_gossip_lists_from_failed_relays(
                sync_id,
                gossip.store(),
                gossip_kinds,
                &output,
                &stored_events,
                &mut missing_public_keys,
            )
            .await?;

            // There are still missing public keys to update.
            if !missing_public_keys.is_empty() {
                let completed_fetch = self
                    .fetch_missing_gossip_lists_from_failed_relays(
                        sync_id,
                        gossip_kinds,
                        &output,
                        &missing_public_keys,
                    )
                    .await?;

                // Mark the missing gossip public keys as checked only if we have at least one
                // successful relay response. A total failure, such as missing network, MUST NOT
                // block retries until the TTL expires.
                if has_success || completed_fetch {
                    self.mark_gossip_public_keys_checked(
                        gossip.store(),
                        gossip_kinds,
                        missing_public_keys,
                    )
                    .await?;
                }
            }
        } else if !missing_public_keys.is_empty() && has_success {
            // Mark the missing gossip public keys as checked only if we have at least one successful sync.
            // A total failure, such as missing network, MUST NOT block retries until the TTL expires!
            self.mark_gossip_public_keys_checked(gossip.store(), gossip_kinds, missing_public_keys)
                .await?;
        }

        tracing::debug!(sync_id, kind = ?gossip_kinds, "Gossip sync terminated.");

        Ok(())
    }

    async fn sync_gossip_public_keys_with_negentropy(
        &self,
        sync_id: u64,
        gossip: &Arc<dyn NostrGossip>,
        gossip_kinds: &[GossipListKind],
        outdated_public_keys: BTreeSet<PublicKey>,
    ) -> Result<(Output<SyncSummary>, BTreeSet<Event>), Error> {
        let mut kinds: Vec<Kind> = Vec::with_capacity(gossip_kinds.len());

        for gossip_kind in gossip_kinds {
            kinds.push(gossip_kind.to_event_kind());
        }

        tracing::debug!(
            sync_id,
            public_keys = outdated_public_keys.len(),
            "Syncing outdated gossip data."
        );

        let filter: Filter = Filter::default().authors(outdated_public_keys).kinds(kinds);

        let urls: HashSet<RelayUrl> = self
            .pool()
            .relay_urls_with_any_cap(RelayCapabilities::DISCOVERY | RelayCapabilities::READ)
            .await;

        let opts: SyncOptions = SyncOptions::default()
            .initial_timeout(self.config().gossip_config.sync_initial_timeout)
            .idle_timeout(self.config().gossip_config.sync_idle_timeout)
            .direction(SyncDirection::Down);
        let output: Output<SyncSummary> = self.sync(filter.clone()).with(urls).opts(opts).await?;

        let stored_events: BTreeSet<Event> = self.database().query(filter).await?;

        for event in stored_events.iter() {
            for gossip_kind in gossip_kinds {
                gossip
                    .update_fetch_attempt(&event.pubkey, *gossip_kind)
                    .await?;
            }

            if output.received.contains_key(&event.id) {
                continue;
            }

            gossip.process(event, None).await?;
        }

        Ok((output, stored_events))
    }

    async fn fetch_newer_gossip_lists_from_failed_relays(
        &self,
        sync_id: u64,
        gossip: &Arc<dyn NostrGossip>,
        gossip_kinds: &[GossipListKind],
        output: &Output<SyncSummary>,
        stored_events: &BTreeSet<Event>,
        missing_public_keys: &mut BTreeSet<PublicKey>,
    ) -> Result<(), Error> {
        let mut filters: Vec<Filter> = Vec::new();

        let received: HashSet<EventId> = output.received.keys().copied().collect();
        let skip_ids: HashSet<EventId> = output.local.union(&received).copied().collect();

        for event in stored_events.iter() {
            missing_public_keys.remove(&event.pubkey);

            if skip_ids.contains(&event.id) {
                continue;
            }

            let filter: Filter = Filter::new()
                .author(event.pubkey)
                .kind(event.kind)
                .since(event.created_at + Duration::from_secs(1))
                .limit(1);

            filters.push(filter);
        }

        if filters.is_empty() {
            tracing::debug!(
                sync_id,
                "Skipping gossip fetch, as it's no longer required."
            );
            return Ok(());
        }

        tracing::debug!(
            sync_id,
            filters = filters.len(),
            "Fetching outdated gossip data from relays."
        );

        for chunk in filters.chunks(self.config().gossip_config.fetch_chunks) {
            let mut targets = HashMap::with_capacity(output.failed.len());

            for url in output.failed.keys() {
                targets.insert(url.clone(), chunk.to_vec());
            }

            let mut stream = self
                .pool()
                .stream_events(
                    targets,
                    None,
                    Some(self.config().gossip_config.fetch_timeout),
                    ReqExitPolicy::ExitOnEOSE,
                    true,
                )
                .await?;

            while let Some((url, event)) = stream.next().await {
                match event {
                    RelayStreamEvent::Event(event) => {
                        for gossip_kind in gossip_kinds {
                            gossip
                                .update_fetch_attempt(&event.pubkey, *gossip_kind)
                                .await?;
                        }
                    }
                    RelayStreamEvent::Error(e) => {
                        tracing::error!(%url, error = %e, "Failed to fetch outdated gossip data from relay.");
                    }
                    RelayStreamEvent::Completed | RelayStreamEvent::LimitReached => {}
                }
            }
        }

        Ok(())
    }

    async fn fetch_missing_gossip_lists_from_failed_relays(
        &self,
        sync_id: u64,
        gossip_kinds: &[GossipListKind],
        output: &Output<SyncSummary>,
        missing_public_keys: &BTreeSet<PublicKey>,
    ) -> Result<bool, Error> {
        let mut kinds: Vec<Kind> = Vec::with_capacity(gossip_kinds.len());

        for gossip_kind in gossip_kinds {
            kinds.push(gossip_kind.to_event_kind());
        }

        tracing::debug!(
            sync_id,
            public_keys = missing_public_keys.len(),
            "Fetching missing gossip data from relays."
        );

        let missing_filter: Filter = Filter::default()
            .authors(missing_public_keys.clone())
            .kinds(kinds);

        let mut targets = HashMap::with_capacity(output.failed.len());

        for url in output.failed.keys() {
            targets.insert(url.clone(), vec![missing_filter.clone()]);
        }

        let mut stream = self
            .pool()
            .stream_events(
                targets,
                None,
                Some(self.config().gossip_config.fetch_timeout),
                ReqExitPolicy::ExitOnEOSE,
                true,
            )
            .await?;

        let mut completed_fetch: bool = false;

        while let Some((url, event)) = stream.next().await {
            match event {
                RelayStreamEvent::Event(..)
                | RelayStreamEvent::Completed
                | RelayStreamEvent::LimitReached => {
                    completed_fetch = true;
                }
                RelayStreamEvent::Error(e) => {
                    tracing::error!(%url, error = %e, "Failed to fetch missing gossip data from relay.");
                }
            }
        }

        Ok(completed_fetch)
    }

    /// Update the last check timestamp for the specified keys and list kinds.
    async fn mark_gossip_public_keys_checked<I>(
        &self,
        gossip: &Arc<dyn NostrGossip>,
        gossip_kinds: &[GossipListKind],
        public_keys: I,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        for public_key in public_keys {
            for gossip_kind in gossip_kinds {
                gossip
                    .update_fetch_attempt(&public_key, *gossip_kind)
                    .await?;
            }
        }

        Ok(())
    }

    /// Ensure relay-list data is fresh for currently active keys.
    ///
    /// This method blocks request paths for both missing and outdated keys.
    pub(in crate::client) async fn ensure_gossip_public_keys_fresh(
        &self,
        gossip: &Gossip,
        public_keys: BTreeSet<PublicKey>,
        gossip_kinds: &[GossipListKind],
    ) -> Result<(), Error> {
        // If background refresh is enabled, track public keys
        if self.config().gossip_config.background_refresh.is_some() {
            for gossip_kind in gossip_kinds {
                gossip
                    .refresher()
                    .track_public_keys(gossip_kind, public_keys.iter().copied())
                    .await;
            }
        }

        // Compute the set of outdated keys
        let to_update: BTreeSet<PublicKey> = self
            .compute_gossip_update_candidates(gossip.store(), public_keys, gossip_kinds)
            .await?;

        // Sync
        self.sync_gossip_public_keys(gossip, to_update, gossip_kinds)
            .await
    }

    /// Break down a filter for gossip and discovery relays.
    pub(in crate::client) async fn gossip_break_down_filter(
        &self,
        gossip: &Gossip,
        filter: Filter,
    ) -> Result<HashMap<RelayUrl, Filter>, Error> {
        let public_keys: BTreeSet<PublicKey> = filter.extract_public_keys();
        let pattern: GossipFilterPattern = find_filter_pattern(&filter);

        match &pattern {
            GossipFilterPattern::Nip65 => {
                self.ensure_gossip_public_keys_fresh(gossip, public_keys, &[GossipListKind::Nip65])
                    .await?;
            }
            GossipFilterPattern::Nip65AndNip17 => {
                self.ensure_gossip_public_keys_fresh(
                    gossip,
                    public_keys,
                    &[GossipListKind::Nip65, GossipListKind::Nip17],
                )
                .await?;
            }
        }

        let filters: HashMap<RelayUrl, Filter> = match gossip
            .resolver()
            .break_down_filter(
                filter,
                pattern,
                &self.config().gossip_config.limits,
                self.config().gossip_config.allowed,
            )
            .await?
        {
            BrokenDownFilters::Filters(filters) => filters,
            BrokenDownFilters::Orphan(filter) | BrokenDownFilters::Other(filter) => {
                let read_relays: HashSet<RelayUrl> = self.pool().read_relay_urls().await;

                let mut map = HashMap::with_capacity(read_relays.len());
                for url in read_relays.into_iter() {
                    map.insert(url, filter.clone());
                }
                map
            }
        };

        for url in filters.keys() {
            self.add_relay(url)
                .capabilities(RelayCapabilities::GOSSIP)
                .and_connect()
                .await?;
        }

        if filters.is_empty() {
            return Err(Error::state_msg("broken down filters are empty"));
        }

        Ok(filters)
    }

    /// Break down multiple filters for gossip and discovery relays.
    pub(in crate::client) async fn gossip_break_down_filters<F>(
        &self,
        gossip: &Gossip,
        filters: F,
    ) -> Result<HashMap<RelayUrl, Vec<Filter>>, Error>
    where
        F: Into<Vec<Filter>>,
    {
        let filters: Vec<Filter> = filters.into();

        let mut output: HashMap<RelayUrl, HashSet<Filter>> = HashMap::new();

        for filter in filters {
            let f = self.gossip_break_down_filter(gossip, filter).await?;

            for (url, filter) in f {
                output.entry(url).or_default().insert(filter);
            }
        }

        Ok(output
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use nostr_gossip_memory::prelude::*;
    use nostr_memory::MemoryDatabase;

    use super::*;
    use crate::client::{ClientBuilder, GossipConfig};
    use crate::local_relay::*;

    fn client_builder_with_gossip() -> ClientBuilder {
        let gossip = NostrGossipMemory::unbounded();
        let config = GossipConfig::default()
            .sync_initial_timeout(Duration::from_nanos(1))
            .sync_idle_timeout(Duration::from_secs(1))
            .fetch_timeout(Duration::from_secs(2))
            .no_background_refresh();

        Client::builder().gossip(gossip).gossip_config(config)
    }

    fn client_with_gossip() -> Client {
        client_builder_with_gossip().build()
    }

    /// Run a relay that rejects every negentropy request, so the gossip sync fails
    /// and the client falls back to a `REQ`.
    async fn run_relay_without_negentropy() -> LocalRelay {
        let relay = LocalRelay::builder()
            .max_negentropy_subscriptions(0)
            .build();
        relay.run().await.unwrap();
        relay
    }

    async fn assert_nip65_status(
        client: &Client,
        public_key: PublicKey,
        expected_status: GossipPublicKeyStatus,
    ) {
        let status: GossipPublicKeyStatus = client
            .gossip()
            .unwrap()
            .store()
            .status(&public_key, GossipListKind::Nip65)
            .await
            .unwrap();

        assert_eq!(status, expected_status);
    }

    async fn sync_nip65(client: &Client, public_key: PublicKey) {
        let gossip = client.gossip().unwrap();

        tokio::time::timeout(
            Duration::from_secs(5),
            client.sync_gossip_public_keys(
                gossip,
                BTreeSet::from([public_key]),
                &[GossipListKind::Nip65],
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn test_mark_missing_gossip_key_as_updated() {
        let gossip = NostrGossipMemory::unbounded();
        let client = Client::builder().gossip(gossip).build();

        let gossip = client.gossip().unwrap();
        let public_key = Keys::generate().public_key();

        let status = gossip
            .store()
            .status(&public_key, GossipListKind::Nip65)
            .await
            .unwrap();
        assert!(matches!(status, GossipPublicKeyStatus::Missing));

        client
            .mark_gossip_public_keys_checked(gossip.store(), &[GossipListKind::Nip65], [public_key])
            .await
            .unwrap();

        let status = gossip
            .store()
            .status(&public_key, GossipListKind::Nip65)
            .await
            .unwrap();
        assert!(matches!(status, GossipPublicKeyStatus::Updated));
    }

    #[tokio::test]
    async fn test_marks_missing_gossip_key_checked_when_all_fallback_relays_active() {
        let relay1 = run_relay_without_negentropy().await;
        let url1 = relay1.url().await;
        let relay2 = run_relay_without_negentropy().await;
        let url2 = relay2.url().await;

        let client = client_with_gossip();
        client.add_relay(&url1).await.unwrap();
        client.add_relay(&url2).await.unwrap();

        let connect_output = client.try_connect().timeout(Duration::from_secs(3)).await;
        assert_eq!(connect_output.success.len(), 2);
        assert!(connect_output.failed.is_empty());

        let public_key = Keys::generate().public_key();
        assert_nip65_status(&client, public_key, GossipPublicKeyStatus::Missing).await;

        sync_nip65(&client, public_key).await;

        assert_nip65_status(&client, public_key, GossipPublicKeyStatus::Updated).await;
    }

    #[tokio::test]
    async fn test_marks_missing_gossip_key_checked_when_some_fallback_relays_active() {
        let relay1 = run_relay_without_negentropy().await;
        let url1 = relay1.url().await;

        let inactive1 = RelayUrl::parse("ws://inactive1-fake.myfakedomain.local").unwrap();

        let client = client_with_gossip();
        client.add_relay(&url1).await.unwrap();
        client.add_relay(&inactive1).await.unwrap();

        let connect_output = client.try_connect().timeout(Duration::from_secs(3)).await;
        assert_eq!(connect_output.success.len(), 1);
        assert_eq!(connect_output.failed.len(), 1);

        let public_key = Keys::generate().public_key();
        assert_nip65_status(&client, public_key, GossipPublicKeyStatus::Missing).await;

        sync_nip65(&client, public_key).await;

        assert_nip65_status(&client, public_key, GossipPublicKeyStatus::Updated).await;
    }

    #[tokio::test]
    async fn test_fetches_newer_gossip_list_from_failed_sync_relays() {
        let local = run_relay_without_negentropy().await;
        let url = local.url().await;

        let keys = Keys::generate();
        let stored: Event =
            RelayList::new([(RelayUrl::parse("wss://old.example.com").unwrap(), None)])
                .into_event_builder()
                .custom_created_at(Timestamp::from_secs(1_000))
                .finalize(&keys)
                .unwrap();
        let newer: Event =
            RelayList::new([(RelayUrl::parse("wss://new.example.com").unwrap(), None)])
                .into_event_builder()
                .custom_created_at(Timestamp::from_secs(2_000))
                .finalize(&keys)
                .unwrap();
        local.add_event(newer.clone()).await.unwrap();

        let client = client_builder_with_gossip()
            .database(MemoryDatabase::unbounded())
            .build();
        client.database().save_event(&stored).await.unwrap();
        client.add_relay(&url).await.unwrap();

        let connect_output = client.try_connect().timeout(Duration::from_secs(3)).await;
        assert_eq!(connect_output.success.len(), 1);

        // The client asks the relay for a list newer than the stored one.
        sync_nip65(&client, keys.public_key()).await;

        let filter: Filter = Filter::new()
            .author(keys.public_key())
            .kind(Kind::RelayList);
        let events: BTreeSet<Event> = client.database().query(filter).await.unwrap();
        assert!(events.iter().any(|event| event.id == newer.id));
    }

    #[tokio::test]
    async fn test_keeps_missing_gossip_key_unchecked_when_all_fallback_relays_inactive() {
        let inactive1 = RelayUrl::parse("wss://inactive1.example.com").unwrap();
        let inactive2 = RelayUrl::parse("wss://inactive2.example.com").unwrap();

        let client = client_with_gossip();
        client.add_relay(&inactive1).await.unwrap();
        client.add_relay(&inactive2).await.unwrap();

        let public_key = Keys::generate().public_key();
        assert_nip65_status(&client, public_key, GossipPublicKeyStatus::Missing).await;

        sync_nip65(&client, public_key).await;

        // All relays are inactive, so the key should still be missing.
        assert_nip65_status(&client, public_key, GossipPublicKeyStatus::Missing).await;
    }
}
