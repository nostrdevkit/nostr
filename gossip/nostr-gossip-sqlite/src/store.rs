//! Nostr gossip SQLite store.

use std::cmp;
use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::num::NonZeroUsize;
use std::path::Path;
use std::pin::Pin;

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
use rusqlite::{OptionalExtension, Transaction, params};

use crate::constant::{MAX_RELAYS_PER_PK, READ_WRITE_FLAGS, RELAYS_QUERY_LIMIT, TTL_OUTDATED};
use crate::error::StoreError;
use crate::migration;
use crate::model::ListRow;
use crate::pool::Pool;

/// Nostr Gossip SQLite store.
#[derive(Debug, Clone)]
pub struct NostrGossipSqlite {
    pool: Pool,
}

impl NostrGossipSqlite {
    async fn new(pool: Pool) -> Result<Self, Error> {
        pool.interact(|conn| {
            if conn.pragma_update(None, "journal_mode", "WAL").is_err() {
                conn.pragma_update(None, "journal_mode", "DELETE")?;
            }
            conn.pragma_update(None, "foreign_keys", "ON")?;

            let tx = conn.transaction()?;

            // Run migrations
            migration::run(&tx)?;

            tx.commit()?;

            Ok(())
        })
        .await?;

        Ok(Self { pool })
    }

    /// Creates an in-memory database
    pub async fn in_memory() -> Result<Self, Error> {
        let pool: Pool = Pool::open_in_memory()?;
        Self::new(pool).await
    }

    /// Connect to a SQL database
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn open<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().to_path_buf();

        let pool: Pool = Pool::open_with_path(path).await?;

        Self::new(pool).await
    }

    /// Connect to a SQL database
    pub async fn open_with_vfs<P>(path: P, vfs: &str) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let pool: Pool = Pool::open_with_vfs(path, vfs).await?;
        Self::new(pool).await
    }

    async fn process_event(
        &self,
        event: &Event,
        relay_url: Option<&RelayUrl>,
    ) -> Result<(), StoreError> {
        let event = event.clone();
        let relay_url = relay_url.cloned();

        self.pool
            .interact(move |conn| {
                let tx = conn.transaction()?;

                // Save public key and get ID
                let pk_id: i32 = get_or_save_public_key(&tx, &event.pubkey)?;

                // Check the event kind
                match &event.kind {
                    // Extract NIP-65 relays
                    Kind::RelayList => {
                        update_nip65_relays(&tx, pk_id, nip65::extract_relay_list(&event))?
                    }
                    // Extract NIP-17 relays
                    Kind::InboxRelays => {
                        update_nip17_relays(&tx, pk_id, nip17::extract_relay_list(&event))?
                    }
                    // Extract hints
                    _ => update_hints(&tx, &event)?,
                }

                if let Some(relay_url) = relay_url.as_ref() {
                    update_relay_per_user(&tx, pk_id, relay_url, GossipFlags::RECEIVED)?;
                }

                // Commit the transaction
                tx.commit()?;

                Ok(())
            })
            .await
    }

    async fn get_status(
        &self,
        public_key: &PublicKey,
        list: GossipListKind,
    ) -> Result<GossipPublicKeyStatus, StoreError> {
        let public_key = *public_key;

        self.pool
            .interact(move |conn| {
                let tx = conn.transaction()?;

                match get_id_by_public_key(&tx, &public_key)? {
                    Some(pk_id) => {
                        let mut stmt = tx.prepare(
                            "SELECT event_created_at, last_checked_at FROM lists WHERE public_key_id = ?1 AND event_kind = ?2",
                        )?;
                        let row: Option<ListRow> = stmt
                            .query_row(
                                params![pk_id, i64::from(list.to_event_kind().as_u16())],
                                ListRow::from_row,
                            )
                            .optional()?;

                        match row {
                            Some(row) => {
                                let now: Timestamp = Timestamp::now();
                                let last: i64 = row.last_checked_at.unwrap_or(0);
                                let last: Timestamp = last.try_into()?;

                                if last + TTL_OUTDATED < now {
                                    Ok(GossipPublicKeyStatus::Outdated {
                                        created_at: match row.event_created_at {
                                            Some(t) => Some(t.try_into()?),
                                            None => None,
                                        },
                                    })
                                } else {
                                    Ok(GossipPublicKeyStatus::Updated)
                                }
                            }
                            None => Ok(GossipPublicKeyStatus::Missing),
                        }
                    }
                    None => Ok(GossipPublicKeyStatus::Missing),
                }
            })
            .await
    }

    async fn _update_fetch_attempt(
        &self,
        public_key: PublicKey,
        list: GossipListKind,
    ) -> Result<(), StoreError> {
        self.pool
            .interact(move |conn| {
                let tx = conn.transaction()?;

                let pk_id: i32 = get_or_save_public_key(&tx, &public_key)?;
                let now: i64 = Timestamp::now().as_secs() as i64;

                tx.execute(
                    r#"
            INSERT INTO lists (public_key_id, event_kind, last_checked_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT (public_key_id, event_kind)
            DO UPDATE SET last_checked_at = excluded.last_checked_at
            "#,
                    params![pk_id, i64::from(list.to_event_kind().as_u16()), now],
                )?;

                tx.commit()?;
                Ok(())
            })
            .await
    }

    async fn get_outdated_public_keys(
        &self,
        list: GossipListKind,
        limit: NonZeroUsize,
    ) -> Result<BTreeSet<OutdatedPublicKey>, StoreError> {
        let now: i64 = Timestamp::now().as_secs() as i64;
        let threshold: i64 = now.saturating_sub(TTL_OUTDATED.as_secs() as i64);
        self.pool
            .interact(move |conn| {
                let query = r#"
                    SELECT pk.public_key, l.last_checked_at
                    FROM lists l
                    INNER JOIN public_keys pk ON l.public_key_id = pk.id
                    WHERE l.event_kind = ?1
                      AND COALESCE(l.last_checked_at, 0) > 0
                      AND l.last_checked_at < ?2
                    ORDER BY l.last_checked_at ASC
                    LIMIT ?3
                "#;

                let mut stmt = conn.prepare(query)?;
                let query_limit: i64 = limit.get().try_into()?;
                let rows = stmt.query_map(
                    params![
                        i64::from(list.to_event_kind().as_u16()),
                        threshold,
                        query_limit
                    ],
                    |row| {
                        let public_key: Vec<u8> = row.get(0)?;
                        let last_checked_at: Option<i64> = row.get(1)?;
                        Ok((public_key, last_checked_at))
                    },
                )?;

                let mut public_keys: BTreeSet<OutdatedPublicKey> = BTreeSet::new();
                for row in rows {
                    let (public_key, timestamp) = row?;
                    let last: i64 = timestamp.unwrap_or(0);

                    if let (Ok(public_key), Ok(last)) =
                        (PublicKey::from_slice(&public_key), last.try_into())
                    {
                        public_keys.insert(OutdatedPublicKey::new(public_key, last));
                    }
                }

                Ok(public_keys)
            })
            .await
    }

    async fn _get_best_relays(
        &self,
        public_key: PublicKey,
        selection: BestRelaySelection,
        allowed: GossipAllowedRelays,
    ) -> Result<HashSet<RelayUrl>, StoreError> {
        let mut relays: HashSet<RelayUrl> = HashSet::new();

        match selection {
            BestRelaySelection::All {
                read,
                write,
                hints,
                most_received,
            } => {
                // Get read relays
                relays.extend(
                    self.get_relays_by_flag(public_key, GossipFlags::READ, allowed, read)
                        .await?,
                );

                // Get write relays
                relays.extend(
                    self.get_relays_by_flag(public_key, GossipFlags::WRITE, allowed, write)
                        .await?,
                );

                // Get hint relays
                relays.extend(
                    self.get_relays_by_flag(public_key, GossipFlags::HINT, allowed, hints)
                        .await?,
                );

                // Get most received relays
                relays.extend(
                    self.get_relays_by_flag(
                        public_key,
                        GossipFlags::RECEIVED,
                        allowed,
                        most_received,
                    )
                    .await?,
                );
            }
            BestRelaySelection::Read { limit } => {
                relays.extend(
                    self.get_relays_by_flag(public_key, GossipFlags::READ, allowed, limit)
                        .await?,
                );
            }
            BestRelaySelection::Write { limit } => {
                relays.extend(
                    self.get_relays_by_flag(public_key, GossipFlags::WRITE, allowed, limit)
                        .await?,
                );
            }
            BestRelaySelection::PrivateMessage { limit } => {
                relays.extend(
                    self.get_relays_by_flag(
                        public_key,
                        GossipFlags::PRIVATE_MESSAGE,
                        allowed,
                        limit,
                    )
                    .await?,
                );
            }
            BestRelaySelection::Hints { limit } => {
                relays.extend(
                    self.get_relays_by_flag(public_key, GossipFlags::HINT, allowed, limit)
                        .await?,
                );
            }
            BestRelaySelection::MostReceived { limit } => {
                relays.extend(
                    self.get_relays_by_flag(public_key, GossipFlags::RECEIVED, allowed, limit)
                        .await?,
                );
            }
        }

        Ok(relays)
    }

    async fn get_relays_by_flag(
        &self,
        public_key: PublicKey,
        flag: GossipFlags,
        allowed: GossipAllowedRelays,
        limit: u8,
    ) -> Result<Vec<RelayUrl>, StoreError> {
        self.pool
            .interact(move |conn| {
                let query = r#"
            SELECT r.url
            FROM relays_per_user rpu
            INNER JOIN relays r ON rpu.relay_id = r.id
            INNER JOIN public_keys pk ON rpu.public_key_id = pk.id
            WHERE pk.public_key = ?1 AND (rpu.bitflags & ?2) = ?2
            ORDER BY rpu.received_events DESC, rpu.last_received_event DESC
            LIMIT ?3
        "#;

                let query_limit: u8 = cmp::max(limit, RELAYS_QUERY_LIMIT);

                let mut stmt = conn.prepare(query)?;
                let rows = stmt.query_map(
                    params![
                        public_key.as_bytes().as_slice(),
                        flag.as_u32(),
                        i64::from(query_limit)
                    ],
                    |row| row.get::<_, String>(0),
                )?;

                let mut relays = Vec::new();
                for row in rows {
                    let url = row?;
                    if relays.len() >= limit as usize {
                        break;
                    }

                    if let Ok(relay_url) = RelayUrl::parse(&url) {
                        if !allowed.is_allowed(&relay_url) {
                            continue;
                        }

                        relays.push(relay_url);
                    }
                }

                Ok(relays)
            })
            .await
    }
}

fn get_or_save_public_key(tx: &Transaction<'_>, public_key: &PublicKey) -> Result<i32, StoreError> {
    match get_id_by_public_key(tx, public_key)? {
        Some(id) => Ok(id),
        None => save_public_key(tx, public_key),
    }
}

fn get_id_by_public_key(
    tx: &Transaction<'_>,
    public_key: &PublicKey,
) -> Result<Option<i32>, StoreError> {
    let pk_id: Option<i32> = tx
        .query_row(
            "SELECT id FROM public_keys WHERE public_key = ?1",
            params![public_key.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(pk_id)
}

fn save_public_key(tx: &Transaction<'_>, public_key: &PublicKey) -> Result<i32, StoreError> {
    tx.execute(
        "INSERT INTO public_keys (public_key) VALUES (?1) ON CONFLICT (public_key) DO NOTHING",
        params![public_key.as_bytes().as_slice()],
    )?;
    let pk_id: i32 = tx.query_row(
        "SELECT id FROM public_keys WHERE public_key = ?1",
        params![public_key.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    Ok(pk_id)
}

fn get_or_save_relay_url(tx: &Transaction<'_>, relay_url: &RelayUrl) -> Result<i32, StoreError> {
    match get_id_by_relay_url(tx, relay_url)? {
        Some(id) => Ok(id),
        None => save_relay_url(tx, relay_url),
    }
}

fn get_id_by_relay_url(
    tx: &Transaction<'_>,
    relay_url: &RelayUrl,
) -> Result<Option<i32>, StoreError> {
    let relay_id: Option<i32> = tx
        .query_row(
            "SELECT id FROM relays WHERE url = ?1",
            params![relay_url.as_str_without_trailing_slash()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(relay_id)
}

fn save_relay_url(tx: &Transaction<'_>, relay_url: &RelayUrl) -> Result<i32, StoreError> {
    tx.execute(
        "INSERT INTO relays (url) VALUES (?1) ON CONFLICT (url) DO NOTHING",
        params![relay_url.as_str_without_trailing_slash()],
    )?;
    let relay_id: i32 = tx.query_row(
        "SELECT id FROM relays WHERE url = ?1",
        params![relay_url.as_str_without_trailing_slash()],
        |row| row.get(0),
    )?;
    Ok(relay_id)
}

fn remove_flag_from_user_relays(
    tx: &Transaction<'_>,
    public_key_id: i32,
    flags_to_remove: GossipFlags,
) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE relays_per_user SET bitflags = (bitflags & ~?1) WHERE public_key_id = ?2",
        params![flags_to_remove.as_u32(), public_key_id],
    )?;
    Ok(())
}

/// Add relay per user or update the received events and bitflags.
fn update_relay_per_user(
    tx: &Transaction<'_>,
    public_key_id: i32,
    relay_url: &RelayUrl,
    flags: GossipFlags,
) -> Result<(), StoreError> {
    let relay_id: i32 = get_or_save_relay_url(tx, relay_url)?;

    // Cap the number of distinct relays per public key, mirroring the
    // in-memory backend (MAX_RELAYS_PER_PK). Only update when the relay
    // already exists for this key; otherwise skip once the cap is reached.
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM relays_per_user WHERE public_key_id = ?1 AND relay_id = ?2)",
            params![public_key_id, relay_id],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !exists {
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM relays_per_user WHERE public_key_id = ?1",
                params![public_key_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if count >= MAX_RELAYS_PER_PK as i64 {
            return Ok(());
        }
    }

    let now: u64 = Timestamp::now().as_secs();

    tx.execute(
        r#"
        INSERT INTO relays_per_user (public_key_id, relay_id, bitflags, received_events, last_received_event)
        VALUES (?1, ?2, ?3, 1, ?4)
        ON CONFLICT (public_key_id, relay_id)
        DO UPDATE SET
            bitflags = bitflags | excluded.bitflags,
            received_events = received_events + 1,
            last_received_event = excluded.last_received_event
        "#,
        params![public_key_id, relay_id, flags.as_u32(), now as i64],
    )?;

    Ok(())
}

fn update_nip65_relays<I>(
    tx: &Transaction<'_>,
    public_key_id: i32,
    iter: I,
) -> Result<(), StoreError>
where
    I: IntoIterator<Item = (RelayUrl, Option<RelayMetadata>)>,
{
    // Remove all READ and WRITE flags from the relays of the public key
    remove_flag_from_user_relays(tx, public_key_id, READ_WRITE_FLAGS)?;

    // Extract relay list
    for (relay_url, metadata) in iter {
        // Save relay and get ID
        let relay_id: i32 = get_or_save_relay_url(tx, &relay_url)?;

        // New bitflag for the relay
        let bitflag: GossipFlags = match metadata {
            Some(RelayMetadata::Read) => GossipFlags::READ,
            Some(RelayMetadata::Write) => GossipFlags::WRITE,
            None => READ_WRITE_FLAGS,
        };

        // Update bitflag
        tx.execute(
            r#"
                    INSERT INTO relays_per_user (public_key_id, relay_id, bitflags)
                    VALUES (?1, ?2, ?3)
                    ON CONFLICT (public_key_id, relay_id)
                    DO UPDATE SET
                        bitflags = bitflags | excluded.bitflags
                    "#,
            params![public_key_id, relay_id, bitflag.as_u32()],
        )?;
    }

    Ok(())
}

fn update_nip17_relays<I>(
    tx: &Transaction<'_>,
    public_key_id: i32,
    iter: I,
) -> Result<(), StoreError>
where
    I: IntoIterator<Item = RelayUrl>,
{
    // Remove all PRIVATE_MESSAGE flag from the relays of the public key
    remove_flag_from_user_relays(tx, public_key_id, GossipFlags::PRIVATE_MESSAGE)?;

    // Extract relay list
    for relay_url in iter {
        let relay_id: i32 = get_or_save_relay_url(tx, &relay_url)?;

        tx.execute(
            r#"
                    INSERT INTO relays_per_user (public_key_id, relay_id, bitflags)
                    VALUES (?1, ?2, ?3)
                    ON CONFLICT (public_key_id, relay_id)
                    DO UPDATE SET
                        bitflags = bitflags | excluded.bitflags
                    "#,
            params![
                public_key_id,
                relay_id,
                GossipFlags::PRIVATE_MESSAGE.as_u32()
            ],
        )?;
    }

    Ok(())
}

fn update_hints(tx: &Transaction<'_>, event: &Event) -> Result<(), StoreError> {
    for tag in event.tags.iter().filter_map(|t| {
        if t.kind() != "p" {
            return None;
        }

        Nip01Tag::try_from(t).ok()
    }) {
        if let Nip01Tag::PublicKey {
            public_key,
            relay_hint: Some(relay_url),
        } = tag
        {
            let p_tag_pk_id: i32 = get_or_save_public_key(tx, &public_key)?;
            update_relay_per_user(tx, p_tag_pk_id, &relay_url, GossipFlags::HINT)?;
        }
    }

    Ok(())
}

impl NostrGossip for NostrGossipSqlite {
    fn process<'a>(
        &'a self,
        event: &'a Event,
        relay_url: Option<&'a RelayUrl>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            self.process_event(event, relay_url)
                .await
                .map_err(Into::into)
        })
    }

    fn status<'a>(
        &'a self,
        public_key: &'a PublicKey,
        list: GossipListKind,
    ) -> Pin<Box<dyn Future<Output = Result<GossipPublicKeyStatus, Error>> + Send + 'a>> {
        Box::pin(async move { self.get_status(public_key, list).await.map_err(Into::into) })
    }

    fn update_fetch_attempt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        list: GossipListKind,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            self._update_fetch_attempt(*public_key, list)
                .await
                .map_err(Into::into)
        })
    }

    fn outdated_public_keys(
        &self,
        list: GossipListKind,
        limit: NonZeroUsize,
    ) -> Pin<Box<dyn Future<Output = Result<BTreeSet<OutdatedPublicKey>, Error>> + Send + '_>> {
        Box::pin(async move {
            self.get_outdated_public_keys(list, limit)
                .await
                .map_err(Into::into)
        })
    }

    fn get_best_relays<'a>(
        &'a self,
        public_key: &'a PublicKey,
        selection: BestRelaySelection,
        allowed: GossipAllowedRelays,
    ) -> Pin<Box<dyn Future<Output = Result<HashSet<RelayUrl>, Error>> + Send + 'a>> {
        Box::pin(async move {
            self._get_best_relays(*public_key, selection, allowed)
                .await
                .map_err(Into::into)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use nostr_gossip_test_suite::gossip_unit_tests;
    use tempfile::TempDir;

    use super::*;

    #[derive(Debug)]
    struct NostrGossipSqliteUnitTest {
        store: NostrGossipSqlite,
        _temp_dir: TempDir,
    }

    impl Deref for NostrGossipSqliteUnitTest {
        type Target = NostrGossipSqlite;

        fn deref(&self) -> &Self::Target {
            &self.store
        }
    }

    async fn setup() -> NostrGossipSqliteUnitTest {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let path = temp_dir.path().join("test.db");

        let store = NostrGossipSqlite::open(path).await.unwrap();

        NostrGossipSqliteUnitTest {
            store,
            _temp_dir: temp_dir,
        }
    }

    gossip_unit_tests!(NostrGossipSqliteUnitTest, setup);
}
