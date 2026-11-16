//! Nostr SQLite database

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
use std::pin::Pin;

use nostr::nips::nip01::Coordinate;
use nostr::nips::nip62;
use nostr_database::error::Error;
use nostr_database::prelude::*;
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Transaction, params, params_from_iter};

use crate::builder::{DatabaseConnType, NostrSqliteBuilder};
use crate::error::StoreError;
use crate::migration;
use crate::model::{EventDb, extract_tags};
use crate::pool::Pool;

const EVENTS_QUERY_LIMIT: usize = 10_000;
const NIP50_SEARCHABLE_TAGS_SQL: &str = "'title', 'description', 'subject', 'name'";

#[derive(Clone, Copy)]
enum SqlSelectClause {
    Select,
    Negentropy,
    Count,
    Delete,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct NostrSqliteOptions {
    /// Whether to process request to vanish (NIP-62) events
    pub(crate) process_nip62: bool,
    /// Whether to process event deletion request (NIP-09) events
    pub(crate) process_nip09: bool,
    /// Relay URL for relay-specific request to vanish (NIP-62).
    pub(crate) relay_url: Option<RelayUrl>,
}

/// Nostr SQLite database
///
/// Use [`NostrSqlite::builder`] to build it
#[derive(Debug, Clone)]
pub struct NostrSqlite {
    pool: Pool,
}

impl NostrSqlite {
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
    async fn in_memory(options: NostrSqliteOptions) -> Result<Self, Error> {
        let pool: Pool = Pool::open_in_memory(options)?;
        Self::new(pool).await
    }

    /// Connect to a SQL database
    #[cfg(not(target_arch = "wasm32"))]
    async fn open<P>(path: P, options: NostrSqliteOptions) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let path: PathBuf = path.as_ref().to_path_buf();

        let pool: Pool = Pool::open_with_path(path, options).await?;

        Self::new(pool).await
    }

    /// Connect to a SQL database
    async fn open_with_vfs<P>(
        path: P,
        vfs: &str,
        options: NostrSqliteOptions,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let pool: Pool = Pool::open_with_vfs(path, vfs, options).await?;
        Self::new(pool).await
    }

    pub(crate) async fn from_builder(builder: NostrSqliteBuilder) -> Result<Self, Error> {
        let options = NostrSqliteOptions {
            process_nip09: builder.process_nip09,
            process_nip62: builder.process_nip62,
            relay_url: builder.relay_url,
        };

        match builder.db_type {
            DatabaseConnType::InMemory => Self::in_memory(options).await,
            #[cfg(not(target_arch = "wasm32"))]
            DatabaseConnType::File(path) => Self::open(path, options).await,
            DatabaseConnType::WithVFS { path, vfs } => {
                Self::open_with_vfs(path, &vfs, options).await
            }
        }
    }

    /// The database builder
    #[inline]
    pub fn builder() -> NostrSqliteBuilder {
        NostrSqliteBuilder::default()
    }

    /// Returns true if successfully inserted
    fn insert_event_tx(tx: &Transaction<'_>, event: &Event) -> Result<bool, StoreError> {
        let tags = serde_json::to_string(&event.tags)?;

        let rows = tx.execute(
            "INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, content, tags, sig) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.id.as_bytes().as_slice(),
                event.pubkey.as_bytes().as_slice(),
                event.created_at.as_secs() as i64,
                event.kind.as_u16() as i64,
                &event.content,
                tags,
                event.sig.as_bytes(),
            ],
        )?;

        Ok(rows > 0)
    }

    fn handle_deletion_event(tx: &Transaction<'_>, event: &Event) -> Result<bool, StoreError> {
        for id in event.tags.event_ids() {
            if let Some(pubkey) = Self::get_pubkey_of_event_by_id(tx, &id)? {
                // Author must match
                if pubkey != event.pubkey {
                    return Ok(true);
                }

                // Mark the event ID as deleted (for NIP-09 deletion events)
                Self::mark_event_as_deleted(tx, &id)?;

                // Remove event from store
                Self::remove_event(tx, &id)?;
            }
        }

        for coordinate in event.tags.coordinates() {
            // Author must match
            if coordinate.public_key != event.pubkey {
                return Ok(true);
            }

            // Mark deleted
            Self::mark_coordinate_deleted(tx, &coordinate, event.created_at)?;

            // Remove events (up to the created_at of the deletion event)
            if coordinate.kind.is_replaceable() {
                Self::remove_replaceable(tx, &coordinate, &event.created_at)?;
            } else if coordinate.kind.is_addressable() {
                Self::remove_addressable(tx, &coordinate, event.created_at)?;
            }
        }

        Ok(false)
    }

    fn save_event_sync(
        conn: &mut Connection,
        event: &Event,
        options: &NostrSqliteOptions,
    ) -> Result<SaveEventStatus, StoreError> {
        if event.kind.is_ephemeral() {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Ephemeral));
        }

        let tx = conn.transaction()?;

        // Already exists
        if Self::has_event(&tx, &event.id)? {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Duplicate));
        }

        // Reject event if ID was deleted
        if Self::event_is_deleted(&tx, &event.id)? {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Deleted));
        }

        // Reject event if the public key was vanished
        if Self::pubkey_is_vanished(&tx, &event.pubkey)? {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Vanished));
        }

        // Reject event if ADDR was deleted after it's created_at date
        // (replaceable or addressable)
        if let Some(coordinate) = event.coordinate() {
            let timestamp: Option<Timestamp> = Self::when_is_coordinate_deleted(&tx, &coordinate)?;

            if let Some(time) = timestamp {
                if event.created_at <= time {
                    return Ok(SaveEventStatus::Rejected(RejectedReason::Deleted));
                }
            }
        }

        // Remove replaceable events being replaced
        if event.kind.is_replaceable() {
            // Find existing replaceable event
            let mut stmt =
                tx.prepare("SELECT * FROM events WHERE pubkey = ?1 AND kind = ?2 LIMIT 1")?;
            let existing: Option<EventDb> = stmt
                .query_row(
                    params![
                        event.pubkey.as_bytes().as_slice(),
                        event.kind.as_u16() as i64
                    ],
                    EventDb::from_row,
                )
                .optional()?;

            if let Some(stored) = existing {
                // Check if new event should replace stored
                if has_event_been_replaced(&stored, event) {
                    // New event is older or same timestamp with higher ID - reject it
                    return Ok(SaveEventStatus::Rejected(RejectedReason::Replaced));
                }

                // Delete the old event (CASCADE will delete tags too)
                tx.execute("DELETE FROM events WHERE id = ?1", params![stored.id])?;
            }
        }

        // Remove addressable events being replaced
        if event.kind.is_addressable() {
            if let Some(identifier) = event.tags.identifier() {
                let mut stmt = tx.prepare(
                    "SELECT e.* FROM events e\n                 INNER JOIN event_tags t ON e.id = t.event_id\n                 WHERE e.pubkey = ?1 AND e.kind = ?2\n                 AND t.tag_name = 'd' AND t.tag_value = ?3\n                 LIMIT 1",
                )?;
                let existing: Option<EventDb> = stmt
                    .query_row(
                        params![
                            event.pubkey.as_bytes().as_slice(),
                            event.kind.as_u16() as i64,
                            identifier
                        ],
                        EventDb::from_row,
                    )
                    .optional()?;

                if let Some(stored) = existing {
                    if has_event_been_replaced(&stored, event) {
                        return Ok(SaveEventStatus::Rejected(RejectedReason::Replaced));
                    }

                    // Delete the old addressable event
                    tx.execute("DELETE FROM events WHERE id = ?1", params![stored.id])?;
                }
            }
        }

        // Handle deletion events
        if options.process_nip09 && event.kind == Kind::EventDeletion {
            let invalid: bool = Self::handle_deletion_event(&tx, event)?;

            if invalid {
                tx.rollback()?;
                return Ok(SaveEventStatus::Rejected(RejectedReason::InvalidDelete));
            }
        }

        if options.process_nip62
            && event.kind == Kind::RequestToVanish
            && nip62::is_valid_vanish_request_for_relay(
                event.tags.as_slice(),
                options.relay_url.as_ref(),
            )
        {
            Self::handle_request_to_vanish(&tx, &event.pubkey)?;
        }

        // Insert event first
        let inserted: bool = Self::insert_event_tx(&tx, event)?;

        // Check if the event has been inserted
        if inserted {
            // Insert tags
            for tag in extract_tags(event) {
                tx.execute(
                    "INSERT OR IGNORE INTO event_tags(event_id, tag_name, tag_value) VALUES (?1, ?2, ?3)",
                    params![tag.event_id, tag.tag_name.as_str(), tag.tag_value],
                )?;
            }

            // Commit transaction
            tx.commit()?;

            Ok(SaveEventStatus::Success)
        } else {
            // Event has not been inserted, rollback transaction
            tx.rollback()?;
            Ok(SaveEventStatus::Rejected(RejectedReason::Duplicate))
        }
    }

    fn mark_event_as_deleted(tx: &Transaction<'_>, id: &EventId) -> Result<(), StoreError> {
        tx.execute(
            "INSERT OR IGNORE INTO deleted_ids(event_id) VALUES (?1)",
            params![id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    fn mark_coordinate_deleted(
        tx: &Transaction<'_>,
        coordinate: &Coordinate,
        deleted_at: Timestamp,
    ) -> Result<(), StoreError> {
        tx.execute(
            "INSERT OR IGNORE INTO deleted_coordinates(pubkey, kind, identifier, deleted_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                coordinate.public_key.as_bytes().as_slice(),
                coordinate.kind.as_u16() as i64,
                &coordinate.identifier,
                deleted_at.as_secs() as i64
            ],
        )?;
        Ok(())
    }

    fn event_is_deleted(tx: &Transaction<'_>, id: &EventId) -> Result<bool, StoreError> {
        let is_deleted: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM deleted_ids WHERE event_id = ?1)",
            params![id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(is_deleted != 0)
    }

    fn when_is_coordinate_deleted(
        tx: &Transaction<'_>,
        coordinate: &Coordinate,
    ) -> Result<Option<Timestamp>, StoreError> {
        let timestamp: Option<i64> = tx
            .query_row(
                "SELECT deleted_at FROM deleted_coordinates WHERE pubkey = ?1 AND kind = ?2 AND identifier = ?3",
                params![
                    coordinate.public_key.as_bytes().as_slice(),
                    coordinate.kind.as_u16() as i64,
                    &coordinate.identifier
                ],
                |row| row.get(0),
            )
            .optional()?;

        match timestamp {
            Some(timestamp) => Ok(Some(timestamp.try_into()?)),
            None => Ok(None),
        }
    }

    fn pubkey_is_vanished(tx: &Transaction<'_>, pubkey: &PublicKey) -> Result<bool, StoreError> {
        let is_vanished: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM vanished_public_keys WHERE pubkey = ?1)",
            params![pubkey.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(is_vanished != 0)
    }

    fn mark_pubkey_as_vanished(tx: &Transaction<'_>, pubkey: &PublicKey) -> Result<(), StoreError> {
        tx.execute(
            "INSERT OR IGNORE INTO vanished_public_keys(pubkey) VALUES (?1)",
            params![pubkey.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    fn handle_request_to_vanish(
        tx: &Transaction<'_>,
        pubkey: &PublicKey,
    ) -> Result<(), StoreError> {
        Self::mark_pubkey_as_vanished(tx, pubkey)?;

        // Delete all user events
        tx.execute(
            "DELETE FROM events where pubkey = ?1",
            params![pubkey.as_bytes().as_slice()],
        )?;

        // Delete all gift wraps that mention the public key
        tx.execute(
            r#"
        DELETE FROM events
        WHERE id IN (
            SELECT e.id
            FROM events AS e
            INNER JOIN event_tags AS et
                ON e.id = et.event_id
            WHERE
                e.kind = 1059 AND
                et.tag_name = 'p' AND
                et.tag_value = ?1
        )
        "#,
            params![pubkey.to_hex()],
        )?;

        Ok(())
    }

    fn has_event(tx: &Transaction<'_>, id: &EventId) -> Result<bool, StoreError> {
        let exists: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE id = ?1)",
            params![id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(exists != 0)
    }

    fn get_pubkey_of_event_by_id(
        tx: &Transaction<'_>,
        id: &EventId,
    ) -> Result<Option<PublicKey>, StoreError> {
        let pubkey: Option<Vec<u8>> = tx
            .query_row(
                "SELECT pubkey FROM events WHERE id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match pubkey {
            Some(pk) => Ok(Some(PublicKey::from_slice(&pk)?)),
            None => Ok(None),
        }
    }

    fn get_event_by_id(conn: &Connection, id: &EventId) -> Result<Option<Event>, StoreError> {
        let mut stmt = conn.prepare("SELECT * FROM events WHERE id = ?1")?;
        let event: Option<EventDb> = stmt
            .query_row(params![id.as_bytes().as_slice()], EventDb::from_row)
            .optional()?;
        match event {
            Some(event) => Ok(Some(event.to_event()?)),
            None => Ok(None),
        }
    }

    fn remove_event(tx: &Transaction<'_>, id: &EventId) -> Result<(), StoreError> {
        tx.execute(
            "DELETE FROM events where id = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Remove all replaceable events with the matching author-kind
    fn remove_replaceable(
        tx: &Transaction<'_>,
        coordinate: &Coordinate,
        until: &Timestamp,
    ) -> Result<(), StoreError> {
        tx.execute(
            "DELETE FROM events\n         WHERE pubkey = ?1 AND kind = ?2 AND created_at <= ?3",
            params![
                coordinate.public_key.as_bytes().as_slice(),
                coordinate.kind.as_u16() as i64,
                until.as_secs() as i64
            ],
        )?;

        Ok(())
    }

    /// Remove all addressable events with the matching author-kind-identifier
    fn remove_addressable(
        tx: &Transaction<'_>,
        coordinate: &Coordinate,
        until: Timestamp,
    ) -> Result<(), StoreError> {
        tx.execute(
            "DELETE FROM events\n         WHERE id IN (\n             SELECT e.id FROM events e\n             INNER JOIN event_tags t ON e.id = t.event_id\n             WHERE e.pubkey = ?1 AND e.kind = ?2\n             AND t.tag_name = 'd' AND t.tag_value = ?3\n             AND e.created_at <= ?4\n         )",
            params![
                coordinate.public_key.as_bytes().as_slice(),
                coordinate.kind.as_u16() as i64,
                &coordinate.identifier,
                until.as_secs() as i64
            ],
        )?;

        Ok(())
    }
}

impl NostrDatabase for NostrSqlite {
    #[inline]
    fn backend(&self) -> &'static str {
        "SQLite"
    }

    fn features(&self) -> Features {
        Features {
            persistent: true,
            event_expiration: false,
            full_text_search: true,
            request_to_vanish: true,
        }
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<SaveEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move {
            let event = event.clone();
            Ok(self
                .pool
                .interact_options(move |conn, options| Self::save_event_sync(conn, &event, options))
                .await?)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<DatabaseEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move {
            let event_id = *event_id;
            Ok(self
                .pool
                .interact(move |conn| {
                    let tx = conn.transaction()?;

                    if Self::event_is_deleted(&tx, &event_id)? {
                        Ok(DatabaseEventStatus::Deleted)
                    } else if Self::has_event(&tx, &event_id)? {
                        Ok(DatabaseEventStatus::Saved)
                    } else {
                        Ok(DatabaseEventStatus::NotExistent)
                    }
                })
                .await?)
        })
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Event>, Error>> + Send + 'a>> {
        Box::pin(async move {
            let event_id = *event_id;
            Ok(self
                .pool
                .interact(move |conn| Self::get_event_by_id(conn, &event_id))
                .await?)
        })
    }

    fn count(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<usize, Error>> + Send + '_>> {
        Box::pin(async move {
            let filter = with_limit(filter, EVENTS_QUERY_LIMIT);
            Ok(self
                .pool
                .interact(move |conn| {
                    let query = build_filter(&filter, SqlSelectClause::Count);
                    let mut stmt = conn.prepare(&query.sql)?;
                    let count: i64 =
                        stmt.query_row(params_from_iter(query.params), |row| row.get(0))?;
                    Ok(count as usize)
                })
                .await?)
        })
    }

    fn query(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<BTreeSet<Event>, Error>> + Send + '_>> {
        Box::pin(async move {
            let filter = with_limit(filter, EVENTS_QUERY_LIMIT);
            Ok(self
                .pool
                .interact(move |conn| {
                    let mut events: BTreeSet<Event> = BTreeSet::new();
                    let query = build_filter(&filter, SqlSelectClause::Select);
                    let mut stmt = conn.prepare(&query.sql)?;
                    let rows = stmt.query_map(params_from_iter(query.params), EventDb::from_row)?;

                    for row in rows {
                        if let Ok(event) = row?.to_event() {
                            events.insert(event);
                        }
                    }

                    Ok(events)
                })
                .await?)
        })
    }

    fn negentropy_items(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(EventId, Timestamp)>, Error>> + Send + '_>> {
        Box::pin(async move {
            let filter = with_limit(filter, EVENTS_QUERY_LIMIT);
            Ok(self
                .pool
                .interact(move |conn| {
                    let query = build_filter(&filter, SqlSelectClause::Negentropy);
                    let mut stmt = conn.prepare(&query.sql)?;
                    let rows = stmt.query_map(params_from_iter(query.params), |row| {
                        Ok((
                            row.get::<_, Vec<u8>>("id")?,
                            row.get::<_, i64>("created_at")?,
                            row.get::<_, String>("tags")?,
                        ))
                    })?;
                    let now = Timestamp::now();
                    let mut items = Vec::new();

                    for row in rows {
                        let (id, created_at, tags) = row?;
                        let tags: Tags = serde_json::from_str(&tags)?;

                        if tags.expiration().is_some_and(|expiration| expiration < now) {
                            continue;
                        }

                        items.push((EventId::from_slice(&id)?, created_at.try_into()?));
                    }

                    Ok(items)
                })
                .await?)
        })
    }

    fn delete(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move {
            Ok(self
                .pool
                .interact(move |conn| {
                    let query = build_filter(&filter, SqlSelectClause::Delete);
                    conn.execute(&query.sql, params_from_iter(query.params))?;
                    Ok(())
                })
                .await?)
        })
    }

    fn wipe(&self) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move {
            Ok(self
                .pool
                .interact(move |conn| {
                    // Delete all data (CASCADE will handle event_tags)
                    conn.execute("DELETE FROM events", [])?;
                    conn.execute("DELETE FROM deleted_ids", [])?;
                    conn.execute("DELETE FROM deleted_coordinates", [])?;

                    // Vacuum to reclaim space
                    conn.execute("VACUUM", [])?;

                    Ok(())
                })
                .await?)
        })
    }
}

fn has_event_been_replaced(stored: &EventDb, event: &Event) -> bool {
    match stored.created_at.cmp(&(event.created_at.as_secs() as i64)) {
        Ordering::Greater => true, // Stored is newer, reject incoming event
        Ordering::Equal => {
            // NIP-01: When timestamps are identical, keep the event with the LOWEST ID
            // Return true if stored.id < event.id (stored should be kept, reject incoming)
            // Return false if event.id < stored.id (incoming should replace stored)
            stored.id.as_slice() < event.id.as_bytes().as_slice()
        }
        Ordering::Less => false, // Stored is older, accept incoming event (will replace stored)
    }
}

struct FilterQuery {
    sql: String,
    params: Vec<Value>,
}

fn build_filter(filter: &Filter, select_clause: SqlSelectClause) -> FilterQuery {
    // If no filters, simple query without JOIN
    if filter.is_empty() {
        let mut sql = String::from(match select_clause {
            SqlSelectClause::Select => "SELECT * FROM events",
            SqlSelectClause::Negentropy => "SELECT id, created_at, tags FROM events",
            SqlSelectClause::Count => "SELECT COUNT(*) FROM events",
            SqlSelectClause::Delete => "DELETE FROM events",
        });

        if let SqlSelectClause::Select | SqlSelectClause::Negentropy | SqlSelectClause::Count =
            select_clause
        {
            sql.push_str(" ORDER BY created_at DESC");
            if let Some(limit) = filter.limit {
                sql.push_str(" LIMIT ?");
                return FilterQuery {
                    sql,
                    params: vec![Value::Integer(limit as i64)],
                };
            }
        }

        return FilterQuery {
            sql,
            params: Vec::new(),
        };
    }

    let mut sql = match select_clause {
        SqlSelectClause::Select => "SELECT DISTINCT e.*".to_string(),
        SqlSelectClause::Negentropy => "SELECT DISTINCT e.id, e.created_at, e.tags".to_string(),
        SqlSelectClause::Count => "SELECT COUNT(DISTINCT e.id)".to_string(),
        // For DELETE, we need to use a subquery because SQLite doesn't support DELETE with JOIN directly
        SqlSelectClause::Delete => {
            let mut sql =
                "DELETE FROM events WHERE id IN (SELECT DISTINCT e.id FROM events e".to_string();

            // Only JOIN if we have tag filters
            if !filter.generic_tags.is_empty() {
                sql.push_str(" INNER JOIN event_tags et ON e.id = et.event_id");
            }

            sql.push_str(" WHERE 1=1");

            let mut query = FilterQuery {
                sql,
                params: Vec::new(),
            };

            add_filter_conditions(filter, &mut query);

            query.sql.push(')');
            return query;
        }
    };

    sql.push_str(" FROM events e");

    // Only JOIN if we have tag filters
    if !filter.generic_tags.is_empty() {
        sql.push_str(" INNER JOIN event_tags et ON e.id = et.event_id");
    }

    sql.push_str(" WHERE 1=1");

    let mut query = FilterQuery {
        sql,
        params: Vec::new(),
    };

    // Add all the filter conditions
    add_filter_conditions(filter, &mut query);

    // Only add ORDER BY and LIMIT for queries that select event data
    query.sql.push_str(" ORDER BY e.created_at DESC");

    if let Some(limit) = filter.limit {
        query.sql.push_str(" LIMIT ?");
        query.params.push(Value::Integer(limit as i64));
    }

    query
}

// Extract filter conditions to avoid duplication
fn add_filter_conditions(filter: &Filter, query: &mut FilterQuery) {
    if let Some(ids) = &filter.ids {
        if !ids.is_empty() {
            query.sql.push_str(" AND e.id IN (");
            for (idx, id) in ids.iter().enumerate() {
                if idx > 0 {
                    query.sql.push_str(", ");
                }
                query.sql.push('?');
                query
                    .params
                    .push(Value::Blob(id.as_bytes().as_slice().to_vec()));
            }
            query.sql.push(')');
        }
    }

    if let Some(authors) = &filter.authors {
        if !authors.is_empty() {
            query.sql.push_str(" AND e.pubkey IN (");
            for (idx, author) in authors.iter().enumerate() {
                if idx > 0 {
                    query.sql.push_str(", ");
                }
                query.sql.push('?');
                query
                    .params
                    .push(Value::Blob(author.as_bytes().as_slice().to_vec()));
            }
            query.sql.push(')');
        }
    }

    if let Some(kinds) = &filter.kinds {
        if !kinds.is_empty() {
            query.sql.push_str(" AND e.kind IN (");
            for (idx, kind) in kinds.iter().enumerate() {
                if idx > 0 {
                    query.sql.push_str(", ");
                }
                query.sql.push('?');
                query.params.push(Value::Integer(kind.as_u16() as i64));
            }
            query.sql.push(')');
        }
    }

    if let Some(since) = filter.since {
        query.sql.push_str(" AND e.created_at >= ?");
        query.params.push(Value::Integer(since.as_secs() as i64));
    }

    if let Some(until) = filter.until {
        query.sql.push_str(" AND e.created_at <= ?");
        query.params.push(Value::Integer(until.as_secs() as i64));
    }

    // Search filter (if exists)
    if let Some(search) = &filter.search {
        if search.is_empty() {
            query.sql.push_str(" AND 0");
        } else {
            query
                .sql
                .push_str(" AND (INSTR(LOWER(e.content), LOWER(?)) > 0");
            query.params.push(Value::Text(search.clone()));
            query.sql.push_str(
                " OR EXISTS (\n                    SELECT 1 FROM json_each(e.tags) AS jt\n                    WHERE json_type(jt.value) = 'array'\n                    AND json_array_length(jt.value) > 1\n                    AND json_extract(jt.value, '$[0]') IN (",
            );
            query.sql.push_str(NIP50_SEARCHABLE_TAGS_SQL);
            query.sql.push_str(
                ")\n                    AND INSTR(LOWER(COALESCE(json_extract(jt.value, '$[1]'), '')), LOWER(?)) > 0\n                ))",
            );
            query.params.push(Value::Text(search.clone()));
        }
    }

    if !filter.generic_tags.is_empty() {
        for (tag, values) in &filter.generic_tags {
            if !values.is_empty() {
                query.sql.push_str(
                    " AND EXISTS (\n                    SELECT 1 FROM event_tags et2\n                    WHERE et2.event_id = e.id\n                    AND et2.tag_name = ? AND et2.tag_value IN (",
                );
                query.params.push(Value::Text(tag.to_string()));

                for (idx, value) in values.iter().enumerate() {
                    if idx > 0 {
                        query.sql.push_str(", ");
                    }
                    query.sql.push('?');
                    query.params.push(Value::Text(value.to_string()));
                }
                query.sql.push_str("))");
            }
        }
    }
}

/// sets the given default limit on a Nostr filter if not set
fn with_limit(filter: Filter, default_limit: usize) -> Filter {
    match filter.limit {
        Some(..) => filter,
        None => filter.limit(default_limit),
    }
}

#[cfg(test)]
mod tests {
    use nostr::event::{EventBuilder, Tag};
    use nostr::key::Keys;
    use nostr_database_test_suite::database_unit_tests;

    use super::*;

    struct TempDatabase {
        db: NostrSqlite,
    }

    impl Deref for TempDatabase {
        type Target = NostrSqlite;

        fn deref(&self) -> &Self::Target {
            &self.db
        }
    }

    impl TempDatabase {
        async fn new() -> Self {
            Self {
                db: NostrSqliteBuilder::default().build().await.unwrap(),
            }
        }

        async fn new_with_relay_url(url: RelayUrl) -> Self {
            Self {
                db: NostrSqliteBuilder::default()
                    .relay_url(url)
                    .build()
                    .await
                    .unwrap(),
            }
        }
    }

    database_unit_tests!(
        TempDatabase,
        TempDatabase::new,
        TempDatabase::new_with_relay_url
    );

    #[tokio::test]
    async fn test_full_text_search_matches_selected_tags_only() {
        let db = NostrSqliteBuilder::default().build().await.unwrap();
        let keys = Keys::generate();

        let event = EventBuilder::new(Kind::TextNote)
            .content("content")
            .tag(Tag::parse(["title", "alpha-token"]).unwrap())
            .tag(Tag::parse(["description", "beta-token"]).unwrap())
            .tag(Tag::parse(["subject", "gamma-token"]).unwrap())
            .tag(Tag::parse(["name", "delta-token"]).unwrap())
            .tag(Tag::identifier("epsilon-token"))
            .finalize(&keys)
            .unwrap();

        assert!(db.save_event(&event).await.unwrap().is_success());

        let events = db.query(Filter::new().search("ALPHA-token")).await.unwrap();
        assert_eq!(events.len(), 1);

        let events = db.query(Filter::new().search("beta-token")).await.unwrap();
        assert_eq!(events.len(), 1);

        let events = db.query(Filter::new().search("gamma-token")).await.unwrap();
        assert_eq!(events.len(), 1);

        let events = db.query(Filter::new().search("delta-token")).await.unwrap();
        assert_eq!(events.len(), 1);

        let events = db
            .query(Filter::new().search("epsilon-token"))
            .await
            .unwrap();
        assert_eq!(events.len(), 0);

        let events = db.query(Filter::new().search("")).await.unwrap();
        assert_eq!(events.len(), 0);
    }
}
