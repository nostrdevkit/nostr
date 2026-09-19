// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! LMDB storage backend for nostr apps
//!
//! Fork of [Pocket](https://github.com/mikedilger/pocket) database.

#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use nostr_database::error::Error;
use nostr_database::prelude::*;

mod fbs;
pub mod prelude;
mod store;

use self::store::Store;

// 64-bit
#[cfg(target_pointer_width = "64")]
const MAP_SIZE: usize = 1024 * 1024 * 1024 * 32; // 32GB

// 32-bit
#[cfg(target_pointer_width = "32")]
const MAP_SIZE: usize = 0xFFFFF000; // 4GB (2^32-4096)

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use NostrLmdb instead")]
pub type NostrLMDB = NostrLmdb;

/// Nostr LMDB database builder
#[derive(Debug, Clone)]
pub struct NostrLmdbBuilder {
    /// Database path
    pub path: PathBuf,
    /// Custom map size
    ///
    /// By default, the following map size is used:
    /// - 32GB for 64-bit arch
    /// - 4GB for 32-bit arch
    pub map_size: usize,
    /// Maximum number of reader threads
    ///
    /// Defaults to 126 if not set
    pub max_readers: u32,
    /// Number of additional databases to allocate beyond the 9 internal ones
    ///
    /// Defaults to 0 if not set
    pub additional_dbs: u32,
    /// Whether to process request to vanish (NIP-62) events
    ///
    /// Defaults to `true`
    pub process_nip62: bool,
    /// Whether to process event deletion request (NIP-09) events
    ///
    /// Defaults to `true`
    pub process_nip09: bool,
    /// Relay URL for relay-specific request to vanish (NIP-62)
    pub relay_url: Option<RelayUrl>,
}

impl NostrLmdbBuilder {
    /// New LMDb builder
    pub fn new<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            path: path.as_ref().to_path_buf(),
            map_size: MAP_SIZE,
            max_readers: 126,
            additional_dbs: 0,
            process_nip62: true,
            process_nip09: true,
            relay_url: None,
        }
    }

    /// Map size
    ///
    /// By default, the following map size is used:
    /// - 32GB for 64-bit arch
    /// - 4GB for 32-bit arch
    pub fn map_size(mut self, map_size: usize) -> Self {
        self.map_size = map_size;
        self
    }

    /// Maximum number of reader threads
    ///
    /// Defaults to 126 if not set
    pub fn max_readers(mut self, max_readers: u32) -> Self {
        self.max_readers = max_readers;
        self
    }

    /// Number of additional databases to allocate beyond the 9 internal ones
    ///
    /// Defaults to 0 if not set
    pub fn additional_dbs(mut self, additional_dbs: u32) -> Self {
        self.additional_dbs = additional_dbs;
        self
    }

    /// Whether to process request to vanish (NIP-62) events
    ///
    /// Defaults to `true`
    pub fn process_nip62(mut self, process_nip62: bool) -> Self {
        self.process_nip62 = process_nip62;
        self
    }

    /// Whether to process event deletion request (NIP-09) events
    ///
    /// Defaults to `true`
    pub fn process_nip09(mut self, process_nip09: bool) -> Self {
        self.process_nip09 = process_nip09;
        self
    }

    /// Set the relay URL to handle relay-specific request to vanish
    #[inline]
    pub fn relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.relay_url = Some(relay_url);
        self
    }

    /// Build
    pub async fn build(self) -> Result<NostrLmdb, Error> {
        let db: Store = Store::from_builder(self).await?;
        Ok(NostrLmdb { db })
    }
}

/// LMDB Nostr Database
#[derive(Debug)]
pub struct NostrLmdb {
    db: Store,
}

impl NostrLmdb {
    /// Open LMDB database
    #[inline]
    pub async fn open<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::builder(path).build().await
    }

    /// Get a new builder
    #[inline]
    pub fn builder<P>(path: P) -> NostrLmdbBuilder
    where
        P: AsRef<Path>,
    {
        NostrLmdbBuilder::new(path)
    }

    /// Re-index the database.
    #[inline]
    pub async fn reindex(&self) -> Result<(), Error> {
        Ok(self.db.reindex().await?)
    }
}

impl NostrDatabase for NostrLmdb {
    #[inline]
    fn backend(&self) -> &'static str {
        "LMDB"
    }

    fn features(&self) -> Features {
        Features {
            persistent: true,
            event_expiration: true,
            full_text_search: true,
            request_to_vanish: true,
        }
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<SaveEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move { Ok(self.db.save_event(event).await?) })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<DatabaseEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move { Ok(self.db.check_id(*event_id).await?) })
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Event>, Error>> + Send + 'a>> {
        Box::pin(async move { Ok(self.db.get_event_by_id(*event_id).await?) })
    }

    fn count(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<usize, Error>> + Send + '_>> {
        Box::pin(async move { Ok(self.db.count(filter).await?) })
    }

    fn query(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<BTreeSet<Event>, Error>> + Send + '_>> {
        Box::pin(async move { Ok(self.db.query(filter).await?) })
    }

    fn negentropy_items(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(EventId, Timestamp)>, Error>> + Send + '_>> {
        Box::pin(async move { Ok(self.db.negentropy_items(filter).await?) })
    }

    fn delete(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move { Ok(self.db.delete(filter).await?) })
    }

    #[inline]
    fn wipe(&self) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move { Ok(self.db.wipe().await?) })
    }

    fn collect_garbage(&self) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move {
            self.db.delete_expired().await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use nostr_database_test_suite::database_unit_tests;
    use tempfile::TempDir;

    use super::*;

    struct TempDatabase {
        db: NostrLmdb,
        // Needed to avoid the drop and deletion of temp folder
        _temp: TempDir,
    }

    impl Deref for TempDatabase {
        type Target = NostrLmdb;

        fn deref(&self) -> &Self::Target {
            &self.db
        }
    }

    impl TempDatabase {
        async fn new() -> Self {
            let path = tempfile::tempdir().unwrap();
            Self {
                db: NostrLmdb::open(&path).await.unwrap(),
                _temp: path,
            }
        }

        async fn new_with_relay_url(url: RelayUrl) -> Self {
            let path = tempfile::tempdir().unwrap();
            Self {
                db: NostrLmdb::builder(&path)
                    .relay_url(url)
                    .build()
                    .await
                    .unwrap(),
                _temp: path,
            }
        }
    }

    database_unit_tests!(
        TempDatabase,
        TempDatabase::new,
        TempDatabase::new_with_relay_url
    );
}
