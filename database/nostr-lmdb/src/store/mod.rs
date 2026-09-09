// Copyright (c) 2024 Michael Dilger
// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::collections::BTreeSet;
use std::fs;

use async_utility::task;
use flume::Sender;
use heed::RoTxn;
use nostr_database::prelude::*;

mod error;
mod event;
mod filter;
mod ingester;
pub(crate) mod lmdb;

use self::error::StoreError;
use self::ingester::{Ingester, IngesterItem};
use self::lmdb::Lmdb;
use crate::NostrLmdbBuilder;

#[derive(Debug)]
pub(super) struct Store {
    db: Lmdb,
    ingester: Sender<IngesterItem>,
}

impl Store {
    pub(super) async fn from_builder(builder: NostrLmdbBuilder) -> Result<Store, StoreError> {
        // Open the database in a blocking task
        let db: Lmdb = task::spawn_blocking(move || {
            // Create the directory if it doesn't exist
            fs::create_dir_all(&builder.path)?;

            let db: Lmdb = Lmdb::from_builder(builder)?;

            Ok::<Lmdb, StoreError>(db)
        })
        .await??;

        // Run the ingester
        let ingester: Sender<IngesterItem> = Ingester::run(db.clone());

        Ok(Self { db, ingester })
    }

    #[inline]
    async fn interact<F, R>(&self, f: F) -> Result<R, StoreError>
    where
        F: FnOnce(Lmdb) -> R + Send + 'static,
        R: Send + 'static,
    {
        // TODO: is this clone cheap?
        let db = self.db.clone();
        Ok(task::spawn_blocking(move || f(db)).await?)
    }

    pub(crate) async fn reindex(&self) -> Result<(), StoreError> {
        let (item, rx) = IngesterItem::reindex();
        self.ingester
            .send(item)
            .map_err(|_| StoreError::FlumeSend)?;
        rx.await?
    }

    pub(super) async fn save_event(&self, event: &Event) -> Result<SaveEventStatus, StoreError> {
        let (item, rx) = IngesterItem::save_event_with_feedback(event.clone());
        self.ingester
            .send(item)
            .map_err(|_| StoreError::FlumeSend)?;
        rx.await?
    }

    pub(super) async fn get_event_by_id(&self, id: EventId) -> Result<Option<Event>, StoreError> {
        self.interact(move |db| {
            let txn = db.read_txn()?;
            let event: Option<Event> = db
                .get_event_by_id(&txn, id.as_bytes())?
                .map(|e| e.into_owned());
            txn.commit()?;
            Ok(event)
        })
        .await?
    }

    pub(super) async fn check_id(&self, id: EventId) -> Result<DatabaseEventStatus, StoreError> {
        self.interact(move |db| {
            let txn = db.read_txn()?;

            let status: DatabaseEventStatus = if db.is_deleted(&txn, &id)? {
                DatabaseEventStatus::Deleted
            } else if db.has_event(&txn, &id)? {
                DatabaseEventStatus::Saved
            } else {
                DatabaseEventStatus::NotExistent
            };

            txn.commit()?;

            Ok(status)
        })
        .await?
    }

    pub(super) async fn count(&self, filter: Filter) -> Result<usize, StoreError> {
        self.interact(move |db| {
            let txn = db.read_txn()?;
            let len: usize = db.count(&txn, filter)?;
            txn.commit()?;
            Ok(len)
        })
        .await?
    }

    // Lookup ID: EVENT_ORD_IMPL
    pub(super) async fn query(&self, filter: Filter) -> Result<BTreeSet<Event>, StoreError> {
        self.interact(move |db| {
            let mut events: BTreeSet<Event> = BTreeSet::new();

            let txn: RoTxn = db.read_txn()?;
            let output = db.query(&txn, filter)?;
            let now = Timestamp::now();

            events.extend(
                output
                    .into_iter()
                    .filter(|e| !e.is_expired_at(now))
                    .map(|e| e.into_owned()),
            );
            txn.commit()?;

            Ok(events)
        })
        .await?
    }

    pub(super) async fn negentropy_items(
        &self,
        filter: Filter,
    ) -> Result<Vec<(EventId, Timestamp)>, StoreError> {
        self.interact(move |db| {
            let txn = db.read_txn()?;
            let events = db.query(&txn, filter)?;
            let now = Timestamp::now();
            let items = events
                .into_iter()
                .filter(|event| !event.is_expired_at(now))
                .map(|e| (EventId::from_byte_array(*e.id), e.created_at))
                .collect();
            txn.commit()?;
            Ok(items)
        })
        .await?
    }

    pub(super) async fn delete(&self, filter: Filter) -> Result<(), StoreError> {
        let (item, rx) = IngesterItem::delete_with_feedback(filter);
        self.ingester
            .send(item)
            .map_err(|_| StoreError::FlumeSend)?;
        rx.await?
    }

    pub(super) async fn delete_expired(&self) -> Result<(), StoreError> {
        let (item, rx) = IngesterItem::delete_expired_with_feedback();
        self.ingester
            .send(item)
            .map_err(|_| StoreError::FlumeSend)?;
        rx.await?
    }

    pub(super) async fn wipe(&self) -> Result<(), StoreError> {
        let (item, rx) = IngesterItem::wipe_with_feedback();
        self.ingester
            .send(item)
            .map_err(|_| StoreError::FlumeSend)?;
        rx.await?
    }
}
