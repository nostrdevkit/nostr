// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Event ingester for LMDB storage backend
//!
//! This module implements an asynchronous event ingester that processes database operations
//! in the background using a dedicated thread.
//!
//! The ingester provides automatic batching of operations for optimal LMDB write performance.
//! Events are collected from a channel and committed in batches using a single transaction.

use std::{iter, thread};

use flatbuffers::FlatBufferBuilder;
use flume::{Receiver, Sender};
use heed::RwTxn;
use nostr::event::Event;
use nostr::filter::Filter;
use nostr_database::SaveEventStatus;
use tokio::sync::oneshot;

use super::error::StoreError;
use super::lmdb::Lmdb;

/// Pre-allocated buffer size for FlatBufferBuilder
///
/// This size is chosen to handle most Nostr events without reallocation.
/// Large events (with many tags or large content) may still trigger reallocation.
const FLATBUFFER_CAPACITY: usize = 70_000;

enum OperationResult {
    Reindex {
        result: Result<(), StoreError>,
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
    Save {
        result: Result<SaveEventStatus, StoreError>,
        tx: Option<oneshot::Sender<Result<SaveEventStatus, StoreError>>>,
    },
    Delete {
        result: Result<(), StoreError>,
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
    DeleteExpired {
        result: Result<(), StoreError>,
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
    Wipe {
        result: Result<(), StoreError>,
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
}

impl OperationResult {
    /// Send the result through the channel if present, or log errors
    fn send(self) {
        match self {
            Self::Reindex { result, tx } => {
                if let Some(tx) = tx {
                    if tx.send(result).is_err() {
                        tracing::debug!("Failed to send rebuild index result: receiver dropped");
                    }
                } else if let Err(e) = result {
                    tracing::error!(error = %e, "Failed to rebuild index");
                }
            }
            Self::Save { result, tx } => {
                if let Some(tx) = tx {
                    if tx.send(result).is_err() {
                        tracing::debug!("Failed to send save result: receiver dropped");
                    }
                } else if let Err(e) = result {
                    tracing::error!(error = %e, "Event save failed in batch");
                }
            }
            Self::Delete { result, tx } => {
                if let Some(tx) = tx {
                    if tx.send(result).is_err() {
                        tracing::debug!("Failed to send delete result: receiver dropped");
                    }
                } else if let Err(e) = result {
                    tracing::error!(error = %e, "Delete operation failed in batch");
                }
            }
            Self::DeleteExpired { result, tx } => {
                if let Some(tx) = tx {
                    if tx.send(result).is_err() {
                        tracing::debug!("Failed to send delete expired result: receiver dropped");
                    }
                } else if let Err(e) = result {
                    tracing::error!(error = %e, "delete expired operation failed in batch");
                }
            }
            Self::Wipe { result, tx } => {
                if let Some(tx) = tx {
                    if tx.send(result).is_err() {
                        tracing::debug!("Failed to send wipe result: receiver dropped");
                    }
                } else if let Err(e) = result {
                    tracing::error!(error = %e, "Wipe operation failed in batch");
                }
            }
        }
    }
}

enum IngesterOperation {
    Reindex {
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
    SaveEvent {
        event: Event,
        tx: Option<oneshot::Sender<Result<SaveEventStatus, StoreError>>>,
    },
    Delete {
        filter: Filter,
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
    DeleteExpired {
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
    Wipe {
        tx: Option<oneshot::Sender<Result<(), StoreError>>>,
    },
}

impl IngesterOperation {
    /// Create an error result for this operation type, moving the channel
    fn into_error_result(self, error: StoreError) -> OperationResult {
        match self {
            Self::Reindex { tx } => OperationResult::Reindex {
                result: Err(error),
                tx,
            },
            Self::SaveEvent { tx, .. } => OperationResult::Save {
                result: Err(error),
                tx,
            },
            Self::Delete { tx, .. } => OperationResult::Delete {
                result: Err(error),
                tx,
            },
            Self::DeleteExpired { tx } => OperationResult::DeleteExpired {
                result: Err(error),
                tx,
            },
            Self::Wipe { tx } => OperationResult::Wipe {
                result: Err(error),
                tx,
            },
        }
    }
}

pub(super) struct IngesterItem {
    operation: IngesterOperation,
}

impl IngesterItem {
    #[must_use]
    pub(super) fn reindex() -> (Self, oneshot::Receiver<Result<(), StoreError>>) {
        let (tx, rx) = oneshot::channel();
        let item: Self = Self {
            operation: IngesterOperation::Reindex { tx: Some(tx) },
        };
        (item, rx)
    }

    #[must_use]
    pub(super) fn save_event_with_feedback(
        event: Event,
    ) -> (Self, oneshot::Receiver<Result<SaveEventStatus, StoreError>>) {
        let (tx, rx) = oneshot::channel();
        let item: Self = Self {
            operation: IngesterOperation::SaveEvent {
                event,
                tx: Some(tx),
            },
        };
        (item, rx)
    }

    #[must_use]
    pub(super) fn delete_with_feedback(
        filter: Filter,
    ) -> (Self, oneshot::Receiver<Result<(), StoreError>>) {
        let (tx, rx) = oneshot::channel();
        let item: Self = Self {
            operation: IngesterOperation::Delete {
                filter,
                tx: Some(tx),
            },
        };
        (item, rx)
    }

    #[must_use]
    pub(super) fn delete_expired_with_feedback() -> (Self, oneshot::Receiver<Result<(), StoreError>>)
    {
        let (tx, rx) = oneshot::channel();
        let item: Self = Self {
            operation: IngesterOperation::DeleteExpired { tx: Some(tx) },
        };
        (item, rx)
    }

    #[must_use]
    pub(super) fn wipe_with_feedback() -> (Self, oneshot::Receiver<Result<(), StoreError>>) {
        let (tx, rx) = oneshot::channel();
        let item: Self = Self {
            operation: IngesterOperation::Wipe { tx: Some(tx) },
        };
        (item, rx)
    }
}

#[derive(Debug)]
pub(super) struct Ingester {
    db: Lmdb,
    rx: Receiver<IngesterItem>,
}

impl Ingester {
    /// Build and spawn a new ingester
    pub(super) fn run(db: Lmdb) -> Sender<IngesterItem> {
        // Create a new flume channel (unbounded for maximum performance)
        let (tx, rx) = flume::unbounded();

        // Construct and spawn ingester
        let ingester: Self = Self { db, rx };
        ingester.spawn_ingester();

        tx
    }

    #[inline]
    fn spawn_ingester(self) {
        thread::spawn(move || self.run_ingester_loop());
    }

    fn run_ingester_loop(self) {
        tracing::debug!("Ingester thread started");

        let mut fbb: FlatBufferBuilder = FlatBufferBuilder::with_capacity(FLATBUFFER_CAPACITY);
        let mut results: Vec<OperationResult> = Vec::new();

        loop {
            // Recv the first item
            let first_item: IngesterItem = match self.rx.recv() {
                Ok(item) => item,
                // All senders have been dropped, exit the loop
                Err(flume::RecvError::Disconnected) => {
                    tracing::debug!("Ingester channel disconnected, exiting.");
                    break;
                }
            };

            // Drain the rest of the channel into a batch
            let batch = iter::once(first_item).chain(self.rx.drain());

            // Process batch, reusing the "results" vector
            self.process_batch_in_transaction(batch, &mut fbb, &mut results);

            tracing::debug!("Processed batch of {} operations", results.len());

            // Drain the results and send them back through channels
            for result in results.drain(..) {
                result.send();
            }
        }

        tracing::debug!("Ingester thread exited");
    }

    fn process_batch_in_transaction<I>(
        &self,
        batch: I,
        fbb: &mut FlatBufferBuilder,
        results: &mut Vec<OperationResult>,
    ) where
        I: Iterator<Item = IngesterItem>,
    {
        // Note: We're only using a write transaction here since LMDB doesn't require
        // a separate read transaction for queries within a write transaction
        let mut write_txn = match self.db.write_txn() {
            Ok(txn) => txn,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create write transaction");

                // Send error for all items
                for item in batch {
                    results.push(
                        item.operation
                            .into_error_result(StoreError::BatchTransactionFailed),
                    );
                }

                return;
            }
        };

        let mut batch_iter = batch.peekable();

        // Process all operations in the batch
        while let Some(item) = batch_iter.next() {
            let result: OperationResult = self.process_operation(&mut write_txn, item, fbb);

            // Check if we need to abort on actual database errors (not on rejections)
            let abort_on_error: bool = match &result {
                OperationResult::Save { result: Err(e), .. } => {
                    tracing::error!(error = %e, "Failed to save event, aborting batch");
                    true
                }
                OperationResult::Delete { result: Err(e), .. } => {
                    tracing::error!(error = %e, "Failed to delete event, aborting batch");
                    true
                }
                OperationResult::Save {
                    result: Ok(SaveEventStatus::Rejected(_)),
                    ..
                } => false, // Rejections are expected, don't abort
                _ => false,
            };

            // Add operation to results
            results.push(result);

            if abort_on_error {
                // Mark all previous operations as failed
                mark_all_as_failed(results);

                // All remaining operations get BatchTransactionFailed error
                for item in batch_iter {
                    results.push(
                        item.operation
                            .into_error_result(StoreError::BatchTransactionFailed),
                    );
                }

                // Abort the write transaction first, then drop read transaction
                write_txn.abort();
                return;
            }
        }

        // All operations succeeded, commit the transaction
        if let Err(e) = write_txn.commit() {
            tracing::error!(error = %e, "Failed to commit batch transaction");

            // Mark all operations as failed
            mark_all_as_failed(results);
        }
    }

    fn process_operation(
        &self,
        txn: &mut RwTxn,
        item: IngesterItem,
        fbb: &mut FlatBufferBuilder,
    ) -> OperationResult {
        match item.operation {
            IngesterOperation::Reindex { tx } => OperationResult::Reindex {
                result: self.db.reindex(txn),
                tx,
            },
            IngesterOperation::SaveEvent { event, tx } => {
                let result = self.db.save_event_with_txn(txn, fbb, &event);
                OperationResult::Save { result, tx }
            }
            IngesterOperation::Delete { filter, tx } => {
                let result = self.db.delete(txn, filter);
                OperationResult::Delete { result, tx }
            }
            IngesterOperation::DeleteExpired { tx } => {
                let result = self.db.delete_expired(txn);
                OperationResult::DeleteExpired { result, tx }
            }
            IngesterOperation::Wipe { tx } => {
                let result = self.db.wipe(txn);
                OperationResult::Wipe { result, tx }
            }
        }
    }
}

/// Mark all operations as failed
fn mark_all_as_failed(results: &mut [OperationResult]) {
    // All previously processed operations get BatchTransactionFailed error
    for prev_result in results.iter_mut() {
        match prev_result {
            OperationResult::Reindex { result: res, .. } => {
                *res = Err(StoreError::BatchTransactionFailed)
            }
            OperationResult::Save { result: res, .. } => {
                *res = Err(StoreError::BatchTransactionFailed)
            }
            OperationResult::Delete { result: res, .. } => {
                *res = Err(StoreError::BatchTransactionFailed)
            }
            OperationResult::DeleteExpired { result: res, .. } => {
                *res = Err(StoreError::BatchTransactionFailed)
            }
            OperationResult::Wipe { result: res, .. } => {
                *res = Err(StoreError::BatchTransactionFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures::future::join_all;
    use nostr::event::{EventBuilder, FinalizeEvent, Kind};
    use nostr::key::Keys;
    use tempfile::TempDir;

    use super::*;
    use crate::NostrLmdbBuilder;
    use crate::store::Store;

    async fn setup_test_store() -> (Arc<Store>, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let builder = NostrLmdbBuilder::new(temp_dir.path())
            .map_size(1024 * 1024 * 10)
            .max_readers(10)
            .additional_dbs(50);

        let store = Store::from_builder(builder)
            .await
            .expect("Failed to open test store");
        (Arc::new(store), temp_dir)
    }

    #[tokio::test]
    async fn test_batch_error_handling() {
        let (store, _temp_dir) = setup_test_store().await;
        let keys = Keys::generate();

        // Create a mix of valid and duplicate events
        let event1 = EventBuilder::new(Kind::TextNote, "Event 1")
            .finalize(&keys)
            .expect("Failed to finalize event");

        // Save event1 first
        store
            .save_event(&event1)
            .await
            .expect("Failed to save event");

        // Now try to save a batch with duplicate and new events
        let event2 = EventBuilder::new(Kind::TextNote, "Event 2")
            .finalize(&keys)
            .expect("Failed to finalize event");

        let event3 = EventBuilder::new(Kind::TextNote, "Event 3")
            .finalize(&keys)
            .expect("Failed to finalize event");

        let futures = vec![
            store.save_event(&event1), // Duplicate
            store.save_event(&event2), // New
            store.save_event(&event3), // New
        ];

        let results = join_all(futures).await;

        // First should be rejected as duplicate
        assert!(matches!(
            results[0],
            Ok(SaveEventStatus::Rejected(
                nostr_database::RejectedReason::Duplicate
            ))
        ));

        // Others should succeed
        assert!(matches!(results[1], Ok(SaveEventStatus::Success)));
        assert!(matches!(results[2], Ok(SaveEventStatus::Success)));

        // Verify the new events were saved
        let saved_count = store
            .query(Filter::new())
            .await
            .expect("Failed to query")
            .len();
        assert_eq!(saved_count, 3); // event1, event2, event3
    }

    #[tokio::test]
    async fn test_mixed_operations_batch() {
        let (store, _temp_dir) = setup_test_store().await;
        let keys = Keys::generate();

        // Create some events
        let mut events = Vec::new();
        for i in 0..10 {
            let event = EventBuilder::new(Kind::TextNote, format!("Event to delete {}", i))
                .finalize(&keys)
                .expect("Failed to finalize event");
            store
                .save_event(&event)
                .await
                .expect("Failed to save event");
            events.push(event);
        }

        // Now create a mixed batch of saves and deletes
        let new_event1 = EventBuilder::new(Kind::TextNote, "New event 1")
            .finalize(&keys)
            .expect("Failed to finalize event");

        let new_event2 = EventBuilder::new(Kind::TextNote, "New event 2")
            .finalize(&keys)
            .expect("Failed to finalize event");

        // Execute mixed operations concurrently
        let save_fut1 = store.save_event(&new_event1);
        let save_fut2 = store.save_event(&new_event2);
        let delete_fut = store.delete(Filter::new().kind(Kind::TextNote).limit(5));

        let (save1_result, save2_result, delete_result) =
            tokio::join!(save_fut1, save_fut2, delete_fut);

        save1_result.expect("Failed to save new event 1");
        save2_result.expect("Failed to save new event 2");
        delete_result.expect("Failed to delete events");

        // Verify results
        let remaining = store
            .query(Filter::new())
            .await
            .expect("Failed to query")
            .len();

        // We had 10 events, deleted 5, added 2
        assert_eq!(remaining, 7);
    }
}
