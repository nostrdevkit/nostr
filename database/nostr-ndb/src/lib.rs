// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! [`nostrdb`](https://github.com/damus-io/nostrdb) storage backend for Nostr apps

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::pin::Pin;

pub extern crate nostr;
pub extern crate nostr_database as database;
pub extern crate nostrdb;

use nostr_database::error::{Error, ErrorKind};
use nostr_database::prelude::*;
use nostrdb::{
    Config, Filter as NdbFilter, IngestMetadata, Ndb, NdbStrVariant, Note, QueryResult, Transaction,
};

const MAX_RESULTS: i32 = 10_000;

// Wrap `Ndb` into `NdbDatabase` because only traits defined in the current crate can be implemented for types defined outside the crate!

/// [`nostrdb`](https://github.com/damus-io/nostrdb) backend
#[derive(Debug, Clone)]
pub struct NdbDatabase {
    db: Ndb,
}

impl NdbDatabase {
    /// Open nostrdb
    pub fn open<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let path: &Path = path.as_ref();
        let path: &str = path
            .to_str()
            .ok_or_else(|| Error::with_static_message(ErrorKind::Other, "path is not valid"))?;

        let config: Config = Config::new();

        Ok(Self {
            db: Ndb::new(path, &config).map_err(Error::storage)?,
        })
    }
}

impl Deref for NdbDatabase {
    type Target = Ndb;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for NdbDatabase {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

impl From<Ndb> for NdbDatabase {
    fn from(db: Ndb) -> Self {
        Self { db }
    }
}

impl NostrDatabase for NdbDatabase {
    #[inline]
    fn backend(&self) -> &'static str {
        "nostrdb (LMDB)"
    }

    fn features(&self) -> Features {
        Features {
            persistent: true,
            event_expiration: false,
            full_text_search: true,
            request_to_vanish: false,
        }
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> Pin<Box<dyn Future<Output = Result<SaveEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move {
            let msg = RelayMessage::Event {
                subscription_id: Cow::Owned(SubscriptionId::new("ndb")),
                event: Cow::Borrowed(event),
            };
            let json: String = msg.as_json();
            self.db
                .process_event_with(&json, IngestMetadata::new())
                .map_err(Error::storage)?;
            // TODO: shouldn't return a success since we don't know if the ingestion was successful or not.
            Ok(SaveEventStatus::Success)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<DatabaseEventStatus, Error>> + Send + 'a>> {
        Box::pin(async move {
            let txn = Transaction::new(&self.db).map_err(Error::storage)?;
            let res = self.db.get_note_by_id(&txn, event_id.as_bytes());
            Ok(if res.is_ok() {
                DatabaseEventStatus::Saved
            } else {
                DatabaseEventStatus::NotExistent
            })
        })
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Event>, Error>> + Send + 'a>> {
        Box::pin(async move {
            let txn: Transaction = Transaction::new(&self.db).map_err(Error::storage)?;
            let res: Result<Note, nostrdb::Error> =
                self.db.get_note_by_id(&txn, event_id.as_bytes());
            match res {
                Ok(note) => Ok(Some(ndb_note_to_event(note)?)),
                Err(nostrdb::Error::NotFound) => Ok(None),
                Err(e) => Err(Error::storage(e)),
            }
        })
    }

    fn count(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<usize, Error>> + Send + '_>> {
        Box::pin(async move {
            let txn: Transaction = Transaction::new(&self.db).map_err(Error::storage)?;
            let res: Vec<QueryResult> = ndb_query(&self.db, &txn, &filter)?;
            Ok(res.len())
        })
    }

    fn query(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<BTreeSet<Event>, Error>> + Send + '_>> {
        Box::pin(async move {
            let txn: Transaction = Transaction::new(&self.db).map_err(Error::storage)?;
            let res: Vec<QueryResult> = ndb_query(&self.db, &txn, &filter)?;
            Ok(res
                .into_iter()
                .filter_map(|r| ndb_note_to_event(r.note).ok())
                .collect())
        })
    }

    fn negentropy_items(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(EventId, Timestamp)>, Error>> + Send + '_>> {
        Box::pin(async move {
            let txn: Transaction = Transaction::new(&self.db).map_err(Error::storage)?;
            let res: Vec<QueryResult> = ndb_query(&self.db, &txn, &filter)?;
            let now = Timestamp::now();
            Ok(res
                .into_iter()
                .filter(|result| !ndb_note_is_expired_at(&result.note, now))
                .map(|r| ndb_note_to_neg_item(r.note))
                .collect())
        })
    }

    #[inline]
    fn delete(
        &self,
        _filter: Filter,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move { Err(Error::unsupported("delete is not supported by nostrdb")) })
    }

    #[inline]
    fn wipe(&self) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move { Err(Error::unsupported("wiping is not supported by nostrdb")) })
    }

    #[inline]
    fn collect_garbage(&self) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move { Err(Error::unsupported("delete is not supported by nostrdb")) })
    }
}

fn ndb_query<'a>(
    db: &Ndb,
    txn: &'a Transaction,
    filter: &Filter,
) -> Result<Vec<QueryResult<'a>>, Error> {
    let filter: nostrdb::Filter = ndb_filter_conversion(filter);
    let max_results = filter
        .limit()
        .map(|n| n.try_into().unwrap_or(i32::MAX))
        .unwrap_or(MAX_RESULTS);

    db.query(txn, &[filter], max_results)
        .map_err(Error::storage)
}

fn ndb_filter_conversion(f: &Filter) -> nostrdb::Filter {
    let mut filter = NdbFilter::new();

    if let Some(ids) = &f.ids {
        if !ids.is_empty() {
            filter = filter.ids(ids.iter().map(|p| p.as_bytes()));
        }
    }

    if let Some(authors) = &f.authors {
        if !authors.is_empty() {
            filter = filter.authors(authors.iter().map(|p| p.as_bytes()));
        }
    }

    if let Some(kinds) = &f.kinds {
        if !kinds.is_empty() {
            filter = filter.kinds(kinds.iter().map(|p| p.as_u16() as u64));
        }
    }

    if !f.generic_tags.is_empty() {
        for (single_letter, set) in f.generic_tags.iter() {
            filter = filter.tags(set.iter().map(|s| s.as_str()), single_letter.as_char());
        }
    }

    if let Some(since) = f.since {
        filter = filter.since(since.as_secs());
    }

    if let Some(until) = f.until {
        filter = filter.until(until.as_secs());
    }

    if let Some(limit) = f.limit {
        filter = filter.limit(limit as u64);
    }

    if let Some(search) = &f.search {
        filter = filter.search(search);
    }

    filter.build()
}

fn ndb_note_to_event(note: Note) -> Result<Event, Error> {
    let id: EventId = EventId::from_byte_array(*note.id());
    let pk = PublicKey::from_byte_array(*note.pubkey());
    let timestamp = Timestamp::from_secs(note.created_at());
    let kind: u16 = note
        .kind()
        .try_into()
        .map_err(|e| Error::new(ErrorKind::Protocol, e))?;
    let kind: Kind = Kind::from_u16(kind);
    let sig: Signature =
        Signature::from_slice(note.sig()).map_err(|e| Error::new(ErrorKind::Protocol, e))?;

    Ok(Event::new(
        id,
        pk,
        timestamp,
        kind,
        ndb_note_to_tags(&note)?,
        note.content(),
        sig,
    ))
}

fn ndb_note_to_tags<'a>(note: &Note<'a>) -> Result<Vec<Tag>, Error> {
    let ndb_tags = note.tags();
    let mut tags: Vec<Tag> = Vec::with_capacity(ndb_tags.count() as usize);
    for tag in ndb_tags.iter() {
        let tag_str: Vec<Cow<'a, str>> = tag
            .into_iter()
            .map(|s| match s.variant() {
                NdbStrVariant::Id(id) => Cow::Owned(EventId::from_byte_array(*id).to_hex()),
                NdbStrVariant::Str(s) => Cow::Borrowed(s),
            })
            .collect();
        let tag = Tag::parse(tag_str)?;
        tags.push(tag);
    }
    Ok(tags)
}

fn ndb_note_to_neg_item(note: Note) -> (EventId, Timestamp) {
    let id = EventId::from_byte_array(*note.id());
    let created_at = Timestamp::from_secs(note.created_at());
    (id, created_at)
}

fn ndb_note_is_expired_at(note: &Note, now: Timestamp) -> bool {
    note.tags()
        .iter()
        .find(|tag| tag.get_str(0) == Some("expiration"))
        .and_then(|tag| tag.get_str(1))
        .and_then(|timestamp| timestamp.parse::<Timestamp>().ok())
        .is_some_and(|expiration| expiration < now)
}
