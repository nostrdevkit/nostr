use core::iter;
use core::num::NonZeroUsize;
use core::ops::Deref;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use btreecap::{BTreeCapSet, Capacity, Insert, OverCapacityPolicy};
use nostr::event::{Event, EventId, Kind};
use nostr::filter::{Filter, MatchEventOptions, SingleLetterTag};
use nostr::key::PublicKey;
use nostr::nips::nip01::Coordinate;
use nostr::nips::nip62;
use nostr::types::Timestamp;
use nostr_database::prelude::*;

type DatabaseEvent = Arc<Event>;

struct QueryByAuthorParams {
    author: PublicKey,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
}

struct QueryByKindAndAuthorParams {
    kind: Kind,
    author: PublicKey,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
}

impl QueryByKindAndAuthorParams {
    #[inline]
    pub fn new(kind: Kind, author: PublicKey) -> Self {
        Self {
            kind,
            author,
            since: None,
            until: None,
        }
    }
}

struct QueryByParamReplaceable {
    kind: Kind,
    author: PublicKey,
    identifier: String,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
}

impl QueryByParamReplaceable {
    #[inline]
    pub fn new(kind: Kind, author: PublicKey, identifier: String) -> Self {
        Self {
            kind,
            author,
            identifier,
            since: None,
            until: None,
        }
    }
}

/// Options for the memory database
#[derive(Debug, Clone, Default)]
pub(crate) struct MemoryOptions {
    pub(crate) process_nip09: bool,
    pub(crate) process_nip62: bool,
    pub(crate) relay_url: Option<RelayUrl>,
}

enum QueryPattern {
    Author(QueryByAuthorParams),
    KindAuthor(QueryByKindAndAuthorParams),
    ParamReplaceable(QueryByParamReplaceable),
    Generic(Box<Filter>),
}

impl From<Filter> for QueryPattern {
    fn from(filter: Filter) -> Self {
        let (kinds_len, first_kind): (usize, Option<Kind>) = filter
            .kinds
            .as_ref()
            .map(|set| (set.len(), set.iter().next().copied()))
            .unwrap_or_default();
        let (authors_len, first_author): (usize, Option<PublicKey>) = filter
            .authors
            .as_ref()
            .map(|set| (set.len(), set.iter().next().copied()))
            .unwrap_or_default();
        let ids_len: usize = filter.ids.as_ref().map(|set| set.len()).unwrap_or_default();
        let generic_tags_len: usize = filter.generic_tags.len();
        let identifier = filter
            .generic_tags
            .get(&SingleLetterTag::LOWERCASE_D)
            .and_then(|v| v.iter().next().cloned());

        match (
            kinds_len,
            first_kind,
            authors_len,
            first_author,
            ids_len,
            generic_tags_len,
            identifier,
            filter.search.as_ref(),
        ) {
            (0, None, 1, Some(author), 0, 0, None, None) => Self::Author(QueryByAuthorParams {
                author,
                since: filter.since,
                until: filter.until,
            }),
            (1, Some(kind), 1, Some(author), 0, 0, None, None) => {
                Self::KindAuthor(QueryByKindAndAuthorParams {
                    kind,
                    author,
                    since: filter.since,
                    until: filter.until,
                })
            }
            (1, Some(kind), 1, Some(author), 0, _, Some(identifier), None)
                if kind.is_addressable() =>
            {
                Self::ParamReplaceable(QueryByParamReplaceable {
                    kind,
                    author,
                    identifier,
                    since: filter.since,
                    until: filter.until,
                })
            }
            _ => Self::Generic(Box::new(filter)),
        }
    }
}

enum InternalQueryResult<'a> {
    All,
    Set(BTreeSet<&'a DatabaseEvent>),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MemoryStore {
    /// Database options
    options: MemoryOptions,
    /// Sorted events
    events: BTreeCapSet<DatabaseEvent>,
    /// Events by ID
    ids: HashMap<EventId, DatabaseEvent>,
    author_index: HashMap<PublicKey, BTreeSet<DatabaseEvent>>,
    kind_author_index: HashMap<(Kind, PublicKey), BTreeSet<DatabaseEvent>>,
    param_replaceable_index: HashMap<(Kind, PublicKey, String), DatabaseEvent>,
    deleted_ids: HashSet<EventId>,
    deleted_coordinates: HashMap<Coordinate, Timestamp>,
    vanished_public_keys: HashSet<PublicKey>,
}

impl MemoryStore {
    pub(crate) fn new(max_events: Option<NonZeroUsize>, options: MemoryOptions) -> Self {
        let mut store: Self = Self {
            options,
            ..Default::default()
        };

        if let Some(size) = max_events {
            store.events.change_capacity(Capacity::Bounded {
                max: size,
                policy: OverCapacityPolicy::Last,
            });
        }

        store
    }

    #[inline]
    fn is_pubkey_vanished(&self, pubkey: &PublicKey) -> bool {
        self.vanished_public_keys.contains(pubkey)
    }

    fn internal_index_event(&mut self, event: &Event, now: Timestamp) -> SaveEventStatus {
        // Check if was already added
        if self.ids.contains_key(&event.id) {
            return SaveEventStatus::Rejected(RejectedReason::Duplicate);
        }

        // Check if was deleted or is expired
        if self.deleted_ids.contains(&event.id) {
            return SaveEventStatus::Rejected(RejectedReason::Deleted);
        }

        if self.is_pubkey_vanished(&event.pubkey) {
            return SaveEventStatus::Rejected(RejectedReason::Vanished);
        }

        // Reject event if ADDR was deleted after it's created_at date
        // (replaceable or addressable)
        if let Some(coordinate) = event.coordinate() {
            if let Some(time) = self.deleted_coordinates.get(&coordinate) {
                if &event.created_at <= time {
                    return SaveEventStatus::Rejected(RejectedReason::Deleted);
                }
            }
        }

        if event.is_expired_at(now) {
            return SaveEventStatus::Rejected(RejectedReason::Expired);
        }

        let mut to_discard: HashSet<EventId> = HashSet::new();

        // Compose others fields
        let author: PublicKey = event.pubkey;
        let created_at: Timestamp = event.created_at;
        let kind: Kind = event.kind;

        let mut status: SaveEventStatus = SaveEventStatus::Success;

        if kind.is_replaceable() {
            let params: QueryByKindAndAuthorParams = QueryByKindAndAuthorParams::new(kind, author);
            for ev in self.internal_query_by_kind_and_author(params) {
                if has_event_been_replaced(ev, event) || ev.id == event.id {
                    status = SaveEventStatus::Rejected(RejectedReason::Replaced);
                } else {
                    to_discard.insert(ev.id);
                }
            }
        } else if kind.is_addressable() {
            match event.tags.identifier() {
                Some(identifier) => {
                    let coordinate: Coordinate =
                        Coordinate::new(kind, author).identifier(identifier.clone());

                    // Check if coordinate was deleted
                    if self.has_coordinate_been_deleted(&coordinate, &event.created_at) {
                        status = SaveEventStatus::Rejected(RejectedReason::Deleted);
                    } else {
                        let params: QueryByParamReplaceable =
                            QueryByParamReplaceable::new(kind, author, identifier);
                        if let Some(ev) = self.internal_query_param_replaceable(params) {
                            if has_event_been_replaced(ev, event) || ev.id == event.id {
                                status = SaveEventStatus::Rejected(RejectedReason::Replaced);
                            } else {
                                to_discard.insert(ev.id);
                            }
                        }
                    }
                }
                None => status = SaveEventStatus::Rejected(RejectedReason::Other),
            }
        } else if self.options.process_nip09 && kind == Kind::EventDeletion {
            // Check `e` tags
            for id in event.tags.event_ids() {
                if let Some(ev) = self.ids.get(&id) {
                    if ev.pubkey != author {
                        status = SaveEventStatus::Rejected(RejectedReason::InvalidDelete);
                        break;
                    }

                    if ev.created_at <= created_at {
                        to_discard.insert(ev.id);
                        self.deleted_ids.insert(ev.id);
                    }
                }
            }

            // Check `a` tags
            for coordinate in event.tags.coordinates() {
                if coordinate.public_key != author {
                    status = SaveEventStatus::Rejected(RejectedReason::InvalidDelete);
                    break;
                }

                // Save deleted coordinate at certain timestamp
                self.deleted_coordinates
                    .entry(coordinate.clone())
                    .and_modify(|t| {
                        // Update only if newer
                        if created_at > *t {
                            *t = created_at
                        }
                    })
                    .or_insert(created_at);

                // Not check if ev.pubkey match the author because assume that query
                // returned only the events owned by author
                if !coordinate.identifier.is_empty() {
                    let mut params: QueryByParamReplaceable = QueryByParamReplaceable::new(
                        coordinate.kind,
                        coordinate.public_key,
                        coordinate.identifier.clone(),
                    );
                    params.until = Some(created_at);
                    if let Some(ev) = self.internal_query_param_replaceable(params) {
                        to_discard.insert(ev.id);
                    }
                } else {
                    let mut params: QueryByKindAndAuthorParams =
                        QueryByKindAndAuthorParams::new(coordinate.kind, coordinate.public_key);
                    params.until = Some(created_at);
                    to_discard.extend(self.internal_query_by_kind_and_author(params).map(|e| e.id));
                }
            }
        } else if self.options.process_nip62
            && event.kind == Kind::RequestToVanish
            && nip62::is_valid_vanish_request_for_relay(
                &event.tags,
                self.options.relay_url.as_ref(),
            )
        {
            self.handle_request_to_vanish(&event.pubkey);
        }

        // Remove events
        self.discard_events(to_discard);

        // Insert event
        if status.is_success() {
            let e: DatabaseEvent = Arc::new(event.clone()); // TODO: avoid clone?

            let Insert { inserted, pop } = self.events.insert(e.clone());

            if inserted {
                self.ids.insert(e.id, e.clone());
                self.author_index
                    .entry(author)
                    .or_default()
                    .insert(e.clone());

                if kind.is_addressable() {
                    if let Some(identifier) = e.tags.identifier() {
                        self.param_replaceable_index
                            .insert((kind, author, identifier.to_string()), e.clone());
                    }
                }

                if kind.is_replaceable() {
                    let mut set = BTreeSet::new();
                    set.insert(e);
                    self.kind_author_index.insert((kind, author), set);
                } else {
                    self.kind_author_index
                        .entry((kind, author))
                        .or_default()
                        .insert(e);
                }
            }

            if let Some(event) = pop {
                self.discard_event(event);
            }
        }

        status
    }

    fn handle_request_to_vanish(&mut self, pubkey: &PublicKey) {
        // Mark public key as vanished
        self.vanished_public_keys.insert(*pubkey);

        // Delete all authored events
        self.delete(Filter::new().author(*pubkey));

        // Delete gift wraps that mention the pubkey
        // (kind = GiftWrap || 1059, tag "p" with the hex of the pubkey)
        self.delete(Filter::new().kind(Kind::GiftWrap).pubkey(*pubkey));
    }

    fn discard_events(&mut self, ids: HashSet<EventId>) {
        for id in ids.iter() {
            if let Some(ev) = self.ids.remove(id) {
                self.events.remove(&ev);

                if let Some(set) = self.author_index.get_mut(&ev.pubkey) {
                    set.remove(&ev);
                }

                if ev.kind.is_addressable() {
                    if let Some(identifier) = ev.tags.identifier() {
                        self.param_replaceable_index.remove(&(
                            ev.kind,
                            ev.pubkey,
                            identifier.to_string(),
                        ));
                    }
                }

                if let Some(set) = self.kind_author_index.get_mut(&(ev.kind, ev.pubkey)) {
                    set.remove(&ev);
                }
            }
        }
    }

    fn discard_event(&mut self, ev: DatabaseEvent) {
        self.ids.remove(&ev.id);

        if let Some(set) = self.author_index.get_mut(&ev.pubkey) {
            set.remove(&ev);
        }

        if ev.kind.is_addressable() {
            if let Some(identifier) = ev.tags.identifier() {
                self.param_replaceable_index
                    .remove(&(ev.kind, ev.pubkey, identifier.to_string()));
            }
        }

        if let Some(set) = self.kind_author_index.get_mut(&(ev.kind, ev.pubkey)) {
            set.remove(&ev);
        }
    }

    /// Import [Event]
    ///
    /// **This method assume that [`Event`] was already verified**
    pub fn index_event(&mut self, event: &Event) -> SaveEventStatus {
        // Check if it's ephemeral
        if event.kind.is_ephemeral() {
            return SaveEventStatus::Rejected(RejectedReason::Ephemeral);
        }
        let now = Timestamp::now();
        self.internal_index_event(event, now)
    }

    /// Query by public key
    fn internal_query_by_author<'a>(
        &'a self,
        params: QueryByAuthorParams,
    ) -> Box<dyn Iterator<Item = &'a DatabaseEvent> + 'a> {
        let QueryByAuthorParams {
            author,
            since,
            until,
        } = params;
        match self.author_index.get(&author) {
            Some(set) => Box::new(set.iter().filter(move |ev| {
                if self.deleted_ids.contains(&ev.id) {
                    return false;
                }

                if let Some(since) = since {
                    if ev.created_at < since {
                        return false;
                    }
                }

                if let Some(until) = until {
                    if ev.created_at > until {
                        return false;
                    }
                }

                true
            })),
            None => Box::new(iter::empty()),
        }
    }

    /// Query by [`Kind`] and [`PublicKeyPrefix`]
    fn internal_query_by_kind_and_author<'a>(
        &'a self,
        params: QueryByKindAndAuthorParams,
    ) -> Box<dyn Iterator<Item = &'a DatabaseEvent> + 'a> {
        let QueryByKindAndAuthorParams {
            kind,
            author,
            since,
            until,
        } = params;
        match self.kind_author_index.get(&(kind, author)) {
            Some(set) => Box::new(set.iter().filter(move |ev| {
                if self.deleted_ids.contains(&ev.id) {
                    return false;
                }

                if let Some(since) = since {
                    if ev.created_at < since {
                        return false;
                    }
                }

                if let Some(until) = until {
                    if ev.created_at > until {
                        return false;
                    }
                }

                true
            })),
            None => Box::new(iter::empty()),
        }
    }

    /// Query by param. replaceable
    fn internal_query_param_replaceable(
        &self,
        params: QueryByParamReplaceable,
    ) -> Option<&DatabaseEvent> {
        let QueryByParamReplaceable {
            kind,
            author,
            identifier,
            since,
            until,
        } = params;

        if !kind.is_addressable() {
            return None;
        }

        let ev = self
            .param_replaceable_index
            .get(&(kind, author, identifier))?;

        if self.deleted_ids.contains(&ev.id) {
            return None;
        }

        if let Some(since) = since {
            if ev.created_at < since {
                return None;
            }
        }

        if let Some(until) = until {
            if ev.created_at > until {
                return None;
            }
        }

        Some(ev)
    }

    /// Generic query
    #[inline]
    fn internal_generic_query(&self, filter: Filter) -> impl Iterator<Item = &DatabaseEvent> {
        self.events.iter().filter(move |event| {
            !self.deleted_ids.contains(&event.id)
                && filter.match_event(event, MatchEventOptions::new())
        })
    }

    fn internal_query(&self, filter: Filter) -> InternalQueryResult<'_> {
        if filter.is_empty() {
            return InternalQueryResult::All;
        }

        if let (Some(since), Some(until)) = (filter.since, filter.until) {
            if since > until {
                return InternalQueryResult::Set(BTreeSet::new());
            }
        }

        let mut matching_ids: BTreeSet<&DatabaseEvent> = BTreeSet::new();
        let limit: Option<usize> = filter.limit;

        let evs: Box<dyn Iterator<Item = &DatabaseEvent>> = match QueryPattern::from(filter) {
            QueryPattern::Author(params) => self.internal_query_by_author(params),
            QueryPattern::KindAuthor(params) => self.internal_query_by_kind_and_author(params),
            QueryPattern::ParamReplaceable(params) => {
                match self.internal_query_param_replaceable(params) {
                    Some(ev) => Box::new(iter::once(ev)),
                    None => Box::new(iter::empty()),
                }
            }
            QueryPattern::Generic(filter) => Box::new(self.internal_generic_query(*filter)),
        };

        if let Some(limit) = limit {
            matching_ids.extend(evs.take(limit))
        } else {
            matching_ids.extend(evs)
        }

        InternalQueryResult::Set(matching_ids)
    }

    #[inline]
    pub fn event_by_id(&self, id: &EventId) -> Option<&Event> {
        self.ids.get(id).map(|e| e.deref())
    }

    #[inline]
    pub fn has_event(&self, id: &EventId) -> bool {
        self.ids.contains_key(id)
    }

    /// Query
    pub fn query<'a>(&'a self, filter: Filter) -> Box<dyn Iterator<Item = &'a Event> + 'a> {
        match self.internal_query(filter) {
            InternalQueryResult::All => Box::new(self.events.iter().map(|ev| ev.as_ref())),
            InternalQueryResult::Set(set) => Box::new(set.into_iter().map(|ev| ev.as_ref())),
        }
    }

    /// Count events
    pub fn count(&self, filter: Filter) -> usize {
        match self.internal_query(filter) {
            InternalQueryResult::All => self.events.len(),
            InternalQueryResult::Set(set) => set.len(),
        }
    }

    pub fn negentropy_items(&self, filter: Filter) -> Vec<(EventId, Timestamp)> {
        let now = Timestamp::now();
        match self.internal_query(filter) {
            InternalQueryResult::All => self
                .events
                .iter()
                .filter(|event| !event.is_expired_at(now))
                .map(|ev| (ev.id, ev.created_at))
                .collect(),
            InternalQueryResult::Set(set) => set
                .into_iter()
                .filter(|event| !event.is_expired_at(now))
                .map(|ev| (ev.id, ev.created_at))
                .collect(),
        }
    }

    /// Check if an event with [`EventId`] has been deleted
    pub fn has_event_id_been_deleted(&self, event_id: &EventId) -> bool {
        self.deleted_ids.contains(event_id)
    }

    /// Check if event with [`Coordinate`] has been deleted before [`Timestamp`]
    pub fn has_coordinate_been_deleted(
        &self,
        coordinate: &Coordinate,
        timestamp: &Timestamp,
    ) -> bool {
        if let Some(t) = self.deleted_coordinates.get(coordinate) {
            t >= timestamp
        } else {
            false
        }
    }

    pub fn delete(&mut self, filter: Filter) {
        match self.internal_query(filter) {
            InternalQueryResult::All => {
                self.clear();
            }
            InternalQueryResult::Set(set) => {
                let ids: HashSet<EventId> = set.into_iter().map(|ev| ev.id).collect();
                self.discard_events(ids);
            }
        }
    }

    pub fn clear(&mut self) {
        // Get current capacity
        let capacity: Capacity = self.events.capacity();

        // Reset helper to default
        *self = Self {
            options: self.options.clone(),
            ..Default::default()
        };

        // Change capacity
        self.events.change_capacity(capacity);
    }
}

/// Check if the new event should be rejected because an existing one has precedence.
#[inline]
fn has_event_been_replaced(stored: &Event, incoming: &Event) -> bool {
    match stored.created_at.cmp(&incoming.created_at) {
        Ordering::Greater => true,
        Ordering::Equal => {
            // NIP-01: when timestamps are equal, keep the event with the lowest ID.
            stored.id < incoming.id
        }
        Ordering::Less => false,
    }
}
