// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-09: Event Deletion Request
//!
//! <https://github.com/nostr-protocol/nips/blob/master/09.md>

use alloc::string::String;
use alloc::vec::Vec;

use super::nip01::Coordinate;
use crate::event::{EventBuilder, EventId, IntoEventBuilder, Kind, Tag};

/// Event deletion request
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventDeletionRequest {
    /// Event IDs
    pub ids: Vec<EventId>,
    /// Event coordinates
    pub coordinates: Vec<Coordinate>,
    /// Optional reason
    pub reason: Option<String>,
}

impl EventDeletionRequest {
    /// New **empty** deletion request
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add single event ID
    #[inline]
    pub fn id(mut self, id: EventId) -> Self {
        self.ids.push(id);
        self
    }

    /// Add event IDs
    #[inline]
    pub fn ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.ids.extend(ids);
        self
    }

    /// Add single event coordinate
    #[inline]
    pub fn coordinate(mut self, coordinate: Coordinate) -> Self {
        self.coordinates.push(coordinate);
        self
    }

    /// Add event coordinates
    #[inline]
    pub fn coordinates<I>(mut self, coordinates: I) -> Self
    where
        I: IntoIterator<Item = Coordinate>,
    {
        self.coordinates.extend(coordinates);
        self
    }

    /// Add deletion reason
    #[inline]
    pub fn reason<S>(mut self, reason: S) -> Self
    where
        S: Into<String>,
    {
        self.reason = Some(reason.into());
        self
    }
}

impl IntoEventBuilder for EventDeletionRequest {
    fn into_event_builder(self) -> EventBuilder {
        let mut tags: Vec<Tag> = Vec::with_capacity(self.ids.len() + self.coordinates.len());

        for id in self.ids.into_iter() {
            tags.push(Tag::event(id));
        }

        for coordinate in self.coordinates.into_iter() {
            tags.push(Tag::coordinate(coordinate, None));
        }

        EventBuilder::new(Kind::EventDeletion)
            .content(self.reason.unwrap_or_default())
            .tags(tags)
    }
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use super::*;
    use crate::event::Tags;
    use crate::prelude::*;

    #[test]
    fn test_event_deletion_request() {
        let keys = Keys::generate();

        let event_id =
            EventId::from_hex("7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96")
                .unwrap();
        let coordinate = Coordinate::parse(
            "30023:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:ipsum",
        )
        .unwrap();

        // Event ID, coordinate and reason
        let request = EventDeletionRequest::new()
            .id(event_id)
            .coordinate(coordinate)
            .reason("these posts were published by accident");

        let event: Event = request.finalize(&keys).unwrap();

        assert_eq!(event.kind, Kind::EventDeletion);
        assert_eq!(event.content, "these posts were published by accident");

        let tags = Tags::parse([
            vec![
                "e",
                "7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96",
            ],
            vec![
                "a",
                "30023:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:ipsum",
            ],
        ])
        .unwrap();
        assert_eq!(event.tags, tags);

        // Event ID without reason
        let request = EventDeletionRequest::new().id(event_id);

        let event: Event = request.finalize(&keys).unwrap();

        assert_eq!(event.kind, Kind::EventDeletion);
        assert!(event.content.is_empty());

        let tags = Tags::parse([vec![
            "e",
            "7469af3be8c8e06e1b50ef1caceba30392ddc0b6614507398b7d7daa4c218e96",
        ]])
        .unwrap();
        assert_eq!(event.tags, tags);
    }
}
