// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use std::slice::Iter;
use std::str::FromStr;

use flatbuffers::{FlatBufferBuilder, ForwardsUOffset, Vector, VectorIter};
use nostr::error::{Error, ErrorKind};
use nostr::event::{Event, EventId, Kind, Signature, Tag, Tags};
use nostr::filter::SingleLetterTag;
use nostr::key::PublicKey;
use nostr::types::Timestamp;

use super::error::{MissingField, StoreError};
use crate::fbs::event_fbs::{self, StringVector};

#[derive(Debug, Clone)]
enum InnerTags<'a> {
    FlatBuf(Vector<'a, ForwardsUOffset<StringVector<'a>>>),
    Tags(&'a Tags),
}

#[derive(Debug, Clone)]
pub(crate) struct DatabaseTags<'a>(InnerTags<'a>);

impl<'a> DatabaseTags<'a> {
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        match &self.0 {
            InnerTags::FlatBuf(vec) => vec.is_empty(),
            InnerTags::Tags(vec) => vec.is_empty(),
        }
    }

    #[inline]
    pub(crate) fn iter(&'a self) -> DatabaseTagsIter<'a> {
        DatabaseTagsIter(match &self.0 {
            InnerTags::FlatBuf(vec) => InnerTagsIter::FlatBuf(vec.iter()),
            InnerTags::Tags(vec) => InnerTagsIter::Vector(vec.iter()),
        })
    }
}

enum InnerTagsIter<'a> {
    FlatBuf(VectorIter<'a, ForwardsUOffset<StringVector<'a>>>),
    Vector(Iter<'a, Tag>),
}

pub(crate) struct DatabaseTagsIter<'a>(InnerTagsIter<'a>);

impl<'a> Iterator for DatabaseTagsIter<'a> {
    type Item = DatabaseTag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            InnerTagsIter::FlatBuf(iter) => loop {
                let item: StringVector = iter.next()?;

                let Some(data) = item.data() else {
                    continue;
                };

                let Ok(tag) = DatabaseTag::new(InnerTag::FlatBuf(data)) else {
                    continue;
                };

                return Some(tag);
            },
            InnerTagsIter::Vector(iter) => loop {
                let item: &Tag = iter.next()?;
                let data: &[String] = item.as_slice();

                let Ok(tag) = DatabaseTag::new(InnerTag::Slice(data)) else {
                    continue;
                };

                return Some(tag);
            },
        }
    }
}

#[derive(Debug, Clone)]
enum InnerTag<'a> {
    FlatBuf(Vector<'a, ForwardsUOffset<&'a str>>),
    Slice(&'a [String]),
}

#[derive(Debug, Clone)]
pub(crate) struct DatabaseTag<'a>(InnerTag<'a>);

impl<'a> DatabaseTag<'a> {
    fn new(tag: InnerTag<'a>) -> Result<Self, Error> {
        let is_empty: bool = match &tag {
            InnerTag::FlatBuf(vec) => vec.is_empty(),
            InnerTag::Slice(vec) => vec.is_empty(),
        };

        if is_empty {
            return Err(Error::with_static_message(ErrorKind::Invalid, "empty tag"));
        }

        Ok(Self(tag))
    }

    #[inline]
    fn len(&self) -> usize {
        match &self.0 {
            InnerTag::FlatBuf(vec) => vec.len(),
            InnerTag::Slice(vec) => vec.len(),
        }
    }

    fn get(&self, index: usize) -> &'a str {
        match &self.0 {
            InnerTag::FlatBuf(vec) => vec.get(index),
            InnerTag::Slice(vec) => vec[index].as_str(),
        }
    }

    /// Get the tag kind
    #[inline]
    pub(super) fn kind(&self) -> &'a str {
        // SAFETY: we checked that buf is not empty
        self.get(0)
    }

    /// Return the **first** tag value (index `1`), if exists.
    #[inline]
    pub(super) fn content(&self) -> Option<&'a str> {
        if self.len() < 2 {
            return None;
        }

        Some(self.get(1))
    }

    /// Extract tag name and value
    pub(super) fn extract(&self) -> Option<(SingleLetterTag, &'a str)> {
        if self.len() < 2 {
            return None;
        }

        let tag_name: SingleLetterTag = SingleLetterTag::from_str(self.get(0)).ok()?;
        let tag_value: &str = self.get(1);
        Some((tag_name, tag_value))
    }

    fn into_owned(self) -> Tag {
        let buf: Vec<String> = match self.0 {
            InnerTag::FlatBuf(vec) => vec.into_iter().map(|t| t.to_string()).collect(),
            InnerTag::Slice(vec) => vec.iter().map(|t| t.to_string()).collect(),
        };
        // SAFETY: buf is not empty
        unsafe { Tag::new_unchecked(buf) }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DatabaseEvent<'a> {
    /// Event ID
    pub id: &'a [u8; 32],
    /// Author
    pub pubkey: &'a [u8; 32],
    /// UNIX timestamp (seconds)
    pub created_at: Timestamp,
    /// Kind
    pub kind: u16,
    /// Tag list
    pub tags: DatabaseTags<'a>,
    /// Content
    pub content: &'a str,
    /// Signature
    pub sig: &'a [u8; 64],
}

impl PartialEq for DatabaseEvent<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for DatabaseEvent<'_> {}

impl PartialOrd for DatabaseEvent<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DatabaseEvent<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.created_at != other.created_at {
            // Descending order
            // Lookup ID: EVENT_ORD_IMPL
            self.created_at.cmp(&other.created_at).reverse()
        } else {
            self.id.cmp(other.id)
        }
    }
}

impl Hash for DatabaseEvent<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<'a> DatabaseEvent<'a> {
    pub(super) fn is_expired_at(&self, now: Timestamp) -> bool {
        self.tags
            .iter()
            .find(|tag| tag.kind() == "expiration")
            .and_then(|t| t.content())
            .and_then(|timestamp| Timestamp::from_str(timestamp).ok())
            .is_some_and(|expiration| expiration < now)
    }

    pub(crate) fn from_flatbuf(buf: &'a [u8]) -> Result<Self, StoreError> {
        let ev = event_fbs::root_as_event(buf)?;

        let fb_tags = ev
            .tags()
            .ok_or(StoreError::FlatBufFieldNotFound(MissingField::Tags))?;
        let tags = DatabaseTags(InnerTags::FlatBuf(fb_tags));

        Ok(Self {
            id: &ev
                .id()
                .ok_or(StoreError::FlatBufFieldNotFound(MissingField::Id))?
                .0,
            pubkey: &ev
                .pubkey()
                .ok_or(StoreError::FlatBufFieldNotFound(MissingField::Pubkey))?
                .0,
            created_at: Timestamp::from_secs(ev.created_at()),
            kind: ev.kind().try_into()?,
            tags,
            content: ev
                .content()
                .ok_or(StoreError::FlatBufFieldNotFound(MissingField::Content))?,
            sig: &ev
                .sig()
                .ok_or(StoreError::FlatBufFieldNotFound(MissingField::Sig))?
                .0,
        })
    }

    pub(crate) fn encode_flatbuf<'f>(&self, fbb: &'f mut FlatBufferBuilder) -> &'f [u8] {
        fbb.reset();

        let id = event_fbs::Fixed32Bytes::new(self.id);
        let pubkey = event_fbs::Fixed32Bytes::new(self.pubkey);
        let sig = event_fbs::Fixed64Bytes::new(self.sig);
        let tags = self
            .tags
            .iter()
            .map(|t| {
                let data: Vec<_> = (0..t.len()).map(|i| fbb.create_string(t.get(i))).collect();
                let args = event_fbs::StringVectorArgs {
                    data: Some(fbb.create_vector(&data)),
                };
                StringVector::create(fbb, &args)
            })
            .collect::<Vec<_>>();
        let args = event_fbs::EventArgs {
            id: Some(&id),
            pubkey: Some(&pubkey),
            created_at: self.created_at.as_secs(),
            kind: self.kind as u64,
            tags: Some(fbb.create_vector(&tags)),
            content: Some(fbb.create_string(self.content)),
            sig: Some(&sig),
        };

        let offset = event_fbs::Event::create(fbb, &args);

        event_fbs::finish_event_buffer(fbb, offset);

        fbb.finished_data()
    }

    /// Extract event IDs from `e` tags.
    #[inline]
    pub(crate) fn event_ids(&self) -> impl Iterator<Item = EventId> + '_ {
        self.tags.iter().filter_map(|t| {
            if t.kind() != "e" {
                return None;
            }

            let content: &str = t.content()?;
            EventId::from_hex(content).ok()
        })
    }

    /// Into owned event
    pub fn into_owned(self) -> Event {
        Event::new(
            EventId::from_byte_array(*self.id),
            PublicKey::from_byte_array(*self.pubkey),
            self.created_at,
            Kind::from_u16(self.kind),
            Tags::from_list(self.tags.iter().map(|t| t.into_owned()).collect()),
            self.content,
            // SAFETY: signature panic only if it's not 64 byte long
            Signature::from_slice(self.sig.as_slice()).expect("valid signature"),
        )
    }
}

impl<'a> From<&'a Event> for DatabaseEvent<'a> {
    fn from(event: &'a Event) -> Self {
        Self {
            id: event.id.as_bytes(),
            pubkey: event.pubkey.as_bytes(),
            created_at: event.created_at,
            kind: event.kind.as_u16(),
            tags: DatabaseTags(InnerTags::Tags(&event.tags)),
            content: &event.content,
            sig: event.sig.as_ref(),
        }
    }
}
