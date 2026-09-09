// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use std::borrow::Cow;
use std::str::FromStr;

use flatbuffers::FlatBufferBuilder;
use nostr::error::{Error, ErrorKind};
use nostr::event::{Event, EventId, Kind, Signature, Tag, Tags};
use nostr::filter::SingleLetterTag;
use nostr::key::PublicKey;
use nostr::types::Timestamp;

use super::error::{MissingField, StoreError};
use crate::fbs::event_fbs;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DatabaseTag<'a> {
    buf: Vec<Cow<'a, str>>,
}

impl<'a> DatabaseTag<'a> {
    /// Parse tag
    ///
    /// Return error if the tag is empty!
    pub(super) fn parse(tag: Vec<Cow<'a, str>>) -> Result<Self, Error> {
        // Check if it's empty
        if tag.is_empty() {
            return Err(Error::with_static_message(ErrorKind::Invalid, "empty tag"));
        }

        Ok(Self { buf: tag })
    }

    /// Get the tag kind
    #[inline]
    pub(super) fn kind(&self) -> &str {
        // SAFETY: we checked that buf is not empty
        self.buf[0].as_ref()
    }

    /// Return the **first** tag value (index `1`), if exists.
    #[inline]
    pub(super) fn content(&self) -> Option<&str> {
        self.buf.get(1).map(|s| s.as_ref())
    }

    /// Extract tag name and value
    pub(super) fn extract(&self) -> Option<(SingleLetterTag, &str)> {
        if self.buf.len() >= 2 {
            let tag_name: SingleLetterTag = SingleLetterTag::from_str(&self.buf[0]).ok()?;
            let tag_value: &str = &self.buf[1];
            Some((tag_name, tag_value))
        } else {
            None
        }
    }

    /// Return the expiration timestamp if it's `expiration` tag
    #[inline]
    pub(super) fn expiration(&self) -> Option<u64> {
        if self.kind() == "expiration" {
            return self.content().and_then(|t| u64::from_str(t).ok());
        }

        None
    }

    /// Into owned tag
    pub(super) fn into_owned(self) -> Tag {
        let buf: Vec<String> = self.buf.into_iter().map(|t| t.into_owned()).collect();
        // SAFETY: buf is not empty
        unsafe { Tag::new_unchecked(buf) }
    }
}

impl<'a> From<&'a Tag> for DatabaseTag<'a> {
    fn from(tag: &'a Tag) -> Self {
        Self {
            buf: tag
                .as_slice()
                .iter()
                .map(|v| Cow::Borrowed(v.as_str()))
                .collect(),
        }
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
    pub tags: Vec<DatabaseTag<'a>>,
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
            .and_then(DatabaseTag::content)
            .and_then(|timestamp| Timestamp::from_str(timestamp).ok())
            .is_some_and(|expiration| expiration < now)
    }

    pub(crate) fn from_flatbuf(buf: &'a [u8]) -> Result<Self, StoreError> {
        let ev = event_fbs::root_as_event(buf)?;

        let fb_tags = ev
            .tags()
            .ok_or(StoreError::FlatBufFieldNotFound(MissingField::Tags))?;
        let mut tags = Vec::with_capacity(fb_tags.len());

        for tag in fb_tags.iter().filter_map(|t| t.data()) {
            tags.push(DatabaseTag::parse(
                tag.into_iter().map(Cow::Borrowed).collect(),
            )?);
        }

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
                let tags = t
                    .buf
                    .iter()
                    .map(|t| fbb.create_string(t))
                    .collect::<Vec<_>>();
                let args = event_fbs::StringVectorArgs {
                    data: Some(fbb.create_vector(&tags)),
                };
                event_fbs::StringVector::create(fbb, &args)
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

    /// Into owned event
    pub fn into_owned(self) -> Event {
        Event::new(
            EventId::from_byte_array(*self.id),
            PublicKey::from_byte_array(*self.pubkey),
            self.created_at,
            Kind::from_u16(self.kind),
            Tags::from_list(self.tags.into_iter().map(|t| t.into_owned()).collect()),
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
            tags: event.tags.iter().map(DatabaseTag::from).collect(),
            content: &event.content,
            sig: event.sig.as_ref(),
        }
    }
}
