// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP38: User Statuses
//!
//! <https://github.com/nostr-protocol/nips/blob/master/38.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::event::{EventBuilder, IntoEventBuilder, Kind, Tag};
use crate::types::Timestamp;

/// NIP38 types
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StatusType {
    /// General status: "Working", "Hiking", etc.
    #[default]
    General,
    /// Music what you are currently listening to
    Music,
    /// Custom status: "Playing", "Reading", etc.
    Custom(String),
}

impl fmt::Display for StatusType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl StatusType {
    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::General => "general",
            Self::Music => "music",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// User status
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveStatus {
    /// Status type, includes: General, Music or Custom
    pub status_type: StatusType,
    /// Expiration time of the status (Optional)
    pub expiration: Option<Timestamp>,
    /// Reference to the external resource (Optional)
    pub reference: Option<String>,
}

/// User status event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveStatusEvent {
    status: LiveStatus,
    content: String,
}

impl LiveStatusEvent {
    /// Create a user status event.
    pub fn new<S>(status: LiveStatus, content: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            status,
            content: content.into(),
        }
    }
}

impl IntoEventBuilder for LiveStatusEvent {
    fn into_event_builder(self) -> EventBuilder {
        let tags: Vec<Tag> = self.status.into();
        EventBuilder::new(Kind::UserStatus)
            .content(self.content)
            .tags(tags)
    }
}

impl LiveStatus {
    /// Create a new user status
    #[inline]
    pub fn new(status_type: StatusType) -> Self {
        Self {
            status_type,
            expiration: None,
            reference: None,
        }
    }
}

impl From<LiveStatus> for Vec<Tag> {
    fn from(
        LiveStatus {
            status_type,
            expiration,
            reference,
        }: LiveStatus,
    ) -> Self {
        let mut tags =
            Vec::with_capacity(1 + expiration.is_some() as usize + reference.is_some() as usize);

        tags.push(Tag::identifier(status_type.to_string()));

        if let Some(expire_at) = expiration {
            tags.push(Tag::expiration(expire_at));
        }

        if let Some(content) = reference {
            tags.push(Tag::new(vec![String::from("r"), content]));
        }

        tags
    }
}
