// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-A0: Voice Messages
//!
//! <https://github.com/nostr-protocol/nips/blob/master/A0.md>

use alloc::string::{String, ToString};

use url::Url;

use super::nip22::CommentTarget;
use crate::event::{EventBuilder, IntoEventBuilder, Kind};

/// Voice message reply builder.
#[derive(Debug, Clone)]
pub struct VoiceMessageReplyBuilder<'a> {
    voice_url: String,
    parent: CommentTarget<'a>,
    root: Option<CommentTarget<'a>>,
}

impl<'a> VoiceMessageReplyBuilder<'a> {
    /// Create a voice message reply.
    pub fn new<T, U>(voice_url: U, parent: T) -> Self
    where
        T: Into<CommentTarget<'a>>,
        U: Into<Url>,
    {
        Self {
            voice_url: voice_url.into().to_string(),
            parent: parent.into(),
            root: None,
        }
    }

    /// Set the root voice message.
    pub fn root<T>(mut self, root: T) -> Self
    where
        T: Into<CommentTarget<'a>>,
    {
        self.root = Some(root.into());
        self
    }
}

impl IntoEventBuilder for VoiceMessageReplyBuilder<'_> {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::VoiceMessageReply)
            .content(self.voice_url)
            .tags(
                self.root
                    .map(|target| target.as_vec(true))
                    .unwrap_or_default(),
            )
            .tags(self.parent.as_vec(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventId, IntoEventBuilder};

    #[test]
    fn voice_message_reply_builder() {
        let parent = CommentTarget::event(EventId::all_zeros(), Kind::VoiceMessage, None, None);
        let builder = VoiceMessageReplyBuilder::new(
            Url::parse("https://example.com/message.ogg").unwrap(),
            parent,
        )
        .into_event_builder();

        assert_eq!(builder.kind, Kind::VoiceMessageReply);
        assert_eq!(builder.content, "https://example.com/message.ogg");
        assert!(builder.tags.iter().any(|tag| tag.kind() == "e"));
    }
}
