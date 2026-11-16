// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-C7: Chats
//!
//! <https://github.com/nostr-protocol/nips/blob/master/C7.md>

use alloc::format;
use alloc::string::String;

use super::nip18::Nip18Tag;
use super::nip19::Nip19Event;
use super::nip21::ToNostrUri;
use crate::error::Error;
use crate::event::{Event, EventBuilder, EventId, IntoEventBuilder, Kind};
use crate::key::PublicKey;
use crate::parser::{NostrParser, NostrParserOptions, Token};
use crate::types::RelayUrl;

/// Chat message reply.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChatMessageReply {
    content: String,
    reply_to: EventId,
    reply_to_author: PublicKey,
    relay_hint: Option<RelayUrl>,
}

impl ChatMessageReply {
    /// Create a chat message reply.
    pub fn new<S>(content: S, reply_to: &Event, relay_url: Option<RelayUrl>) -> Result<Self, Error>
    where
        S: Into<String>,
    {
        let mut content = content.into();

        if !has_nostr_event_uri(&content, &reply_to.id) {
            let nevent = Nip19Event {
                event_id: reply_to.id,
                author: None,
                kind: None,
                relays: relay_url.clone().into_iter().collect(),
            };
            content = format!("{}\n{content}", nevent.to_nostr_uri()?);
        }

        Ok(Self {
            content,
            reply_to: reply_to.id,
            reply_to_author: reply_to.pubkey,
            relay_hint: relay_url,
        })
    }
}

impl IntoEventBuilder for ChatMessageReply {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::ChatMessage)
            .content(self.content)
            .tag(Nip18Tag::Quote {
                id: self.reply_to,
                relay_hint: self.relay_hint,
                public_key: Some(self.reply_to_author),
            })
    }
}

fn has_nostr_event_uri(content: &str, event_id: &EventId) -> bool {
    const OPTS: NostrParserOptions = NostrParserOptions::disable_all().nostr_uris(true);

    NostrParser::new()
        .parse(content)
        .opts(OPTS)
        .any(|token| match token {
            Token::Nostr(nip21) => nip21.event_id().as_ref() == Some(event_id),
            _ => false,
        })
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use super::*;
    use crate::event::{FinalizeEvent, IntoEventBuilder};
    use crate::key::Keys;

    #[test]
    fn chat_reply_adds_event_uri_once() {
        let target = EventBuilder::new(Kind::ChatMessage)
            .content("target")
            .finalize(&Keys::generate())
            .unwrap();

        let builder = ChatMessageReply::new("reply", &target, None)
            .unwrap()
            .into_event_builder();
        assert!(has_nostr_event_uri(&builder.content, &target.id));
        assert_eq!(builder.tags.len(), 1);

        let builder = ChatMessageReply::new(builder.content.clone(), &target, None)
            .unwrap()
            .into_event_builder();
        assert_eq!(builder.content.lines().count(), 2);
    }
}
