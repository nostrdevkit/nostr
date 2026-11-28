// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-17: Private Direct Message
//!
//! <https://github.com/nostr-protocol/nips/blob/master/17.md>

#![allow(rustdoc::redundant_explicit_links)]

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use core::future::Future;
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use core::pin::Pin;
use core::time::Duration;

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use super::nip44::{AsyncNip44, Nip44};
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use super::nip59::GiftWrapBuilder;
use super::util::{missing_tag_kind, take_relay_url, unknown_tag};
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use crate::error::Error;
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use crate::event::{
    AsyncSignEvent, FinalizeEvent, FinalizeEventAsync, FinalizeUnsignedEvent, SignEvent,
    UnsignedEvent,
};
use crate::event::{
    Event, EventBuilder, IntoEventBuilder, Kind, TagsMut, WriteTag, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use crate::key::{AsyncGetPublicKey, GetPublicKey};
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
use crate::nips::nip01::Nip01Tag;
use crate::types::url::RelayUrl;

const RELAY: &str = "relay";

/// Private direct message inbox relay list.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboxRelayList {
    relays: Vec<RelayUrl>,
}

impl InboxRelayList {
    /// Create an inbox relay list.
    pub fn new<I>(relays: I) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        Self {
            relays: relays.into_iter().collect(),
        }
    }
}

impl IntoEventBuilder for InboxRelayList {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::InboxRelays).tags(self.relays.into_iter().map(Nip17Tag::Relay))
    }
}

/// Private Direct Message event builder.
///
/// # Example
///
/// ```rust,no_run
/// # use nostr::prelude::*;
/// # #[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
/// # fn main() -> Result<(), Box<dyn core::error::Error>> {
/// let receiver = PublicKey::from_hex("<receiver-public-key>")?;
/// let signer = Keys::parse("<my-secret-key>")?;
/// let private_msg: Event =
///     PrivateDirectMessageBuilder::new(receiver, "Hello, world!").finalize(&signer)?;
/// # Ok(())
/// # }
/// # #[cfg(not(all(feature = "std", feature = "os-rng", feature = "nip59")))]
/// # fn main() {}
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PrivateDirectMessageBuilder {
    /// Receiver public key.
    pub receiver: PublicKey,
    /// Message.
    pub message: String,
    /// Extra tags to add to the **rumor** event.
    pub rumor_extra_tags: TagsMut,
    /// Extra tags to add to the **gift wrap** event.
    pub extra_tags: TagsMut,
    /// NIP-40 expiration for the **gift wrap**, relative to `created_at`.
    pub expiration: Option<Duration>,
}

// TODO: should this be under the required features, like for the Finalize traits?
impl PrivateDirectMessageBuilder {
    /// Create a new private direct message event builder.
    #[inline]
    pub fn new<M>(receiver: PublicKey, message: M) -> Self
    where
        M: Into<String>,
    {
        Self {
            receiver,
            message: message.into(),
            rumor_extra_tags: TagsMut::new(),
            extra_tags: TagsMut::new(),
            expiration: None,
        }
    }

    /// Extra tags to add to the **rumor** event.
    #[inline]
    pub fn rumor_extra_tags<I, T>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: WriteTag,
    {
        self.rumor_extra_tags.extend(tags);
        self
    }

    /// Extra tags to add to the **gift wrap** event.
    #[inline]
    pub fn extra_tags<I, T>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: WriteTag,
    {
        self.extra_tags.extend(tags);
        self
    }

    /// Set a NIP-40 expiration on the **gift wrap**.
    ///
    /// The expiration tag is relative to the gift wrap's `created_at`
    /// so it doesn't leak the real send time.
    /// Choose a `duration` greater than the 2 days
    /// or the event may be created in an expired state.
    #[inline]
    pub fn expiration(mut self, duration: Duration) -> Self {
        self.expiration = Some(duration);
        self
    }
}

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
impl<S> FinalizeEvent<S> for PrivateDirectMessageBuilder
where
    S: GetPublicKey + SignEvent + Nip44,
{
    type Error = Error;

    fn finalize(self, signer: &S) -> Result<Event, Self::Error> {
        let public_key: PublicKey = signer.get_public_key().map_err(Error::other)?;
        let rumor: UnsignedEvent = make_rumor(
            public_key,
            self.receiver,
            self.message,
            self.rumor_extra_tags,
        );
        let mut builder = GiftWrapBuilder::new(self.receiver, rumor);
        builder.extra_tags = self.extra_tags;
        if let Some(duration) = self.expiration {
            builder = builder.expiration(duration);
        }
        builder.finalize(signer)
    }
}

#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
impl<S> FinalizeEventAsync<S> for PrivateDirectMessageBuilder
where
    S: AsyncGetPublicKey + AsyncSignEvent + AsyncNip44,
{
    type Error = Error;

    fn finalize_async<'a>(
        self,
        signer: &'a S,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + 'a>>
    where
        Self: 'a,
        S: 'a,
    {
        Box::pin(async move {
            let public_key: PublicKey =
                signer.get_public_key_async().await.map_err(Error::other)?;
            let rumor: UnsignedEvent = make_rumor(
                public_key,
                self.receiver,
                self.message,
                self.rumor_extra_tags,
            );
            let mut builder = GiftWrapBuilder::new(self.receiver, rumor);
            builder.extra_tags = self.extra_tags;
            if let Some(duration) = self.expiration {
                builder = builder.expiration(duration);
            }
            builder.finalize_async(signer).await
        })
    }
}

#[inline]
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
fn make_rumor(
    sender: PublicKey,
    receiver: PublicKey,
    message: String,
    extra_tags: TagsMut,
) -> UnsignedEvent {
    let mut builder: EventBuilder = EventBuilder::new(Kind::PrivateDirectMessage).content(message);
    builder.tags = extra_tags;
    builder
        .tag(Nip01Tag::public_key(receiver))
        .finalize_unsigned(sender)
}

/// Standardized NIP-17 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/17.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip17Tag {
    /// Relay
    ///
    /// `["relay", <relay URL>]`
    Relay(RelayUrl),
}

impl_tag_codec_conversions! {
    Nip17Tag,
    fn parse(tag) {
        // Take iterator
        let mut iter = tag.into_iter();

        // Extract first value
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        // Match kind
        match kind.as_ref() {
            RELAY => {
                let url: RelayUrl = take_relay_url(&mut iter)?;
                Ok(Self::Relay(url))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Relay(url) = self;

        tx.push_str(RELAY);
        tx.push_str(url.as_str());
    }
}

/// Extracts the relay list
///
/// This function doesn't verify if the event kind is [`Kind::InboxRelays`]!
pub fn extract_relay_list(event: &Event) -> impl Iterator<Item = RelayUrl> + '_ {
    event
        .tags
        .iter()
        .filter_map(|tag| match Nip17Tag::try_from(tag) {
            Ok(Nip17Tag::Relay(url)) => Some(url),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::error::ErrorKind;
    use crate::event::Tags;

    #[test]
    fn test_parse_empty_tag() {
        let tag: Vec<String> = Vec::new();
        let err = Nip17Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }

    #[test]
    fn test_non_existing_tag() {
        let tag = vec!["p"];
        let err = Nip17Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Malformed);
    }

    #[test]
    fn test_standardized_relay_tag() {
        let relay = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let tag = vec!["relay", relay.as_str()];

        let parsed = Nip17Tag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip17Tag::Relay(relay.clone()));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_missing_relay_url() {
        let tag = vec!["relay"];
        let err = Nip17Tag::parse(&tag).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Missing);
    }
}

#[cfg(test)]
#[cfg(all(feature = "std", feature = "os-rng", feature = "nip59"))]
mod expiration_tests {
    use core::time::Duration;

    use super::*;
    use crate::key::Keys;
    use crate::nips::nip59::extract_rumor;

    #[test]
    fn test_private_dm_expiration_on_gift_wrap() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let duration: Duration = Duration::from_secs(7 * 24 * 3600);

        let gift_wrap: Event = PrivateDirectMessageBuilder::new(receiver.public_key(), "hello")
            .expiration(duration)
            .finalize(&sender)
            .unwrap();

        assert_eq!(gift_wrap.kind, Kind::GiftWrap);

        // Anchored to the gift wrap's tweaked `created_at`: no send-time leak.
        let expiration = gift_wrap.tags.expiration().expect("missing expiration tag");
        assert_eq!(
            expiration.as_secs() - gift_wrap.created_at.as_secs(),
            duration.as_secs()
        );

        // The DM still unwraps and the sender is verified.
        let unwrapped = extract_rumor(&receiver, &gift_wrap).unwrap();
        assert_eq!(unwrapped.sender, sender.public_key());
        assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage);

        // Decision: expiration goes on the gift wrap only, not the inner rumor.
        assert!(unwrapped.rumor.tags.expiration().is_none());
    }

    #[test]
    fn test_private_dm_without_expiration() {
        let sender = Keys::generate();
        let receiver = Keys::generate();

        let gift_wrap: Event = PrivateDirectMessageBuilder::new(receiver.public_key(), "hello")
            .finalize(&sender)
            .unwrap();

        assert!(gift_wrap.tags.expiration().is_none());
    }

    #[tokio::test]
    async fn test_private_dm_expiration_async() {
        let sender = Keys::generate();
        let receiver = Keys::generate();
        let duration: Duration = Duration::from_secs(7 * 24 * 3600);

        let gift_wrap: Event = PrivateDirectMessageBuilder::new(receiver.public_key(), "hello")
            .expiration(duration)
            .finalize_async(&sender)
            .await
            .unwrap();

        let expiration = gift_wrap.tags.expiration().expect("missing expiration tag");
        assert_eq!(
            expiration.as_secs() - gift_wrap.created_at.as_secs(),
            duration.as_secs()
        );
    }
}
