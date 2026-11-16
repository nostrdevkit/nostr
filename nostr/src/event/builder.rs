// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Event builder

use alloc::boxed::Box;
use alloc::string::String;
use core::future::Future;
use core::pin::Pin;

use super::{
    AsyncSignEvent, Event, FinalizeEvent, FinalizeEventAsync, FinalizeUnsignedEvent, Kind,
    SignEvent, Tag, Tags, UnsignedEvent,
};
use crate::error::Error;
use crate::key::{AsyncGetPublicKey, GetPublicKey, PublicKey};
use crate::types::Timestamp;

/// Template that can be converted into a generic [`EventBuilder`].
pub trait IntoEventBuilder: Sized {
    /// Convert into the generic event builder.
    fn into_event_builder(self) -> EventBuilder;
}

impl<B> FinalizeUnsignedEvent for B
where
    B: IntoEventBuilder,
{
    #[inline]
    fn finalize_unsigned(self, public_key: PublicKey) -> UnsignedEvent {
        let builder: EventBuilder = self.into_event_builder();
        builder.finalize_unsigned(public_key)
    }
}

impl<B, S> FinalizeEvent<S> for B
where
    B: IntoEventBuilder,
    S: GetPublicKey + SignEvent + ?Sized,
{
    /// Error type
    type Error = Error;

    fn finalize(self, signer: &S) -> Result<Event, Self::Error> {
        let builder: EventBuilder = self.into_event_builder();
        builder.finalize(signer)
    }
}

impl<B, S> FinalizeEventAsync<S> for B
where
    B: IntoEventBuilder + Send,
    S: AsyncGetPublicKey + AsyncSignEvent + ?Sized,
{
    type Error = Error;

    fn finalize_async<'a>(
        self,
        signer: &'a S,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Error>> + Send + 'a>>
    where
        Self: 'a,
        S: 'a,
    {
        Box::pin(async move {
            let builder: EventBuilder = self.into_event_builder();
            builder.finalize_async(signer).await
        })
    }
}

/// Event builder
#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EventBuilder {
    /// Event kind.
    pub kind: Kind,
    /// Event tags.
    pub tags: Tags,
    /// Event content.
    pub content: String,
    /// Custom timestamp.
    pub created_at: Option<Timestamp>,
}

impl EventBuilder {
    /// New event builder
    #[inline]
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            tags: Tags::new(),
            content: String::new(),
            created_at: None,
        }
    }

    /// Add tag
    #[inline]
    pub fn tag<T>(mut self, tag: T) -> Self
    where
        T: Into<Tag>,
    {
        self.tags.push(tag.into());
        self
    }

    /// Add tag if `Some`.
    pub fn tag_maybe<T>(mut self, tag: Option<T>) -> Self
    where
        T: Into<Tag>,
    {
        if let Some(tag) = tag {
            self.tags.push(tag.into());
        }
        self
    }

    /// Add tags
    ///
    /// This method extends the current tags.
    #[inline]
    pub fn tags<I, T>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Tag>,
    {
        self.tags.extend(tags.into_iter().map(Into::into));
        self
    }

    /// Set content
    #[inline]
    pub fn content<T>(mut self, content: T) -> Self
    where
        T: Into<String>,
    {
        self.content = content.into();
        self
    }

    /// Set a custom `created_at` UNIX timestamp.
    #[inline]
    pub fn custom_created_at(mut self, created_at: Timestamp) -> Self {
        self.created_at = Some(created_at);
        self
    }
}

impl FinalizeUnsignedEvent for EventBuilder {
    #[inline]
    fn finalize_unsigned(self, public_key: PublicKey) -> UnsignedEvent {
        UnsignedEvent {
            // Not compute event ID, as the user may want POW, so would be an unnecessary computation.
            id: None,
            pubkey: public_key,
            created_at: self.created_at.unwrap_or_else(Timestamp::now),
            kind: self.kind,
            tags: self.tags,
            content: self.content,
        }
    }
}

impl<S> FinalizeEvent<S> for EventBuilder
where
    S: GetPublicKey + SignEvent + ?Sized,
{
    type Error = Error;

    fn finalize(self, signer: &S) -> Result<Event, Self::Error> {
        let public_key: PublicKey = signer.get_public_key().map_err(Error::other)?;
        let unsigned: UnsignedEvent = self.finalize_unsigned(public_key);
        signer.sign_event(unsigned).map_err(Error::other)
    }
}

impl<S> FinalizeEventAsync<S> for EventBuilder
where
    S: AsyncGetPublicKey + AsyncSignEvent + ?Sized,
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
            let unsigned: UnsignedEvent = self.finalize_unsigned(public_key);
            signer
                .sign_event_async(unsigned)
                .await
                .map_err(Error::other)
        })
    }
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::key::{Keys, SecretKey};

    #[test]
    fn round_trip() {
        let keys = Keys::new(
            SecretKey::from_str("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap(),
        );

        let event = EventBuilder::new(Kind::TextNote)
            .content("hello")
            .finalize(&keys)
            .unwrap();

        let serialized = event.as_json();
        let deserialized = Event::from_json(serialized).unwrap();

        assert_eq!(event, deserialized);
    }
}

#[cfg(bench)]
#[cfg(all(feature = "std", feature = "os-rng"))]
mod benches {
    use test::{Bencher, black_box};

    use super::*;
    use crate::key::Keys;

    #[bench]
    pub fn builder_to_event(bh: &mut Bencher) {
        let keys = Keys::generate();
        bh.iter(|| {
            black_box(
                EventBuilder::new(Kind::TextNote)
                    .content("hello")
                    .finalize(&keys),
            )
            .unwrap();
        });
    }
}
