// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Unsigned Event

use alloc::boxed::Box;
use alloc::string::String;
use core::future::Future;
use core::num::NonZeroU8;
use core::pin::Pin;

use secp256k1::{Secp256k1, Verification};

use super::signature::Signature;
use super::{
    AsyncSignEvent, Event, EventId, FinalizeEvent, FinalizeEventAsync, Kind, SignEvent, Tags,
};
use crate::error::{Error, ErrorKind};
use crate::key::PublicKey;
use crate::nips::nip13::{AsyncPowAdapter, PowAdapter};
use crate::types::Timestamp;
#[cfg(feature = "std")]
use crate::util::SECP256K1;
use crate::util::impl_json_methods;

#[inline]
fn invalid_event_id() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "invalid event ID")
}

/// Unsigned event
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UnsignedEvent {
    /// Event ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<EventId>,
    /// Author
    pub pubkey: PublicKey,
    /// Timestamp (seconds)
    pub created_at: Timestamp,
    /// Kind
    pub kind: Kind,
    /// Tag list
    pub tags: Tags,
    /// Content
    pub content: String,
}

impl UnsignedEvent {
    /// Construct new unsigned event
    pub fn new<I, S>(
        public_key: PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: I,
        content: S,
    ) -> Self
    where
        I: Into<Tags>,
        S: Into<String>,
    {
        Self {
            id: None,
            pubkey: public_key,
            created_at,
            kind,
            tags: tags.into(),
            content: content.into(),
        }
    }

    /// Ensure to set [EventId]
    ///
    /// If `id` is `None`, compute and set it.
    #[inline]
    pub fn ensure_id(&mut self) {
        if self.id.is_none() {
            self.id = Some(self.compute_id());
        }
    }

    /// Get the unsigned event ID
    ///
    /// If the [`EventId`] is not set, will be computed and saved in the struct.
    pub fn id(&mut self) -> EventId {
        // Ensure that the ID is set
        self.ensure_id();

        // This can't fail, because we already ensured that the ID is set
        self.id.unwrap()
    }

    /// Compute the event ID
    #[inline]
    pub fn compute_id(&self) -> EventId {
        EventId::compute(
            &self.pubkey,
            &self.created_at,
            &self.kind,
            &self.tags,
            &self.content,
        )
    }

    /// Verify if the [`EventId`] it's composed correctly
    pub fn verify_id(&self) -> Result<(), Error> {
        if let Some(id) = self.id {
            let computed_id: EventId = self.compute_id();
            if id != computed_id {
                return Err(invalid_event_id());
            }
        }

        Ok(())
    }

    /// Mine an unsigned event synchronously
    #[inline]
    pub fn mine<T>(self, adapter: &T, difficulty: NonZeroU8) -> Result<Self, T::Error>
    where
        T: PowAdapter,
    {
        adapter.compute(self, difficulty)
    }

    /// Mine an unsigned event asynchronously
    #[inline]
    pub async fn mine_async<T>(self, adapter: &T, difficulty: NonZeroU8) -> Result<Self, T::Error>
    where
        T: AsyncPowAdapter,
    {
        adapter.compute_async(self, difficulty).await
    }

    /// Add a signature to an unsigned event
    ///
    /// This method internally verifies the event ID and signature.
    #[inline]
    #[cfg(feature = "std")]
    pub fn add_signature(self, sig: Signature) -> Result<Event, Error> {
        self.add_signature_with_ctx(&SECP256K1, sig)
    }

    /// Add a signature to an unsigned event
    ///
    /// Internally verifies the event ID and signature.
    pub fn add_signature_with_ctx<C>(
        self,
        secp: &Secp256k1<C>,
        sig: Signature,
    ) -> Result<Event, Error>
    where
        C: Verification,
    {
        let (id, verify_id): (EventId, bool) = match self.id {
            // Mark the ID as verified if it's already set, as may be wrong.
            Some(id) => (id, true),
            // No event ID, we are computing it so we don't need to verify it.
            None => (self.compute_id(), false),
        };

        let event: Event = Event::new(
            id,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
            sig,
        );

        // Verify the event ID
        if verify_id && !event.verify_id() {
            return Err(invalid_event_id());
        }

        // Verify event signature
        if !event.verify_signature_with_ctx(secp) {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "invalid signature",
            ));
        }

        Ok(event)
    }
}

impl<S> FinalizeEvent<S> for UnsignedEvent
where
    S: SignEvent + ?Sized,
{
    type Error = Error;

    #[inline]
    fn finalize(self, signer: &S) -> Result<Event, Self::Error> {
        signer.sign_event(self).map_err(Error::other)
    }
}

impl<S> FinalizeEventAsync<S> for UnsignedEvent
where
    S: AsyncSignEvent + ?Sized,
{
    type Error = Error;

    #[inline]
    fn finalize_async<'a>(
        self,
        signer: &'a S,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + 'a>>
    where
        Self: 'a,
        S: 'a,
    {
        Box::pin(async move { signer.sign_event_async(self).await.map_err(Error::other) })
    }
}

impl_json_methods!(UnsignedEvent);

impl From<Event> for UnsignedEvent {
    fn from(event: Event) -> Self {
        Self {
            id: Some(event.id),
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags,
            content: event.content,
        }
    }
}

/// Finalize a builder into an unsigned event.
pub trait FinalizeUnsignedEvent: Sized {
    /// Build the unsigned event with the supplied public key.
    fn finalize_unsigned(self, public_key: PublicKey) -> UnsignedEvent;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_id() {
        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let mut unsigned = UnsignedEvent::from_json(json).unwrap();
        let expected_id: EventId =
            EventId::from_hex("2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45")
                .unwrap();

        assert!(unsigned.id.is_none());
        assert_eq!(unsigned.id(), expected_id);
    }

    #[test]
    fn test_deserialize_unsigned_event_with_id() {
        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let event_id: EventId =
            EventId::from_hex("2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45")
                .unwrap();
        let unsigned = UnsignedEvent::from_json(json).unwrap();
        assert_eq!(unsigned.id, Some(event_id));
        assert_eq!(
            unsigned.content,
            "uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA=="
        );
        assert_eq!(unsigned.kind, Kind::EncryptedDirectMessage);
    }

    #[test]
    fn test_deserialize_unsigned_event_without_id() {
        let json = r#"{"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","created_at":1640839235,"kind":4,"pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]]}"#;
        let unsigned = UnsignedEvent::from_json(json).unwrap();
        assert_eq!(unsigned.id, None);
        assert_eq!(
            unsigned.content,
            "uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA=="
        );
        assert_eq!(unsigned.kind, Kind::EncryptedDirectMessage);
    }
}
