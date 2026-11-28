// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-59: Gift Wrap
//!
//! <https://github.com/nostr-protocol/nips/blob/master/59.md>

#[cfg(all(feature = "std", feature = "os-rng"))]
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(all(feature = "std", feature = "os-rng"))]
use core::future::Future;
#[cfg(all(feature = "std", feature = "os-rng"))]
use core::ops::Range;
#[cfg(all(feature = "std", feature = "os-rng"))]
use core::pin::Pin;
use core::time::Duration;

#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::RngExt;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rand_core::UnwrapErr;
#[cfg(all(feature = "std", feature = "os-rng"))]
use rand::rngs::SysRng;
use secp256k1::{Secp256k1, Verification};

use crate::error::{Error, ErrorKind};
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::event::{AsyncSignEvent, EventBuilder, FinalizeEvent, FinalizeEventAsync, SignEvent};
use crate::event::{Event, Kind, Tag, UnsignedEvent};
use crate::key::PublicKey;
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::key::{AsyncGetPublicKey, GetPublicKey, Keys};
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::nips::nip44;
use crate::nips::nip44::{AsyncNip44, Nip44};
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::types::Timestamp;
#[cfg(feature = "std")]
use crate::util::SECP256K1;

#[cfg(all(feature = "std", feature = "os-rng"))]
const RANGE_RANDOM_TIMESTAMP_TWEAK: Range<u64> = 0..172800; // From 0 secs to 2 days

#[inline]
fn not_gift_wrap() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "not a gift wrap")
}

#[inline]
fn sender_mismatch() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "sender mismatch")
}

/// Unwrapped Gift Wrap (NIP59)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnwrappedGift {
    /// The public key of the sender included in the `seal`
    pub sender: PublicKey,
    /// The rumor
    pub rumor: UnsignedEvent,
}

impl UnwrappedGift {
    /// Unwrap Gift Wrap event
    ///
    /// Internally verify the `seal` event
    #[inline]
    #[cfg(feature = "std")]
    pub fn from_gift_wrap<T>(signer: &T, gift_wrap: &Event) -> Result<Self, Error>
    where
        T: Nip44,
    {
        Self::from_gift_wrap_with_ctx(&SECP256K1, signer, gift_wrap)
    }

    /// Unwrap Gift Wrap event
    ///
    /// Internally verify the `seal` event
    #[inline]
    #[cfg(feature = "std")]
    pub async fn from_gift_wrap_async<T>(signer: &T, gift_wrap: &Event) -> Result<Self, Error>
    where
        T: AsyncNip44,
    {
        Self::from_gift_wrap_with_ctx_async(&SECP256K1, signer, gift_wrap).await
    }

    /// Unwrap Gift Wrap event
    ///
    /// Internally verify the `seal` event
    pub fn from_gift_wrap_with_ctx<C, T>(
        secp: &Secp256k1<C>,
        signer: &T,
        gift_wrap: &Event,
    ) -> Result<Self, Error>
    where
        C: Verification,
        T: Nip44,
    {
        // Check event kind
        if gift_wrap.kind != Kind::GiftWrap {
            return Err(not_gift_wrap());
        }
        // Authenticate the outer event before using its metadata or decrypting its content.
        gift_wrap.verify_with_ctx(secp)?;

        // Decrypt and verify seal
        let seal: String = signer
            .nip44_decrypt(&gift_wrap.pubkey, &gift_wrap.content)
            .map_err(Error::crypto)?;
        let seal: Event = parse_and_verify_seal(secp, seal)?;

        // Decrypt rumor
        let rumor: String = signer
            .nip44_decrypt(&seal.pubkey, &seal.content)
            .map_err(Error::crypto)?;

        parse_unwrapped_gift(seal, rumor)
    }

    /// Unwrap Gift Wrap event
    ///
    /// Internally verify the `seal` event
    pub async fn from_gift_wrap_with_ctx_async<C, T>(
        secp: &Secp256k1<C>,
        signer: &T,
        gift_wrap: &Event,
    ) -> Result<Self, Error>
    where
        C: Verification,
        T: AsyncNip44,
    {
        // Check event kind
        if gift_wrap.kind != Kind::GiftWrap {
            return Err(not_gift_wrap());
        }
        // Authenticate the outer event before using its metadata or decrypting its content.
        gift_wrap.verify_with_ctx(secp)?;

        // Decrypt and verify seal
        let seal: String = signer
            .nip44_decrypt_async(&gift_wrap.pubkey, &gift_wrap.content)
            .await
            .map_err(Error::crypto)?;
        let seal: Event = parse_and_verify_seal(secp, seal)?;

        // Decrypt rumor
        let rumor: String = signer
            .nip44_decrypt_async(&seal.pubkey, &seal.content)
            .await
            .map_err(Error::crypto)?;

        parse_unwrapped_gift(seal, rumor)
    }
}

/// Gift wrap seal event builder.
///
/// # Example
///
/// ```rust,no_run
/// # use nostr::prelude::*;
/// # use nostr::nips::nip59::GiftWrapSealBuilder;
/// # #[cfg(all(feature = "std", feature = "os-rng"))]
/// # fn main() -> Result<(), Box<dyn core::error::Error>> {
/// let receiver = PublicKey::from_hex("<receiver-public-key>")?;
/// let rumor = UnsignedEvent::from_json("<rumor-json>")?;
/// let signer = Keys::parse("<my-secret-key>")?;
/// let seal: Event = GiftWrapSealBuilder::new(rumor, receiver).finalize(&signer)?;
/// # Ok(())
/// # }
/// # #[cfg(not(all(feature = "std", feature = "os-rng")))]
/// # fn main() {}
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GiftWrapSealBuilder {
    /// The rumor
    pub rumor: UnsignedEvent,
    /// The public key of the receiver
    pub receiver: PublicKey,
}

impl GiftWrapSealBuilder {
    /// Create a new gift wrap builder.
    // Take an `UnsignedEvent` as rumor and not an `EventBuilder`!
    // May be useful to take an `EventBuilder` but it can create issues:
    // if a dev passes the same cloned `EventBuilder` to send the rumor to multiple users,
    // the final rumor will have different `created_at` timestamps, so different event IDs.
    #[inline]
    pub fn new(rumor: UnsignedEvent, receiver: PublicKey) -> Self {
        Self { rumor, receiver }
    }
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl<S> FinalizeEvent<S> for GiftWrapSealBuilder
where
    S: GetPublicKey + SignEvent + Nip44,
{
    type Error = Error;

    fn finalize(mut self, signer: &S) -> Result<Event, Self::Error> {
        // Make sure that rumor has event ID before it's serialized:
        // the encrypted JSON is exactly what the receiver will parse.
        self.rumor.ensure_id();

        // Encrypt content
        let content: String = signer
            .nip44_encrypt(&self.receiver, &self.rumor.as_json())
            .map_err(Error::crypto)?;

        let seal: EventBuilder = build_seal(content);
        seal.finalize(signer)
    }
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl<S> FinalizeEventAsync<S> for GiftWrapSealBuilder
where
    S: AsyncGetPublicKey + AsyncSignEvent + AsyncNip44,
{
    type Error = Error;

    fn finalize_async<'a>(
        mut self,
        signer: &'a S,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + 'a>>
    where
        Self: 'a,
        S: 'a,
    {
        // Make sure that rumor has event ID before it's serialized:
        // the encrypted JSON is exactly what the receiver will parse.
        self.rumor.ensure_id();

        Box::pin(async move {
            // Encrypt content
            let content: String = signer
                .nip44_encrypt_async(&self.receiver, &self.rumor.as_json())
                .await
                .map_err(Error::crypto)?;

            let seal: EventBuilder = build_seal(content);
            seal.finalize_async(signer).await
        })
    }
}

/// Gift wrap event builder.
///
/// # Example
///
/// ```rust,no_run
/// # use nostr::prelude::*;
/// # use nostr::nips::nip59::GiftWrapBuilder;
/// # #[cfg(all(feature = "std", feature = "os-rng"))]
/// # fn main() -> Result<(), Box<dyn core::error::Error>> {
/// let receiver = PublicKey::from_hex("<receiver-public-key>")?;
/// let rumor = UnsignedEvent::from_json("<rumor-json>")?;
/// let signer = Keys::parse("<my-secret-key>")?;
/// let gift_wrap: Event = GiftWrapBuilder::new(receiver, rumor).finalize(&signer)?;
/// # Ok(())
/// # }
/// # #[cfg(not(all(feature = "std", feature = "os-rng")))]
/// # fn main() {}
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GiftWrapBuilder {
    /// The public key of the receiver
    pub receiver: PublicKey,
    /// The rumor
    pub rumor: UnsignedEvent,
    /// Extra tags to add to the event
    pub extra_tags: Vec<Tag>,
    /// NIP-40 expiration, relative to the gift wrap's `created_at`
    pub expiration: Option<Duration>,
}

impl GiftWrapBuilder {
    /// Create a new gift wrap builder.
    #[inline]
    pub fn new(receiver: PublicKey, rumor: UnsignedEvent) -> Self {
        Self {
            receiver,
            rumor,
            extra_tags: Vec::new(),
            expiration: None,
        }
    }

    /// Add extra tags.
    #[inline]
    pub fn extra_tags<T>(mut self, tags: T) -> Self
    where
        T: IntoIterator<Item = Tag>,
    {
        self.extra_tags.extend(tags);
        self
    }

    /// Set a NIP-40 expiration on the gift wrap.
    ///
    /// The expiration tag is anchored to the gift wrap's randomized `created_at`
    /// so it doesn't leak the real send time.
    /// `duration` should be greater than 2 days
    /// or it may created in an expired state.
    #[inline]
    pub fn expiration(mut self, duration: Duration) -> Self {
        self.expiration = Some(duration);
        self
    }
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl<S> FinalizeEvent<S> for GiftWrapBuilder
where
    S: GetPublicKey + SignEvent + Nip44,
{
    type Error = Error;

    fn finalize(self, signer: &S) -> Result<Event, Self::Error> {
        let seal: Event = GiftWrapSealBuilder::new(self.rumor, self.receiver).finalize(signer)?;
        make_gift_wrap(seal, self.receiver, self.extra_tags, self.expiration)
    }
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl<S> FinalizeEventAsync<S> for GiftWrapBuilder
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
            let seal: Event = GiftWrapSealBuilder::new(self.rumor, self.receiver)
                .finalize_async(signer)
                .await?;
            make_gift_wrap(seal, self.receiver, self.extra_tags, self.expiration)
        })
    }
}

#[cfg(all(feature = "std", feature = "os-rng"))]
fn make_gift_wrap(
    seal: Event,
    receiver: PublicKey,
    extra_tags: Vec<Tag>,
    expiration: Option<Duration>,
) -> Result<Event, Error> {
    // Generate the random keys
    let keys: Keys = Keys::generate();

    // Encrypt content
    let content: String = nip44::encrypt(
        keys.secret_key(),
        &receiver,
        seal.as_json(),
        nip44::Version::default(),
    )
    .map_err(Error::crypto)?;

    // Collect extra tags
    let mut tags: Vec<Tag> = extra_tags;

    // Push received public key
    tags.push(Tag::public_key(receiver));

    // Use a tweaked timestamp to thwart time-analysis attacks
    let created_at: Timestamp = tweaked_timestamp();

    // Anchor the NIP-40 expiration to the tweaked `created_at` so we don't
    // leak the real creation time.
    // `expiration - created_at` stays constant.
    if let Some(duration) = expiration {
        tags.push(Tag::expiration(created_at + duration));
    }

    EventBuilder::new(Kind::GiftWrap, content)
        .tags(tags)
        .custom_created_at(created_at)
        .finalize(&keys)
}

fn parse_and_verify_seal<C>(secp: &Secp256k1<C>, seal: String) -> Result<Event, Error>
where
    C: Verification,
{
    let seal: Event = Event::from_json(seal)?;

    if seal.kind != Kind::Seal {
        return Err(Error::with_static_message(ErrorKind::Invalid, "not a seal"));
    }

    if !seal.tags.is_empty() {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "seal tags aren't empty",
        ));
    }

    seal.verify_with_ctx(secp)?;

    Ok(seal)
}

fn parse_unwrapped_gift(seal: Event, rumor: String) -> Result<UnwrappedGift, Error> {
    let rumor: UnsignedEvent = UnsignedEvent::from_json(rumor)?;

    rumor.verify_id()?;

    // Ensure the rumor author matches the seal
    if rumor.pubkey != seal.pubkey {
        return Err(sender_mismatch());
    }

    Ok(UnwrappedGift {
        sender: seal.pubkey,
        rumor,
    })
}

/// Extract `rumor` from Gift Wrap event
#[inline]
#[cfg(feature = "std")]
pub fn extract_rumor<T>(signer: &T, gift_wrap: &Event) -> Result<UnwrappedGift, Error>
where
    T: Nip44,
{
    UnwrappedGift::from_gift_wrap(signer, gift_wrap)
}

/// Extract `rumor` from Gift Wrap event
#[inline]
#[cfg(feature = "std")]
pub async fn extract_rumor_async<T>(signer: &T, gift_wrap: &Event) -> Result<UnwrappedGift, Error>
where
    T: AsyncNip44,
{
    UnwrappedGift::from_gift_wrap_async(signer, gift_wrap).await
}

#[cfg(all(feature = "std", feature = "os-rng"))]
fn build_seal(content: String) -> EventBuilder {
    EventBuilder::new(Kind::Seal, content).custom_created_at(tweaked_timestamp())
}

#[cfg(all(feature = "std", feature = "os-rng"))]
fn tweaked_timestamp() -> Timestamp {
    let now: Timestamp = Timestamp::now();

    let secs: u64 = UnwrapErr(SysRng).random_range(RANGE_RANDOM_TIMESTAMP_TWEAK);
    let new_timestamp: u64 = now.as_secs().saturating_sub(secs);

    Timestamp::from_secs(new_timestamp)
}

#[cfg(test)]
#[cfg(all(feature = "std", feature = "os-rng"))]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn test_extract_rumor() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        // Compose Gift Wrap event
        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let event: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor)
            .finalize(&sender_keys)
            .unwrap();
        let unwrapped = extract_rumor(&receiver_keys, &event).unwrap();
        assert_eq!(unwrapped.sender, sender_keys.public_key());
        assert_eq!(unwrapped.rumor.kind, Kind::TextNote);
        assert_eq!(unwrapped.rumor.content, "Test");
        assert!(unwrapped.rumor.tags.is_empty());
        assert!(extract_rumor(&sender_keys, &event).is_err());

        let event: Event = EventBuilder::new(Kind::TextNote, "")
            .finalize(&sender_keys)
            .unwrap();
        assert_eq!(
            extract_rumor(&receiver_keys, &event).unwrap_err().kind(),
            not_gift_wrap().kind()
        );
    }

    #[test]
    fn test_extract_rumor_rejects_modified_gift_wrap() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let rumor =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let mut gift_wrap = GiftWrapBuilder::new(receiver_keys.public_key(), rumor)
            .finalize(&sender_keys)
            .unwrap();
        gift_wrap.created_at = gift_wrap.created_at + Duration::from_secs(1);

        assert!(extract_rumor(&receiver_keys, &gift_wrap).is_err());
    }

    #[tokio::test]
    async fn test_extract_rumor_async() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let event: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor)
            .finalize_async(&sender_keys)
            .await
            .unwrap();

        let unwrapped = extract_rumor_async(&receiver_keys, &event).await.unwrap();
        assert_eq!(unwrapped.sender, sender_keys.public_key());
        assert_eq!(unwrapped.rumor.kind, Kind::TextNote);
        assert_eq!(unwrapped.rumor.content, "Test");
    }

    #[test]
    fn test_rumor_id_serialized_inside_wrap() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let event: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor.clone())
            .finalize(&sender_keys)
            .unwrap();

        // The rumor id must survive the wrap: it has to be computed *before*
        // the rumor JSON is encrypted into the seal.
        let unwrapped = extract_rumor(&receiver_keys, &event).unwrap();
        assert_eq!(unwrapped.rumor.id, Some(rumor.compute_id()));
    }

    #[tokio::test]
    async fn test_rumor_id_serialized_inside_wrap_async() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let event: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor.clone())
            .finalize_async(&sender_keys)
            .await
            .unwrap();

        // The rumor id must survive the wrap: it has to be computed *before*
        // the rumor JSON is encrypted into the seal.
        let unwrapped = extract_rumor_async(&receiver_keys, &event).await.unwrap();
        assert_eq!(unwrapped.rumor.id, Some(rumor.compute_id()));
    }

    #[test]
    fn test_make_seal() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let seal = GiftWrapSealBuilder::new(rumor, receiver_keys.public_key())
            .finalize(&sender_keys)
            .unwrap();

        assert_eq!(seal.kind, Kind::Seal);
        assert!(!seal.content.is_empty());
    }

    #[tokio::test]
    async fn test_make_seal_async() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let seal = GiftWrapSealBuilder::new(rumor, receiver_keys.public_key())
            .finalize_async(&sender_keys)
            .await
            .unwrap();

        assert_eq!(seal.kind, Kind::Seal);
        assert!(!seal.content.is_empty());
    }

    #[tokio::test]
    async fn test_sender_mismatch() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let impersonated_keys =
            Keys::parse("5b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        // Construct a rumor that lies about its pubkey but is still wrapped/signed
        // by `sender_keys`. This mimics a spoofing attempt the recipient must reject.
        let rumor: UnsignedEvent = EventBuilder::new(Kind::TextNote, "spoofed")
            .finalize_unsigned(impersonated_keys.public_key());

        let gift_wrap: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor)
            .finalize(&sender_keys)
            .unwrap();

        assert_eq!(
            extract_rumor(&receiver_keys, &gift_wrap)
                .unwrap_err()
                .kind(),
            sender_mismatch().kind()
        );
    }

    #[test]
    fn test_gift_wrap_expiration_anchored_to_created_at() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let duration: Duration = Duration::from_secs(7 * 24 * 3600);
        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let event: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor)
            .expiration(duration)
            .finalize(&sender_keys)
            .unwrap();

        assert_eq!(event.kind, Kind::GiftWrap);

        // The expiration is anchored to the (tweaked) `created_at`, so the
        // difference is exactly the requested duration and leaks no send time.
        let expiration = event.tags.expiration().expect("missing expiration tag");
        assert_eq!(
            expiration.as_secs() - event.created_at.as_secs(),
            duration.as_secs()
        );
    }

    #[test]
    fn test_gift_wrap_without_expiration() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let event: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor)
            .finalize(&sender_keys)
            .unwrap();

        assert!(event.tags.expiration().is_none());
    }

    #[tokio::test]
    async fn test_gift_wrap_expiration_anchored_to_created_at_async() {
        let sender_keys =
            Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver_keys =
            Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();

        let duration: Duration = Duration::from_secs(7 * 24 * 3600);
        let rumor: UnsignedEvent =
            EventBuilder::new(Kind::TextNote, "Test").finalize_unsigned(sender_keys.public_key());
        let event: Event = GiftWrapBuilder::new(receiver_keys.public_key(), rumor)
            .expiration(duration)
            .finalize_async(&sender_keys)
            .await
            .unwrap();

        let expiration = event.tags.expiration().expect("missing expiration tag");
        assert_eq!(
            expiration.as_secs() - event.created_at.as_secs(),
            duration.as_secs()
        );
    }
}
