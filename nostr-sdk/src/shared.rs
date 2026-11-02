use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use nostr::error::{Error, ErrorKind};
use nostr::event::{Event, EventId};
use nostr_database::NostrDatabase;
use nostr_gossip::NostrGossip;
use tokio::sync::Mutex;

use crate::authenticator::Authenticator;
use crate::monitor::Monitor;
use crate::policy::AdmitPolicy;
use crate::transport::websocket::WebSocketTransport;

// LruCache pre-allocate, so keep this at a reasonable value.
// A good value may be <= 128k.
const MAX_VERIFICATION_CACHE_SIZE: usize = 128_000;

#[derive(Debug)]
pub(crate) struct EventVerifier(Mutex<LruCache<EventId, ()>>);

impl EventVerifier {
    #[inline]
    fn new() -> Self {
        let max_verification_cache_size: NonZeroUsize =
            NonZeroUsize::new(MAX_VERIFICATION_CACHE_SIZE)
                .expect("MAX_VERIFICATION_CACHE_SIZE must be greater than 0");
        Self(Mutex::new(LruCache::new(max_verification_cache_size)))
    }

    /// Check if the event was already verified or verify it.
    ///
    /// This is useful if someone continues to send the same invalid event:
    /// since invalid events aren't stored in the database,
    /// skipping this check would result in the re-verification of the event.
    /// This may also be useful to avoid double verification if the event is received at the exact same time by many different Relay instances.
    ///
    /// This is important since event signature verification is a heavy job!
    pub(crate) async fn verify_and_cache(&self, event: &Event) -> Result<(), Error> {
        let mut cache = self.0.lock().await;

        // Verify the event ID, ensuring no field has changed
        if !event.verify_id() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Invalid event ID",
            ));
        }

        // Skip signature verification if the event is already cached
        if cache.contains(&event.id) {
            return Ok(());
        }

        // We now verify the event
        // If the event verification fails, the cache is not populated
        if !event.verify_signature() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "Invalid signature",
            ));
        }

        // Event is fully (ID + signature) verified, so we can cache it.
        cache.put(event.id, ());

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SharedState {
    pub(crate) database: Arc<dyn NostrDatabase>,
    pub(crate) transport: Arc<dyn WebSocketTransport>,
    pub(crate) gossip: Option<Arc<dyn NostrGossip>>,
    event_verifier: Arc<EventVerifier>,
    pub(crate) admit_policy: Option<Arc<dyn AdmitPolicy>>,
    pub(crate) authenticator: Option<Arc<dyn Authenticator>>,
    pub(crate) monitor: Option<Monitor>,
}

impl SharedState {
    pub(crate) fn new(
        database: Arc<dyn NostrDatabase>,
        transport: Arc<dyn WebSocketTransport>,
        gossip: Option<Arc<dyn NostrGossip>>,
        admit_policy: Option<Arc<dyn AdmitPolicy>>,
        authenticator: Option<Arc<dyn Authenticator>>,
        monitor: Option<Monitor>,
    ) -> Self {
        Self {
            database,
            transport,
            gossip,
            event_verifier: Arc::new(EventVerifier::new()),
            admit_policy,
            authenticator,
            monitor,
        }
    }

    #[inline]
    pub(crate) fn database(&self) -> &Arc<dyn NostrDatabase> {
        &self.database
    }

    #[inline]
    pub(crate) fn event_verifier(&self) -> &Arc<EventVerifier> {
        &self.event_verifier
    }

    #[inline]
    pub(crate) fn is_authenticator_available(&self) -> bool {
        self.authenticator.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify_and_cache_accepts_valid_event() {
        let json = r#"{
  "id": "7c9093cb5aa056f994da84b8200de3a1941d25040584c887d7d35e5d0b0fb00c",
  "pubkey": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
  "created_at": 1735659740,
  "kind": 0,
  "tags": [
    [
      "alt",
      "User profile for Yuki Kishimoto"
    ],
    [
      "i",
      "github:yukibtc",
      "69d9980b6e6b5d77a3e1e369ccaca9ba"
    ]
  ],
  "content": "{\"banner\":\"https://i.imgur.com/f1h1GgJ.jpg\",\"website\":\"https://yukikishimoto.com\",\"nip05\":\"_@yukikishimoto.com\",\"picture\":\"https://yukikishimoto.com/images/avatar.jpg\",\"lud16\":\"pay@yukikishimoto.com\",\"display_name\":\"Yuki Kishimoto\",\"about\":\"GitHub: https://github.com/yukibtc\\nPGP: 86F3 105A DFA8 AB58 7268  DCD7 8D3D CD04 2496 19D1\",\"name\":\"Yuki Kishimoto\",\"displayName\":\"Yuki Kishimoto\"}",
  "sig": "09e2a8b5cc4b9143138400f4ed4d00ccfb543cd9346ac01429ef4124a47284abcb72887d898b22d7433b3d72a7c6627294b64f5e93ed5bd1d27441319758276a"
}"#;

        let event_verifier: EventVerifier = EventVerifier::new();

        // Valid event
        let event: Event = Event::from_json(json).unwrap();
        assert!(event.verify().is_ok());

        // Verify it and cache
        assert!(event_verifier.verify_and_cache(&event).await.is_ok());

        // At this point the event ID must be in cache, meaning that has already been verified
        {
            let guard = event_verifier.0.lock().await;
            assert!(guard.peek(&event.id).is_some());
        }
    }

    #[tokio::test]
    async fn verify_and_cache_rejects_invalid_event() {
        let json = r#"{
  "id": "7c9093cb5aa056f994da84b8200de3a1941d25040584c887d7d35e5d0b0fb00c",
  "pubkey": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
  "created_at": 1735659740,
  "kind": 0,
  "tags": [],
  "content": "this event is invalid",
  "sig": "09e2a8b5cc4b9143138400f4ed4d00ccfb543cd9346ac01429ef4124a47284abcb72887d898b22d7433b3d72a7c6627294b64f5e93ed5bd1d27441319758276a"
}"#;

        let event_verifier: EventVerifier = EventVerifier::new();

        // This is an invalid event
        let event: Event = Event::from_json(json).unwrap();
        assert!(event.verify().is_err());

        assert!(event_verifier.verify_and_cache(&event).await.is_err());

        // The cache must not contains it
        {
            let guard = event_verifier.0.lock().await;
            assert!(guard.peek(&event.id).is_none());
        }
    }

    #[tokio::test]
    async fn verify_and_cache_rejects_tampered_event() {
        let json = r#"{
  "id": "7c9093cb5aa056f994da84b8200de3a1941d25040584c887d7d35e5d0b0fb00c",
  "pubkey": "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
  "created_at": 1735659740,
  "kind": 0,
  "tags": [
    [
      "alt",
      "User profile for Yuki Kishimoto"
    ],
    [
      "i",
      "github:yukibtc",
      "69d9980b6e6b5d77a3e1e369ccaca9ba"
    ]
  ],
  "content": "{\"banner\":\"https://i.imgur.com/f1h1GgJ.jpg\",\"website\":\"https://yukikishimoto.com\",\"nip05\":\"_@yukikishimoto.com\",\"picture\":\"https://yukikishimoto.com/images/avatar.jpg\",\"lud16\":\"pay@yukikishimoto.com\",\"display_name\":\"Yuki Kishimoto\",\"about\":\"GitHub: https://github.com/yukibtc\\nPGP: 86F3 105A DFA8 AB58 7268  DCD7 8D3D CD04 2496 19D1\",\"name\":\"Yuki Kishimoto\",\"displayName\":\"Yuki Kishimoto\"}",
  "sig": "09e2a8b5cc4b9143138400f4ed4d00ccfb543cd9346ac01429ef4124a47284abcb72887d898b22d7433b3d72a7c6627294b64f5e93ed5bd1d27441319758276a"
}"#;

        let event_verifier: EventVerifier = EventVerifier::new();

        // Valid event
        let event: Event = Event::from_json(json).unwrap();
        assert!(event.verify().is_ok());

        // Verify it and cache
        assert!(event_verifier.verify_and_cache(&event).await.is_ok());

        // At this point the event ID must be in cache, meaning that has already been verified
        {
            let guard = event_verifier.0.lock().await;
            assert!(guard.peek(&event.id).is_some());
        }

        // Try to change some content, without changing the event ID
        let mut invalid_event: Event = event;
        invalid_event.content = String::from("{}");
        invalid_event.tags.clear();

        // Event verification MUST NOT pass
        assert!(
            event_verifier
                .verify_and_cache(&invalid_event)
                .await
                .is_err()
        );
    }
}
