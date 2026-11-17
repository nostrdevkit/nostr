// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use negentropy::{Negentropy, NegentropyStorageVector};
use nostr::event::{Event, Kind};
use nostr::filter::Filter;
use nostr::key::PublicKey;
use nostr::message::SubscriptionId;
use nostr::nips::nip42;
use nostr::types::Timestamp;
use nostr::types::url::RelayUrl;

pub(super) enum RateLimiterResponse {
    Allowed,
    Limited,
}

#[derive(Default)]
pub(super) struct Nip42Session {
    /// Is authenticated
    pub public_key: Option<PublicKey>,
    /// Challenges
    pub challenges: HashSet<String>,
}

impl Nip42Session {
    /// Get or generate challenge
    pub fn generate_challenge(&mut self) -> String {
        // TODO: alternatives?

        // Too many challenges without reply
        if self.challenges.len() > 20 {
            // Clean to avoid possible attack where client never complete auth
            self.challenges.clear();
        }

        let challenge: String = SubscriptionId::generate().to_string();
        self.challenges.insert(challenge.clone());
        challenge
    }

    #[inline]
    pub fn is_authenticated(&self) -> bool {
        self.public_key.is_some()
    }

    pub fn check_challenge(&mut self, event: &Event, relay_url: &RelayUrl) -> Result<(), String> {
        // Authentication must be bound to the NIP-42 kind, this relay, and this connection.
        if event.kind != Kind::Authentication {
            return Err(String::from("invalid authentication event kind"));
        }

        match event.tags.challenge() {
            Some(challenge) => {
                if !self.challenges.contains(&challenge) {
                    return Err(String::from("received invalid challenge"));
                }

                // Check created_at
                let now = Timestamp::now();
                let diff: u64 = now.as_secs().abs_diff(event.created_at.as_secs());
                if diff > 120 {
                    return Err(String::from("challenge is too old (max allowed 2 min)"));
                }

                // Verify event
                event.verify().map_err(|e| e.to_string())?;

                if !nip42::is_valid_auth_event(event, relay_url, &challenge) {
                    return Err(String::from("invalid authentication event"));
                }

                // Consume only after every check, so malformed replies cannot invalidate it.
                self.challenges.remove(&challenge);

                // Mark as authenticated
                self.public_key = Some(event.pubkey);

                Ok(())
            }
            None => Err(String::from("challenge not found")),
        }
    }
}

pub(super) struct Session<'a> {
    pub subscriptions: HashMap<SubscriptionId, Subscription>,
    pub subscription_bytes: usize,
    pub negentropy_subscription: HashMap<SubscriptionId, NegentropySubscription<'a>>,
    pub nip42: Nip42Session,
    pub write_tokens: Tokens,
    pub query_tokens: Tokens,
    pub negentropy_tokens: Tokens,
    pub auth_tokens: Tokens,
    pub message_tokens: Tokens,
}

pub(super) struct NegentropySubscription<'a> {
    pub state: Negentropy<'a, NegentropyStorageVector>,
    pub items: usize,
}

pub(super) struct Subscription {
    pub filters: Vec<Filter>,
    size: usize,
}

impl Session<'_> {
    const MIN: Duration = Duration::from_secs(60);

    fn calculate_elapsed_time(now: Instant, last: Instant) -> Duration {
        let mut elapsed_time: Duration = now - last;

        if elapsed_time > Self::MIN {
            elapsed_time = Self::MIN;
        }

        elapsed_time
    }

    pub fn check_rate_limit(&mut self, max_per_minute: u32) -> RateLimiterResponse {
        Self::take_token(&mut self.write_tokens, max_per_minute)
    }

    pub fn check_query_rate_limit(&mut self, max_per_minute: u32) -> RateLimiterResponse {
        Self::take_token(&mut self.query_tokens, max_per_minute)
    }

    pub fn check_negentropy_rate_limit(&mut self, max_per_minute: u32) -> RateLimiterResponse {
        Self::take_token(&mut self.negentropy_tokens, max_per_minute)
    }

    pub fn check_auth_rate_limit(&mut self, max_per_minute: u32) -> RateLimiterResponse {
        Self::take_token(&mut self.auth_tokens, max_per_minute)
    }

    pub fn check_message_rate_limit(&mut self, max_per_minute: u32) -> RateLimiterResponse {
        Self::take_token(&mut self.message_tokens, max_per_minute)
    }

    fn take_token(tokens: &mut Tokens, max_per_minute: u32) -> RateLimiterResponse {
        let now = Instant::now();
        if let Some(last) = tokens.last {
            let elapsed_time: Duration = Self::calculate_elapsed_time(now, last);
            tokens.replenish(max_per_minute, elapsed_time);
        }
        tokens.last = Some(now);

        // Every admitted operation consumes one token, including the first one.
        if tokens.count == 0 {
            return RateLimiterResponse::Limited;
        }

        tokens.count -= 1;
        RateLimiterResponse::Allowed
    }

    pub fn subscription_fits(&self, id: &SubscriptionId, size: usize, max_size: usize) -> bool {
        // Replacements release their old budget; overflow is treated as exceeding the limit.
        let replaced_size = self.subscriptions.get(id).map_or(0, |sub| sub.size);
        self.subscription_bytes
            .saturating_sub(replaced_size)
            .checked_add(size)
            .is_some_and(|total| total <= max_size)
    }

    pub fn insert_subscription(&mut self, id: SubscriptionId, filters: Vec<Filter>, size: usize) {
        if let Some(previous) = self
            .subscriptions
            .insert(id, Subscription { filters, size })
        {
            self.subscription_bytes = self.subscription_bytes.saturating_sub(previous.size);
        }
        self.subscription_bytes = self.subscription_bytes.saturating_add(size);
    }

    pub fn remove_subscription(&mut self, id: &SubscriptionId) {
        if let Some(subscription) = self.subscriptions.remove(id) {
            self.subscription_bytes = self.subscription_bytes.saturating_sub(subscription.size);
        }
    }
}

/// Tokens to keep track of session limits
pub(super) struct Tokens {
    pub count: u32,
    pub last: Option<Instant>,
}

impl Tokens {
    #[inline]
    pub fn new(tokens: u32) -> Self {
        Self {
            count: tokens,
            last: None,
        }
    }

    fn replenish(&mut self, max_per_minute: u32, elapsed_time: Duration) {
        let percent: f32 = (elapsed_time.as_secs() as f32) / 60.0;
        let new_tokens: u32 = (percent * max_per_minute as f32).floor() as u32;

        // Idle time cannot accumulate a burst above the configured per-minute capacity.
        self.count = self.count.saturating_add(new_tokens).min(max_per_minute);
    }
}

#[cfg(test)]
mod tests {
    use nostr::event::{EventBuilder, FinalizeEvent, IntoEventBuilder};
    use nostr::key::Keys;

    use super::*;

    fn session(tokens: u32) -> Session<'static> {
        Session {
            subscriptions: HashMap::new(),
            subscription_bytes: 0,
            negentropy_subscription: HashMap::new(),
            nip42: Nip42Session::default(),
            write_tokens: Tokens::new(tokens),
            query_tokens: Tokens::new(tokens),
            negentropy_tokens: Tokens::new(tokens),
            auth_tokens: Tokens::new(tokens),
            message_tokens: Tokens::new(tokens),
        }
    }

    #[test]
    fn zero_rate_limit_rejects_the_first_event() {
        let mut session = session(0);

        assert!(matches!(
            session.check_rate_limit(0),
            RateLimiterResponse::Limited
        ));
    }

    #[test]
    fn rate_limit_allows_exactly_the_available_tokens() {
        let mut session = session(2);

        assert!(matches!(
            session.check_rate_limit(2),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_rate_limit(2),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_rate_limit(2),
            RateLimiterResponse::Limited
        ));
    }

    #[test]
    fn query_rate_limit_starts_full_and_caps_refill_at_capacity() {
        let mut session = session(2);

        assert!(matches!(
            session.check_query_rate_limit(2),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_query_rate_limit(2),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_query_rate_limit(2),
            RateLimiterResponse::Limited
        ));

        session.query_tokens.last = Some(Instant::now() - Duration::from_secs(60));

        assert!(matches!(
            session.check_query_rate_limit(2),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_query_rate_limit(2),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_query_rate_limit(2),
            RateLimiterResponse::Limited
        ));
    }

    #[test]
    fn rate_limits_use_separate_buckets() {
        let mut session = session(1);

        assert!(matches!(
            session.check_rate_limit(1),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_query_rate_limit(1),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_negentropy_rate_limit(1),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_auth_rate_limit(1),
            RateLimiterResponse::Allowed
        ));
        assert!(matches!(
            session.check_message_rate_limit(1),
            RateLimiterResponse::Allowed
        ));
    }

    #[test]
    fn authentication_rejects_signatures_from_other_event_kinds() {
        let keys = Keys::generate();
        let mut session = Nip42Session::default();
        let challenge = session.generate_challenge();
        let relay_url = RelayUrl::parse("ws://127.0.0.1:8080").unwrap();
        let event = EventBuilder::new(Kind::TextNote)
            .content("unrelated")
            .tag(["challenge", challenge.as_str()])
            .finalize(&keys)
            .unwrap();

        let error = session.check_challenge(&event, &relay_url).unwrap_err();
        assert_eq!(error, "invalid authentication event kind");
        assert!(session.challenges.contains(&challenge));
        assert!(!session.is_authenticated());
    }

    #[test]
    fn authentication_rejects_events_for_another_relay() {
        let keys = Keys::generate();
        let mut session = Nip42Session::default();
        let challenge = session.generate_challenge();
        let expected_relay = RelayUrl::parse("ws://127.0.0.1:8080").unwrap();
        let other_relay = RelayUrl::parse("wss://attacker.example.com").unwrap();
        let event = nip42::ClientAuthentication::new(challenge.clone(), other_relay)
            .into_event_builder()
            .finalize(&keys)
            .unwrap();

        let error = session
            .check_challenge(&event, &expected_relay)
            .unwrap_err();
        assert_eq!(error, "invalid authentication event");
        assert!(session.challenges.contains(&challenge));
        assert!(!session.is_authenticated());
    }
}
