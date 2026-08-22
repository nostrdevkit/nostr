// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Nostr Relay Builder and Mock Relay for tests

mod builder;
mod local;
mod mock;

pub use self::builder::*;
pub use self::local::*;
pub use self::mock::*;

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use nostr::event::{EventBuilder, EventId, FinalizeEvent, Kind, Tag};
    use nostr::filter::Filter;
    use nostr::key::{Keys, PublicKey};
    use nostr::nips::nip17::PrivateDirectMessageBuilder;
    use nostr_memory::MemoryDatabase;
    use tokio_stream::StreamExt;

    use super::*;
    use crate::client::Client;
    use crate::error::Error;

    const UPDATE_TAG: &str = "updated";

    #[derive(Debug)]
    struct UpdateFilterPlugin;

    impl QueryPolicy for UpdateFilterPlugin {
        fn admit_query<'a>(
            &'a self,
            query: &'a mut Filter,
            _addr: &'a std::net::SocketAddr,
        ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
            Box::pin(async move {
                *query = query.clone().hashtag(UPDATE_TAG);
                QueryPolicyResult::Accept
            })
        }
    }

    #[tokio::test]
    async fn update_filter() {
        let relay = LocalRelay::builder()
            .database(MemoryDatabase::unbounded())
            .query_policy(UpdateFilterPlugin)
            .build();
        relay.run().await.unwrap();

        let keys = Keys::generate();
        let client = Client::default();

        client
            .add_relay(relay.url().await)
            .and_connect()
            .await
            .unwrap();

        // Event with our target tag
        let event = EventBuilder::new(Kind::TextNote, ":)")
            .tag(Tag::hashtag(UPDATE_TAG))
            .finalize(&keys)
            .unwrap();
        client.send_event(&event).await.unwrap();

        // This event has a random tag and should be filtered out in the REQ.
        // It would only appear if the filter had not been updated correctly.
        let event = EventBuilder::new(Kind::TextNote, ":)")
            .tag(Tag::hashtag("TEST"))
            .finalize(&keys)
            .unwrap();
        client.send_event(&event).await.unwrap();

        // Empty filter to get all events. It should be updated to have `UPDATE_TAG`
        let events = client.fetch_events(Filter::new()).await.unwrap();

        assert!(!events.is_empty(), "Should not be empty");
        assert!(
            events
                .iter()
                .all(|e| { e.tags.hashtags().all(|hashtag| hashtag == UPDATE_TAG) }),
            "All tags should have the updated filter tag"
        );
    }

    #[tokio::test]
    async fn kind_blacklist() {
        let relay = LocalRelay::builder()
            .database(MemoryDatabase::unbounded())
            .blacklist_kinds(&[Kind::TextNote])
            .build();
        relay.run().await.unwrap();

        let keys = Keys::generate();
        let client = Client::default();

        client
            .add_relay(relay.url().await)
            .and_connect()
            .await
            .unwrap();
        let event = EventBuilder::new(Kind::TextNote, ":)")
            .finalize(&keys)
            .unwrap();
        let output = client.send_event(&event).await.unwrap();

        assert_eq!(
            "blocked: kind `1` is not accepted by this relay",
            output.failed.values().next().unwrap()
        )
    }

    #[tokio::test]
    async fn invalid_gift_wrap() {
        let relay = LocalRelay::builder()
            .database(MemoryDatabase::unbounded())
            .blacklist_kinds(&[Kind::TextNote])
            .build();
        relay.run().await.unwrap();

        let keys = Keys::generate();
        let client = Client::default();

        client
            .add_relay(relay.url().await)
            .and_connect()
            .await
            .unwrap();
        let event = PrivateDirectMessageBuilder::new(keys.public_key(), "Hey")
            .extra_tags([Tag::public_key(PublicKey::from_slice(&[0; 32]).unwrap())])
            .finalize(&keys)
            .unwrap();
        let output = client.send_event(&event).await.unwrap();

        assert_eq!(
            "blocked: GiftWrap must contain exactly one recipient public key",
            output.failed.values().next().unwrap()
        );

        let event = EventBuilder::new(Kind::GiftWrap, "Hey")
            .finalize(&keys)
            .unwrap();
        let output = client.send_event(&event).await.unwrap();

        assert_eq!(
            "blocked: GiftWrap must contain exactly one recipient public key",
            output.failed.values().next().unwrap()
        );
    }

    #[tokio::test]
    async fn event_size() {
        const MAX_SIZE: usize = 500;

        let relay = LocalRelay::builder()
            .max_event_size(MAX_SIZE)
            .database(MemoryDatabase::unbounded())
            .build();
        relay.run().await.unwrap();

        let keys = Keys::generate();
        let client = Client::default();

        client
            .add_relay(relay.url().await)
            .and_connect()
            .await
            .unwrap();

        let base_event_size = EventBuilder::new(Kind::TextNote, "")
            .finalize(&keys)
            .unwrap()
            .as_json()
            .len();

        let equal_max_size =
            EventBuilder::new(Kind::TextNote, ".".repeat(MAX_SIZE - base_event_size))
                .finalize(&keys)
                .unwrap();
        let greater_max_size =
            EventBuilder::new(Kind::TextNote, ".".repeat((MAX_SIZE - base_event_size) + 1))
                .finalize(&keys)
                .unwrap();

        let output = client.send_event(&equal_max_size).await.unwrap();
        dbg!(&output);
        assert!(!output.success.is_empty());

        let output = client.send_event(&greater_max_size).await.unwrap();
        assert_eq!(
            "blocked: event size (501 bytes) exceeds maximum allowed size (500 bytes)",
            output.failed.values().next().unwrap()
        );
    }

    #[tokio::test]
    async fn protected_repost() {
        let relay = LocalRelay::builder()
            .database(MemoryDatabase::unbounded())
            .build();
        relay.run().await.unwrap();

        let keys = Keys::generate();
        let client = Client::default();

        client
            .add_relay(relay.url().await)
            .and_connect()
            .await
            .unwrap();

        let event = EventBuilder::new(Kind::TextNote, "IDK")
            .tag(Tag::protected())
            .finalize(&keys)
            .unwrap();

        let repost = EventBuilder::new(Kind::Repost, event.as_json())
            .tag(event.id)
            .tag(Tag::public_key(event.pubkey))
            .finalize(&Keys::generate())
            .unwrap();

        let output = client.send_event(&repost).await.unwrap();
        assert!(output.success.is_empty());
        assert_eq!(
            "blocked: repost of a protected event",
            output.failed.values().next().unwrap()
        );
    }

    #[tokio::test]
    async fn test_max_filter_limit() {
        let relay = LocalRelay::builder()
            .database(MemoryDatabase::unbounded())
            .max_filter_limit(3)
            .build();
        relay.run().await.unwrap();

        let keys = Keys::generate();
        let client = Client::default();

        client
            .add_relay(relay.url().await)
            .and_connect()
            .await
            .unwrap();

        for i in 0..20 {
            client
                .send_event(
                    &EventBuilder::new(
                        if i % 2 == 1 {
                            Kind::TextNote
                        } else {
                            Kind::Comment
                        },
                        i.to_string(),
                    )
                    .finalize(&keys)
                    .unwrap(),
                )
                .await
                .unwrap();
        }

        let result = client
            .fetch_events([
                Filter::new().kind(Kind::TextNote),
                Filter::new().kind(Kind::Comment),
            ])
            .await
            .unwrap();

        assert_eq!(6, result.len(), "max result is 6");
        assert_eq!(
            3,
            result.iter().filter(|e| e.kind == Kind::TextNote).count()
        );
        assert_eq!(3, result.iter().filter(|e| e.kind == Kind::Comment).count());

        let mut stream = client
            .stream_events([Filter::new().ids([
                EventId::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                EventId::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap(),
                EventId::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000002",
                )
                .unwrap(),
                EventId::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000003",
                )
                .unwrap(),
            ])])
            .await
            .unwrap();

        let (_, res) = stream.next().await.unwrap();
        assert_eq!(
            res.unwrap_err(),
            Error::relay_msg(String::from("blocked: requested too many event IDs"))
        );
    }

    #[tokio::test]
    async fn test_max_req_filter_size() {
        let relay = LocalRelay::builder()
            .database(MemoryDatabase::unbounded())
            .max_filters_per_req(1)
            .build();
        relay.run().await.unwrap();

        let client = Client::default();

        client
            .add_relay(relay.url().await)
            .and_connect()
            .await
            .unwrap();

        let mut stream = client
            .stream_events([
                Filter::new().kind(Kind::TextNote),
                Filter::new().kind(Kind::Comment),
            ])
            .await
            .unwrap();

        let (_, res) = stream.next().await.unwrap();
        assert_eq!(
            res.unwrap_err(),
            Error::relay_msg(String::from("blocked: too many filters"))
        );
    }
}
