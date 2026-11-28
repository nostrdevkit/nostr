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
    use std::collections::BTreeSet;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::time::Duration;

    use async_wsocket::{ConnectionMode, Message, Url, WebSocket};
    use futures::{SinkExt, StreamExt};
    use negentropy::{Negentropy, NegentropyStorageVector};
    use nostr::event::{Event, EventBuilder, EventId, FinalizeEvent, Kind};
    use nostr::filter::Filter;
    use nostr::key::{Keys, PublicKey};
    use nostr::message::{MachineReadablePrefix, RelayMessage};
    use nostr::nips::nip17::PrivateDirectMessageBuilder;
    use nostr::nips::nip70::Nip70Tag;
    use nostr::types::RelayUrl;
    use nostr_memory::MemoryDatabase;
    use tokio::time;

    use super::*;
    use crate::authenticator::SignerAuthenticator;
    use crate::client::Client;
    use crate::error::{Error, ErrorKind};
    use crate::relay::Relay;

    const UPDATE_TAG: &str = "updated";

    #[derive(Debug)]
    struct RejectQueries;

    impl QueryPolicy for RejectQueries {
        fn admit_query<'a>(
            &'a self,
            _query: &'a mut Filter,
            _addr: &'a SocketAddr,
        ) -> Pin<Box<dyn Future<Output = QueryPolicyResult> + Send + 'a>> {
            Box::pin(async {
                QueryPolicyResult::reject(MachineReadablePrefix::Blocked, "query rejected")
            })
        }
    }

    #[derive(Debug)]
    struct UpdateFilterPlugin;

    impl QueryPolicy for UpdateFilterPlugin {
        fn admit_query<'a>(
            &'a self,
            query: &'a mut Filter,
            _addr: &'a SocketAddr,
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
        let event = EventBuilder::new(Kind::TextNote)
            .content(":)")
            .tag(["t", UPDATE_TAG])
            .finalize(&keys)
            .unwrap();
        client.send_event(&event).await.unwrap();

        // This event has a random tag and should be filtered out in the REQ.
        // It would only appear if the filter had not been updated correctly.
        let event = EventBuilder::new(Kind::TextNote)
            .content(":)")
            .tag(["t", "TEST"])
            .finalize(&keys)
            .unwrap();
        client.send_event(&event).await.unwrap();

        // Empty filter to get all events. It should be updated to have `UPDATE_TAG`
        let stream = client.stream_events(Filter::new()).await.unwrap();
        let events: BTreeSet<Event> = stream
            .filter_map(|(_, event)| async { event.ok() })
            .collect()
            .await;

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
        let event = EventBuilder::new(Kind::TextNote)
            .content(":)")
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
            .extra_tags([PublicKey::from_slice(&[0; 32]).unwrap()])
            .finalize(&keys)
            .unwrap();
        let output = client.send_event(&event).await.unwrap();

        assert_eq!(
            "blocked: GiftWrap must contain exactly one recipient public key",
            output.failed.values().next().unwrap()
        );

        let event = EventBuilder::new(Kind::GiftWrap)
            .content("Hey")
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

        let base_event_size = EventBuilder::new(Kind::TextNote)
            .content("")
            .finalize(&keys)
            .unwrap()
            .as_json()
            .len();

        let equal_max_size = EventBuilder::new(Kind::TextNote)
            .content(".".repeat(MAX_SIZE - base_event_size))
            .finalize(&keys)
            .unwrap();
        let greater_max_size = EventBuilder::new(Kind::TextNote)
            .content(".".repeat((MAX_SIZE - base_event_size) + 1))
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

        let event = EventBuilder::new(Kind::TextNote)
            .content("IDK")
            .tag(Nip70Tag::Protected)
            .finalize(&keys)
            .unwrap();

        let repost = EventBuilder::new(Kind::Repost)
            .content(event.as_json())
            .tag(event.id)
            .tag(event.pubkey)
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
                    &EventBuilder::new(if i % 2 == 1 {
                        Kind::TextNote
                    } else {
                        Kind::Comment
                    })
                    .content(i.to_string())
                    .finalize(&keys)
                    .unwrap(),
                )
                .await
                .unwrap();
        }

        let stream = client
            .stream_events([
                Filter::new().kind(Kind::TextNote),
                Filter::new().kind(Kind::Comment),
            ])
            .await
            .unwrap();
        let result: BTreeSet<Event> = stream
            .filter_map(|(_, event)| async { event.ok() })
            .collect()
            .await;

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

    #[tokio::test]
    async fn add_event_rejects_unverified_events() {
        let relay = LocalRelay::new();
        let keys = Keys::generate();
        let mut event = EventBuilder::new(Kind::TextNote)
            .content("original")
            .finalize(&keys)
            .unwrap();
        event.content = String::from("forged");

        let err = relay.add_event(event).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol);
    }

    #[test]
    fn notify_event_rejects_unverified_events() {
        let relay = LocalRelay::new();
        let keys = Keys::generate();
        let mut event = EventBuilder::new(Kind::TextNote)
            .content("original")
            .finalize(&keys)
            .unwrap();
        event.content = String::from("forged");

        assert!(!relay.notify_event(event));
    }

    #[tokio::test]
    async fn test_malformed_client_message_does_not_close_connection() {
        let relay = LocalRelay::new();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();

        socket
            .send(Message::Text(
                r#"["REQ","short-author",{"authors":["deadbeef"]}]"#.into(),
            ))
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["REQ","valid",{}]"#.into()))
            .await
            .unwrap();

        time::timeout(Duration::from_secs(1), async {
            let mut received_notice = false;

            loop {
                let message = socket
                    .next()
                    .await
                    .expect("WebSocket connection terminated")
                    .unwrap();

                if let Message::Text(json) = message {
                    match RelayMessage::from_json(json.as_bytes()).unwrap() {
                        RelayMessage::Notice(..) => received_notice = true,
                        RelayMessage::EndOfStoredEvents {
                            subscription_id, ..
                        } if subscription_id.as_str() == "valid" => {
                            assert!(received_notice);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for EOSE");
    }

    #[tokio::test]
    async fn test_malformed_negentropy_messages_do_not_close_connection() {
        let relay = LocalRelay::new();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();

        socket
            .send(Message::Text(r#"["NEG-OPEN","neg-odd",{},"abc"]"#.into()))
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["NEG-OPEN","neg-nonhex",{},"zz"]"#.into()))
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["NEG-MSG","neg-msg","abc"]"#.into()))
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["REQ","valid",{}]"#.into()))
            .await
            .unwrap();

        time::timeout(Duration::from_secs(1), async {
            let mut neg_errors: usize = 0;

            loop {
                let message = socket
                    .next()
                    .await
                    .expect("WebSocket connection terminated")
                    .unwrap();

                if let Message::Text(json) = message {
                    match RelayMessage::from_json(json.as_bytes()).unwrap() {
                        RelayMessage::NegErr { message, .. } => {
                            assert_eq!(message, "error: invalid negentropy message");
                            neg_errors += 1;
                        }
                        RelayMessage::EndOfStoredEvents {
                            subscription_id, ..
                        } if subscription_id.as_str() == "valid" => {
                            assert_eq!(neg_errors, 3);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for EOSE");
    }

    #[tokio::test]
    async fn test_invalid_neg_msg_terminates_only_the_negentropy_subscription() {
        let relay = LocalRelay::new();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();

        // Open a valid negentropy subscription
        let mut storage = NegentropyStorageVector::new();
        storage.seal().unwrap();
        let mut negentropy = Negentropy::owned(storage, 60_000).unwrap();
        let initial_message = faster_hex::hex_string(&negentropy.initiate().unwrap());
        socket
            .send(Message::Text(
                format!(r#"["NEG-OPEN","neg",{{}},"{initial_message}"]"#).into(),
            ))
            .await
            .unwrap();

        let reply = socket.next().await.unwrap().unwrap();
        let Message::Text(reply) = reply else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(reply.as_bytes()).unwrap(),
            RelayMessage::NegMsg { .. }
        ));

        // A malformed payload must terminate only this negentropy subscription
        socket
            .send(Message::Text(r#"["NEG-MSG","neg","zz"]"#.into()))
            .await
            .unwrap();

        let neg_err = socket.next().await.unwrap().unwrap();
        let Message::Text(neg_err) = neg_err else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(neg_err.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "neg"
                && message == "error: invalid negentropy message"
        ));

        // The subscription is gone, but the connection keeps serving requests
        socket
            .send(Message::Text(r#"["NEG-MSG","neg","6100"]"#.into()))
            .await
            .unwrap();

        let neg_err = socket.next().await.unwrap().unwrap();
        let Message::Text(neg_err) = neg_err else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(neg_err.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "neg"
                && message == "error: subscription not found"
        ));

        socket
            .send(Message::Text(r#"["REQ","valid",{}]"#.into()))
            .await
            .unwrap();

        let eose = socket.next().await.unwrap().unwrap();
        let Message::Text(eose) = eose else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(eose.as_bytes()).unwrap(),
            RelayMessage::EndOfStoredEvents { subscription_id, .. }
                if subscription_id.as_str() == "valid"
        ));
    }

    #[tokio::test]
    async fn test_nip42_read_auth_is_required_for_count() {
        let relay = LocalRelay::builder()
            .nip42(LocalRelayBuilderNip42::read())
            .build();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["COUNT","count",{}]"#.into()))
            .await
            .unwrap();

        let auth = socket.next().await.unwrap().unwrap();
        let Message::Text(auth) = auth else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(auth.as_bytes()).unwrap(),
            RelayMessage::Auth { .. }
        ));

        let closed = socket.next().await.unwrap().unwrap();
        let Message::Text(closed) = closed else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(closed.as_bytes()).unwrap(),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == "count"
                && message.starts_with("auth-required:")
        ));
    }

    #[tokio::test]
    async fn test_nip42_read_auth_is_required_for_negentropy() {
        let relay = LocalRelay::builder()
            .nip42(LocalRelayBuilderNip42::read())
            .build();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["NEG-OPEN","neg",{},""]"#.into()))
            .await
            .unwrap();

        let auth = socket.next().await.unwrap().unwrap();
        let Message::Text(auth) = auth else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(auth.as_bytes()).unwrap(),
            RelayMessage::Auth { .. }
        ));

        let neg_err = socket.next().await.unwrap().unwrap();
        let Message::Text(neg_err) = neg_err else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(neg_err.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "neg"
                && message.starts_with("auth-required:")
        ));
    }

    #[tokio::test]
    async fn test_nip42_read_auth_is_required_for_gift_wraps_when_auth_dm_enabled() {
        let relay = LocalRelay::builder().auth_dm(true).build();
        relay.run().await.unwrap();

        let receiver = Keys::generate();
        let sender = Keys::generate();
        let other = Keys::generate();

        let event = PrivateDirectMessageBuilder::new(receiver.public_key(), "Testing")
            .finalize(&sender)
            .unwrap();
        relay.add_event(event.clone()).await.unwrap();

        let url: RelayUrl = relay.url().await;

        // A client without an authenticator
        let unauth_client = Relay::new(url.clone());
        unauth_client.connect();

        // A client with other authenticator
        let other_auth_client = Relay::builder(url.clone())
            .authenticator(SignerAuthenticator::new(other.clone()))
            .build();
        other_auth_client.connect();

        // A client with the right authenticator
        let auth_client = Relay::builder(url)
            .authenticator(SignerAuthenticator::new(receiver.clone()))
            .build();
        auth_client.connect();

        // Attempt to request the events by p tag and kind...
        let filter: Filter = Filter::new()
            .pubkey(receiver.public_key())
            .kind(Kind::GiftWrap);
        // ...with unauth client
        let received = unauth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(
            received,
            Some(Err(Error::with_static_message(
                ErrorKind::Rejected,
                "auth-required: you must auth"
            )))
        );
        // ...with the other auth client
        let received = other_auth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(
            received,
            Some(Err(Error::with_static_message(
                ErrorKind::Rejected,
                "error: you cannot request another user's gift wrap"
            )))
        );
        // ...with the right auth client
        let received = auth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(received, Some(Ok(event.clone())));

        // Attempt to request the events by p tag without kind...
        let filter: Filter = Filter::new().pubkey(receiver.public_key());
        // ...with unauth client
        let received = unauth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(
            received,
            Some(Err(Error::with_static_message(
                ErrorKind::Rejected,
                "auth-required: you must auth"
            )))
        );
        // ...with the other auth client
        let received = other_auth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(
            received,
            Some(Err(Error::with_static_message(
                ErrorKind::Rejected,
                "error: you cannot request another user's gift wrap"
            )))
        );
        // ...with the right auth client
        let received = auth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(received, Some(Ok(event.clone())));

        // Attempt to request the events by p tag with empty kinds...
        let filter: Filter = Filter::new().pubkey(receiver.public_key()).kinds([]);
        // ...with unauth client
        let received = unauth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(
            received,
            Some(Err(Error::with_static_message(
                ErrorKind::Rejected,
                "auth-required: you must auth"
            )))
        );
        // ...with the other auth client
        let received = other_auth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(
            received,
            Some(Err(Error::with_static_message(
                ErrorKind::Rejected,
                "error: you cannot request another user's gift wrap"
            )))
        );
        // ...with the right auth client
        let received = auth_client
            .stream_events(filter.clone())
            .await
            .unwrap()
            .next()
            .await;
        assert_eq!(received, Some(Ok(event.clone())));
    }

    #[tokio::test]
    async fn test_query_policy_is_applied_to_count_and_negentropy() {
        let relay = LocalRelay::builder().query_policy(RejectQueries).build();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["COUNT","count",{}]"#.into()))
            .await
            .unwrap();

        let closed = socket.next().await.unwrap().unwrap();
        let Message::Text(closed) = closed else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(closed.as_bytes()).unwrap(),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == "count"
                && message == "blocked: query rejected"
        ));

        socket
            .send(Message::Text(r#"["NEG-OPEN","neg",{},""]"#.into()))
            .await
            .unwrap();

        let neg_err = socket.next().await.unwrap().unwrap();
        let Message::Text(neg_err) = neg_err else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(neg_err.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "neg"
                && message == "blocked: query rejected"
        ));
    }

    #[tokio::test]
    async fn test_negentropy_subscription_limit() {
        let relay = LocalRelay::builder()
            .max_negentropy_subscriptions(0)
            .build();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["NEG-OPEN","neg",{},""]"#.into()))
            .await
            .unwrap();

        let neg_err = socket.next().await.unwrap().unwrap();
        let Message::Text(neg_err) = neg_err else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(neg_err.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "neg"
                && message.starts_with("rate-limited:")
        ));
    }

    #[tokio::test]
    async fn test_subscription_id_limit_counts_utf8_bytes() {
        let relay = LocalRelay::builder().max_subid_length(3).build();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["NEG-OPEN","éé",{},""]"#.into()))
            .await
            .unwrap();

        let neg_err = socket.next().await.unwrap().unwrap();
        let Message::Text(neg_err) = neg_err else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(neg_err.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "éé"
                && message == "blocked: subscription ID exceeds max length 3"
        ));
    }

    #[tokio::test]
    async fn test_negentropy_item_limit() {
        let relay = LocalRelay::builder().max_negentropy_items(2).build();
        let keys = Keys::generate();
        for i in 0..3 {
            relay
                .add_event(
                    EventBuilder::new(Kind::TextNote)
                        .content(i.to_string())
                        .finalize(&keys)
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();
        socket
            .send(Message::Text(r#"["NEG-OPEN","neg",{},""]"#.into()))
            .await
            .unwrap();

        let neg_err = socket.next().await.unwrap().unwrap();
        let Message::Text(neg_err) = neg_err else {
            panic!("unexpected websocket message");
        };
        assert!(matches!(
            RelayMessage::from_json(neg_err.as_bytes()).unwrap(),
            RelayMessage::NegErr {
                subscription_id,
                message,
            } if subscription_id.as_str() == "neg"
                && message == "rate-limited: too many negentropy items"
        ));
    }

    #[tokio::test]
    async fn test_default_message_limit_allows_301_protocol_frames() {
        let relay = LocalRelay::new();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();

        time::timeout(Duration::from_secs(5), async {
            for _ in 0..301 {
                socket
                    .send(Message::Text(r#"["CLOSE","harmless"]"#.into()))
                    .await
                    .unwrap();
            }
            socket
                .send(Message::Text(r#"["REQ","valid",{}]"#.into()))
                .await
                .unwrap();

            let eose = socket.next().await.unwrap().unwrap();
            assert!(matches!(
                eose,
                Message::Text(json)
                    if matches!(
                        RelayMessage::from_json(json.as_bytes()).unwrap(),
                        RelayMessage::EndOfStoredEvents { subscription_id, .. }
                            if subscription_id.as_str() == "valid"
                    )
            ));
        })
        .await
        .expect("timed out waiting for EOSE after 301 harmless frames");
    }

    #[tokio::test]
    async fn test_default_message_limit_closes_rapid_burst_over_6000_frames() {
        let relay = LocalRelay::new();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();

        time::timeout(Duration::from_secs(5), async {
            for _ in 0..6_001 {
                socket
                    .send(Message::Text(r#"["CLOSE","harmless"]"#.into()))
                    .await
                    .unwrap();
            }

            let closed = socket.next().await;
            assert!(matches!(
                closed,
                None | Some(Ok(Message::Close(..))) | Some(Err(..))
            ));
        })
        .await
        .expect("connection did not close after 6,001 rapid frames");
    }

    #[tokio::test]
    async fn test_configured_message_limit_is_exact_for_binary_frames() {
        let relay = LocalRelay::builder().messages_per_minute(3).build();
        relay.run().await.unwrap();

        let url = Url::parse(relay.url().await.as_str()).unwrap();
        let mut socket = WebSocket::connect(&url, &ConnectionMode::direct())
            .await
            .unwrap();

        time::timeout(Duration::from_secs(5), async {
            for byte in 1..=3 {
                let bytes: Vec<u8> = vec![byte];
                socket.send(Message::Binary(bytes.into())).await.unwrap();
                let notice = socket.next().await.unwrap().unwrap();
                assert!(matches!(
                    notice,
                    Message::Text(json)
                        if matches!(
                            RelayMessage::from_json(json.as_bytes()).unwrap(),
                            RelayMessage::Notice(..)
                        )
                ));
            }

            let bytes: &[u8] = &[4];
            socket.send(Message::Binary(bytes.into())).await.unwrap();
            let closed = socket.next().await;
            assert!(matches!(
                closed,
                None | Some(Ok(Message::Close(..))) | Some(Err(..))
            ));
        })
        .await
        .expect("connection did not enforce the configured three-frame limit");
    }
}
