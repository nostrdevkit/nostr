//! Gossip test suite

pub extern crate tokio;

/// Macro to generate common gossip store tests.
#[macro_export]
macro_rules! gossip_unit_tests {
    ($store_type:ty, $setup_fn:expr) => {
        use nostr::prelude::*;
        use nostr_gossip::prelude::*;

        use $crate::tokio;

        #[tokio::test]
        async fn test_process_event() {
            let store: $store_type = $setup_fn().await;

            let json = r#"{"id":"b7b1fb52ad8461a03e949820ae29a9ea07e35bcd79c95c4b59b0254944f62805","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644581,"kind":1,"tags":[],"content":"Text note","sig":"ed73a8a4e7c26cd797a7b875c634d9ecb6958c57733305fed23b978109d0411d21b3e182cb67c8ad750884e30ca383b509382ae6187b36e76ee76e6a142c4284"}"#;
            let event = Event::from_json(json).unwrap();

            // First process
            store.process(&event, None).await.unwrap();

            // Re-process the same event
            store.process(&event, None).await.unwrap();
        }

        #[tokio::test]
        async fn test_process_nip65_relay_list() {
            let store: $store_type = $setup_fn().await;

            // NIP-65 relay list event with read and write relays
            let json = r#"{"id":"0a49bed4a1eb0973a68a0d43b7ca62781ffd4e052b91bbadef09e5cf756f6e68","pubkey":"68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","created_at":1759351841,"kind":10002,"tags":[["alt","Relay list to discover the user's content"],["r","wss://relay.damus.io/"],["r","wss://nostr.wine/"],["r","wss://nostr.oxtr.dev/"],["r","wss://relay.nostr.wirednet.jp/"]],"content":"","sig":"f5bc6c18b0013214588d018c9086358fb76a529aa10867d4d02a75feb239412ae1c94ac7c7917f6e6e2303d72f00dc4e9b03b168ef98f3c3c0dec9a457ce0304"}"#;
            let event = Event::from_json(json).unwrap();

            store.process(&event, None).await.unwrap();

            let public_key = event.pubkey;

            // Test Read selection
            let read_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Read { limit: 2 },
                    GossipAllowedRelays::default(),
                )
                .await.unwrap();

            assert_eq!(read_relays.len(), 2); // relay.damus.io and nos.lol

            // Test Write selection
            let write_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Write { limit: 2 },
                    GossipAllowedRelays::default(),
                )
                .await.unwrap();

            assert_eq!(write_relays.len(), 2); // relay.damus.io and relay.nostr.band
        }

        #[tokio::test]
        async fn test_process_nip17_inbox_relays() {
            let store: $store_type = $setup_fn().await;

            // NIP-17 inbox relays event
            let json = r#"{"id":"8d9b40907f80bd7d5014bdc6a2541227b92f4ae20cbff59792b4746a713da81e","pubkey":"68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","created_at":1756718818,"kind":10050,"tags":[["relay","wss://auth.nostr1.com/"],["relay","wss://nostr.oxtr.dev/"],["relay","wss://nip17.com"]],"content":"","sig":"05611df32f5c4e55bb8d74ab2840378b7707ad162f785a78f8bdaecee5b872667e4e43bcbbf3c6c638335c637f001155b48b7a7040ce2695660467be62f142d5"}"#;
            let event = Event::from_json(json).unwrap();

            store.process(&event, None).await.unwrap();

            let public_key = event.pubkey;

            // Test PrivateMessage selection
            let pm_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::PrivateMessage { limit: 4 },
                    GossipAllowedRelays::default(),
                )
                .await.unwrap();

            assert_eq!(pm_relays.len(), 3); // inbox.nostr.wine and relay.primal.net
        }

        #[tokio::test]
        async fn test_process_hints_from_p_tags() {
            let store: $store_type = $setup_fn().await;

            let public_key =
                PublicKey::parse("npub1drvpzev3syqt0kjrls50050uzf25gehpz9vgdw08hvex7e0vgfeq0eseet")
                    .unwrap();
            let relay_url = RelayUrl::parse("wss://hint.relay.io").unwrap();

            let keys = Keys::generate();
            let event = EventBuilder::new(Kind::TextNote).content("test")
                .tag(Tag::from(
                    Nip01Tag::PublicKey {
                        public_key,
                        relay_hint: Some(relay_url.clone()),
                    },
                ))
                .finalize(&keys)
                .unwrap();

            store.process(&event, None).await.unwrap();

            let hint_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Hints { limit: 5 },
                    GossipAllowedRelays::default(),
                )
                .await.unwrap();

            assert_eq!(hint_relays.len(), 1);
            assert!(hint_relays.iter().any(|r| r == &relay_url));
        }

        #[tokio::test]
        async fn test_received_events_tracking() {
            let store: $store_type = $setup_fn().await;

            let keys = Keys::generate();
            let relay_url = RelayUrl::parse("wss://test.relay.io").unwrap();

            // Process multiple events from the same relay
            for i in 0..5 {
                let event = EventBuilder::new(Kind::TextNote).content(format!("Test {i}"))
                    .finalize(&keys)
                    .unwrap();

                store.process(&event, Some(&relay_url)).await.unwrap();
            }

            // Test MostReceived selection
            let most_received = store
                .get_best_relays(
                    &keys.public_key(),
                    BestRelaySelection::MostReceived { limit: 10 },
                    GossipAllowedRelays::default(),
                )
                .await.unwrap();

            assert_eq!(most_received.len(), 1);
            assert!(most_received.iter().any(|r| r == &relay_url));
        }

        #[tokio::test]
        async fn test_best_relays_all_selection() {
            let store: $store_type = $setup_fn().await;

            let public_key =
                PublicKey::from_hex("68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272")
                    .unwrap();

            // Add NIP-65 relays
            let nip65_json = r#"{"id":"0000000000000000000000000000000000000000000000000000000000000000","pubkey":"68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","created_at":1704644581,"kind":10002,"tags":[["r","wss://read.relay.io","read"],["r","wss://write.relay.io","write"]],"content":"","sig":"f5bc6c18b0013214588d018c9086358fb76a529aa10867d4d02a75feb239412ae1c94ac7c7917f6e6e2303d72f00dc4e9b03b168ef98f3c3c0dec9a457ce0304"}"#;
            let nip65_event = Event::from_json(nip65_json).unwrap();
            store.process(&nip65_event, None).await.unwrap();

            // Add event with hints
            let hint_json = r#"{"id":"0000000000000000000000000000000000000000000000000000000000000001","pubkey":"bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644581,"kind":1,"tags":[["p","68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","wss://hint.relay.io"]],"content":"Hint","sig":"f5bc6c18b0013214588d018c9086358fb76a529aa10867d4d02a75feb239412ae1c94ac7c7917f6e6e2303d72f00dc4e9b03b168ef98f3c3c0dec9a457ce0304"}"#;
            let hint_event = Event::from_json(hint_json).unwrap();
            store.process(&hint_event, None).await.unwrap();

            // Add received events
            let relay_url = RelayUrl::parse("wss://received.relay.io").unwrap();
            let received_json = r#"{"id":"0000000000000000000000000000000000000000000000000000000000000002","pubkey":"68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","created_at":1704644581,"kind":1,"tags":[],"content":"Received","sig":"f5bc6c18b0013214588d018c9086358fb76a529aa10867d4d02a75feb239412ae1c94ac7c7917f6e6e2303d72f00dc4e9b03b168ef98f3c3c0dec9a457ce0304"}"#;
            let received_event = Event::from_json(received_json).unwrap();
            store
                .process(&received_event, Some(&relay_url))
                .await
                .unwrap();

            // Test All selection
            let all_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::All {
                        read: 5,
                        write: 5,
                        hints: 5,
                        most_received: 5,
                    },
                    GossipAllowedRelays::default(),
                )
                .await.unwrap();

            // Should have relays from all categories (duplicates removed by HashSet)
            assert!(all_relays.len() >= 3);
            assert!(all_relays
                .iter()
                .any(|r| r.as_str() == "wss://read.relay.io"));
            assert!(all_relays
                .iter()
                .any(|r| r.as_str() == "wss://write.relay.io"));
            assert!(all_relays
                .iter()
                .any(|r| r.as_str() == "wss://hint.relay.io"));
            assert!(all_relays
                .iter()
                .any(|r| r.as_str() == "wss://received.relay.io"));
        }

        #[tokio::test]
        async fn test_selection_with_allowed_relays() {
            let store: $store_type = $setup_fn().await;

            // NIP-65 relay list event with read and write relays
            let json = r#"{"id":"0a49bed4a1eb0973a68a0d43b7ca62781ffd4e052b91bbadef09e5cf756f6e68","pubkey":"68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","created_at":1759351841,"kind":10002,"tags":[["alt","Relay list to discover the user's content"],["r","wss://relay.damus.io/"],["r","ws://192.168.1.11:7777"],["r","ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion"]],"content":"","sig":"f5bc6c18b0013214588d018c9086358fb76a529aa10867d4d02a75feb239412ae1c94ac7c7917f6e6e2303d72f00dc4e9b03b168ef98f3c3c0dec9a457ce0304"}"#;
            let event = Event::from_json(json).unwrap();

            store.process(&event, None).await.unwrap();

            let public_key = event.pubkey;
            let damus_relay = RelayUrl::parse("wss://relay.damus.io").unwrap();
            let local_relay = RelayUrl::parse("ws://192.168.1.11:7777").unwrap();
            let oxtr_relay =
                RelayUrl::parse("ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion")
                    .unwrap();

            // Test selection with all relays
            let read_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Read { limit: u8::MAX },
                    GossipAllowedRelays {
                        onion: true,
                        local: true,
                        without_tls: true,
                    },
                )
                .await.unwrap();

            assert_eq!(read_relays.len(), 3);
            assert!(read_relays.contains(&damus_relay));
            assert!(read_relays.contains(&local_relay));
            assert!(read_relays.contains(&oxtr_relay));

            // Test selection without local relays
            let read_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Read { limit: u8::MAX },
                    GossipAllowedRelays {
                        onion: true,
                        local: false,
                        without_tls: true,
                    },
                )
                .await.unwrap();

            assert_eq!(read_relays.len(), 2);
            assert!(read_relays.contains(&damus_relay));
            assert!(read_relays.contains(&oxtr_relay));

            // Test selection without onion and local relays
            let read_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Read { limit: u8::MAX },
                    GossipAllowedRelays {
                        onion: false,
                        local: true,
                        without_tls: true,
                    },
                )
                .await.unwrap();

            assert_eq!(read_relays.len(), 2);
            assert!(read_relays.contains(&damus_relay));
            assert!(read_relays.contains(&local_relay));

            // Test selection TLS-only relays
            let read_relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Read { limit: u8::MAX },
                    GossipAllowedRelays {
                        onion: true,
                        local: true,
                        without_tls: false,
                    },
                )
                .await.unwrap();

            assert_eq!(read_relays.len(), 1);
            assert!(read_relays.contains(&damus_relay));
        }

        #[tokio::test]
        async fn test_status_tracking() {
            let store: $store_type = $setup_fn().await;

            let public_key =
                PublicKey::from_hex("68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272")
                    .unwrap();

            // Initially both lists should be missing
            let status = store.status(&public_key, GossipListKind::Nip65).await.unwrap();
            assert!(status.is_missing());

            let status = store.status(&public_key, GossipListKind::Nip17).await.unwrap();
            assert!(status.is_missing());

            // Process a NIP-65 event
            let json = r#"{"id":"0a49bed4a1eb0973a68a0d43b7ca62781ffd4e052b91bbadef09e5cf756f6e68","pubkey":"68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272","created_at":1759351841,"kind":10002,"tags":[["alt","Relay list to discover the user's content"],["r","wss://relay.damus.io/"],["r","wss://nostr.wine/"],["r","wss://nostr.oxtr.dev/"],["r","wss://relay.nostr.wirednet.jp/"]],"content":"","sig":"f5bc6c18b0013214588d018c9086358fb76a529aa10867d4d02a75feb239412ae1c94ac7c7917f6e6e2303d72f00dc4e9b03b168ef98f3c3c0dec9a457ce0304"}"#;
            let event = Event::from_json(json).unwrap();
            store.process(&event, None).await.unwrap();

            // Processing a list event doesn't imply a fetch attempt was tracked yet
            let status = store.status(&public_key, GossipListKind::Nip65).await.unwrap();
            assert!(status.is_missing());

            // Update fetch attempt
            store
                .update_fetch_attempt(&public_key, GossipListKind::Nip65)
                .await.unwrap();

            // NIP-65 should now be updated, NIP-17 should still be missing
            let status = store.status(&public_key, GossipListKind::Nip65).await.unwrap();
            assert!(status.is_updated());

            let status = store.status(&public_key, GossipListKind::Nip17).await.unwrap();
            assert!(status.is_missing());
        }

        #[tokio::test]
        async fn test_empty_results() {
            let store: $store_type = $setup_fn().await;

            // Random public key with no data
            let public_key =
                PublicKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap();

            // Should return empty set
            let relays = store
                .get_best_relays(
                    &public_key,
                    BestRelaySelection::Read { limit: 10 },
                    GossipAllowedRelays::default(),
                )
                .await.unwrap();

            assert_eq!(relays.len(), 0);
        }
    };
}
