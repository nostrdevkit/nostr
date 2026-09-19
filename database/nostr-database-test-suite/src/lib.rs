//! Database test suite

pub extern crate tokio;

/// Macro to generate common database store tests.
#[macro_export]
macro_rules! database_unit_tests {
    ($store_type:ty, $setup_fn:expr, $setup_with_relay_url:expr) => {
        use std::collections::{BTreeSet, HashSet};
        use std::ops::Deref;
        use std::time::Duration;

        use nostr::prelude::*;
        use nostr_database::prelude::*;

        use $crate::tokio::{self, time};

        const EVENTS: [&str; 14] = [
            r#"{"id":"b7b1fb52ad8461a03e949820ae29a9ea07e35bcd79c95c4b59b0254944f62805","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644581,"kind":1,"tags":[],"content":"Text note","sig":"ed73a8a4e7c26cd797a7b875c634d9ecb6958c57733305fed23b978109d0411d21b3e182cb67c8ad750884e30ca383b509382ae6187b36e76ee76e6a142c4284"}"#,
            r#"{"id":"7296747d91c53f1d71778ef3e12d18b66d494a41f688ef244d518abf37c959b6","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644586,"kind":32121,"tags":[["d","id-1"]],"content":"Empty 1","sig":"8848989a8e808f7315e950f871b231c1dff7752048f8957d4a541881d2005506c30e85c7dd74dab022b3e01329c88e69c9d5d55d961759272a738d150b7dbefc"}"#,
            r#"{"id":"ec6ea04ba483871062d79f78927df7979f67545b53f552e47626cb1105590442","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644591,"kind":32122,"tags":[["d","id-1"]],"content":"Empty 2","sig":"89946113a97484850fe35fefdb9120df847b305de1216dae566616fe453565e8707a4da7e68843b560fa22a932f81fc8db2b5a2acb4dcfd3caba9a91320aac92"}"#,
            r#"{"id":"63b8b829aa31a2de870c3a713541658fcc0187be93af2032ec2ca039befd3f70","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644596,"kind":32122,"tags":[["d","id-2"]],"content":"","sig":"607b1a67bef57e48d17df4e145718d10b9df51831d1272c149f2ab5ad4993ae723f10a81be2403ae21b2793c8ed4c129e8b031e8b240c6c90c9e6d32f62d26ff"}"#,
            r#"{"id":"6fe9119c7db13ae13e8ecfcdd2e5bf98e2940ba56a2ce0c3e8fba3d88cd8e69d","pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","created_at":1704644601,"kind":32122,"tags":[["d","id-3"]],"content":"","sig":"d07146547a726fc9b4ec8d67bbbe690347d43dadfe5d9890a428626d38c617c52e6945f2b7144c4e0c51d1e2b0be020614a5cadc9c0256b2e28069b70d9fc26e"}"#,
            r#"{"id":"a82f6ebfc709f4e7c7971e6bf738e30a3bc112cfdb21336054711e6779fd49ef","pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","created_at":1704644606,"kind":32122,"tags":[["d","id-1"]],"content":"","sig":"96d3349b42ed637712b4d07f037457ab6e9180d58857df77eb5fa27ff1fd68445c72122ec53870831ada8a4d9a0b484435f80d3ff21a862238da7a723a0d073c"}"#,
            r#"{"id":"8ab0cb1beceeb68f080ec11a3920b8cc491ecc7ec5250405e88691d733185832","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644611,"kind":32122,"tags":[["d","id-1"]],"content":"Test","sig":"49153b482d7110e2538eb48005f1149622247479b1c0057d902df931d5cea105869deeae908e4e3b903e3140632dc780b3f10344805eab77bb54fb79c4e4359d"}"#,
            r#"{"id":"63dc49a8f3278a2de8dc0138939de56d392b8eb7a18c627e4d78789e2b0b09f2","pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","created_at":1704644616,"kind":5,"tags":[["a","32122:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:"]],"content":"","sig":"977e54e5d57d1fbb83615d3a870037d9eb5182a679ca8357523bbf032580689cf481f76c88c7027034cfaf567ba9d9fe25fc8cd334139a0117ad5cf9fe325eef"}"#,
            r#"{"id":"6975ace0f3d66967f330d4758fbbf45517d41130e2639b54ca5142f37757c9eb","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704644621,"kind":5,"tags":[["a","32122:aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4:id-2"]],"content":"","sig":"9bb09e4759899d86e447c3fa1be83905fe2eda74a5068a909965ac14fcdabaed64edaeb732154dab734ca41f2fc4d63687870e6f8e56e3d9e180e4a2dd6fb2d2"}"#,
            r#"{"id":"33f5b4e6a38e107638c20f4536db35191d4b8651ba5a2cefec983b9ec2d65084","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704645586,"kind":0,"tags":[],"content":"{\"name\":\"Key A\"}","sig":"285d090f45a6adcae717b33771149f7840a8c27fb29025d63f1ab8d95614034a54e9f4f29cee9527c4c93321a7ebff287387b7a19ba8e6f764512a40e7120429"}"#,
            r#"{"id":"90a761aec9b5b60b399a76826141f529db17466deac85696a17e4a243aa271f9","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704645606,"kind":0,"tags":[],"content":"{\"name\":\"key-a\",\"display_name\":\"Key A\",\"lud16\":\"keya@ln.address\"}","sig":"ec8f49d4c722b7ccae102d49befff08e62db775e5da43ef51b25c47dfdd6a09dc7519310a3a63cbdb6ec6b3250e6f19518eb47be604edeb598d16cdc071d3dbc"}"#,
            r#"{"id":"a295422c636d3532875b75739e8dae3cdb4dd2679c6e4994c9a39c7ebf8bc620","pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","created_at":1704646569,"kind":5,"tags":[["e","90a761aec9b5b60b399a76826141f529db17466deac85696a17e4a243aa271f9"]],"content":"","sig":"d4dc8368a4ad27eef63cacf667345aadd9617001537497108234fc1686d546c949cbb58e007a4d4b632c65ea135af4fbd7a089cc60ab89b6901f5c3fc6a47b29"}"#, // Invalid event deletion
            r#"{"id":"999e3e270100d7e1eaa98fcfab4a98274872c1f2dfdab024f32e42a5a12d5b5e","pubkey":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","created_at":1704646606,"kind":5,"tags":[["e","90a761aec9b5b60b399a76826141f529db17466deac85696a17e4a243aa271f9"]],"content":"","sig":"4f3a33fd52784cea7ca8428fd35d94d65049712e9aa11a70b1a16a1fcd761c7b7e27afac325728b1c00dfa11e33e78b2efd0430a7e4b28f4ede5b579b3f32614"}"#,
            r#"{"id":"99a022e6d61c4e39c147d08a2be943b664e8030c0049325555ac1766429c2832","pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","created_at":1705241093,"kind":30333,"tags":[["d","multi-id"],["p","aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4"]],"content":"Multi-tags","sig":"0abfb2b696a7ed7c9e8e3bf7743686190f3f1b3d4045b72833ab6187c254f7ed278d289d52dfac3de28be861c1471421d9b1bfb5877413cbc81c84f63207a826"}"#,
        ];

        fn decode_events() -> Vec<Event> {
            EVENTS
                .iter()
                .map(|e| Event::from_json(e).expect("Failed to parse event"))
                .collect()
        }

        fn build_event<T>(keys: &Keys, builder: T) -> Event
        where
            T: FinalizeEvent<Keys>
        {
            builder.finalize(keys).expect("Failed to build and finalize event")
        }

        // Return the number of added events
        async fn add_random_events(store: &$store_type) -> usize {
            let keys_a = Keys::generate();
            let keys_b = Keys::generate();

            let events = vec![
                build_event(&keys_a, EventBuilder::new(Kind::TextNote, "Text Note A")),
                build_event(&keys_b, EventBuilder::new(Kind::TextNote, "Text Note B")),
                build_event(&keys_a, Metadata::new().name("account-a").display_name("Account A")),
                build_event(&keys_b, Metadata::new().name("account-b").display_name("Account B")),
                build_event(&keys_a, EventBuilder::new(Kind::Custom(33_333), "")
                    .tag(Tag::identifier("my-id-a"))),
                build_event(&keys_b, EventBuilder::new(Kind::Custom(33_333), "")
                    .tag(Tag::identifier("my-id-b"))),
            ];

            // Store
            for event in events.iter() {
                store.save_event(event).await.expect("Failed to save event");
            }

            events.len()
        }

        async fn add_event(store: &$store_type, builder: EventBuilder) -> (Keys, Event) {
            let keys = Keys::generate();
            let (event, ..) = add_event_with_keys(store, builder, &keys).await;
            (keys, event)
        }

        async fn add_event_with_keys(
            store: &$store_type,
            builder: EventBuilder,
            keys: &Keys,
        ) -> (Event, SaveEventStatus) {
            let event = builder.finalize(keys).expect("Failed to finalize event");
            let status = store.save_event(&event).await.expect("Failed to save event");
            (event, status)
        }

        async fn get_event_by_id(store: &$store_type, id: &EventId) -> Option<Event> {
            store.event_by_id(id).await.expect("Failed to get event by ID")
        }

        async fn get_existent_event_by_id(store: &$store_type, id: &EventId) -> Event {
            get_event_by_id(store, id).await.expect("Expected event to exist")
        }

        async fn count_all(store: &$store_type) -> usize {
            store.count(Filter::new()).await.expect("Failed to count events")
        }

        async fn dummy_nip62(store: &$store_type) -> Keys {
            let to_vanish = Keys::generate();
            let helper = Keys::generate();

            let event1 = EventBuilder::new(Kind::TextNote, "Hi 1")
                .finalize(&to_vanish)
                .unwrap();
            let event2 = EventBuilder::new(Kind::TextNote, "Hi 2")
                .finalize(&to_vanish)
                .unwrap();
            let replaceable = ContactListBuilder::new([
                Contact::new(Keys::generate().public_key()),
                Contact::new(Keys::generate().public_key()),
            ])
            .finalize(&to_vanish)
            .unwrap();
            let addresable = EventBuilder::new(Kind::LongFormTextNote, "LONG")
                .tag(Tag::identifier("lorem-ipsum".to_string()))
                .finalize(&to_vanish)
                .unwrap();
            let dummy_gift_wrap = EventBuilder::new(Kind::GiftWrap, ":)")
                .tag(to_vanish.public_key())
                .finalize(&helper)
                .unwrap();

            store.save_event(&event1).await.unwrap();
            store.save_event(&event2).await.unwrap();
            store.save_event(&replaceable).await.unwrap();
            store.save_event(&addresable).await.unwrap();
            store.save_event(&dummy_gift_wrap).await.unwrap();

            // Make sure the event are there
            assert_eq!(
                store
                    .count(Filter::new().author(to_vanish.public_key()))
                    .await
                    .unwrap(),
                4
            );
            assert_eq!(
                store
                    .count(
                        Filter::new()
                            .kind(Kind::GiftWrap)
                            .pubkey(to_vanish.public_key())
                    )
                    .await
                    .unwrap(),
                1
            );
            to_vanish
        }

        #[tokio::test]
        async fn test_save_and_query() {
            let store: $store_type = $setup_fn().await;
            let events = decode_events();

            // Save all events (some will be rejected due to invalid deletions)
            for (i, event) in events.iter().enumerate() {
                let status = store.save_event(event).await.expect("Failed to save event");
                if i == 7 || i == 11 {
                    // These should be rejected for invalid deletions
                    assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::InvalidDelete));
                } else {
                    assert_eq!(status, SaveEventStatus::Success);
                }

                // NOTE: Sleep prevents automatic batching - events in the same batch share
                // a database snapshot and can't see each other's changes. Deletion events
                // (7,11) must "see" target events, and replaceable events must observe
                // earlier events to replace them. Sleep forces sequential processing.
                // Use this pattern when event N must observe changes from event N-1.
                time::sleep(Duration::from_millis(10)).await;
            }

            // Query all events
            let saved_events = store.query(Filter::new()).await.expect("Failed to query");
            // Expected: 8 events after applying coordinate deletion validation
            assert_eq!(saved_events.len(), 8);
        }

        #[tokio::test]
        async fn test_save_duplicate() {
            let store: $store_type = $setup_fn().await;
            let events = decode_events();
            let event = &events[0];

            // Save event first time
            let status = store.save_event(event).await.expect("Failed to save event");
            assert_eq!(status, SaveEventStatus::Success);

            // Try to save again
            let status = store.save_event(event).await.expect("Failed to save event");
            assert_eq!(
                status,
                SaveEventStatus::Rejected(nostr_database::RejectedReason::Duplicate)
            );
        }

        #[tokio::test]
        async fn test_query_by_filter() {
            let store: $store_type = $setup_fn().await;
            let events = decode_events();

            // Save all events
            for event in &events {
                store.save_event(event).await.expect("Failed to save event");
            }

            // Query by author
            let author_filter = Filter::new().author(events[0].pubkey);
            let author_events = store.query(author_filter).await.expect("Failed to query");
            assert!(!author_events.is_empty());
            assert!(author_events.iter().all(|e| e.pubkey == events[0].pubkey));

            // Query by kind
            let kind_filter = Filter::new().kind(Kind::TextNote);
            let kind_events = store.query(kind_filter).await.expect("Failed to query");
            assert!(!kind_events.is_empty());
            assert!(kind_events.iter().all(|e| e.kind == Kind::TextNote));

            // Query by time range
            let since = Timestamp::from_secs(1704644590);
            let until = Timestamp::from_secs(1704644620);
            let time_filter = Filter::new().since(since).until(until);
            let time_events = store.query(time_filter).await.expect("Failed to query");
            assert!(!time_events.is_empty());
            assert!(time_events
                .iter()
                .all(|e| e.created_at >= since && e.created_at <= until));
        }

        #[tokio::test]
        async fn test_delete_by_filter() {
            let store: $store_type = $setup_fn().await;
            let events = decode_events();

            // Save all events
            for event in &events {
                store.save_event(event).await.expect("Failed to save event");
            }

            // Count before delete (8 visible after processing deletions/replacements)
            let count_before = store
                .count(Filter::new())
                .await
                .expect("Failed to count events");
            assert_eq!(count_before, 8);

            // Delete text notes
            let delete_filter = Filter::new().kind(Kind::TextNote);
            store.delete(delete_filter)
                .await
                .expect("Failed to delete events");

            // Count after delete (text notes: indices 0,4,13 - but 0 is deleted = 2 visible text notes deleted)
            let count_after = store
                .count(Filter::new())
                .await
                .expect("Failed to count events");
            assert_eq!(count_after, 7); // 8 - 1 text note = 7

            // Verify no text notes remain
            let text_notes = store
                .query(Filter::new().kind(Kind::TextNote))
                .await
                .expect("Failed to query");
            assert_eq!(text_notes.len(), 0);
        }

        #[tokio::test]
        async fn test_replaceable_events() {
            let store: $store_type = $setup_fn().await;
            let keys = Keys::generate();

            // Create first replaceable event (kind 0 - metadata)
            let metadata1 = Metadata::new().name("First");
            let event1 = metadata1
                .into_event_builder()
                .custom_created_at(Timestamp::from_secs(1000))
                .finalize(&keys)
                .expect("Failed to finalize");

            store.save_event(&event1).await.expect("Failed to save event");

            // Create newer replaceable event with later timestamp
            let metadata2 = Metadata::new().name("Second");
            let event2 = metadata2
                .into_event_builder()
                .custom_created_at(Timestamp::from_secs(2000))
                .finalize(&keys)
                .expect("Failed to finalize");

            store.save_event(&event2).await.expect("Failed to save event");

            // Query metadata events
            let filter = Filter::new().author(keys.public_key()).kind(Kind::Metadata);
            let results = store.query(filter).await.expect("Failed to query");

            // Should only have the newer event
            assert_eq!(results.len(), 1);
            // Verify it's the newer event by content
            let result_event = results.first().expect("Failed to get first event");
            assert!(result_event.content.contains("Second"));
        }

        #[tokio::test]
        async fn test_addressable_events() {
            let store: $store_type = $setup_fn().await;
            let keys = Keys::generate();

            // Create first addressable event
            let event1 = EventBuilder::new(Kind::from(32121), "Content 1")
                .tag(Tag::identifier("test-id"))
                .custom_created_at(Timestamp::from_secs(1000))
                .finalize(&keys)
                .expect("Failed to finalize");

            store.save_event(&event1).await.expect("Failed to save event");

            // Create newer addressable event with same identifier
            let event2 = EventBuilder::new(Kind::from(32121), "Content 2")
                .tag(Tag::identifier("test-id"))
                .custom_created_at(Timestamp::from_secs(2000))
                .finalize(&keys)
                .expect("Failed to finalize");

            store.save_event(&event2).await.expect("Failed to save event");

            // Query addressable events
            let filter = Filter::new()
                .author(keys.public_key())
                .kind(Kind::from(32121));
            let results = store.query(filter).await.expect("Failed to query");

            // Should only have the newer event
            assert_eq!(results.len(), 1);
            // Verify it's the newer event by content
            let result_event = results.first().expect("Failed to get first event");
            assert_eq!(result_event.content, "Content 2");
        }

        #[tokio::test]
        async fn test_event_deletion_by_id() {
            let store: $store_type = $setup_fn().await;
            let keys = Keys::generate();

            // Create events to delete
            let event1 = EventBuilder::new(Kind::TextNote, "To be deleted 1")
                .finalize(&keys)
                .expect("Failed to finalize");
            let event2 = EventBuilder::new(Kind::TextNote, "To be deleted 2")
                .finalize(&keys)
                .expect("Failed to finalize");

            store.save_event(&event1).await.expect("Failed to save event");
            store.save_event(&event2).await.expect("Failed to save event");

            // Create deletion event
            let deletion =
                EventDeletionRequest::new().id(event1.id).id(event2.id)
                    .finalize(&keys)
                    .expect("Failed to finalize");

            store.save_event(&deletion)
                .await
                .expect("Failed to save deletion");

            // Sleep to ensure deletion is processed in the ingester
            time::sleep(Duration::from_millis(50)).await;

            // Check events are marked as deleted
            let status1 = store
                .check_id(&event1.id)
                .await
                .expect("Failed to check event");
            let status2 = store
                .check_id(&event2.id)
                .await
                .expect("Failed to check event");

            // Deleted events return Deleted status
            // (even though they're physically removed from the database)
            assert_eq!(status1, DatabaseEventStatus::Deleted);
            assert_eq!(status2, DatabaseEventStatus::Deleted);
        }

        #[tokio::test]
        async fn test_event_deletion_by_coordinate() {
            let store: $store_type = $setup_fn().await;
            let keys = Keys::generate();

            // Create events to delete
            let event = EventBuilder::new(Kind::Custom(11_111), "To be deleted 1")
                .finalize(&keys)
                .expect("Failed to finalize");

            let status = store.save_event(&event).await.expect("Failed to save event");

            assert_eq!(status, SaveEventStatus::Success);

            // Create deletion event
            let req = EventDeletionRequest::new()
                .coordinate(event.coordinate().unwrap());
            let deletion =
                req
                    .finalize(&keys)
                    .expect("Failed to finalize");

            store.save_event(&deletion)
                .await
                .expect("Failed to save deletion");

            // Sleep to ensure deletion is processed in the ingester
            time::sleep(Duration::from_millis(50)).await;

            // Try to resave event
            let status = store.save_event(&event).await.expect("Failed to save event");

            // Deleted events return Deleted status
            // (even though they're physically removed from the database)
            assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Deleted));
        }

        #[tokio::test]
        async fn test_wipe_database() {
            let store: $store_type = $setup_fn().await;
            let events = decode_events();

            // Save all events
            for event in &events {
                store.save_event(event).await.expect("Failed to save event");
            }

            // Verify events exist (7 visible after processing)
            let count = store
                .count(Filter::new())
                .await
                .expect("Failed to count events");
            assert_eq!(count, 8);

            // Wipe database
            store.wipe().await.expect("Failed to wipe database");

            // Verify database is empty
            let count_after = store
                .count(Filter::new())
                .await
                .expect("Failed to count events");
            assert_eq!(count_after, 0);
        }

        #[tokio::test]
        async fn test_negentropy_items() {
            let store: $store_type = $setup_fn().await;
            let events = decode_events();

            // Save all events
            for event in &events {
                store.save_event(event).await.expect("Failed to save event");
            }

            let keys = Keys::generate();
            let expiration = Timestamp::now() + 1;
            let expired_event = build_event(
                &keys,
                EventBuilder::new(Kind::TextNote, "expired")
                    .tag(Tag::expiration(expiration)),
            );
            store
                .save_event(&expired_event)
                .await
                .expect("Failed to save expiring event");

            time::timeout(Duration::from_secs(3), async {
                while !expired_event.is_expired() {
                    time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("event did not expire before the deadline");

            // Get negentropy items
            let items = store
                .negentropy_items(Filter::new())
                .await
                .expect("Failed to get negentropy items");

            assert_eq!(items.len(), 8);
            assert!(!items.iter().any(|(id, _)| id == &expired_event.id));

            // Verify expired events are also excluded when a filter is applied.
            let filtered_items = store
                .negentropy_items(Filter::new().author(keys.public_key()))
                .await
                .expect("Failed to get filtered negentropy items");
            assert!(filtered_items.is_empty());

            // Verify items are from the original events
            let event_ids: HashSet<EventId> = events.iter().map(|e| e.id).collect();

            for (id, _timestamp) in items {
                assert!(
                    event_ids.contains(&id),
                    "Unexpected event ID in negentropy items"
                );
            }
        }

        #[tokio::test]
        async fn test_event_by_id() {
            let store: $store_type = $setup_fn().await;

            let _added_events: usize = add_random_events(&store).await;

            let (_keys, expected_event) = add_event(&store, EventBuilder::new(Kind::TextNote, "Test")).await;

            let event = get_existent_event_by_id(&store, &expected_event.id).await;
            assert_eq!(event, expected_event);
        }

        #[tokio::test]
        async fn test_replaceable_event() {
            let store: $store_type = $setup_fn().await;

            let added_events: usize = add_random_events(&store).await;

            let now = Timestamp::now();
            let metadata = Metadata::new()
                .name("my-account")
                .display_name("My Account");

            let (keys, expected_event) = add_event(
                    &store,
                    (&metadata).into_event_builder().custom_created_at(now - Duration::from_secs(120)),
                )
                .await;

            // Test event by ID
            let event = get_existent_event_by_id(&store, &expected_event.id).await;;
            assert_eq!(event, expected_event);

            // Test filter query
            let events = store
                .query(Filter::new().author(keys.public_key()).kind(Kind::Metadata))
                .await
                .expect("Failed to query events");
            assert_eq!(events, BTreeSet::from([expected_event.clone()]));

            // Check if number of events in database match the expected
            assert_eq!(count_all(&store).await, added_events + 1);

            // Replace previous event
            let (new_expected_event, status) = add_event_with_keys(
                    &store,
                    metadata.into_event_builder().custom_created_at(now),
                    &keys,
                )
                .await;
            assert!(status.is_success());

            // Test event by ID (MUST be None because replaced)
            assert!(get_event_by_id(&store, &expected_event.id).await.is_none());

            // Test event by ID
            let event = get_existent_event_by_id(&store, &new_expected_event.id).await;
            assert_eq!(event, new_expected_event);

            // Test filter query
            let events = store
                .query(Filter::new().author(keys.public_key()).kind(Kind::Metadata))
                .await
                .unwrap();
            assert_eq!(events, BTreeSet::from([new_expected_event]));

            // Check if number of events in database match the expected
            assert_eq!(count_all(&store).await, added_events + 1);
        }

        #[tokio::test]
        async fn test_param_replaceable_event() {
            let store: $store_type = $setup_fn().await;

            let added_events: usize = add_random_events(&store).await;

            let now = Timestamp::now();

            let (keys, expected_event) = add_event(
                    &store,
                    EventBuilder::new(Kind::Custom(33_333), "")
                        .tag(Tag::identifier("my-id-a"))
                        .custom_created_at(now - Duration::from_secs(120)),
                )
                .await;
            let coordinate = Coordinate::new(Kind::from(33_333), keys.public_key()).identifier("my-id-a");

            // Test event by ID
            let event = get_existent_event_by_id(&store, &expected_event.id).await;
            assert_eq!(event, expected_event);

            // Test filter query
            let events = store.query(coordinate.clone().into()).await.unwrap();
            assert_eq!(events, BTreeSet::from([expected_event.clone()]));

            // Check if number of events in database match the expected
            assert_eq!(count_all(&store).await, added_events + 1);

            // Replace previous event
            let (new_expected_event, status) = add_event_with_keys(
                    &store,
                    EventBuilder::new(Kind::Custom(33_333), "Test replace")
                        .tag(Tag::identifier("my-id-a"))
                        .custom_created_at(now),
                    &keys,
                )
                .await;
            assert!(status.is_success());

            // Test event by ID (MUST be None` because replaced)
            assert!(get_event_by_id(&store, &expected_event.id).await.is_none());

            // Test event by ID
            let event = get_existent_event_by_id(&store, &new_expected_event.id).await;
            assert_eq!(event, new_expected_event);

            // Test filter query
            let events = store.query(coordinate.into()).await.unwrap();
            assert_eq!(events, BTreeSet::from([new_expected_event]));

            // Check if number of events in database match the expected
            assert_eq!(count_all(&store).await, added_events + 1);

            // Trey to add param replaceable event with older timestamp (MUSTN'T be stored)
            let (_, status) = add_event_with_keys(
                    &store,
                    EventBuilder::new(Kind::Custom(33_333), "Test replace 2")
                        .tag(Tag::identifier("my-id-a"))
                        .custom_created_at(now - Duration::from_secs(2000)),
                    &keys,
                )
                .await;
            assert!(!status.is_success());
        }

        #[tokio::test]
        async fn test_full_text_search() {
            let store: $store_type = $setup_fn().await;
            let features = store.features();

            if !features.full_text_search {
                println!("Skipping full text search tests as the database doesn't support it!");
                return;
            }

            let _added_events: usize = add_random_events(&store).await;

            let events = store.query(Filter::new().search("Account A")).await.unwrap();
            assert_eq!(events.len(), 1);

            let events = store.query(Filter::new().search("account a")).await.unwrap();
            assert_eq!(events.len(), 1);

            let events = store.query(Filter::new().search("text note")).await.unwrap();
            assert_eq!(events.len(), 2);

            let events = store.query(Filter::new().search("notes")).await.unwrap();
            assert_eq!(events.len(), 0);

            let events = store.query(Filter::new().search("hola")).await.unwrap();
            assert_eq!(events.len(), 0);
        }

        #[tokio::test]
        async fn test_expected_query_result() {
            let store: $store_type = $setup_fn().await;

            // Save events individually to avoid batching issues during test
            for (i, event_str) in EVENTS.into_iter().enumerate() {
                let event = Event::from_json(event_str).unwrap();
                let status = store.save_event(&event).await.unwrap();

                // Invalid deletions (Event 7 and 11) should be rejected
                if i == 7 || i == 11 {
                    assert!(!status.is_success(), "Event {} should be rejected", i);
                }

                // Add a small delay to ensure each event is processed individually
                time::sleep(Duration::from_millis(10)).await;
            }

            // Expected output after applying NIP-09 deletion validation
            // Events 7 and 11 are rejected for invalid deletion attempts
            let expected_output = BTreeSet::from([
                Event::from_json(EVENTS[13]).unwrap(), // Kind:30333 latest
                Event::from_json(EVENTS[12]).unwrap(), // Kind:5 deletion
                Event::from_json(EVENTS[8]).unwrap(),  // Kind:5 coordinate deletion
                Event::from_json(EVENTS[6]).unwrap(),  // Kind:32122 latest
                Event::from_json(EVENTS[5]).unwrap(),  // Kind:32122 from different author
                Event::from_json(EVENTS[4]).unwrap(),  // Kind:32122 from different author
                Event::from_json(EVENTS[1]).unwrap(),  // Kind:32121
                Event::from_json(EVENTS[0]).unwrap(),  // Kind:1 text note
            ]);

            let actual = store.query(Filter::new()).await.unwrap();
            assert_eq!(actual, expected_output);
            assert_eq!(count_all(&store).await, 8); // 8 events after deletion validation
        }

        #[tokio::test]
        async fn test_kind5_deletion_query_bug_fix() {
            let store: $store_type = $setup_fn().await;

            let keys = Keys::generate();

            // Create and save an event
            let event = build_event(&keys, EventBuilder::new(Kind::TextNote, "Test event"));

            let status = store.save_event(&event).await.expect("Failed to save event");
            assert_eq!(status, SaveEventStatus::Success);

            // Sleep to ensure it's committed
            time::sleep(Duration::from_millis(50)).await;

            // Verify it exists with ID filter
            let before_by_id = store
                .query(Filter::new().id(event.id))
                .await
                .expect("Failed to query");
            assert_eq!(before_by_id.len(), 1, "Expected 1 event with ID: {}", event.id);

            // Verify it exists with author-kind filter
            let before_by_author = store
                .query(Filter::new().author(keys.public_key()).kind(Kind::TextNote))
                .await
                .expect("Failed to query");
            assert_eq!(before_by_author.len(), 1);

            // Create and save a Kind 5 deletion event
            let deletion_event = build_event(&keys, EventBuilder::new(Kind::EventDeletion, "")
                .tag(Tag::event(event.id)));

            let del_status = store
                .save_event(&deletion_event)
                .await
                .expect("Failed to save deletion");
            assert_eq!(del_status, SaveEventStatus::Success);

            // Sleep to ensure deletion is processed
            time::sleep(Duration::from_millis(100)).await;

            // Query for the deleted event by ID - should be empty after fix
            let after_by_id = store
                .query(Filter::new().id(event.id))
                .await
                .expect("Failed to query");
            assert_eq!(
                after_by_id.len(),
                0,
                "Deleted event should not be returned in ID query"
            );

            // Query for the deleted event by author-kind - should be empty after fix
            let after_by_author = store
                .query(Filter::new().author(keys.public_key()).kind(Kind::TextNote))
                .await
                .expect("Failed to query");
            assert_eq!(
                after_by_author.len(),
                0,
                "Deleted event should not be returned in author-kind query"
            );

            // The deletion event itself should still be queryable
            let deletion_events = store
                .query(Filter::new().kind(Kind::EventDeletion))
                .await
                .expect("Failed to query");
            assert_eq!(
                deletion_events.len(),
                1,
                "Deletion event should remain queryable"
            );
        }

        #[tokio::test]
        async fn test_nip01_replaceable_events_with_identical_timestamps() {
            let store: $store_type = $setup_fn().await;

            // Parse the two events with identical timestamps but different IDs
            let event1_json = r#"{"kind":0,"id":"b39eda8475d345d4da75418f0ee4a9ec183eb0483634cfdc8415cefdf5c02b96","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1754066538,"tags":[],"content":"smallest id","sig":"22e9f94de060c8e0a958b8fbc42914fab12c90be5ea9153aa11f92ed8c38c18a3374221fe37cb40b461d391e8ee92d6dd5083b0be8e146bf90af694560f18e17"}"#;
            let event2_json = r#"{"kind":0,"id":"eedcb07adabb380e853815534568e05cc5678bc8f9d8cf3dbee8513d37f1c47f","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1754066538,"tags":[],"content":"biggest id","sig":"b127afb6b7967b483bffe0d8ca21335509820bbfc37ba09874cc931c6c8c97dec4d44ac5d1071973d3b337c6fe614a8ca2cdc1e89c3c68cd557f4a2eca90cab3"}"#;

            let event1 = Event::from_json(event1_json).expect("Failed to parse event1");
            let event2 = Event::from_json(event2_json).expect("Failed to parse event2");

            // Confirm both events have the same timestamp
            assert_eq!(event1.created_at, event2.created_at);
            assert_eq!(event1.created_at.as_secs(), 1754066538);

            // Confirm event1 has the smaller ID (lexicographically first)
            assert!(event1.id.to_string() < event2.id.to_string());

            // Test 1: Insert event1 first, then event2
            {
                let status1 = store.save_event(&event1).await.expect("Failed to save event1");
                assert_eq!(status1, SaveEventStatus::Success);

                let status2 = store.save_event(&event2).await.expect("Failed to save event2");
                assert_eq!(
                    status2,
                    SaveEventStatus::Rejected(RejectedReason::Replaced)
                );

                // Query to see which event is stored
                let filter = Filter::new()
                    .author(
                        PublicKey::from_hex(
                            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                        )
                        .unwrap(),
                    )
                    .kind(Kind::Metadata);

                let results = store.query(filter).await.expect("Failed to query");
                assert_eq!(results.len(), 1, "Should have exactly one metadata event");

                // According to NIP-01, event1 should be retained (smaller ID)
                assert_eq!(
                    results.first().unwrap().id,
                    event1.id,
                    "NIP-01: Event with lowest ID should be retained"
                );
            }

            // Clean database
            store.wipe().await.expect("Failed to wipe database");

            // Test 2: Insert event2 first, then event1
            {
                let status2 = store.save_event(&event2).await.expect("Failed to save event2");
                assert_eq!(status2, SaveEventStatus::Success);

                let status1 = store.save_event(&event1).await.expect("Failed to save event1");
                assert_eq!(status1, SaveEventStatus::Success);

                // Query to see which event is stored
                let filter = Filter::new()
                    .author(
                        PublicKey::from_hex(
                            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                        )
                        .unwrap(),
                    )
                    .kind(Kind::Metadata);

                let results = store.query(filter).await.expect("Failed to query");
                assert_eq!(results.len(), 1, "Should have exactly one metadata event");

                // According to NIP-01, event1 should be retained (smaller ID)
                assert_eq!(
                    results.first().unwrap().id,
                    event1.id,
                    "NIP-01: Event with lowest ID should be retained"
                );
            }
        }

        #[tokio::test]
        async fn test_nip01_addressable_events_with_identical_timestamps() {
            let store: $store_type = $setup_fn().await;

            // Create two addressable events (kind 30023) with identical timestamps but different IDs
            let event1_json = r#"{"kind":30023,"id":"a11eda8475d345d4da75418f0ee4a9ec183eb0483634cfdc8415cefdf5c02b96","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1754066538,"tags":[["d","article-123"],["title","Test Article"]],"content":"Article with smallest id","sig":"22e9f94de060c8e0a958b8fbc42914fab12c90be5ea9153aa11f92ed8c38c18a3374221fe37cb40b461d391e8ee92d6dd5083b0be8e146bf90af694560f18e17"}"#;
            let event2_json = r#"{"kind":30023,"id":"feedb07adabb380e853815534568e05cc5678bc8f9d8cf3dbee8513d37f1c47f","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1754066538,"tags":[["d","article-123"],["title","Test Article"]],"content":"Article with biggest id","sig":"b127afb6b7967b483bffe0d8ca21335509820bbfc37ba09874cc931c6c8c97dec4d44ac5d1071973d3b337c6fe614a8ca2cdc1e89c3c68cd557f4a2eca90cab3"}"#;

            let event1 = Event::from_json(event1_json).expect("Failed to parse event1");
            let event2 = Event::from_json(event2_json).expect("Failed to parse event2");

            // Confirm both events have the same timestamp and d-tag
            assert_eq!(event1.created_at, event2.created_at);
            assert_eq!(event1.created_at.as_secs(), 1754066538);
            assert_eq!(event1.tags.identifier(), event2.tags.identifier());
            assert_eq!(event1.tags.identifier(), Some(String::from("article-123")));

            // Confirm event1 has the smaller ID (lexicographically first)
            assert!(event1.id.to_string() < event2.id.to_string());

            // Test 1: Insert event1 first, then event2
            {
                let status1 = store.save_event(&event1).await.expect("Failed to save event1");
                assert_eq!(status1, SaveEventStatus::Success);

                let status2 = store.save_event(&event2).await.expect("Failed to save event2");
                assert_eq!(
                    status2,
                    SaveEventStatus::Rejected(RejectedReason::Replaced)
                );

                // Query to see which event is stored
                let filter = Filter::new()
                    .author(
                        PublicKey::from_hex(
                            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                        )
                        .unwrap(),
                    )
                    .kind(Kind::Custom(30023));

                let results = store.query(filter).await.expect("Failed to query");
                assert_eq!(
                    results.len(),
                    1,
                    "Should have exactly one addressable event"
                );

                // According to NIP-01, event1 should be retained (smaller ID)
                assert_eq!(
                    results.first().unwrap().id,
                    event1.id,
                    "NIP-01: Event with lowest ID should be retained"
                );
            }

            // Clean database
            store.wipe().await.expect("Failed to wipe database");

            // Test 2: Insert event2 first, then event1
            {
                let status2 = store.save_event(&event2).await.expect("Failed to save event2");
                assert_eq!(status2, SaveEventStatus::Success);

                let status1 = store.save_event(&event1).await.expect("Failed to save event1");
                assert_eq!(status1, SaveEventStatus::Success);

                // Query to see which event is stored
                let filter = Filter::new()
                    .author(
                        PublicKey::from_hex(
                            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                        )
                        .unwrap(),
                    )
                    .kind(Kind::Custom(30023));

                let results = store.query(filter).await.expect("Failed to query");
                assert_eq!(
                    results.len(),
                    1,
                    "Should have exactly one addressable event"
                );

                // According to NIP-01, event1 should be retained (smaller ID)
                assert_eq!(
                    results.first().unwrap().id,
                    event1.id,
                    "NIP-01: Event with lowest ID should be retained"
                );
            }
        }

        #[tokio::test]
        async fn test_request_to_vanish() {
            let store: $store_type = $setup_fn().await;
            let features = store.features();

            if !features.request_to_vanish {
                println!("Skipping request to vanish tests as the database doesn't support it!");
                return;
            }

            let to_vanish = dummy_nip62(&store).await;

            // Request to vanish
            let request_to_vanish = VanishRequest::new(VanishTarget::AllRelays)
                .finalize(&to_vanish)
                .unwrap();
            store.save_event(&request_to_vanish).await.unwrap();

            // Check if the events deleted
            assert_eq!(
                store
                    .count(Filter::new().author(to_vanish.public_key()))
                    .await
                    .unwrap(),
                1 // The request to vanish event
            );
            assert_eq!(
                store
                    .count(
                        Filter::new()
                            .kind(Kind::GiftWrap)
                            .pubkey(to_vanish.public_key())
                    )
                    .await
                    .unwrap(),
                0
            );

            let new_event = EventBuilder::new(Kind::TextNote, "It was a mistake, please accept my event")
                .finalize(&to_vanish)
                .unwrap();

            // Try adding new event, should get rejected
            let status = store.save_event(&new_event).await.unwrap();
            assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Vanished));
        }

        #[tokio::test]
        async fn test_request_to_vanish_relay() {
            let store: $store_type = $setup_fn().await;
            let features = store.features();

            if !features.request_to_vanish {
                println!("Skipping request to vanish tests as the database doesn't support it!");
                return;
            }

            let url = RelayUrl::parse("wss://nostr.example.com").unwrap();
            let store: $store_type = $setup_with_relay_url(url.clone()).await;

            let to_vanish = dummy_nip62(&store).await;

            // Request to vanish
            let request_to_vanish = VanishRequest::new(VanishTarget::relay(url))
                .finalize(&to_vanish)
                .unwrap();
            store.save_event(&request_to_vanish).await.unwrap();

            // Check if the events deleted
            assert_eq!(
                store
                    .count(Filter::new().author(to_vanish.public_key()))
                    .await
                    .unwrap(),
                1 // The request to vanish event
            );
            assert_eq!(
                store
                    .count(
                        Filter::new()
                            .kind(Kind::GiftWrap)
                            .pubkey(to_vanish.public_key())
                    )
                    .await
                    .unwrap(),
                0
            );

            let new_event = EventBuilder::new(Kind::TextNote, "It was a mistake, please accept my event")
                .finalize(&to_vanish)
                .unwrap();

            // Try adding new event, should get rejected
            let status = store.save_event(&new_event).await.unwrap();
            assert_eq!(status, SaveEventStatus::Rejected(RejectedReason::Vanished));
        }

        #[tokio::test]
        async fn test_expire_events() {
            let store: $store_type = $setup_fn().await;
            let features = store.features();

            if !features.event_expiration {
                println!("Skipping event expiration tests as the database doesn't support it!");
                return;
            }

            let keys = Keys::generate();
            let event = EventBuilder::new(Kind::TextNote, "Nothing in my mind")
                .tag(Tag::expiration(Timestamp::now() - 10))
                .finalize(&keys)
                .unwrap();

            assert!(
                store.save_event(&event).await.unwrap().is_success(),
                "Database should not check if the event is expired"
            );

            let count = store
                .count(Filter::new().author(keys.public_key()))
                .await
                .unwrap();
            assert_eq!(count, 1, "We stored a single event");

            // Remove expired events
            store.collect_garbage().await.unwrap();

            let count = store
                .count(Filter::new().author(keys.public_key()))
                .await
                .unwrap();
            assert_eq!(count, 0, "Garbage collected");
        }
    };
}
