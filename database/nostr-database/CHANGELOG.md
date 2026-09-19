# Changelog

<!-- All notable changes to this project will be documented in this file. -->

<!-- The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), -->
<!-- and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). -->

<!-- Template

## Unreleased

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated

### Performance

### Security

-->

## Unreleased

### Added

- New function to collect garbage `NostrDatabase::collect_garbage` (https://github.com/nostrdevkit/nostr/pull/1474)

## v0.45.1 - 2026/08/07

### Fixed

- Exclude expired events from negentropy items

## v0.45.0 - 2026/08/05

### Breaking changes

- Remove `Backend::is_persistent` method (https://github.com/nostrdevkit/nostr/pull/1138)
- Use `NonZeroUsize` for bounded capacities instead of `usize` (https://github.com/nostrdevkit/nostr/pull/1139)
- Move `MemoryDatabase` to `nostr-memory` crate (https://github.com/nostrdevkit/nostr/pull/1263)
- Remove `flatbuf` feature and remove `flatbuffers` module

### Changed

- Extend `Backend` variants (https://github.com/nostrdevkit/nostr/pull/1138)
- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

### Added

- Add `Backend::custom` constructor (https://github.com/nostrdevkit/nostr/pull/1138)
- Add `NostrDatabase::features` method (https://github.com/nostrdevkit/nostr/pull/1138)

## v0.44.0 - 2025/11/06

No notable changes in this release.

## v0.43.0 - 2025/07/28

### Breaking changes

- Merge traits into `NostrDatabase` (https://github.com/nostrdevkit/nostr/pull/916)
- Remove `NostrDatabase::has_coordinate_been_deleted` (https://github.com/nostrdevkit/nostr/pull/917)

### Changed

- Impl `Any` for `NostrDatabase` (https://github.com/nostrdevkit/nostr/pull/918)
- Impl `Default` for `Events` struct
- impl `FromIterator<Event>` for `Events` struct
- Bump lru from 0.14 to 0.16

## v0.42.0 - 2025/05/20

No notable changes in this release.

## v0.41.0 - 2025/04/15

No notable changes in this release.

## v0.40.0 - 2025/03/18

### Added

- Add `Events::force_insert`

### Removed

- Remove deprecated

## v0.39.0 - 2025/01/31

### Added

- Add `Events::first_owned` and `Events::last_owned`
- Impl `FlatBufferDecodeBorrowed` for `EventBorrow`
- Add `NostrDatabaseWipe` trait

### Removed

- Remove `async-trait` dep

### Deprecated

- Deprecate `NostrEventsDatabase::event_id_seen`
- Deprecate `NostrEventsDatabase::event_seen_on_relays`

## v0.38.0 - 2024/12/31

### Breaking changes

- Reduce default in-memory database limit to `35_000`
- Update `NostrEventsDatabase::save_event` method signature

### Changed

- Add manual trait implementations for `BTreeCappedSet`
- Replace LRU with custom memory cache for IDs tracking

### Added

- Impl PartialEq and Eq for `Events`
- Add `SaveEventStatus` enum

### Removed

- Remove `lru`, `thiserror` and `tracing` deps

## v0.37.0 - 2024/11/27

### Added

- Add `NostrEventsDatabase` trait

## v0.36.0 - 2024/11/05

### Changed

- Improve `BTreeCappedSet`
- Don't save invalid event deletion

### Added

- Add `Backend::is_persistent` method
- Add `Events` struct

## v0.35.0 - 2024/09/19

### Changed

- Update `NostrDatabase` supertraits
- Impl `Clone` for `MemoryDatabase`
- Update `NostrDatabase::event_by_id` fingerprint

### Added

- Add `DatabaseHelper::fast_query`
- Add `NostrDatabase::check_id`
- Add `NostrDatabaseExt::relay_lists`

### Removed

- Remove `has_event_already_been_saved`, `has_event_already_been_seen` and `has_event_id_been_deleted` methods from `NostrDatabase`
- Remove `Err` from `NostrDatabase`
- Remove `NostrDatabase::bulk_import`
- Remove `DatabaseError::NotFound` variant
- Remove `DatabaseError::Nostr` variant
- Remove `Order` enum
- Remove `order` arg from `NostrDatabase::query`

## v0.34.0 - 2024/08/15

### Changed

- Bump MSRV to v1.70.0
- Avoid to copy `EventId` in `Event::decode`
- Use `Vec` instead of `BTreeSet` as inner value for `TagIndexValues`
- Rework `DatabaseIndexes` and rename to `DatabaseHelper`
- Allow to set max capacity to `DatabaseHelper`
- Speedup helper bulk load
- Set a default logic for `NostrDatabase::negentropy_items`

### Fixed

- Fix indexes `QueryPattern`
- Fix query issue due to wrong tag value order

### Removed

- Remove `TempEvent`
- Remove `NostrDatabase::event_ids_by_filters`

## v0.33.0 - 2024/07/16

No notable changes in this release.

## v0.32.0 - 2024/06/07

No notable changes in this release.

## v0.31.0 - 2024/05/17

### Changed

- Small improvements to flatbuffers `Event::encode`

### Added

- Add `author` index

## v0.30.0 - 2024/04/15

No notable changes in this release.
