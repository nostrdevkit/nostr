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

- Support event expiration (https://github.com/nostrdevkit/nostr/pull/1474)

## v0.45.2 - 2026/08/19

### Fixed

- Move `negentropy_items` query to `spawn_blocking`

## v0.45.1 - 2026/08/07

### Fixed

- Exclude expired events from negentropy items

## v0.45.0 - 2026/08/05

### Breaking changes

- Make `NostrLMDB::open` async (https://github.com/nostrdevkit/nostr/pull/1141)

### Changed

- Rename `NostrLMDB` to `NostrLmdb`
- Spawn blocking task for read operations (https://github.com/nostrdevkit/nostr/pull/1141)
- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

### Added

- Add `NostrLmdb::reindex` (https://github.com/nostrdevkit/nostr/pull/1143)
- Support NIP-62 `RequestToVanish` event kind (https://github.com/nostrdevkit/nostr/pull/1210)
- Options to enable and disable NIP-09 and NIP-62 (https://github.com/nostrdevkit/nostr/pull/1268)
- Relay specific request to vanish (NIP-62) (https://github.com/nostrdevkit/nostr/pull/1316)

## v0.44.1 - 2026/01/29

### Changed

- Improve scraping and counting performance (https://github.com/nostrdevkit/nostr/pull/1221)

### Fixed

- Fix the performance issues of queries by kinds (https://github.com/nostrdevkit/nostr/pull/1220)

## v0.44.0 - 2025/11/06

### Changed

- Consolidate deletion logic and improve transactional consistency (https://github.com/nostrdevkit/nostr/pull/1010)
- Add automatic event batching for better write performance (https://github.com/nostrdevkit/nostr/pull/1010)
- Improve performance of queries with authors, kinds and tags (https://github.com/nostrdevkit/nostr/pull/1080)

### Added

- Support NIP-50 filtering on both event content and some selected tags (https://github.com/nostrdevkit/nostr/pull/1093)

### Fixed

- Fix NIP-01 compliance for replaceable events with identical timestamps (https://github.com/nostrdevkit/nostr/pull/1017)

## v0.43.0 - 2025/07/28

### Changed

- Set MSRV to 1.70.0 (https://github.com/nostrdevkit/nostr/pull/993)

### Added

- Add NostrLmdbBuilder and allow setting a custom map size (https://github.com/nostrdevkit/nostr/pull/970)
- Add `max_readers` and `additional_dbs` fields to `NostrLmdbBuilder` (https://github.com/nostrdevkit/nostr/pull/1003)

## v0.42.0 - 2025/05/20

No notable changes in this release.

## v0.41.0 - 2025/04/15

### Changed

- Enable POSIX semaphores for macOS and iOS targets (https://github.com/nostrdevkit/nostr/commit/b58e0975f8ea53e794721a09d051b92c6a28212e)

## v0.40.0 - 2025/03/18

### Changed

- Bump MSRV to 1.72.0 (https://github.com/nostrdevkit/nostr/pull/753)
- Implement event ingester (https://github.com/nostrdevkit/nostr/pull/753)
- Avoid spawning thread for read methods (https://github.com/nostrdevkit/nostr/pull/753)
- Avoid long-lived read txn when ingesting event (https://github.com/nostrdevkit/nostr/pull/753)

## v0.39.0 - 2025/01/31

### Changed

- Use `EventBorrow` instead of `DatabaseEvent`

### Fixed

- Fix map size for 32-bit arch

## v0.38.0 - 2024/12/31

### Changed

- Use `async-utility` to spawn blocking tasks

### Removed

- Remove `thiserror` and `tracing` deps

## v0.37.0 - 2024/11/27

### Changed

- Optimize vector initialization in unit tests
- Commit also read txn
- Transactions improvements
- Improve NIP50 search performance

## v0.36.0 - 2024/11/05

### Changed

- Not save event deletion
- Return iterator instead of vector in `Lmdb::single_filter_query`
- Mark event as deleted only if database have the target event

### Fixed

- Add missing commit method call in `Store::delete`
- Fix unit tests
- Fix `Store::save_event` issues

## v0.35.0 - 2024/09/19

First release.
