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

## v0.45.1 - 2026/09/11

### Fixed

- Include LICENSE file

## v0.45.0 - 2026/08/05

### Breaking changes

- Replace `usize` with `u8` for relay limits

### Changed

- Increase TTL for lists to 24 hours
- Replace `Mutex` with `RwLock` for better concurrency (https://github.com/nostrdevkit/nostr/pull/1126)
- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

### Added

- Add support for `GossipAllowedRelays` filtering during relay selection (https://github.com/nostrdevkit/nostr/pull/1128)

## v0.44.0 - 2025/11/06

First release.
