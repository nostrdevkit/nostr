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

## v0.45.2 - 2026/09/11

### Fixed

- Include LICENSE file

## v0.45.1 - 2026/08/07

### Fixed

- Exclude expired events from negentropy items

## v0.45.0 - 2026/08/05

### Changed

- Respect the filter limit (https://github.com/nostrdevkit/nostr/pull/1200)
- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

### Added

- Add search (NIP-50) capability (https://github.com/nostrdevkit/nostr/pull/1196)

### Removed

- Remove `hex` dependency (https://github.com/nostrdevkit/nostr/pull/1319)

## v0.44.0 - 2025/11/06

No notable changes in this release.

## v0.43.0 - 2025/07/28

### Changed

- Bump `nostrdb` from 0.6 to 0.8

## v0.42.0 - 2025/05/20

No notable changes in this release.

## v0.41.0 - 2025/04/15

### Changed

- Bump `nostrdb` to 0.6.1

## v0.40.0 - 2025/03/18

### Changed

- Return `None` in `NostrEventsDatabase::event_by_id` if event doesn't exist
- Avoid event clone when calling `NostrEventsDatabase::save_event`

## v0.39.0 - 2025/01/31

### Changed

-  Refactor note-to-event conversion

## v0.38.0 - 2024/12/31

### Changed

- Bump `nostrdb` to 0.5

## v0.37.0 - 2024/11/27

No notable changes in this release.

## v0.36.0 - 2024/11/05

No notable changes in this release.

## v0.35.0 - 2024/09/19

No notable changes in this release.

## v0.34.0 - 2024/08/15

No notable changes in this release.

## v0.33.0 - 2024/07/16

No notable changes in this release.

## v0.32.0 - 2024/06/07

No notable changes in this release.

## v0.31.0 - 2024/05/17

### Changed

- Bump `nostrdb` to 0.3.3

## v0.30.0 - 2024/04/15

No notable changes in this release.
