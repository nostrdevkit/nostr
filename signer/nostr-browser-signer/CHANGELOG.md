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

- Replace `NostrSigner` implementation with `AsyncNostrSigner` (https://github.com/nostrdevkit/nostr/pull/1329)
- Move browser/extension-related errors to a dedicated enum (https://github.com/nostrdevkit/nostr/pull/1327)

### Changed

- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

## v0.44.1 - 2025/11/09

### Fixed

- Fix doc building by removing `#![cfg_attr(docsrs, feature(doc_auto_cfg))]`

## v0.44.0 - 2025/11/06

No notable changes in this release.

## v0.43.0 - 2025/07/28

First release.
