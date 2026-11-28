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

### Breaking changes

- Require the BUD-02 blob descriptor `type` field and represent blob sizes as `u64`.
- Prevent authorization options from overriding endpoint-mandated BUD-11 actions and hash scopes.

### Added

- Add BUD-03 server-list discovery, URL hash recovery, and ordered upload-and-mirror workflows.
- Add BUD-04 mirroring and BUD-05 media optimization with BUD-06 preflights.
- Add generic BUD-07 payment challenge and proof support.
- Deserialize BUD-08 NIP-94 metadata tags from blob descriptors.
- Add BUD-09 blob reporting and BUD-10 Blossom URI parsing, formatting, and resolution.
- Add BUD-12 cursor-based list pagination.

### Fixed

- Encode BUD-11 authorization as unpadded Base64url and scope tokens to domain names.
- Accept `201 Created` uploads and send `Content-Length` and `X-SHA-256` headers.
- Build all endpoints at the server origin root and preserve `/list/<pubkey>` paths.
- Validate redirect targets and downloaded blob hashes.

### Security

- Drop `Authorization` and payment headers on blob redirects that leave the
  trusted origin or downgrade to plain HTTP

## v0.45.1 - 2026/09/11

### Fixed

- Include LICENSE file

## v0.45.0 - 2026/08/05

### Breaking changes

- Require `AsyncGetPublicKey + AsyncSignEvent` for signed client operations (https://github.com/nostrdevkit/nostr/pull/1329)

### Changed

- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

## v0.44.0 - 2025/11/06

No notable changes in this release.

## v0.43.0 - 2025/07/28

No notable changes in this release.

## v0.42.1 - 2025/07/01

### Fixed

- blossom: fix url serialization (https://github.com/nostrdevkit/nostr/pull/956)

## v0.42.0 - 2025/05/20

First release.
