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

- Log the parsed `NostrConnectMessage` to redact sensitive data, instead of the raw decrypted message (https://github.com/nostrdevkit/nostr/pull/1432)

## v0.45.0 - 2026/08/05

### Breaking changes

- Replace `NostrSigner` implementation with `AsyncNostrSigner` (https://github.com/nostrdevkit/nostr/pull/1329)
- Remove `tor` feature (https://github.com/nostrdevkit/nostr/pull/1253)

### Changed

- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

### Added

- `NostrConnectKeys::new` function (https://github.com/nostrdevkit/nostr/pull/1356)

### Fixed

- Send connect response instead of a request when the connection initiated by the client (https://github.com/nostrdevkit/nostr/pull/1353)

## v0.44.1 - 2026/05/19

### Fixed

- Fixed race condition in `NostrConnectRemoteSigner::serve()` where notifications subscription happened after sending connect response, potentially causing missed client messages (https://github.com/nostrdevkit/nostr/pull/1353 and https://github.com/nostrdevkit/nostr/pull/1363)
- Fix rejections of bunker signers that reply with secret in the connect response (https://github.com/nostrdevkit/nostr/pull/1354 and https://github.com/nostrdevkit/nostr/pull/1361)

## v0.44.0 - 2025/11/06

### Fixed

- Fix `NostrConnectRequest::Connect` message handling (https://github.com/nostrdevkit/nostr/pull/1111)

## v0.43.0 - 2025/07/28

### Breaking changes

- Remove `NostrConnect::get_relays` (https://github.com/nostrdevkit/nostr/pull/894)

## v0.42.0 - 2025/05/20

### Breaking changes

- Encrypt NIP-46 events with NIP-44 instead of NIP-04 (https://github.com/nostrdevkit/nostr/pull/862)
- Drop support for NIP-46 event decryption with NIP-04 (https://github.com/nostrdevkit/nostr/pull/864)

## v0.41.0 - 2025/04/15

No notable changes in this release.

## v0.40.0 - 2025/03/18

No notable changes in this release.

## v0.39.0 - 2025/01/31

### Breaking changes

- Change `NostrConnect::shutdown` method signature

### Removed

- Remove `thiserror` dep
- Remove `async-trait` dep

## v0.38.0 - 2024/12/31

### Changed

- Require `fmt::Debug`, `Send` and `Sync` for `AuthUrlHandler`
- Improve secret matching for `NostrConnectRemoteSigner`
- Support both NIP04 and NIP44 for message decryption

### Added

- Add `NostrConnect::status`
- Add pubkey in `NostrConnectSignerActions::approve`

## v0.37.0 - 2024/11/27

### Breaking changes

- Refactor `NostrConnectRemoteSigner` to use distinct keys for signer and user
- Refactor `NostrConnectRemoteSigner` to use synchronous constructors

### Added

- Add `NostrConnect::non_secure_set_user_public_key`

## v0.36.0 - 2024/11/05

### Changed

- Rename `Nip46Signer` to `NostrConnect`
- Bootstrap NIP46 signer on demand

### Fixed

- Fix `NostrConnect` according to NIP46
