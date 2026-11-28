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

### Security

- Validate request origin (Host, Origin, Sec-Fetch-Site) to block DNS rebinding and XSSI
- Protect `/proxy.js` from cross-origin reads and hide the session token (IIFE)
- Move the session token to the `X-Proxy-Token` header

## v0.45.2 - 2026/11/23

### Security

- Add a per-session secret token to prevent web pages from other origins from reading or answering the signer requests
- Remove the permissive `Access-Control-Allow-Origin: *` CORS policy and drop the CORS preflight handler
- Validate that the event returned for a `sign_event` request matches the requested unsigned event

## v0.45.1 - 2026/09/11

### Fixed

- Include LICENSE file

## v0.45.0 - 2026/08/05

### Breaking changes

- Replace `NostrSigner` implementation with `AsyncNostrSigner` (https://github.com/nostrdevkit/nostr/pull/1329)

### Changed

- Allow customizing HTML page (https://github.com/nostrdevkit/nostr/pull/1203)
- Bump MSRV to 1.85.0 (https://github.com/nostrdevkit/nostr/pull/1267)

## v0.44.0 - 2025/11/06

### Added

- `BrowserSignerProxy::is_started` function to know if the server currently running or not (https://github.com/nostrdevkit/nostr/pull/1025)
- `BrowserSignerProxy::is_session_active` returns whether there is an active session with the browser (https://github.com/nostrdevkit/nostr/pull/1026)

## v0.43.0 - 2025/07/28

First release.
