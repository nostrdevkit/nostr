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

-->

## Unreleased

### Security

- Zeroize normalized passwords, scrypt-derived keys, and decrypted plaintext buffers used by NIP-49.

## v0.44.3 - 2026/05/19

### Fixed

- Add `a` tag of replaceable and addressable events in `EventBuilder::repost` (https://github.com/rust-nostr/nostr/pull/1184)
- Handle legacy events with `mention` marker (https://github.com/rust-nostr/nostr/pull/1193)
- Parse "HEAD" as `TagKing::Head` (https://github.com/rust-nostr/nostr/pull/1215)
- Fix NIP-46 `Error::UnexpectedResponse` formatting (https://github.com/rust-nostr/nostr/commit/5c4f9fe47b83a3baf2e137c4835b14f7ec4fc523)

## v0.44.2 - 2025/12/04

### Fixed

- Fix parsing of e tag with blank values (https://github.com/rust-nostr/nostr/pull/1158)

## v0.44.1 - 2025/11/09

### Fixed

- Fix doc building by removing `#![cfg_attr(docsrs, feature(doc_auto_cfg))]`

## v0.44.0 - 2025/11/06

### Breaking changes

- Change the `address` field type in `CommentTarget::Coordinate` to `CoordinateBorrow` (https://github.com/rust-nostr/nostr/pull/1034)
- Change the `EventBuilder::comment` function `root` and `comment_to` parameters types from `&Event` to `CommentTarget<'_>` (https://github.com/rust-nostr/nostr/pull/1047)
- Set `payment_hash` as optional in `MakeInvoiceResponse` (https://github.com/rust-nostr/nostr/pull/1045)
- Remove `hex` module (https://github.com/rust-nostr/nostr/pull/1051)
- Use `Cow` for non-copy fields in `nip22::CommentTarget` enum (https://github.com/rust-nostr/nostr/pull/1053)
- Change `EventBuilder::reaction` args (https://github.com/rust-nostr/nostr/pull/1063)
- Remove `EventBuilder::reaction_extended` (https://github.com/rust-nostr/nostr/pull/1063)
- Change NIP-47 `GetInfoResponse` `pubkey` type from `PublicKey` to `String`
- Change `methods` type to `Vec<Method>` in `GetInfoResponse` (https://github.com/rust-nostr/nostr/pull/1094)
- Merge `ClientMessage::Req` and `ClientMessage::ReqMultiFilter` variants (https://github.com/rust-nostr/nostr/pull/1101)
- Rename `public_key` to `remote_signer_public_key` in `NostrConnectRequest::Connect` variant (https://github.com/rust-nostr/nostr/pull/1111)

### Added

- Add NIP-B0 support (https://github.com/rust-nostr/nostr/pull/1077)
- Add NIP-7D support (https://github.com/rust-nostr/nostr/pull/1071)
- Add NIP-C7 support (https://github.com/rust-nostr/nostr/pull/1067)
- Add NIP-60 support (https://github.com/rust-nostr/nostr/pull/1092)
- Add NIP-A0 support (https://github.com/rust-nostr/nostr/pull/1032)
- Implement `ToBech32` trait for `Nip21`
- Implement `ToBech32` for `Coordinate`
- Implement `ToNostrUri` for `Coordinate`
- Implement `ToBech32` for `CoordinateBorrow`
- Implement `ToNostrUri` for `CoordinateBorrow`
- Implement `ToBech32` for `Event`
- Implement `ToNostrUri` for `Event`
- Implement `From<&Event>` for `Nip19Event`
- Add `CowTag::kind` and `CowTag::content`
- Add `Timestamp::as_secs`
- Add `EventBuilder::tag_maybe`
- Add `Kind::CashuNutZapInfo` (10019) and `Kind::CashuNutZap` (9321) variants
- Add nip47 holdinvoice methods and notification (https://github.com/rust-nostr/nostr/pull/1019)
- Add `TransactionState` to `LookupInvoiceResponse` and `PaymentNotification` (https://github.com/rust-nostr/nostr/pull/1045)
- Add `description`, `description_hash`, `preimage`, `amount`, `created_at` and `expires_at` optional fields to `MakeInvoiceResponse` (https://github.com/rust-nostr/nostr/pull/1045)
- Add `fees_paid` field to `PayKeysendResponse` (https://github.com/rust-nostr/nostr/pull/1045)
- Add `nip47::Method::as_str` method
- Add `CommentTarget::{event, coordinate, external}` to point to a specific thing (https://github.com/rust-nostr/nostr/pull/1034)
- Add `nips::nip73::Nip73Kind` and `TagStandard::Nip73Kind` (https://github.com/rust-nostr/nostr/pull/1039)
- Add repository state announcements kind `Kind::RepoState` (30618) (https://github.com/rust-nostr/nostr/pull/1041)
- Add `HEAD` tag kind (https://github.com/rust-nostr/nostr/pull/1043)
- Add `CommentTarget::as_vec` to convert the comment target into a vector of tags (https://github.com/rust-nostr/nostr/pull/1038)
- Add `hex` dependency (https://github.com/rust-nostr/nostr/pull/1051)
- Add `nip25::ReactionTarget` (https://github.com/rust-nostr/nostr/pull/1063)
- Add `RelayUrl::host` function (https://github.com/rust-nostr/nostr/pull/1066)
- Add support for multithreaded event POW mining (https://github.com/rust-nostr/nostr/pull/1075)

### Changed

- NIP-47 fields synchronized with current specs (https://github.com/rust-nostr/nostr/pull/1021)
- Check that `a`/`A` and `k`/`K` tags have the same event kind in NIP-22 events (https://github.com/rust-nostr/nostr/pull/1035)
- Deserialize NIP-47 empty strings as `None` (https://github.com/rust-nostr/nostr/pull/1079)
- Make `EventBuilder::reaction` target arg generic over `ReactionTarget` type
- Make `EventBuilder::comment` and `EventBuilder::voice_message_reply` args generic over `CommentTarget` type
- Ensure rumor matches seal author when unwrapping NIP-59 gift (https://github.com/rust-nostr/nostr/pull/1123)

### Deprecated

- Deprecate `Timestamp::as_u64`
- Deprecate `Nip19Event::from_event`
- Deprecate `kind` field in `CommentTarget::Coordinate` variant (https://github.com/rust-nostr/nostr/pull/1035)

## v0.43.1 - 2025/08/21

### Fixed

- Support `Nip05Address` parsing without local part

## v0.43.0 - 2025/07/28

### Breaking changes

- Move NIP-07 from `nostr` to `nip07` crate (https://github.com/rust-nostr/nostr/pull/937)
- Remove `NostrConnectMethod::GetRelays`, `NostrConnectRequest::GetRelays` and `ResponseResult::GetRelays` (https://github.com/rust-nostr/nostr/pull/894)
- Remove `Market::Mention` (NIP-10) (https://github.com/rust-nostr/nostr/pull/895)
- Remove `parser` feature (https://github.com/rust-nostr/nostr/pull/899)
- Update `Nip19Profile::new` and `Nip19Coordinate::new` signature (https://github.com/rust-nostr/nostr/pull/910)
- Update `RelayInformationDocument::get` signature (https://github.com/rust-nostr/nostr/pull/913)
- Remove `TagStandard::Delegation` and `TagKind::Delegation` (https://github.com/rust-nostr/nostr/pull/929)
- Remove `nip05` cargo feature (https://github.com/rust-nostr/nostr/pull/936)
- Convert `nip05` module to be I/O-free (https://github.com/rust-nostr/nostr/pull/936)
- Convert `nip11` module to be I/O-free (https://github.com/rust-nostr/nostr/pull/950)
- Convert `nip96` module to be I/O-free (https://github.com/rust-nostr/nostr/pull/935)
- Add `MatchEventOptions` as a parameter to `Filter::match_event` function (https://github.com/rust-nostr/nostr/pull/976)

### Changed

- Rework `NostrParser` (https://github.com/rust-nostr/nostr/pull/899)
- Enhance `NostrParser` with flexible parsing options (https://github.com/rust-nostr/nostr/pull/912)
- Impl `Any` for `NostrSigner` (https://github.com/rust-nostr/nostr/pull/918)
- Make `TagKind` helper constructors `const`

### Added

- Add NIP-88 support (https://github.com/rust-nostr/nostr/pull/892)
- Add `Nip11GetOptions` (https://github.com/rust-nostr/nostr/pull/913)
- Add `RelayUrl::domain` method (https://github.com/rust-nostr/nostr/pull/914)
- Add `fees_paid` to `nip47::PayInvoiceResponse` (https://github.com/rust-nostr/nostr/pull/971)
- Add `nip96::UploadResponseStatus::is_success` method

### Fixed

- Fix support for NIP-44 on no_std env (https://github.com/rust-nostr/nostr/pull/955)

### Removed

- Remove regex dep (https://github.com/rust-nostr/nostr/pull/899)

### Deprecated

- Deprecate `nip21::extract_from_text` function (https://github.com/rust-nostr/nostr/pull/923)
- Deprecate `Tags::from_text` constructor
- Deprecate NIP-26 (https://github.com/rust-nostr/nostr/pull/928)

## v0.42.2 - 2025/06/28

### Fixed

- Fix index out of bounds in `Tags::dedup` (https://github.com/rust-nostr/nostr/pull/949)

## v0.42.1 - 2025/05/26

### Added

- Add detailed error handling for NIP-47 response deserialization (https://github.com/rust-nostr/nostr/pull/890)

### Fixed

- Fix NIP-47 request params serialization (https://github.com/rust-nostr/nostr/pull/891)

## v0.42.0 - 2025/05/20

### Breaking changes

- Rework nip46 module (https://github.com/rust-nostr/nostr/pull/865)

### Changed

- Rename `nip22::Comment` to `nip22::CommentTarget` (https://github.com/rust-nostr/nostr/pull/882)

### Added

- Add `UnsignedEvent::id` method (https://github.com/rust-nostr/nostr/pull/868)
- Add `TagKind::single_letter` constructor (https://github.com/rust-nostr/nostr/pull/871)
- Add NIP-73 blockchain address and transaction (https://github.com/rust-nostr/nostr/pull/879)

### Fixed

- Handle `A` and `E` standard tags (https://github.com/rust-nostr/nostr/pull/870)
- Fix `nip22::extract_root` to handle uppercase tags when `is_root` is true (https://github.com/rust-nostr/nostr/pull/876)

## v0.41.0 - 2025/04/15

### Breaking changes

- Add optional relay URL arg to `Tag::coordinate`
- Update `TagStandard::Label` and `EventBuilder::label`
- Update `custom` field type in `Metadata` struct

### Added

- Add NIP-C0 (Code Snippets) support
- Add `TagKind::u` constructor
- Derive `Copy` for `HttpMethod`
- Add `nip98::verify_auth_header`
- Add `push`, `pop`, `insert` and `extend` methods to the `Tag` struct (https://github.com/rust-nostr/nostr/pull/817)
- Add `nip47::Notification`
- Add `MachineReadablePrefix::as_str` method
- Derive `Hash` for `EventBuilder` and `Metadata`

### Fixed

- Fix missing `transactions` object in serialization of nip47 ListTransactions ResponseResult
- Fix NIP32 implementation (https://github.com/rust-nostr/nostr/commit/6979744839381ffa2b27f2d1efa5e13e522cdf24)

## v0.40.0 - 2025/03/18

### Breaking changes

- Update `Nip19Event` relays field type from `Vec<String>` to `Vec<RelayUrl>`
- Change the `Err` type of `ToBech32` to `Infallible` for `SecretKey`, `PublicKey` and `EventId`
- Update `Tags::new` signature
- Remove `WeakTag` (https://github.com/rust-nostr/nostr/pull/755)
- Change `TagStandard::Relays` variant inner value from `Vec<Url>` to `Vec<RelayUrl>`
- Split `NostrURI` into `ToNostrUri` and `FromNostrUri` traits
- Replace generic parameter `AsRef<str>` with `&str` in `Coordinate::parse` and `Coordinate::from_kpi_format`
- Replace generic parameter `AsRef<str>` with `&str` in `Nip21::parse`
- Change `EventId::new` signature
- Change `EventBuilder::git_repository_announcement` constructor signature
- Change `EventBuilder::git_issue` constructor signature
- Change `EventBuilder::git_patch` constructor signature
- nostr: `TagStandard::parse` now returns `Err(Error::UnknownStandardizedTag)` for non-lowercase hashtags as per NIP-24
- Update `NostrWalletConnectURI` to support multiple relay URLs
- Remove `EventIdOrCoordinate` enum
- Change `EventBuilder::delete` arguments

### Changed

- Manually impl eq and cmp traits for `RelayUrl`
- Use `Cow` in `ClientMessage` and `RelayMessage`
- Derive `PartialOrd`, `Ord`, and `Hash` traits in `Nip21` enum

### Added

- Add NIP-38 support (https://github.com/rust-nostr/nostr/pull/771)
- Add NIP-60 event kinds
- Add NIP-62 support (https://github.com/rust-nostr/nostr/pull/777)
- Add `NostrParser` (https://github.com/rust-nostr/nostr/pull/781)
- Add `nip21::extract_from_text` function (https://github.com/rust-nostr/nostr/pull/754)
- Add `EventBuilder::allow_self_tagging` (https://github.com/rust-nostr/nostr/pull/744)
- Add `Nip19Event::from_event`
- Add `Tag::client` constructor
- Add `Tag::len` method (https://github.com/rust-nostr/nostr/pull/755)
- Add `push`, `pop`, `insert`, `remove`, `extend` and `retain` methods to `Tags` struct (https://github.com/rust-nostr/nostr/pull/755)
- Add `with_capacity`, `from_list`, `from_text` and `parse` constructors to `Tags` struct (https://github.com/rust-nostr/nostr/pull/755)
- Add `Tags::dedup` method (https://github.com/rust-nostr/nostr/pull/755)
- Add `EncryptedSecretKey::decrypt` method
- Add `Nip19Coordinate` struct
- Add `Coordinate::verify` method
- Add `TagStandard::Client` variant
- Add `EventBuilder::dedup_tags` method (https://github.com/rust-nostr/nostr/pull/772)
- Impl `FromIterator<Tag>` for `Tags`
- Add `EventDeletionRequest` struct
- Add `notifications` field to NIP47 `GetInfoResponse`
- Add `RelayMetadata::as_str` method
- Add `nip42::is_valid_auth_event` function (https://github.com/rust-nostr/nostr/commit/e7a91ec69ab3b804cad0df8fccbcc53fd8dc7cc8)
- Add `Tag::relays` constructor

### Fixed

- Fix `EventBuilder::git_repository_announcement` constructor according to last NIP34 rev (https://github.com/rust-nostr/nostr/pull/764)
- Fix `EventBuilder::git_issue` constructor according to last NIP34 rev (https://github.com/rust-nostr/nostr/pull/764)
- Fix `EventBuilder::git_patch` constructor according to last NIP34 rev (https://github.com/rust-nostr/nostr/pull/764)
- nostr: `Tag::hashtag` now lowercases the hashtag as per NIP-24

### Removed

- Remove `RawRelayMessage`, `RawEvent`, `PartialEvent` and `MissingPartialEvent`

### Deprecated

- Deprecate `EncryptedSecretKey::to_secret_key` method

## v0.39.0 - 2025/01/31

### Breaking changes

- Update `ClientMessage::neg_open` signature
- Remove `ClientMessage::neg_open_deprecated`
- Add `nip98` feature
- Remove support for event JSON order preservation
- Change `EventBuilder::gift_wrap` rumor arg type
- Change `Filter::custom_tag` value arg type
- Rename `Filter::remove_custom_tag` to `Filter::remove_custom_tags`
- Take a single filter per REQ and COUNT
- Rename `contact` module to `nip02`

### Changed

- Refactor `PublicKey` to use byte array internally
- nostr: bump `bip39` to 2.1
- Move `types::filter` to `crate::filter`
- Move `Metadata` struct to `nip01` module
- Cleanup error enums
- Use `SECP256K1` global context from `secp256k1` crate
- Manually implement `PartialEq`, `Eq`, `PartialOrd`, `Ord` and `Hash` for `TagKind`
- Derive `PartialEq` and `Eq` for event builder error
- Rename `Nip07Signer` to `BrowserSigner`
- Remove `#[cfg]` attributes from `NostrSigner` NIP04 and NIP44 methods
- nostr: omit everything after the relay-hint in NIP22 `p` tags
- Make EventBuilder `custom_created_at` and `pow` fields public
- Improve `Filter::match_event` performance

### Added

- Add NIP96 support
- Add `Kind::PeerToPeerOrder` variant
- Add `CowTag`
- Add `EventBorrow`
- Add `HttpData::to_authorization`
- Add `CoordinateBorrow` struct
- Add `Filter::custom_tags`
- Add `nip22::extract_root` and `nip22:extract_parent`
- Add `MachineReadablePrefix::Unsupported` variant

### Removed

- Remove `negentropy` deps
- Remove `bitcoin` dep
- Remove `once_cell` dep
- Remove `async-trait` dep

### Deprecated

- Deprecate `Keys::vanity`

## v0.38.0 - 2024/12/31

### Breaking changes

- Update `FromBech32::from_bech32` method signature
- Update `NostrURI::from_nostr_uri` method signature
- Remove generics from parsing methods in `key` module
- Remove generics from `EventId` parsing methods
- Remove generic from `RelayUrl::parse`
- Refactor `MachineReadablePrefix::parse` method to use `&str` directly
- Update `RelayMessage::Notice` variant

### Changed

- Remove self-tagging when building events
- Don't set root tags when the root is null
- Update `RelayMessage::NegErr` variant
- Accept either `EventBuilder` or `UnsignedEvent` as rumor in NIP59 functions
- Require `fmt::Debug`, `Send` and `Sync` for `NostrSigner`
- Enable support for `Tags::indexes` in `no_std`
- Improve `RelayMessage` docs
- Include public key of root and parent author in `EventBuilder::comment`
- Dedup tags in `EventBuilder::text_note_reply` and `EventBuilder::comment`
- Don't use reply event as root `e` tag i no root is set in `EventBuilder::text_note_reply`

### Added

- Add `Tags::challenge` method
- Add `RelayUrl::is_local_addr`
- Add `TagKind::k` constructor
- Impl `IntoIterator` for `Tag`
- Add NIP35 support
- Add `Kind::is_addressable` and `ADDRESSABLE_RANGE`

### Fixed

- Remove redundant NIP10 tags from `EventBuilder::text_note_reply`

### Removed

- Remove `NegentropyErrorCode`

### Deprecated

- Deprecate `PARAMETERIZED_REPLACEABLE_RANGE`, `Kind::ParameterizedReplaceable` and `Kind::is_parameterized_replaceable`
- Deprecate `JobRequest`, `JobResult`, `Regular`, `Replaceable` and `Ephemeral` kind variants

## v0.37.0 - 2024/11/27

### Breaking changes

- Use `RelayUrl` struct instead of `Url` for relay urls
- Change `EventBuilder::gift_wrap` (and linked methods) args to take `extra_tags` instead of `expiration`
- Change `EventBuilder::gift_wrap` (and linked methods) args to take an `EventBuilder` rumor instead of `UnsignedEvent`
- Change `EventBuilder::private_msg_rumor` arg to take `extra_tags` instead of `reply_to`
- Remove `tags` arg from `EventBuilder::new`
- Remove `tags` arg from `EventBuilder::text_note`
- Remove `tags` arg from `EventBuilder::long_form_text_note`
- Remove `tags` arg from `EventBuilder::job_request`
- Disable all default features except `std`
- Change `Timestamp::to_human_datetime` method signature
- Change `Tag::parse` arg from slice to iterator
- Change `TagStandard::Relay` variant inner type
- Remove `UncheckedUrl` struct
- Update `NostrConnectURI::relays` to return slice
- Update `NostrConnectURI::secret` to return string slice
- Remove `-Params` and `-Result` suffix from NIP47 structs

### Changed

- Rewrite `e` tag de/serialization

### Added

- Add NIP104 tag and event kinds
- Add `SingleLetterTag::as_str` and `TagKind::as_str`
- Add `Kind::Comment`
- Add `EventBuilder::comment`
- Add uppercase field to `TagStandard::Coordinate` and `TagStandard::ExternalIdentity` variants
- Add `TagStandard::Quote`
- Add `Event::coordinate`
- Add `A/a` tags in `EventBuilder::comment` (NIP22) events
- Add NIP73 support
- Add `NostrSigner::backend`
- Add `EventBuilder::private_msg`
- Add `EventBuilder::tag` and `EventBuilder::tags`
- Add `nip17::extract_relay_list` and `nip17::extract_owned_relay_list`
- Add `RelayUrl` struct

### Fixed

- Fix `TagStandard` de/serialization unit tests
- Fix NIP90 kind ranges

### Removed

- Remove `Marker::Custom` variant

### Deprecated

- Deprecate `EventBuilder::add_tags`

## v0.36.0 - 2024/11/05

### Changed

- Move `TagsIndexes` into `Tags` struct
- Use `OnceCell` implementation from `std` lib instead of `once_cell`
- Remove redundant public key from repost events
- Change `impl Ord for Event` behaviour (descending order instead of ascending)
- Change `TagStandard::Relays` variant value from `Vec<UncheckedUrl>` to `Vec<Url>`
- Reserve capacity for tags when POW is enabled in `EventBuilder`
- Add `sign`, `sign_with_keys`, `sign_with_ctx`, `build` and `build_with_supplier` methods to `EventBuilder`
- Deprecate `to_event`, `to_event_with_ctx` and `to_unsigned_event` methods

### Added

- Add `TagKind::Client` variant
- Add some shorthand constructors for `TagKind::SingleLetter`
- Add `Tags` struct
- Add `d` tag extraction test from `Tags`
- Add `TagStandard::GitClone` and `TagKind::Clone` variants
- Add `TagStandard::GitCommit` and `TagKind::Commit` variants
- Add `TagStandard::GitEarliestUniqueCommitId` variant
- Add `TagStandard::GitMaintainers` and `TagKind::Maintainers` variants
- Add `TagStandard::Web` and `TagKind::Web` variants
- Add `EventBuilder::git_repository_announcement`
- Add `EventBuilder::git_issue`
- Add `EventBuilder::git_patch`
- Add `Tag::reference` constructor
- Add `nip59::make_seal` function
- Add `NostrSigner` trait

### Fixed

- Adj. `NostrConnectURI` de/serialization according to NIP46

## v0.35.0 - 2024/09/19

### Changed

- Bump `bitcoin` to `v0.32`
- Bump `base64` to `v0.22`
- Deprecate `Event::from_value`
- Deprecate `Tag::as_vec`
- Re-write `RawRelayMessage` parsing
- Update `Event` fields
- Deprecate `Event::is_*` kind related methods
- Change `TryIntoUrl::Err` to `Infallible` for `Url`
- Change `Event::verify_id` and `Event::verify_signature` fingerprint
- Impl custom `Debug`, `PartialEq` and `Eq` for `Keys`
- Impl `PartialOrd`, `Ord` and `Hash` for `Keys`
- Change `Keys::secret_key` and `Keys::sign_schnorr` methods fingerprint
- Deprecate `Keys::generate_without_keypair`
- Change NIP26 functions fingerprint
- Improve `NostrWalletConnectURI` parsing
- Update `EventBuilder::job_feedback` method fingerprint
- Deprecate `EventBuilder::to_pow_event`
- Impl `Display` for `MachineReadablePrefix`
- Improve `Keys` docs
- Change visibility of `public_key` field in `Keys` struct
- Deprecate `Keys::public_key_ref`
- Use `OsRng` instead of `ThreadRng` for `SECP256K1` global context and schnorr signing
- Improve `Timestamp::to_human_datetime` performance
- Deprecate `EventId::owned`
- Convert `EventId::all_zeroes` to const function
- Convert `Timestamp::from_secs` to const function
- Deprecate `Kind::as_u32` and `Kind::as_u64`

### Added

- Impl `TryFrom<Vec<Tag>>` for `LiveEvent`
- Add `Tag::as_slice`
- Add `NostrWalletConnectURI::parse`
- Add `JobFeedbackData` struct
- Add `EventBuilder::pow` method
- Add `TagKind::custom` constructor
- Add `Timestamp::from_secs`
- Add `EventId::from_byte_array`
- Add `Timestamp::min` and `Timestamp::max`
- Add `nip65::extract_owned_relay_list`
- Add `Kind::from_u16`

### Fixed

- Fix `TagStanderd::to_vec`
- Fix broken intra doc links
- Fix `JsonUtil::try_as_pretty_json` method
- Fix `Kind::is_regular` method

### Removed

- Remove `bech32` from the public API
- Remove `Keys::from_public_key`
- Remove `tracing` dep
- Remove impl `fmt::Display` for `SecretKey`

## v0.34.0 - 2024/08/15

### Changed

- Bump MSRV to v1.70.0
- Deprecate `Event::author_ref` and `Event::iter_tags`
- Calculate `EventId` in `EventBuilder::to_unsigned_event_with_supplier`
- nostr: ensure that NIP59 rumor has `EventId`
- Update `PartialEvent` methods
- Change `EventBuilder::award_badge` fingerprint
- Add NIP50 support to `Filter::match_event` method
- Remove `Arc<T>` from `OnceCell<T>` in `Event` and `Tag`
- Move `sig` field from `PartialEvent` to `MissingPartialEvent`
- nostr: better `Debug` trait impl for `EventId`, `PublicKey` and `Tag`
- Improve `SubscriptionId::generate_with_rng`

### Added

- Add NIP31 support
- Add NIP70 support
- Add `EventId::LEN` const
- Add `UnsignedEvent::ensure_id` method
- Add missing `payload` arg to `EventBuilder::job_result`
- Add `ConversationKey::new`
- Add `Request::multi_pay_invoice` constructor
- Add `Jsonutil::as_pretty_json` and `JsonUtil::try_as_pretty_json` methods
- Add `Coordinate::has_identifier`

### Removed

- Remove support for `nrelay` NIP19 entity
- Remove support for NIP44 v1
- Remove `EventBuilder::encrypted_direct_msg`

## v0.33.0 - 2024/07/16

### Changed

- Rename NIP-51 `EventBuilder` set constructors and `Kind` variants
- Small adj. to NIP-47 `ListTransactionsRequestParams` and `LookupInvoiceResponseResult` structs
- Add `identifier` arg to NIP-51 `EventBuilder` set constructors
- Change `nip65::extract_relay_list` fingerprint
- Avoid allocation where possible in NIP-05 module
- Get NIP-46 relays from NIP-05 address
- Deprecate `EventBuilder::encrypted_direct_msg`

### Added

- Add `EventBuilder::interest_set`
- Add `title`, `image` and `description` constructors to `Tag`
- Add `Timestamp::zero` and `Timestamp::is_zero` methods
- Add `Nip05Profile` struct
- Add `nip05::profile` function
- Add `LEN` const to `PublicKey`, `SecretKey` and `EncryptedSecretKey`
- Add `Report::Malware` variant
- Add `coordinate` methods to `Filter` struct
- Add NIP-34 kinds
- Add `MachineReadablePrefix` enum
- Add `ClientMessage::is_auth`

### Fixed

- Fix NIP-47 `list_transactions` response deserialization

## v0.32.0 - 2024/06/07

### Changed

- Ignore malformed public keys during NIP19 event (`nevent`) parsing
- Update `Event::pubic_keys` and `Event_event_ids` methods
- Adj. NIP-10 support
- Change fingerprint of `nip05::verify`
- Rework `TagStandard::parse`
- Add `a` tag to zap receipts
- Change NIP-07 `Error::Wasm` variant value from `JsValue` to `String`
- Update `EventBuilder::live_event_msg` fingerprint
- Set `kind` arg in `EventBuilder::reaction_extended` as optional

### Added

- Add `Tag::is_root` method
- Add `JsonUtil::try_as_json` method
- Add `public_key` field to `TagStandard::Event`
- Add support to `nrelay` NIP-19 entity
- Add `Event::get_tag_content` method
- Add `Event::get_tags_content` method
- Add `Event::hashtags` method

### Fixed

- Fix re-serialization of events that contains unknown keys during deserialization
- Fix `Nip21::to_nostr_uri` serialization
- Add missing `TagStandard::PublicKeyLiveEvent` variant to `Event::public_keys`

### Removed

- Remove `verify_blocking` and `get_profile_blocking` functions
- Remove `RelayInformationDocument::get_blocking`
- Remove `blocking` feature

## v0.31.0 - 2024/05/17

### Changed

- Update fingerprint of NIP26 functions
- Update fingerprint of `EventBuilder::zap_receipt` constructor
- Update `EventId::new` fingerprint
- Update fingerprint of `nip05::verify` function
- Improve performance of `Filter::match_event`
- Adj. kind to be `u16` instead of `u64` according to NIP01
- Improve NIP19 serialization performance
- Improve `EventId::from_hex` performance
- Rename `Tag` enum to `TagStandard`
- Adj. NIP17 naming
- Allow setting a `Timestamp` tweak range
- Adj. NIP59 timestamp tweak range
- Reorganize `tag` module
- Manually impl `fmt::Debug` for `Publickey`

### Added

- Impl TryIntoUrl for &String
- Derive default traits for `HttpData`, `LiveEventHost` and `LiveEvent`
- Add tags indexes to `Event`
- Add `hex::decode_to_slice`
- Add `SecretKey::generate`
- Add `Tag` struct
- Add `EventBuilder::add_tags` method

### Fixed

- Fix NIP19 event (`nevent`) serialization

### Removed

- Remove `GenericTagValue`

## v0.30.0 - 2024/04/15

### Changed

- Adapted NIP46 to last changes
- Change `Tag::parse` arg from `Vec<S>` to `&[S]`
- Allow parsing public key from NIP21 uri with `PublicKey::parse`
- Allow parsing event ID from NIP21 uri with `EventId::parse`
- Construct `GenericTagValue` based on `SingleLetterTag` in `deserialize_generic_tags`
- Set `UnsignedEvent` ID as optional
- Update `TryIntoUrl::try_into_url` fingerprint
- nostr: bump `bitcoin` to `0.31`

### Added

- Add `Report::Other` variant
- Add `EventBuilder::reaction_extended`
- Add NIP32 support

### Fixed

- Fix `Tag::content` return always `None` when `Tag::Generic`
- Fix NIP46 `Request::from_message` deserialization
- Fix `NostrConnectURI` serialization
- Fix `LookupInvoiceParams`

## v0.29.1 - 2024/03/26

### Fixed

- Fix deserialization issues for events with non-standard `k` and `x` tags
