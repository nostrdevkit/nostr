# Nostr

## Project structure

The project is split up into several crates:

- [**nostr**](./nostr): Rust implementation of Nostr protocol
- Signers
    - [**nostr-browser-signer**](./signer/nostr-browser-signer): Nostr Browser signer implementation (NIP-07)
    - [**nostr-browser-signer-proxy**](./signer/nostr-browser-signer-proxy): Proxy for using the Nostr Browser signer (NIP-07) in native applications
    - [**nostr-connect**](./signer/nostr-connect): Nostr Connect (NIP-46) 
- [**nostr-database**](./database/nostr-database): Events database traits
    - [**nostr-memory**](./database/nostr-memory): In-memory events database
    - [**nostr-lmdb**](./database/nostr-lmdb): LMDB storage backend
    - [**nostr-ndb**](./database/nostr-ndb): [nostrdb](https://github.com/damus-io/nostrdb) storage backend
    - [**nostr-sqlite**](./database/nostr-sqlite): SQLite storage backend
- [**nostr-gossip**](./gossip/nostr-gossip): Gossip traits
    - [**nostr-gossip-memory**](./gossip/nostr-gossip-memory): In-memory gossip database
    - [**nostr-gossip-sqlite**](./gossip/nostr-gossip-sqlite): SQLite storage for gossip
- [**nostr-blossom**](./nostr-blossom): A library for interacting with the Blossom protocol
- [**nostr-sdk**](./nostr-sdk): A full-featured SDK for building high-performance and reliable nostr applications
- [**nwc**](./nwc): Nostr Wallet Connect (NWC) client (NIP-47)

## Supported NIPs

The table below lists which NIPs have implementations somewhere in this workspace. 
Some features are behind crate flags or only available when using a specific crate (e.g., signer integrations). 

✅ means “implemented and tested behind the relevant feature flag”, ❌ means “not available anywhere in this repo yet”.

| Supported | NIP                                                                                                             |
|:---------:|-----------------------------------------------------------------------------------------------------------------|
|     ✅     | [01 - Basic protocol flow description](https://github.com/nostr-protocol/nips/blob/master/01.md)                |
|     ✅     | [02 - Follow List](https://github.com/nostr-protocol/nips/blob/master/02.md)                                    |
|     ✅     | [03 - OpenTimestamps Attestations for Events](https://github.com/nostr-protocol/nips/blob/master/03.md)         |
|     ✅     | [04 - Encrypted Direct Message](https://github.com/nostr-protocol/nips/blob/master/04.md)                       |
|     ✅     | [05 - Mapping Nostr keys to DNS-based internet ids](https://github.com/nostr-protocol/nips/blob/master/05.md)   |
|     ✅     | [06 - Basic key derivation from mnemonic seed phrase](https://github.com/nostr-protocol/nips/blob/master/06.md) |
|     ✅     | [07 - `window.nostr` capability for web browsers](https://github.com/nostr-protocol/nips/blob/master/07.md)     |
|     ❌     | [08 - Handling Mentions](https://github.com/nostr-protocol/nips/blob/master/08.md)                              |
|     ✅     | [09 - Event Deletion](https://github.com/nostr-protocol/nips/blob/master/09.md)                                 |
|     ✅     | [10 - Use of `e` and `p` tags in text events](https://github.com/nostr-protocol/nips/blob/master/10.md)         |
|     ✅     | [11 - Relay Information Document](https://github.com/nostr-protocol/nips/blob/master/11.md)                     |
|     ✅     | [13 - Proof of Work](https://github.com/nostr-protocol/nips/blob/master/13.md)                                  |
|     ✅     | [14 - Subject tag in text events](https://github.com/nostr-protocol/nips/blob/master/14.md)                     |
|     ✅     | [15 - Nostr Marketplace](https://github.com/nostr-protocol/nips/blob/master/15.md)                              |
|     ✅     | [17 - Private Direct Messages](https://github.com/nostr-protocol/nips/blob/master/17.md)                        |
|     ✅     | [18 - Reposts](https://github.com/nostr-protocol/nips/blob/master/18.md)                                        |
|     ✅     | [19 - bech32-encoded entities](https://github.com/nostr-protocol/nips/blob/master/19.md)                        |
|     ✅     | [21 - URI scheme](https://github.com/nostr-protocol/nips/blob/master/21.md)                                     |
|     ✅     | [22 - Comment](https://github.com/nostr-protocol/nips/blob/master/22.md)                                        |
|     ✅     | [23 - Long-form Content](https://github.com/nostr-protocol/nips/blob/master/23.md)                              |
|     ✅     | [24 - Extra metadata fields and tags](https://github.com/nostr-protocol/nips/blob/master/24.md)                 |
|     ✅     | [25 - Reactions](https://github.com/nostr-protocol/nips/blob/master/25.md)                                      |
|     ✅     | [26 - Delegated Event Signing](https://github.com/nostr-protocol/nips/blob/master/26.md)                        |
|     ❌     | [27 - Text Note References](https://github.com/nostr-protocol/nips/blob/master/27.md)                           |
|     ✅     | [28 - Public Chat](https://github.com/nostr-protocol/nips/blob/master/28.md)                                    |
|     ❌     | [29 - Relay-based Groups](https://github.com/nostr-protocol/nips/blob/master/29.md)                             |
|     ✅     | [30 - Custom Emoji](https://github.com/nostr-protocol/nips/blob/master/30.md)                                   |
|     ✅     | [31 - Dealing with Unknown Events](https://github.com/nostr-protocol/nips/blob/master/31.md)                    |
|     ✅     | [32 - Labeling](https://github.com/nostr-protocol/nips/blob/master/32.md)                                       |
|     ✅     | [34 - `git` stuff](https://github.com/nostr-protocol/nips/blob/master/34.md)                                    |
|     ✅     | [35 - Torrents](https://github.com/nostr-protocol/nips/blob/master/35.md)                                       |
|     ✅     | [36 - Sensitive Content](https://github.com/nostr-protocol/nips/blob/master/36.md)                              |
|     ❌     | [37 - Draft Events](https://github.com/nostr-protocol/nips/blob/master/37.md)                                   |
|     ✅     | [38 - User Statuses](https://github.com/nostr-protocol/nips/blob/master/38.md)                                  |
|     ✅     | [39 - External Identities in Profiles](https://github.com/nostr-protocol/nips/blob/master/39.md)                |
|     ✅     | [40 - Expiration Timestamp](https://github.com/nostr-protocol/nips/blob/master/40.md)                           |
|     ✅     | [42 - Authentication of clients to relays](https://github.com/nostr-protocol/nips/blob/master/42.md)            |
|     ✅     | [44 - Encrypted Payloads (Versioned)](https://github.com/nostr-protocol/nips/blob/master/44.md)                 |
|     ✅     | [45 - Event Counts](https://github.com/nostr-protocol/nips/blob/master/45.md)                                   |
|     ✅     | [46 - Nostr Connect](https://github.com/nostr-protocol/nips/blob/master/46.md)                                  |
|     ✅     | [47 - Wallet Connect](https://github.com/nostr-protocol/nips/blob/master/47.md)                                 |
|     ✅     | [48 - Proxy Tags](https://github.com/nostr-protocol/nips/blob/master/48.md)                                     |
|     ✅     | [49 - Private Key Encryption](https://github.com/nostr-protocol/nips/blob/master/49.md)                         |
|     ✅     | [50 - Search Capability](https://github.com/nostr-protocol/nips/blob/master/50.md)                              |
|     ✅     | [51 - Lists](https://github.com/nostr-protocol/nips/blob/master/51.md)                                          |
|     ❌     | [52 - Calendar Events](https://github.com/nostr-protocol/nips/blob/master/52.md)                                |
|     ✅     | [53 - Live Activities](https://github.com/nostr-protocol/nips/blob/master/53.md)                                |
|     ❌     | [54 - Wiki](https://github.com/nostr-protocol/nips/blob/master/54.md)                                           |
|     -     | [55 - Android Signer Application](https://github.com/nostr-protocol/nips/blob/master/55.md)                     |
|     ✅     | [56 - Reporting](https://github.com/nostr-protocol/nips/blob/master/56.md)                                      |
|     ✅     | [57 - Lightning Zaps](https://github.com/nostr-protocol/nips/blob/master/57.md)                                 |
|     ✅     | [58 - Badges](https://github.com/nostr-protocol/nips/blob/master/58.md)                                         |
|     ✅     | [59 - Gift Wrap](https://github.com/nostr-protocol/nips/blob/master/59.md)                                      |
|     ✅     | [60 - Cashu Wallet](https://github.com/nostr-protocol/nips/blob/master/60.md)                                   |
|     ❌     | [61 - Nutzaps](https://github.com/nostr-protocol/nips/blob/master/61.md)                                        |
|     ✅     | [62 - Request to Vanish](https://github.com/nostr-protocol/nips/blob/master/62.md)                              |
|     ❌     | [64 - Chess (PGN)](https://github.com/nostr-protocol/nips/blob/master/64.md)                                    |
|     ✅     | [65 - Relay List Metadata](https://github.com/nostr-protocol/nips/blob/master/65.md)                            |
|     ❌     | [66 - Relay Discovery and Liveness Monitoring](https://github.com/nostr-protocol/nips/blob/master/66.md)        |
|     ❌     | [68 - Picture-first feeds](https://github.com/nostr-protocol/nips/blob/master/68.md)                            |
|     ❌     | [69 - P2P Order events](https://github.com/nostr-protocol/nips/blob/master/69.md)                               |
|     ✅     | [70 - Protected Events](https://github.com/nostr-protocol/nips/blob/master/70.md)                               |
|     ❌     | [71 - Video Events](https://github.com/nostr-protocol/nips/blob/master/71.md)                                   |
|     ❌     | [72 - Moderated Communities](https://github.com/nostr-protocol/nips/blob/master/72.md)                          |
|     ✅     | [73 - External Content IDs](https://github.com/nostr-protocol/nips/blob/master/73.md)                           |
|     ❌     | [75 - Zap Goals](https://github.com/nostr-protocol/nips/blob/master/75.md)                                      |
|     ✅     | [77 - Negentropy Syncing](https://github.com/nostr-protocol/nips/blob/master/77.md)                             |
|     ✅     | [78 - Arbitrary custom app data](https://github.com/nostr-protocol/nips/blob/master/78.md)                      |
|     ✅     | [7D - Threads](https://github.com/nostr-protocol/nips/blob/master/7D.md)                                        |
|     ❌     | [84 - Highlights](https://github.com/nostr-protocol/nips/blob/master/84.md)                                     |
|     ❌     | [86 - Relay Management API](https://github.com/nostr-protocol/nips/blob/master/86.md)                           |
|     ❌     | [87 - Ecash Mint Discoverability](https://github.com/nostr-protocol/nips/blob/master/87.md)                     |
|     ✅     | [88 - Polls](https://github.com/nostr-protocol/nips/blob/master/88.md)                                          |
|     ❌     | [89 - Recommended Application Handlers](https://github.com/nostr-protocol/nips/blob/master/89.md)               |
|     ✅     | [90 - Data Vending Machine](https://github.com/nostr-protocol/nips/blob/master/90.md)                           |
|     ❌     | [92 - Media Attachments](https://github.com/nostr-protocol/nips/blob/master/92.md)                              |
|     ✅     | [94 - File Metadata](https://github.com/nostr-protocol/nips/blob/master/94.md)                                  |
|     ✅     | [98 - HTTP Auth](https://github.com/nostr-protocol/nips/blob/master/98.md)                                      |
|     ❌     | [99 - Classified Listings](https://github.com/nostr-protocol/nips/blob/master/99.md)                            |
|     ✅     | [117 - Double Ratchet sessions](https://github.com/nostr-protocol/nips/pull/1813)                               |
|     ✅     | [118 - Double Ratchet invites](https://github.com/nostr-protocol/nips/pull/1813)                                |
|     ✅     | [A0 - Voice Messages](https://github.com/nostr-protocol/nips/blob/master/A0.md)                                 |
|     ✅     | [B0 - Web Bookmarks](https://github.com/nostr-protocol/nips/blob/master/B0.md)                                  |
|     ✅     | [B7 - Blossom](https://github.com/nostr-protocol/nips/blob/master/B7.md)                                        |
|     ✅     | [C0 - Code Snippets](https://github.com/nostr-protocol/nips/blob/master/C0.md)                                  |
|     ✅     | [C7 - Chats](https://github.com/nostr-protocol/nips/blob/master/C7.md)                                          |

## State

**These libraries are in ALPHA state**, things that are implemented generally work but the API will change in breaking ways.

## Donations

Nostr Dev Kit is free and open-source. This means we do not earn any revenue by selling it. Instead, we rely on your financial support. If you actively use any of the libs/software/services, then please [donate](https://nostrdevkit.org/donate).

## License

This project is distributed under the MIT software license - see the [LICENSE](LICENSE) file for details
