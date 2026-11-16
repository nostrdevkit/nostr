# Nostr SDK

[![crates.io](https://img.shields.io/crates/v/nostr-sdk.svg)](https://crates.io/crates/nostr-sdk)
[![crates.io - Downloads](https://img.shields.io/crates/d/nostr-sdk)](https://crates.io/crates/nostr-sdk)
[![Documentation](https://docs.rs/nostr-sdk/badge.svg)](https://docs.rs/nostr-sdk)
[![CI](https://github.com/nostrdevkit/nostr/actions/workflows/ci.yml/badge.svg)](https://github.com/nostrdevkit/nostr/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/crates/l/nostr-sdk.svg)](../LICENSE)

## Description

A full-featured SDK for building high-performance and reliable nostr applications.

The SDK can be used to build both sides of a nostr application:

- clients, bots, and services that connect to existing relays;
- local relays that run inside your process, including mock relays for tests.

## Getting started

### Client

```rust,no_run
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate new random keys
    let keys = Keys::generate();

    // Or use your already existing (from hex or bech32)
    let keys = Keys::parse("hex-or-bech32-secret-key")?;

    // Show bech32 public key
    let bech32_pubkey: String = keys.public_key().to_bech32()?;
    println!("Bech32 PubKey: {}", bech32_pubkey);

    // Configure client to use proxy for `.onion` relays
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9050));
    let proxy: Proxy = Proxy::onion(addr);
    let client = Client::builder().proxy(proxy).build();

    // Add relays
    client.add_relay("wss://relay.damus.io").await?;
    client.add_relay("ws://jgqaglhautb4k6e6i2g34jakxiemqp6z4wynlirltuukgkft2xuglmqd.onion").await?;

    // Add read relay
    client.add_relay("wss://relay.nostr.info").capabilities(RelayCapabilities::READ).await?;

    // Connect to relays
    client.connect().await;

    // Publish a text note
    let event = EventBuilder::new(Kind::TextNote).content("My first text note from rust-nostr!")
        .finalize(&keys)?;
    client.send_event(&event).await?;

    Ok(())
}
```

### Local Relay

The `local-relay` feature enables in-process relays without re-implementing policies, storage, or protocol handling.

- `LocalRelay` runs a fully fledged relay inside your process.
- `MockRelay` runs an ephemeral relay for unit and integration tests.

```rust,ignore
use std::time::Duration;

use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the relay. If no database is provided, an in-memory database is used.
    let relay = LocalRelay::builder()
        .port(7777)
        .rate_limit(RateLimit {
            max_reqs: 128,
            notes_per_minute: 30,
        })
        .build();

    // Start the relay.
    relay.run().await?;

    println!("Relay listening on {}", relay.url().await);

    // Keep the process running
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
```

More examples can be found in the [examples directory](./examples).

## Crate Feature Flags

The following crate feature flags are available:

| Feature                   | Default | Description                                      |
|---------------------------|:-------:|--------------------------------------------------|
| `ring`                    |   Yes   | Enable `ring` crypto provider                    |
| `rustls-tls-webpki-roots` |   Yes   | Enable rustls with bundled Mozilla root certs    |
| `aws_lc_rs`               |   No    | Enable `aws-lc-rs` crypto provider               |
| `native-tls`              |   No    | Enable platform-native TLS                       |
| `native-tls-vendored`     |   No    | Enable platform-native TLS with vendored OpenSSL |
| `rustls-tls-native-roots` |   No    | Enable rustls with platform-native root certs    |
| `local-relay`             |   No    | Enable `nostr_sdk::local_relay` module           |

## Local Relay supported NIPs

| Supported | NIP                                                                                                  |
|:---------:|------------------------------------------------------------------------------------------------------|
|     ✅     | [01 - Basic protocol flow description](https://github.com/nostr-protocol/nips/blob/master/01.md)     |
|     ✅     | [09 - Event Deletion](https://github.com/nostr-protocol/nips/blob/master/09.md)                      |
|     ❌     | [11 - Relay Information Document](https://github.com/nostr-protocol/nips/blob/master/11.md)          |
|     ✅     | [17 - Private Direct Messages](https://github.com/nostr-protocol/nips/blob/master/17.md)             |
|    🔧*    | [40 - Expiration Timestamp](https://github.com/nostr-protocol/nips/blob/master/40.md)                |
|     ✅     | [42 - Authentication of clients to relays](https://github.com/nostr-protocol/nips/blob/master/42.md) |
|    🔧     | [50 - Search Capability](https://github.com/nostr-protocol/nips/blob/master/50.md)                   |
|    🔧     | [62 - Request to Vanish](https://github.com/nostr-protocol/nips/blob/master/62.md)                   |
|     ✅     | [70 - Protected Events](https://github.com/nostr-protocol/nips/blob/master/70.md)                    |
|     ✅     | [77 - Negentropy Syncing](https://github.com/nostr-protocol/nips/blob/master/77.md)                  |

**Legend:**

- ✅ Fully supported
- 🔧 Depends on the database implementation
- ❌ Not supported

*: The relay does not accept or send expired events. The database has to delete them.

## WASM

This crate supports the `wasm32` targets.

An example can be found at [`nostr-sdk-wasm-example`](https://github.com/nostrdevkit/nostr-sdk-wasm-example) repo.

On macOS, you need to install `llvm`:

```shell
brew install llvm
LLVM_PATH=$(brew --prefix llvm)
AR="${LLVM_PATH}/bin/llvm-ar" CC="${LLVM_PATH}/bin/clang" cargo build --target wasm32-unknown-unknown
```

NOTE: Currently `nip03` feature not support WASM.

## Changelog

All notable changes to this library are documented in the [CHANGELOG.md](CHANGELOG.md).

## State

**This library is in an ALPHA state**, things that are implemented generally work, but the API will change in breaking ways.

## Donations

Nostr Dev Kit is free and open-source. This means we do not earn any revenue by selling it. Instead, we rely on your financial support. If you actively use any of the libs/software/services, then please [donate](https://nostrdevkit.org/donate).

## License

This project is distributed under the MIT software license – see the [LICENSE](../LICENSE) file for details
