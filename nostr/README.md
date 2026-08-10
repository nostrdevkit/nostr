# Nostr

[![crates.io](https://img.shields.io/crates/v/nostr.svg)](https://crates.io/crates/nostr)
[![crates.io - Downloads](https://img.shields.io/crates/d/nostr)](https://crates.io/crates/nostr)
[![Documentation](https://docs.rs/nostr/badge.svg)](https://docs.rs/nostr)
[![CI](https://github.com/nostrdevkit/nostr/actions/workflows/ci.yml/badge.svg)](https://github.com/nostrdevkit/nostr/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/crates/l/nostr.svg)](../../LICENSE)

## Description

Rust implementation of Nostr protocol.

You may be interested in:
* [`nostr-sdk`](https://crates.io/crates/nostr-sdk) if you want to write a typical nostr client or bot
* [`nostr-connect`](https://crates.io/crates/nostr-connect): Nostr Connect (NIP46) client and signer
* [`nwc`](https://crates.io/crates/nwc): Nostr Wallet Connect (NWC) client

## Getting started

```rust,no_run
use std::num::NonZeroU8;

use nostr::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate new random keys
    let keys = Keys::generate();

    // Or use your already existing (from hex or bech32)
    let keys = Keys::parse("hex-or-bech32-secret-key")?;

    // Convert public key to bech32
    println!("Public key: {}", keys.public_key().to_bech32()?);

    let metadata = Metadata::new()
        .name("username")
        .display_name("My Username")
        .about("Description")
        .picture(Url::parse("https://example.com/avatar.png")?)
        .banner(Url::parse("https://example.com/banner.png")?)
        .nip05("username@example.com")
        .lud16("pay@yukikishimoto.com")
        .custom_field("custom_field", "my value");

    let event: Event = metadata.finalize(&keys)?;

    // New text note
    let event: Event =
        EventBuilder::new(Kind::TextNote, "Hello from rust-nostr").finalize(&keys)?;

    // New POW text note
    let difficulty: NonZeroU8 = NonZeroU8::new(16).unwrap();
    let unsigned: UnsignedEvent =
        EventBuilder::new(Kind::TextNote, "POW text note from rust-nostr")
            .finalize_unsigned(keys.public_key());
    let unsigned: UnsignedEvent = unsigned.mine(&SingleThreadPow, difficulty)?;
    let event: Event = unsigned.finalize(&keys)?;

    // Convert client message to JSON
    let json = ClientMessage::event(event).as_json();
    println!("{json}");

    Ok(())
}
```

More examples can be found in the [examples/](https://github.com/nostrdevkit/nostr/tree/master/crates/nostr/examples) directory.

## Crate Feature Flags

The following crate feature flags are available:

| Feature            | Default | Description                                                   |
|--------------------|:-------:|---------------------------------------------------------------|
| `std`              |   Yes   | Enable `std` library                                          |
| `alloc`            |   No    | Needed to use this library in `no_std` context                |
| `rand`             |   No    | Enables `rand` traits                                         |
| `os-rng`           |   No    | Enable OS Random Number Generator                             |
| `pow-multi-thread` |   No    | Enable event POW mining using multi-threads                   |
| `all-nips`         |   No    | Enable all NIPs                                               |
| `nip03`            |   No    | Enable NIP-03: OpenTimestamps Attestations for Events         |
| `nip04`            |   No    | Enable NIP-04: Encrypted Direct Message                       |
| `nip06`            |   No    | Enable NIP-06: Basic key derivation from mnemonic seed phrase |
| `nip44`            |   No    | Enable NIP-44: Encrypted Payloads (Versioned)                 |
| `nip46`            |   No    | Enable NIP-46: Nostr Connect                                  |
| `nip47`            |   No    | Enable NIP-47: Nostr Wallet Connect                           |
| `nip49`            |   No    | Enable NIP-49: Private Key Encryption                         |
| `nip59`            |   No    | Enable NIP-59: Gift Wrap                                      |
| `nip60`            |   No    | Enable NIP-60: Cashu Wallets                                  |
| `nip117`           |   No    | Enable NIP-117: Double Ratchet sessions                       |
| `nip118`           |   No    | Enable NIP-118: Double Ratchet invites                        |

## WASM

This crate supports the `wasm32-unknown-unknown` and `wasm32-wasip2` targets. 
The other WASM targets may be supported bur are not tested.

### wasm32-wasip2

To compile for `wasm32-wasip2` you need to:

- Download the WASI SDK from <https://github.com/WebAssembly/wasi-sdk>
- Extract it and set the `WASI_SDK` environment variable
- Set the `CC_wasm32_wasip2="$WASI_SDK/bin/clang"`, `AR_wasm32_wasip2="$WASI_SDK/bin/llvm-ar"` and `CFLAGS_wasm32_wasip2="--sysroot=$WASI_SDK/share/wasi-sysroot"` environment variables
- Build!

**Example (note, links and version may be outdated):**

```bash
# 1. Download and extract the WASI SDK
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-29/wasi-sdk-29.0-x86_64-linux.tar.gz
tar xvf wasi-sdk-29.0-x86_64-linux.tar.gz

# 2. Set the path variable (adjust if you extracted it somewhere else)
export WASI_SDK="$(pwd)/wasi-sdk-29.0-x86_64-linux"

# 3. Export the environment variables that the 'cc' crate looks for
# This tells the build script specifically which compiler to use for this target
export CC_wasm32_wasip2="$WASI_SDK/bin/clang"
export AR_wasm32_wasip2="$WASI_SDK/bin/llvm-ar"
export CFLAGS_wasm32_wasip2="--sysroot=$WASI_SDK/share/wasi-sysroot"

# 4. Now run your build command
cargo build --target wasm32-wasip2
```

### wasm32-unknown-unknown

On **macOS** you need to install `llvm`:

```shell
brew install llvm
LLVM_PATH=$(brew --prefix llvm)
AR="${LLVM_PATH}/bin/llvm-ar" CC="${LLVM_PATH}/bin/clang" cargo build --target wasm32-unknown-unknown
```

The other platforms should work out of the box.

## Embedded

This crate support [`no_std`](https://docs.rust-embedded.org/book/intro/no-std.html) environments.

Check the example in the [embedded/](https://github.com/nostrdevkit/nostr/tree/master/crates/nostr/examples/embedded) directory.

## Changelog

All notable changes to this library are documented in the [CHANGELOG.md](CHANGELOG.md).

## State

**This library is in an ALPHA state**, things that are implemented generally work but the API will change in breaking ways.

## Donations

Nostr Dev Kit is free and open-source. This means we do not earn any revenue by selling it. Instead, we rely on your financial support. If you actively use any of the libs/software/services, then please [donate](https://nostrdevkit.org/donate).

## License

This project is distributed under the MIT software license - see the [LICENSE](../../LICENSE) file for details
