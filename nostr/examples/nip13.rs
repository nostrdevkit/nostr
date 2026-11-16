// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::num::NonZeroU8;

use nostr::prelude::*;

fn main() -> Result<(), Error> {
    let keys = Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")?;

    let difficulty = NonZeroU8::new(20).unwrap(); // leading zero bits
    let content = "This is a Nostr message with embedded proof-of-work";

    // Build unsigned event
    let unsigned: UnsignedEvent = EventBuilder::new(Kind::TextNote)
        .content(content)
        .finalize_unsigned(keys.public_key());

    #[cfg(not(feature = "pow-multi-thread"))]
    let adapter = SingleThreadPow;
    #[cfg(feature = "pow-multi-thread")]
    let adapter = MultiThreadPow;

    // Compute POW
    let unsigned: UnsignedEvent = unsigned.mine(&adapter, difficulty)?;

    // Sign event
    let event: Event = unsigned.finalize(&keys)?;

    println!("{}", event.as_json());

    Ok(())
}
