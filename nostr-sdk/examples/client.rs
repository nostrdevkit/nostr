// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::num::NonZeroU8;

use nostr::nips::nip13::SingleThreadPow;
use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let client = Client::new();

    client.add_relay("wss://relay.damus.io").await?;
    client.add_relay("wss://nostr.wine").await?;
    client.add_relay("wss://relay.rip").await?;

    client.connect().await;

    let keys = Keys::parse("nsec1ufnus6pju578ste3v90xd5m2decpuzpql2295m3sknqcjzyys9ls0qlc85")?;

    // Publish a text note
    let event = EventBuilder::new(Kind::TextNote)
        .content("Hello world")
        .finalize(&keys)?;
    let output = client.send_event(&event).await?;
    println!("Event ID: {}", output.id().to_bech32()?);
    println!("Sent to: {:?}", output.success);
    println!("Not sent to: {:?}", output.failed);

    // Create a text note POW event to relays
    let unsigned = EventBuilder::new(Kind::TextNote)
        .content("POW text note from NostrDevKit")
        .finalize_unsigned(keys.public_key());
    let unsigned = unsigned
        .mine_async(&SingleThreadPow, NonZeroU8::new(20).unwrap())
        .await?;
    let event = unsigned.finalize(&keys)?;
    client.send_event(&event).await?;

    Ok(())
}
