// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use nostr_connect::prelude::*;
use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let app_keys = Keys::parse("nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99")?;

    // Compose signer from bunker URI
    let uri = NostrConnectUri::parse(
        "bunker://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss://relay.nsec.app",
    )?;
    let signer = NostrConnect::new(uri, app_keys)?;

    // Get bunker URI for future connections
    let bunker_uri: NostrConnectUri = signer.bunker_uri().await?;
    println!("\nBunker URI: {bunker_uri}\n");

    // Compose client
    let client = Client::default();
    client.add_relay("wss://relay.damus.io").await?;
    client.connect().await;

    // Publish events
    let event = EventBuilder::new(Kind::TextNote, "Testing rust-nostr NIP46 signer [bunker]")
        .finalize_async(&signer)
        .await?;
    let output = client.send_event(&event).await?;
    println!("Published text note: {}\n", output.id());

    let receiver =
        PublicKey::from_bech32("npub1drvpzev3syqt0kjrls50050uzf25gehpz9vgdw08hvex7e0vgfeq0eseet")?;
    let msg = PrivateDirectMessageBuilder::new(receiver, "Hello from rust-nostr")
        .finalize_async(&signer)
        .await?;
    let output = client.send_event(&msg).to_nip17().await?;
    println!("Sent DM: {}", output.id());

    Ok(())
}
