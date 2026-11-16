// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::time::Duration;

use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let keys = Keys::parse("nsec1ufnus6pju578ste3v90xd5m2decpuzpql2295m3sknqcjzyys9ls0qlc85")?;

    // Create an authenticator from a signer
    let authenticator = SignerAuthenticator::new(keys.clone());

    // Create a client with the authenticator
    let client = Client::builder().authenticator(authenticator).build();

    client.add_relay("wss://pyramid.fiatjaf.com/").await?;

    client.connect().and_wait(Duration::from_secs(10)).await;

    // Publish a text note
    let event = EventBuilder::new(Kind::TextNote)
        .content("Hello world")
        .finalize(&keys)?;
    let output = client.send_event(&event).await?;
    println!("Event ID: {}", output.id().to_bech32()?);
    println!("Sent to: {:?}", output.success);
    println!("Not sent to: {:?}", output.failed);

    Ok(())
}
