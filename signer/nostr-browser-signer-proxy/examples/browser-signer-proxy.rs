// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::time::Duration;

use nostr_browser_signer_proxy::prelude::*;
use tokio::{signal, time};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let proxy = BrowserSignerProxy::new(BrowserSignerProxyOptions::default());

    proxy.start().await?;

    println!("Url: {}", proxy.url());

    // Waits until the proxy session becomes active, checking every second.
    loop {
        if proxy.is_session_active() {
            break;
        }
        time::sleep(Duration::from_secs(1)).await;
    }

    // Get public key
    let public_key = proxy.get_public_key_async().await?;
    println!("Public key: {}", public_key);

    // Sign event
    let event = EventBuilder::new(Kind::TextNote)
        .content("Testing browser signer proxy")
        .finalize_async(&proxy)
        .await?;
    println!("Event: {}", event.as_json());

    // Build a gift wrap
    let receiver =
        PublicKey::parse("npub1drvpzev3syqt0kjrls50050uzf25gehpz9vgdw08hvex7e0vgfeq0eseet")?;
    let rumor = EventBuilder::new(Kind::Custom(123))
        .content("test")
        .finalize_unsigned(public_key);
    let gift_wrap = GiftWrapBuilder::new(receiver, rumor)
        .finalize_async(&proxy)
        .await?;
    println!("Gift wrap: {}", gift_wrap.as_json());

    // Keep up the program
    signal::ctrl_c().await?;

    Ok(())
}
