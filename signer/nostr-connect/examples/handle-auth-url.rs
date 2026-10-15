// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use nostr_connect::prelude::*;

#[derive(Debug, Clone)]
struct MyAuthUrlHandler;

impl AuthUrlHandler for MyAuthUrlHandler {
    fn on_auth_url(
        &self,
        auth_url: Url,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> {
        Box::pin(async move {
            println!("Opening auth url: {auth_url}");
            webbrowser::open(auth_url.as_str()).unwrap();
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let uri = NostrConnectUri::parse(
        "bunker://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss://relay.nsec.app",
    )?;
    let app_keys = Keys::parse("nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99")?;
    let timeout = Duration::from_secs(120);

    let connect: NostrConnect = NostrConnect::builder(uri, app_keys)
        .timeout(timeout)
        .auth_url_handler(Arc::new(MyAuthUrlHandler))
        .build()?;

    let receiver =
        PublicKey::parse("npub1acg6thl5psv62405rljzkj8spesceyfz2c32udakc2ak0dmvfeyse9p35c")?;
    let content = connect.nip44_encrypt_async(&receiver, "Hi").await?;
    println!("Content: {content}");

    let event = EventBuilder::new(Kind::TextNote, "Testing rust-nostr")
        .finalize_async(&connect)
        .await?;
    println!("Event: {}", event.as_json());

    Ok(())
}
