// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use nostr_ndb::NdbDatabase;
use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let database = NdbDatabase::open("./db/ndb")?;
    let client: Client = Client::builder().database(database).build();

    client.add_relay("wss://relay.damus.io").await?;
    client.add_relay("wss://atl.purplerelay.com").await?;
    client.connect().await;

    let keys = Keys::parse("nsec1ufnus6pju578ste3v90xd5m2decpuzpql2295m3sknqcjzyys9ls0qlc85")?;

    // Publish a text note
    let event = EventBuilder::new(Kind::TextNote)
        .content("Hello world")
        .finalize(&keys)?;
    client.send_event(&event).await?;

    // Negentropy reconcile
    let filter = Filter::new().author(keys.public_key());
    client.sync(filter).await?;

    // Query events from database
    let filter = Filter::new().author(keys.public_key()).limit(10);
    let events = client.database().query(filter).await?;
    println!("Events: {events:?}");

    Ok(())
}
