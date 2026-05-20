// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-05 over Namecoin (`.bit`) — parsing + verification.
//!
//! This crate exposes only the pure pieces of the protocol — identifier
//! parsing, name-value JSON extraction, NAME_UPDATE script encode/decode,
//! and the Electrum scripthash derivation. The transport step (talking
//! to an ElectrumX server, typically over WSS) is left to the caller.

use nostr::nips::nip05namecoin::{
    self, NamecoinAddress, Nip05NamecoinProfile, build_name_index_script, electrum_script_hash,
};

fn main() -> Result<(), nip05namecoin::Error> {
    // Identifier shapes the module recognises.
    for input in [
        "alice@example.bit",
        "example.bit",
        "d/example",
        "id/alice",
        "nostr:alice@example.bit",
    ] {
        let routed = nip05namecoin::is_valid_identifier(input);
        let parsed = NamecoinAddress::parse(input)?;
        println!(
            "{:>32}  routed={}  name={}  local={}",
            input,
            routed,
            parsed.namecoin_name(),
            parsed.local_part()
        );
    }

    // Walkthrough for a single identifier.
    let address = NamecoinAddress::parse("alice@example.bit")?;
    println!("\nNamecoin name to look up:  {}", address.namecoin_name());
    println!(
        "Electrum scripthash:       {}",
        address.electrum_script_hash()
    );
    println!(
        "(Same as electrum_script_hash(build_name_index_script(...)) — {})",
        electrum_script_hash(&build_name_index_script(address.namecoin_name().as_bytes()))
    );

    // Caller fetches the Namecoin name value out-of-band — for example
    // by speaking JSON-RPC to one of the public Namecoin ElectrumX
    // servers in `nip05namecoin::DEFAULT_ELECTRUMX_SERVERS`, calling
    // `blockchain.scripthash.get_history` followed by
    // `blockchain.transaction.get`, and then running the NAME_UPDATE
    // script output through `parse_name_update_script` to extract the
    // JSON value. Here we just hand the value over directly.
    let value = r#"{
        "nostr": {
            "names": {
                "_": "460c25e682fda7832b52d1f22d3d22b3176d972f60dcdc3212ed8c92ef85065c",
                "alice": "94a9eb13c37b3c1519169a426d383c51530f4fe8f693c62f32b321adfdd4ec7f"
            },
            "relays": {
                "94a9eb13c37b3c1519169a426d383c51530f4fe8f693c62f32b321adfdd4ec7f": [
                    "wss://relay.example.com"
                ]
            }
        }
    }"#;

    let profile = Nip05NamecoinProfile::from_raw_json(&address, value)?;
    println!("\nResolved pubkey:           {}", profile.public_key);
    println!("Relays:                    {:?}", profile.relays);

    // Bare-domain root lookup falls back to "_".
    let root = NamecoinAddress::parse("example.bit")?;
    let root_profile = Nip05NamecoinProfile::from_raw_json(&root, value)?;
    println!("\nRoot (_) pubkey:           {}", root_profile.public_key);

    println!("\nOK");
    Ok(())
}
