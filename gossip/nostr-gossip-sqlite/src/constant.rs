// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::time::Duration;

use nostr_gossip::flags::GossipFlags;

// TODO: make this configurable
pub(super) const TTL_OUTDATED: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

pub(super) const READ_WRITE_FLAGS: GossipFlags = {
    let mut flags = GossipFlags::READ;
    flags.add(GossipFlags::WRITE);
    flags
};

pub(super) const MAX_RELAYS_PER_PK: usize = 7;
pub(super) const RELAYS_QUERY_LIMIT: u8 = 21;
