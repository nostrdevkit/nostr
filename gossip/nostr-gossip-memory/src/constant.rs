// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::time::Duration;

// TODO: make this configurable
pub(super) const TTL_OUTDATED: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
pub(super) const MAX_NIP17_SIZE: usize = 7;
pub(super) const MAX_NIP65_SIZE: usize = 7;
pub(super) const MAX_RELAYS_PER_PK: usize = 7;
