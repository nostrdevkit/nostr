// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-35: Torrents
//!
//! This module implements support for sharing BitTorrent metadata and comments through nostr events.
//!
//! <https://github.com/nostr-protocol/nips/blob/master/35.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin_hashes::sha1::Hash as Sha1Hash;

use crate::event::{EventBuilder, IntoEventBuilder, Kind};
use crate::types::url::Url;

/// Represents a file within a torrent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TorrentFile {
    /// File name/path
    pub name: String,
    /// File size in bytes
    pub size: u64,
}

/// Torrent metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Torrent {
    /// Torrent title
    pub title: String,
    /// Long description
    pub description: String,
    /// BitTorrent info hash
    pub info_hash: Sha1Hash,
    /// Files included in torrent
    pub files: Vec<TorrentFile>,
    /// Tracker URLs
    pub trackers: Vec<Url>,
    /// Categories (e.g. "video,movie,4k")
    pub categories: Vec<String>,
    /// Additional hashtags
    pub hashtags: Vec<String>,
}

// TODO: add Nip35Tag enum

impl IntoEventBuilder for Torrent {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::Torrent).content(self.description);

        builder.tags.reserve(
            2 + self.files.len()
                + self.trackers.len()
                + self.categories.len()
                + self.hashtags.len(),
        );

        builder.tags.push(["title", self.title.as_str()]);
        builder
            .tags
            .push(["x", self.info_hash.to_string().as_str()]);

        for file in self.files {
            builder
                .tags
                .push(["file", file.name.as_str(), file.size.to_string().as_str()]);
        }

        for tracker in self.trackers {
            builder.tags.push(["tracker", tracker.to_string().as_str()]);
        }

        for cat in self.categories {
            builder.tags.push(["i", format!("tcat:{cat}").as_str()]);
        }

        for hashtag in self.hashtags {
            builder.tags.push(["t", hashtag.as_str()]);
        }

        builder
    }
}
