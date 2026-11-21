// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Tags (tag list)

// TODO: remove Tags and move the main methods helpers (identifier, challenge, public_keys) in the Event impl?

use alloc::string::String;
use alloc::vec::{IntoIter, Vec};
use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Deref, DerefMut, Index, IndexMut};

use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Error, Tag};
use crate::event::EventId;
use crate::key::PublicKey;
use crate::nips::nip01::{Coordinate, Nip01Tag};
use crate::nips::nip40::Nip40Tag;
use crate::nips::nip42::Nip42Tag;
use crate::types::Timestamp;

/// Tags collection
#[derive(Clone, Default)]
pub struct Tags {
    list: Vec<Tag>,
}

impl fmt::Debug for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.list)
    }
}

impl PartialEq for Tags {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
    }
}

impl Eq for Tags {}

impl PartialOrd for Tags {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tags {
    fn cmp(&self, other: &Self) -> Ordering {
        self.list.cmp(&other.list)
    }
}

impl Hash for Tags {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.list.hash(state);
    }
}

impl Deref for Tags {
    type Target = Vec<Tag>;

    fn deref(&self) -> &Self::Target {
        &self.list
    }
}

impl DerefMut for Tags {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.list
    }
}

impl Index<usize> for Tags {
    type Output = Tag;

    fn index(&self, index: usize) -> &Self::Output {
        self.list.index(index)
    }
}

impl IndexMut<usize> for Tags {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.list.index_mut(index)
    }
}

impl Tags {
    /// Construct a new empty collection.
    #[inline]
    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Constructs a new, empty collection with at least the specified capacity.
    ///
    /// Check [`Vec::with_capacity`] doc to learn more.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            list: Vec::with_capacity(capacity),
        }
    }

    /// Construct the collection from a list of tags.
    pub fn from_list(list: Vec<Tag>) -> Self {
        Self { list }
    }

    /// Parse tags
    pub fn parse<I1, I2, S>(tags: I1) -> Result<Self, Error>
    where
        I1: IntoIterator<Item = I2>,
        I2: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut list: Vec<Tag> = Vec::new();

        for tag in tags.into_iter() {
            let tag: Tag = Tag::parse(tag)?;
            list.push(tag);
        }

        Ok(Self::from_list(list))
    }

    /// Convert [`Tags`] into [`Vec<Tag>`].
    #[inline]
    pub fn to_vec(self) -> Vec<Tag> {
        self.list
    }

    /// Extract identifier (`d` tag), if exists.
    #[inline]
    pub fn identifier(&self) -> Option<String> {
        let tag: &Tag = self.iter().find(|t| t.kind() == "d")?;

        match Nip01Tag::try_from(tag) {
            Ok(Nip01Tag::Identifier(identifier)) => Some(identifier),
            _ => None,
        }
    }

    /// Get [`Timestamp`] expiration, if exists.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/40.md>
    pub fn expiration(&self) -> Option<Timestamp> {
        let tag: &Tag = self.iter().find(|t| t.kind() == "expiration")?;

        match Nip40Tag::try_from(tag) {
            Ok(Nip40Tag::Expiration(expiration)) => Some(expiration),
            _ => None,
        }
    }

    /// Extract NIP42 challenge, if exists.
    #[inline]
    pub fn challenge(&self) -> Option<String> {
        let tag: &Tag = self.iter().find(|t| t.kind() == "challenge")?;

        match Nip42Tag::try_from(tag) {
            Ok(Nip42Tag::Challenge(challenge)) => Some(challenge),
            _ => None,
        }
    }

    /// Extract public keys from `p` tags.
    #[inline]
    pub fn public_keys(&self) -> impl Iterator<Item = PublicKey> + '_ {
        self.iter().filter_map(|t| {
            if t.kind() != "p" {
                return None;
            }

            let content = t.content()?;
            PublicKey::from_hex(content).ok()
        })
    }

    /// Extract event IDs from `e` tags.
    #[inline]
    pub fn event_ids(&self) -> impl Iterator<Item = EventId> + '_ {
        self.iter().filter_map(|t| {
            if t.kind() != "e" {
                return None;
            }

            let content = t.content()?;
            EventId::from_hex(content).ok()
        })
    }

    /// Extract coordinates from `a` tags.
    #[inline]
    pub fn coordinates(&self) -> impl Iterator<Item = Coordinate> + '_ {
        self.iter().filter_map(|t| {
            if t.kind() != "a" {
                return None;
            }

            let content = t.content()?;
            Coordinate::from_kpi_format(content).ok()
        })
    }

    /// Extract hashtags from `t` tags.
    #[inline]
    pub fn hashtags(&self) -> impl Iterator<Item = &str> + '_ {
        self.iter().filter_map(|t| {
            if t.kind() != "t" {
                return None;
            }

            t.content()
        })
    }
}

impl AsRef<[Tag]> for Tags {
    fn as_ref(&self) -> &[Tag] {
        self.as_slice()
    }
}

impl From<Vec<Tag>> for Tags {
    fn from(tags: Vec<Tag>) -> Self {
        Self::from_list(tags)
    }
}

impl IntoIterator for Tags {
    type Item = Tag;
    type IntoIter = IntoIter<Self::Item>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.list.into_iter()
    }
}

impl FromIterator<Tag> for Tags {
    #[inline]
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Tag>,
    {
        Self::from_list(iter.into_iter().collect())
    }
}

impl Serialize for Tags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for element in self.list.iter() {
            seq.serialize_element(&element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Tags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        type Data = Vec<Tag>;
        let tags: Vec<Tag> = Data::deserialize(deserializer)?;
        Ok(Self::from_list(tags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    #[test]
    fn test_collect() {
        let tags = vec![
            Tag::identifier("1"),
            Tag::identifier("2"),
            Tag::identifier("3"),
            Tag::identifier("4"),
        ];
        let tags: Tags = tags
            .into_iter()
            .filter(|t| t.content() == Some("3"))
            .collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags.identifier(), Some(String::from("3")));
    }

    #[test]
    fn test_extract_d_tag() {
        let json = r#"{"id":"3dfdbb371de782f51812dc4809ea1104d80e143cec1091a4be07f518ef09e3d7","pubkey":"b8aef32a5421205c1f89ad09e2d93873df68a8611b247f62af005655eadc0efb","created_at":1728728536,"kind":30000,"sig":"0395c41fd95d52b534eaa29c82cd9437130cf63e67117b1587914375fdfb878137287a1d15653161f91ea919afb06358784217409a9ff0323261f683b2936829","content":"older_param_replaceable","tags":[["d","1"]]}"#;
        let event = Event::from_json(json).unwrap();
        assert_eq!(event.tags.identifier(), Some(String::from("1")));
    }

    // Unit test for issue https://github.com/nostrdevkit/nostr/issues/948
    #[test]
    fn test_hashtags_dedup() {
        let mut tags = Tags::new();

        tags.push(Tag::hashtag("a1"));
        tags.push(Tag::hashtag("a1"));
        tags.push(Tag::hashtag("a2"));
        tags.dedup();
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    fn sample_str_tags() -> Vec<&'static [&'static str]> {
        vec![
            &["d", "1737226417:my-beautiful-event"],
            &[
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "wss://relay.damus.io",
            ],
            &[
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "wss://nostr.oxtr.dev",
            ],
            &[
                "a",
                "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
            ],
            &["t", "nostr"],
            &["t", "bitcoin"],
            &["expiration", "1728728536"],
            &["r", "wss://relay.damus.io", ""],
            &["content-warning", "reason"],
            &["subject", "A beautiful subject"],
        ]
    }

    fn sample_tags() -> Vec<Tag> {
        sample_str_tags()
            .iter()
            .map(|tag| Tag::parse(tag.iter().copied()).unwrap())
            .collect()
    }

    #[bench]
    pub fn parse(bh: &mut Bencher) {
        let sample = sample_str_tags();
        bh.iter(|| {
            let tags = sample.iter().map(|tag| tag.iter().copied());
            black_box(Tags::parse(tags).unwrap());
        });
    }

    #[bench]
    pub fn pack_from_list(bh: &mut Bencher) {
        let tags: Vec<Tag> = sample_tags();
        bh.iter(|| {
            black_box(Tags::from(tags.clone()));
        });
    }

    #[bench]
    pub fn clone(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        bh.iter(|| {
            black_box(tags.clone());
        });
    }

    #[bench]
    pub fn to_vec(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        bh.iter(|| {
            black_box(tags.clone().to_vec());
        });
    }

    #[bench]
    pub fn iter(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        bh.iter(|| {
            black_box(tags.iter().count());
        });
    }

    #[bench]
    pub fn hashtags(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        bh.iter(|| {
            black_box(tags.hashtags().collect::<Vec<&str>>());
        });
    }

    #[bench]
    pub fn identifier(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        bh.iter(|| {
            black_box(tags.identifier());
        });
    }

    #[bench]
    pub fn serialize(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        bh.iter(|| {
            black_box(serde_json::to_string(&tags).unwrap());
        });
    }

    #[bench]
    pub fn deserialize(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        let json: String = serde_json::to_string(&tags).unwrap();
        bh.iter(|| {
            black_box(serde_json::from_str::<Tags>(&json).unwrap());
        });
    }

    #[bench]
    pub fn get_all(bh: &mut Bencher) {
        let tags: Tags = Tags::from(sample_tags());
        bh.iter(|| {
            for i in 0..tags.len() {
                black_box(tags.get(i));
            }
        });
    }
}
