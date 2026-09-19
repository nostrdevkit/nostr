// Copyright (c) 2024 Michael Dilger
// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use core::cmp;

use nostr::event::EventId;
use nostr::filter::SingleLetterTag;
use nostr::key::PublicKey;
use nostr::nips::nip01::Coordinate;
use nostr::types::Timestamp;

use crate::store::event::DatabaseEvent;

const CREATED_AT_BE: usize = 8;
const KIND_BE: usize = 2;
const TAG_VALUE_PAD_LEN: usize = 182;

// TODO: use fixed-size arrays instead of vectors
// TODO: convert `TagIndexKeySet` to an enum instead of `is_indexable`?
pub(super) struct TagIndexKeySet {
    /// Whether the tag is indexable
    pub(super) is_indexable: bool,
    pub(super) atc_index: Vec<u8>,
    pub(super) ktc_index: Vec<u8>,
    pub(super) tc_index: Vec<u8>,
    pub(super) expiration: Option<u64>,
}

// TODO: use fixed-size arrays instead of vectors
pub(super) struct EventIndexKeys {
    pub(super) id: [u8; EventId::LEN],
    pub(super) ci_index: Vec<u8>,
    pub(super) akc_index: Vec<u8>,
    pub(super) ac_index: Vec<u8>,
    pub(super) kc_index: Vec<u8>,
    pub(super) tags: Vec<TagIndexKeySet>,
}

impl EventIndexKeys {
    pub fn new(event: DatabaseEvent<'_>) -> Self {
        // Index by created_at and id
        let ci_index: Vec<u8> = make_ci_index_key(event.created_at, event.id);

        // Index by author and kind (with created_at and id)
        let akc_index: Vec<u8> =
            make_akc_index_key(event.pubkey, event.kind, event.created_at, event.id);

        // Index by author (with created_at and id)
        let ac_index: Vec<u8> = make_ac_index_key(event.pubkey, event.created_at, event.id);

        // Index by kind (with created_at and id)
        let kc_index: Vec<u8> = make_kc_index_key(event.kind, event.created_at, event.id);

        let mut tags: Vec<TagIndexKeySet> = event
            .tags
            .iter()
            .filter_map(|t| t.extract())
            .map(|(tag_name, tag_value)| {
                // Index by author and tag (with created_at and id)
                let atc_index: Vec<u8> = make_atc_index_key(
                    event.pubkey,
                    &tag_name,
                    tag_value,
                    event.created_at,
                    event.id,
                );

                // Index by kind and tag (with created_at and id)
                let ktc_index: Vec<u8> = make_ktc_index_key(
                    event.kind,
                    &tag_name,
                    tag_value,
                    event.created_at,
                    event.id,
                );

                // Index by tag (with created_at and id)
                let tc_index: Vec<u8> =
                    make_tc_index_key(&tag_name, tag_value, event.created_at, event.id);

                TagIndexKeySet {
                    is_indexable: true,
                    atc_index,
                    ktc_index,
                    tc_index,
                    expiration: None,
                }
            })
            .collect();

        // Collect expiration tags, they can't be with `tags` because it's not a single letter tag
        let expiration_tags = event
            .tags
            .iter()
            .filter_map(|t| t.expiration())
            .map(|expire_at| TagIndexKeySet {
                is_indexable: false,
                atc_index: Vec::new(),
                ktc_index: Vec::new(),
                tc_index: Vec::new(),
                expiration: Some(expire_at),
            });
        // Extend the tags with expiration tags
        tags.extend(expiration_tags);

        Self {
            id: *event.id,
            ci_index,
            akc_index,
            ac_index,
            kc_index,
            tags,
        }
    }
}

/// Reverse created_at and convert `u64` to big-endian byte order
#[inline]
fn reverse_and_conv_to_be64(created_at: Timestamp) -> [u8; 8] {
    // Reverse
    let created_at: u64 = u64::MAX - created_at.as_secs();

    // Convert to big-endian
    created_at.to_be_bytes()
}

/// Extend the key with the `tag_value` (fixed len of 182 bytes)
fn extend_key_with_tag_value(key: &mut Vec<u8>, len: usize, tag_value: &str) {
    let tag_value: &[u8] = tag_value.as_bytes();
    if len <= TAG_VALUE_PAD_LEN {
        key.extend(tag_value);
        key.extend(core::iter::repeat_n(0, TAG_VALUE_PAD_LEN - len));
    } else {
        key.extend(&tag_value[..TAG_VALUE_PAD_LEN]);
    }
}

/// Make CreatedAt + ID index key
///
/// ## Structure
///
/// `reverse_created_at(8)` + `event_id(32)`
pub fn make_ci_index_key(created_at: Timestamp, event_id: &[u8; EventId::LEN]) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(CREATED_AT_BE + EventId::LEN);
    key.extend(reverse_and_conv_to_be64(created_at));
    key.extend(event_id);
    key
}

/// Make Tag + CreatedAt + ID index key (for looking up event by `tag`)
///
/// ## Structure
///
/// `tag_name(1)` + `tag_value(182)` + `reverse_created_at(8)` + `event_id(32)`
pub fn make_tc_index_key(
    tag_name: &SingleLetterTag,
    tag_value: &str,
    created_at: Timestamp,
    event_id: &[u8; EventId::LEN],
) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(1 + TAG_VALUE_PAD_LEN + CREATED_AT_BE + EventId::LEN);

    // Push tag name
    key.push(tag_name.as_char() as u8);

    // Add tag value
    extend_key_with_tag_value(&mut key, tag_value.len(), tag_value);

    key.extend(reverse_and_conv_to_be64(created_at));
    key.extend(event_id);
    key
}

/// Make Author + CreatedAt + ID index key (for looking up event by `author`)
///
/// ## Structure
///
/// `author(32)` + `reverse_created_at(8)` + `event_id(32)`
pub fn make_ac_index_key(
    author: &[u8; PublicKey::LEN],
    created_at: Timestamp,
    event_id: &[u8; EventId::LEN],
) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(PublicKey::LEN + CREATED_AT_BE + EventId::LEN);
    key.extend(author);
    key.extend(reverse_and_conv_to_be64(created_at));
    key.extend(event_id);
    key
}

/// Make Author + Kind + CreatedAt + ID index key (for looking up event by `author` and `kind`)
///
/// ## Structure
///
/// `author(32)` + `kind(2)` + `reverse_created_at(8)` + `event_id(32)`
pub fn make_akc_index_key(
    author: &[u8; PublicKey::LEN],
    kind: u16,
    created_at: Timestamp,
    event_id: &[u8; EventId::LEN],
) -> Vec<u8> {
    let mut key: Vec<u8> =
        Vec::with_capacity(PublicKey::LEN + KIND_BE + CREATED_AT_BE + EventId::LEN);
    key.extend(author);
    key.extend(kind.to_be_bytes());
    key.extend(reverse_and_conv_to_be64(created_at));
    key.extend(event_id);
    key
}

/// Make Kind + CreatedAt + ID index key (for looking up event by `kind`)
///
/// ## Structure
///
/// `kind(2)` + `reverse_created_at(8)` + `event_id(32)`
pub fn make_kc_index_key(
    kind: u16,
    created_at: Timestamp,
    event_id: &[u8; EventId::LEN],
) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(KIND_BE + CREATED_AT_BE + EventId::LEN);
    key.extend(kind.to_be_bytes());
    key.extend(reverse_and_conv_to_be64(created_at));
    key.extend(event_id);
    key
}

/// Make Author + Tag + CreatedAt + ID index key (for looking up event by `author` and `tag`)
///
/// ## Structure
///
/// `author(32)` + `tag_name(1)` + `tag_value(182)` + `reverse_created_at(8)` + `event_id(32)`
pub fn make_atc_index_key(
    author: &[u8; PublicKey::LEN],
    tag_name: &SingleLetterTag,
    tag_value: &str,
    created_at: Timestamp,
    event_id: &[u8; EventId::LEN],
) -> Vec<u8> {
    let mut key: Vec<u8> =
        Vec::with_capacity(PublicKey::LEN + 1 + TAG_VALUE_PAD_LEN + CREATED_AT_BE + EventId::LEN);

    // Add author
    key.extend(author);

    // Add tag name
    key.push(tag_name.as_char() as u8);

    // Add tag value
    extend_key_with_tag_value(&mut key, tag_value.len(), tag_value);

    // Add reverse created at
    key.extend(reverse_and_conv_to_be64(created_at));

    // Add event ID
    key.extend(event_id);

    key
}

/// Make Kind + Tag + CreatedAt + ID index (for looking up event by `kind` and `tag`)
///
/// ## Structure
///
/// `kind(2)` + `tag_name(1)` + `tag_value(182)` + `reverse_created_at(8)` + `event_id(32)`
pub fn make_ktc_index_key(
    kind: u16,
    tag_name: &SingleLetterTag,
    tag_value: &str,
    created_at: Timestamp,
    event_id: &[u8; EventId::LEN],
) -> Vec<u8> {
    let mut key: Vec<u8> =
        Vec::with_capacity(KIND_BE + TAG_VALUE_PAD_LEN + CREATED_AT_BE + EventId::LEN);
    key.extend(kind.to_be_bytes());
    key.push(tag_name.as_char() as u8);
    extend_key_with_tag_value(&mut key, tag_value.len(), tag_value);
    key.extend(reverse_and_conv_to_be64(created_at));
    key.extend(event_id);
    key
}

/// Make coordinate index key
///
/// ## Structure
///
/// `kind(2)` + `author(32)` + `d_len(1)` + `d(182)`
pub fn make_coordinate_index_key(coordinate: &Coordinate) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::with_capacity(KIND_BE + PublicKey::LEN + 1 + TAG_VALUE_PAD_LEN);
    key.extend(coordinate.kind.as_u16().to_be_bytes());
    key.extend(coordinate.public_key.to_bytes());

    let identifier: &str = &coordinate.identifier;

    let dlen: usize = cmp::min(identifier.len(), TAG_VALUE_PAD_LEN);
    key.push(dlen as u8);

    extend_key_with_tag_value(&mut key, dlen, identifier);

    key
}
