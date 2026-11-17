// Tags block layout
//
// The whole collection is stored in one contiguous byte block: the tag
// entries, the field refs and the fields' text. All integers are
// **native-endian**.
//
//   +----------------------------------------------------------------+
//   | tag 0: first_field (u32) | tag 0: n_fields (u32)               |  <- tag entries
//   | tag 1: first_field (u32) | tag 1: n_fields (u32)               |
//   |                            ...                                 |
//   +----------------------------------------------------------------+
//   | field 0: start (u32)     | field 0: len (u32)                  |  <- field refs
//   | field 1: start (u32)     | field 1: len (u32)                  |
//   |                            ...                                 |
//   +----------------------------------------------------------------+
//   | tag 0 fields' text | tag 1 fields' text |         ...          |  <- text region
//   +----------------------------------------------------------------+
//
// - tags don't store their field refs: they all live in one flat list, and
//   each tag entry just records its slice of that list (`first_field` is the
//   index of the tag's first field, `n_fields` how many it owns)
// - each field ref points into the text region: its `start` counts bytes
//   from the beginning of the text region, not from the start of the block
// - the text region is the concatenation of every field's text, tag by tag
//   and field by field, with no separators
//
// Example: tags [["d", "id"], ["t", "nostr"]]
//   entries: (first_field: 0, n_fields: 2), (first_field: 2, n_fields: 2)
//   refs:    (start: 0, len: 1), (start: 1, len: 2),
//            (start: 3, len: 1), (start: 4, len: 5)
//   text:    "d" + "id" + "t" + "nostr"  ->  "didtnostr"

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem::{MaybeUninit, size_of};
use core::num::NonZeroUsize;
use core::{fmt, ptr, str};

use serde::de::{DeserializeSeed, Error as DeserializerError, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

mod entry;
mod field;
mod iter;
mod mutable;
mod tag;

use self::entry::TagEntry;
use self::field::TagField;
pub use self::iter::*;
pub use self::mutable::*;
pub use self::tag::*;
use crate::error::{Error, ErrorKind};
use crate::event::EventId;
use crate::key::PublicKey;
use crate::nips::nip01::{Coordinate, Nip01Tag};
use crate::nips::nip40::Nip40Tag;
use crate::nips::nip42::Nip42Tag;
use crate::types::Timestamp;

// The field refs are stored as `u32` pairs, and they must fit into a `usize`.
// We use often "as u32" casing on usize, so on platforms with a pointer size smaller than 32-bit, this may cause issues!
const _: () = assert!(size_of::<usize>() >= size_of::<u32>());

#[derive(Clone)]
enum TagsRepr {
    NonEmpty {
        bytes: Arc<[u8]>,
        tag_count: usize,
        field_count: usize,
    },
    Empty,
}

/// A compact, immutable and cheaply cloneable collection of tags.
///
/// Cloning a collection doesn't allocate.
/// An empty collection doesn't allocate at all.
#[derive(Clone)]
pub struct Tags(TagsRepr);

impl fmt::Debug for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl Default for Tags {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Tags {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
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
        let n: usize = self.len().min(other.len());
        for i in 0..n {
            match self
                .get(i)
                .expect("tag index in range")
                .cmp(&other.get(i).expect("tag index in range"))
            {
                Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        self.len().cmp(&other.len())
    }
}

impl Hash for Tags {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.len().hash(state);
        for tag in self.iter() {
            tag.hash(state);
        }
    }
}

impl Tags {
    /// Construct a new empty collection.
    ///
    /// This doesn't allocate.
    #[inline]
    pub const fn new() -> Self {
        Self(TagsRepr::Empty)
    }

    fn from_parts(entries: &[TagEntry], fields: &[TagField], text: &str) -> Self {
        let tag_count: usize = entries.len();

        // An empty collection doesn't allocate at all.
        if tag_count == 0 {
            return Self::new();
        }

        let field_count: usize = fields.len();
        let entries_bytes_len: usize = tag_count * TagEntry::SIZE;
        let fields_bytes_len: usize = field_count * TagField::SIZE;
        let text_bytes_len: usize = text.len();
        let total_bytes_len: usize = entries_bytes_len + fields_bytes_len + text_bytes_len;

        let mut bytes: Arc<[MaybeUninit<u8>]> = Arc::new_uninit_slice(total_bytes_len);

        let Some(buf): Option<&mut [MaybeUninit<u8>]> = Arc::get_mut(&mut bytes) else {
            unreachable!()
        };

        let base: *mut u8 = buf.as_mut_ptr().cast();
        let entries_ptr: *const u8 = entries.as_ptr().cast();
        let fields_ptr: *const u8 = fields.as_ptr().cast();
        let text_ptr: *const u8 = text.as_ptr();

        unsafe {
            ptr::copy_nonoverlapping(entries_ptr, base, entries_bytes_len);
            ptr::copy_nonoverlapping(fields_ptr, base.add(entries_bytes_len), fields_bytes_len);
            ptr::copy_nonoverlapping(
                text_ptr,
                base.add(entries_bytes_len + fields_bytes_len),
                text_bytes_len,
            );
        }

        // SAFETY: all bytes were initialized above
        let bytes: Arc<[u8]> = unsafe { bytes.assume_init() };

        Self(TagsRepr::NonEmpty {
            bytes,
            tag_count,
            field_count,
        })
    }

    /// Parse tags.
    ///
    /// Return error if a tag is empty!
    pub fn parse<I, T>(tags: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
        T: WriteTag,
    {
        let mut packer: TagsMut = TagsMut::default();

        for tag in tags {
            let added: bool = packer.push(tag);

            if !added {
                return Err(Error::with_static_message(ErrorKind::Invalid, "empty tag"));
            }
        }

        Ok(packer.freeze())
    }

    #[inline]
    fn shared_bytes(&self) -> Option<&Arc<[u8]>> {
        match &self.0 {
            TagsRepr::NonEmpty { bytes, .. } => Some(bytes),
            TagsRepr::Empty => None,
        }
    }

    #[inline]
    fn tag_count(&self) -> usize {
        match &self.0 {
            TagsRepr::NonEmpty { tag_count, .. } => *tag_count,
            TagsRepr::Empty => 0,
        }
    }

    #[inline]
    fn field_count(&self) -> usize {
        match &self.0 {
            TagsRepr::NonEmpty { field_count, .. } => *field_count,
            TagsRepr::Empty => 0,
        }
    }

    /// How many tags.
    #[inline]
    pub fn len(&self) -> usize {
        self.tag_count()
    }

    /// Check if the collection is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Tag `index`, as a borrowed reference.
    #[inline]
    pub fn get(&self, index: usize) -> Option<TagRef<'_>> {
        if index >= self.len() {
            return None;
        }

        let bytes: &Arc<[u8]> = self.shared_bytes()?;

        let entry: TagEntry = get_entry(bytes, index)?;

        let n_fields: NonZeroUsize = entry.n_fields.try_into().ok()?;

        let tag_count: usize = self.tag_count();
        let field_count: usize = self.field_count();

        let entities_bytes_len: usize = tag_count * TagEntry::SIZE;
        let fields_bytes_len: usize = field_count * TagField::SIZE;

        let first_field_bytes_len: usize = entry.first_field as usize * TagField::SIZE;

        let refs_at: usize = entities_bytes_len + first_field_bytes_len;
        let text_at: usize = entities_bytes_len + fields_bytes_len;

        Some(TagRef::from_tags_parts(bytes, refs_at, text_at, n_fields))
    }

    #[inline]
    fn get_owned(&self, index: usize) -> Option<Tag> {
        self.get(index).map(TagRef::into_owned)
    }

    /// The first tag, if the collection isn't empty.
    #[inline]
    pub fn first(&self) -> Option<TagRef<'_>> {
        self.get(0)
    }

    /// The last tag, if the collection isn't empty.
    #[inline]
    pub fn last(&self) -> Option<TagRef<'_>> {
        if self.is_empty() {
            None
        } else {
            self.get(self.len() - 1)
        }
    }

    /// Iterate over the tags.
    #[inline]
    pub fn iter(&self) -> TagsIter<'_> {
        TagsIter::new(self)
    }

    fn into_parts(self) -> (Vec<TagEntry>, Vec<TagField>, String) {
        match self.0 {
            TagsRepr::NonEmpty {
                bytes,
                tag_count,
                field_count,
            } => {
                let entries_bytes_len: usize = tag_count * TagEntry::SIZE;
                let fields_bytes_len: usize = field_count * TagField::SIZE;

                let mut entries: Vec<TagEntry> = Vec::with_capacity(tag_count);
                let mut fields: Vec<TagField> = Vec::with_capacity(field_count);

                let entries_bytes: &[u8] = &bytes[0..entries_bytes_len];
                let fields_bytes: &[u8] =
                    &bytes[entries_bytes_len..entries_bytes_len + fields_bytes_len];
                let text_bytes: &[u8] = &bytes[entries_bytes_len + fields_bytes_len..];

                for entry in entries_bytes.chunks_exact(TagEntry::SIZE) {
                    let entry: [u8; TagEntry::SIZE] = entry.try_into().expect("exact size");
                    let entry: TagEntry = TagEntry::from_ne_bytes(entry).expect("valid entry");
                    entries.push(entry);
                }

                for field in fields_bytes.chunks_exact(TagField::SIZE) {
                    let field: [u8; TagField::SIZE] = field.try_into().expect("exact size");
                    let field: TagField = TagField::from_ne_bytes(field);
                    fields.push(field);
                }

                let text: String = unsafe { str::from_utf8_unchecked(text_bytes) }.to_string();

                (entries, fields, text)
            }
            TagsRepr::Empty => (Vec::new(), Vec::new(), String::new()),
        }
    }

    /// Convert the collection into the mutable staging representation.
    #[inline]
    pub fn into_mut(self) -> TagsMut {
        let (entries, fields, text) = self.into_parts();
        TagsMut::from_parts(entries, fields, text)
    }

    /// Extract identifier (`d` tag), if exists.
    #[inline]
    pub fn identifier(&self) -> Option<String> {
        let tag: TagRef = self.iter().find(|t| t.kind() == "d")?;

        match Nip01Tag::try_from(tag) {
            Ok(Nip01Tag::Identifier(identifier)) => Some(identifier),
            _ => None,
        }
    }

    /// Get [`Timestamp`] expiration, if exists.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/40.md>
    pub fn expiration(&self) -> Option<Timestamp> {
        let tag: TagRef<'_> = self.iter().find(|t| t.kind() == "expiration")?;

        match Nip40Tag::try_from(tag) {
            Ok(Nip40Tag::Expiration(expiration)) => Some(expiration),
            _ => None,
        }
    }

    /// Extract NIP42 challenge, if exists.
    #[inline]
    pub fn challenge(&self) -> Option<String> {
        let tag: TagRef = self.iter().find(|t| t.kind() == "challenge")?;

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

            let content: &str = t.content()?;
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

#[inline]
fn get_entry(bytes: &[u8], index: usize) -> Option<TagEntry> {
    let at: usize = TagEntry::SIZE * index;
    let word: &[u8] = bytes.get(at..at + TagEntry::SIZE)?;
    let word: [u8; TagEntry::SIZE] = word.try_into().ok()?;
    TagEntry::from_ne_bytes(word)
}

impl IntoIterator for Tags {
    type Item = Tag;
    type IntoIter = TagsIntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        TagsIntoIter::new(self)
    }
}

impl<'a> IntoIterator for &'a Tags {
    type Item = TagRef<'a>;
    type IntoIter = TagsIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> FromIterator<T> for Tags
where
    T: WriteTag,
{
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        let mut packer: TagsMut = TagsMut::default();
        packer.extend(iter);
        packer.freeze()
    }
}

impl<T> From<&[T]> for Tags
where
    T: WriteTag + Clone,
{
    fn from(list: &[T]) -> Self {
        list.iter().cloned().collect()
    }
}

impl<T> From<Vec<T>> for Tags
where
    T: WriteTag,
{
    fn from(list: Vec<T>) -> Self {
        list.into_iter().collect()
    }
}

impl<T> From<&Vec<T>> for Tags
where
    T: WriteTag + Clone,
{
    fn from(list: &Vec<T>) -> Self {
        Self::from(list.as_slice())
    }
}

impl<T, const N: usize> From<[T; N]> for Tags
where
    T: WriteTag,
{
    fn from(list: [T; N]) -> Self {
        list.into_iter().collect()
    }
}

impl From<TagsMut> for Tags {
    #[inline]
    fn from(value: TagsMut) -> Self {
        value.freeze()
    }
}

impl Serialize for Tags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for tag in self.iter() {
            seq.serialize_element(&tag)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Tags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(TagsVisitor)
    }
}

struct TagsVisitor;

impl<'de> Visitor<'de> for TagsVisitor {
    type Value = Tags;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of tags")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut packer: TagsMut = TagsMut::default();

        while seq
            .next_element_seed(TagSeed { tags: &mut packer })?
            .is_some()
        {}

        Ok(packer.freeze())
    }
}

struct TagSeed<'a> {
    tags: &'a mut TagsMut,
}

impl<'de> DeserializeSeed<'de> for TagSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for TagSeed<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of tag fields")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut tx: TagWriter<'_> = self.tags.begin();

        while seq.next_element_seed(FieldSeed { tx: &mut tx })?.is_some() {}

        tx.end()
            .map(|_| ())
            .ok_or_else(|| DeserializerError::custom("empty tag"))
    }
}

struct FieldSeed<'a, 'b> {
    tx: &'a mut TagWriter<'b>,
}

impl<'de> DeserializeSeed<'de> for FieldSeed<'_, '_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for FieldSeed<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.tx.push_str(v);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    #[cfg(feature = "std")]
    use crate::test_utils::allocation_delta;

    fn sample_tags() -> Vec<Vec<&'static str>> {
        vec![
            vec!["d", "1737226417:my-beautiful-event"],
            vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "wss://relay.damus.io",
            ],
            vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "wss://nostr.oxtr.dev",
            ],
            vec![
                "a",
                "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
            ],
            vec!["t", "nostr"],
            vec!["t", "bitcoin"],
            vec!["expiration", "1728728536"],
            vec!["r", "wss://relay.damus.io", ""],
            vec!["content-warning", "reason"],
            vec!["subject", "A beautiful subject"],
        ]
    }

    #[test]
    fn test_roundtrip_str() {
        let original: Vec<Vec<&str>> = sample_tags();
        let tags: Tags = Tags::parse(&original).unwrap();

        assert_eq!(tags.len(), original.len());

        for (tag, expected) in tags.iter().zip(&original) {
            let fields: Vec<&str> = tag.iter().collect();
            assert_eq!(&fields, expected);
        }

        // Out-of-bounds access returns `None`.
        assert!(tags.get(original.len()).is_none());

        // Packing again the unpacked fields gives an identical collection.
        let repacked: Tags = tags.iter().collect();
        assert_eq!(repacked, tags);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_roundtrip_json() {
        let tags: Tags = Tags::parse(sample_tags()).unwrap();

        let json: String = serde_json::to_string(&tags).unwrap();
        let back: Tags = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tags);
        assert_eq!(serde_json::to_string(&back).unwrap(), json);

        // An empty collection round-trips as well.
        let empty: Tags = serde_json::from_str("[]").unwrap();
        assert!(empty.is_empty());
        assert_eq!(serde_json::to_string(&Tags::new()).unwrap(), "[]");
    }

    #[test]
    fn test_into_mut_freeze_roundtrip() {
        let tags: Tags = Tags::parse(sample_tags()).unwrap();
        let frozen: Tags = tags.clone().into_mut().freeze();

        assert_eq!(frozen, tags);
    }

    #[test]
    fn test_parse_empty_tag() {
        assert!(Tags::parse([vec!["d", "id"], Vec::<&str>::new()]).is_err());
        assert!(Tags::parse(Vec::<Vec<&str>>::new()).unwrap().is_empty());
    }

    #[test]
    fn test_extract_d_tag() {
        let json = r#"{"id":"3dfdbb371de782f51812dc4809ea1104d80e143cec1091a4be07f518ef09e3d7","pubkey":"b8aef32a5421205c1f89ad09e2d93873df68a8611b247f62af005655eadc0efb","created_at":1728728536,"kind":30000,"sig":"0395c41fd95d52b534eaa29c82cd9437130cf63e67117b1587914375fdfb878137287a1d15653161f91ea919afb06358784217409a9ff0323261f683b2936829","content":"older_param_replaceable","tags":[["d","1"]]}"#;
        let event = Event::from_json(json).unwrap();
        assert_eq!(event.tags.identifier().as_deref(), Some("1"));
    }

    #[test]
    fn test_pack_and_unpack() {
        let raw: Vec<Vec<&str>> = vec![
            vec!["d", "id"],
            vec!["t", "nostr"],
            vec!["r", "wss://relay.damus.io", ""],
        ];
        let packed: Tags = Tags::parse(raw.clone()).unwrap();

        assert_eq!(packed.len(), 3);
        assert_eq!(packed.identifier().as_deref(), Some("id"));
        assert_eq!(packed.hashtags().collect::<Vec<_>>(), ["nostr"]);

        // Repacking the owned tags gives an identical collection.
        assert_eq!(packed.iter().collect::<Tags>(), packed);
    }

    #[test]
    fn test_extracted_tag_shares_the_block() {
        let packed: Tags = Tags::parse([["d", "id"], ["t", "nostr"]]).unwrap();

        // Drop the collection: the extracted tag stays valid.
        let tag: Tag = packed.get_owned(1).unwrap();
        drop(packed);

        assert_eq!(tag.kind(), "t");
        assert_eq!(tag.content(), Some("nostr"));
    }

    #[test]
    fn test_tags_mut() {
        let mut tags: TagsMut = TagsMut::new();
        tags.push(["d", "id"]);
        tags.push(["t", "nostr"]);
        tags.push(Nip01Tag::public_key(
            PublicKey::from_hex("13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d")
                .unwrap(),
        ));

        assert_eq!(tags.len(), 3);

        // An empty tag isn't written.
        assert!(!tags.push(Vec::<&str>::new()));

        let frozen: Tags = tags.freeze();
        assert_eq!(frozen.len(), 3);
        assert_eq!(frozen.identifier().as_deref(), Some("id"));
        assert_eq!(frozen.hashtags().collect::<Vec<_>>(), ["nostr"]);
        assert_eq!(frozen.public_keys().count(), 1);

        // The packer can be reused after `clear`.
        tags.clear();
        tags.push(["t", "bitcoin"]);

        let frozen: Tags = tags.freeze();
        assert_eq!(frozen.len(), 1);
        assert_eq!(frozen.hashtags().collect::<Vec<_>>(), ["bitcoin"]);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_tags_allocations() {
        let tag1 = EventId::from_byte_array([1; 32]);
        let tag2 = EventId::from_byte_array([2; 32]);
        let tag3 = EventId::from_byte_array([3; 32]);

        let (packed, delta) = allocation_delta(|| {
            let tags: Vec<Nip01Tag> = vec![
                Nip01Tag::event(tag1),
                Nip01Tag::event(tag2),
                Nip01Tag::event(tag3),
            ];
            Tags::from(tags)
        });
        assert_eq!(delta, 1, "Tags::from must allocate only the shared block");

        // Clone is free.
        let (_clone, delta) = allocation_delta(|| packed.clone());
        assert_eq!(delta, 0);

        // The extracted tags share the same block: only the `Vec` container
        // allocates.
        let (_tags, delta) = allocation_delta(|| {
            let tags: Vec<Tag> = packed.into_iter().collect();
            tags
        });
        assert_eq!(delta, 1, "only the Vec container allocates");
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

    #[bench]
    pub fn parse(bh: &mut Bencher) {
        let sample = sample_str_tags();
        bh.iter(|| {
            let tags = sample.iter().map(|tag| tag.iter().copied());
            black_box(Tags::parse(tags).unwrap());
        });
    }

    #[bench]
    pub fn pack_from_raw(bh: &mut Bencher) {
        let sample = sample_str_tags();
        bh.iter(|| {
            black_box(Tags::from_iter(sample.iter().copied()));
        });
    }

    #[bench]
    pub fn pack_from_owned(bh: &mut Bencher) {
        let tags: Vec<Tag> = Tags::parse(sample_str_tags())
            .unwrap()
            .into_iter()
            .collect();
        bh.iter(|| {
            black_box(Tags::from(&tags));
        });
    }

    #[bench]
    pub fn pack_reuse(bh: &mut Bencher) {
        let sample = sample_str_tags();

        let mut packer: TagsMut = TagsMut::with_capacity(sample.len());
        for tag in sample.iter().copied() {
            packer.push(tag);
        }

        bh.iter(|| {
            packer.clear();
            for tag in sample.iter().copied() {
                packer.push(tag);
            }
            black_box(packer.freeze());
        });
    }

    #[bench]
    pub fn clone(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        bh.iter(|| {
            black_box(tags.clone());
        });
    }

    #[bench]
    pub fn iter(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        bh.iter(|| {
            black_box(tags.iter().count());
        });
    }

    #[bench]
    pub fn hashtags(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        bh.iter(|| {
            black_box(tags.hashtags().collect::<Vec<&str>>());
        });
    }

    #[bench]
    pub fn identifier(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        bh.iter(|| {
            black_box(tags.identifier());
        });
    }

    #[bench]
    pub fn serialize(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        bh.iter(|| {
            black_box(serde_json::to_string(&tags).unwrap());
        });
    }

    #[bench]
    pub fn deserialize(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        let json: String = serde_json::to_string(&tags).unwrap();
        bh.iter(|| {
            black_box(serde_json::from_str::<Tags>(&json).unwrap());
        });
    }

    #[bench]
    pub fn into_mut(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        bh.iter(|| {
            black_box(tags.clone().into_mut());
        });
    }

    #[bench]
    pub fn freeze(bh: &mut Bencher) {
        let tags: TagsMut = Tags::parse(sample_str_tags()).unwrap().into_mut();
        bh.iter(|| {
            black_box(tags.freeze());
        });
    }

    #[bench]
    pub fn get_all(bh: &mut Bencher) {
        let tags: Tags = Tags::parse(sample_str_tags()).unwrap();
        bh.iter(|| {
            for i in 0..tags.len() {
                black_box(tags.get(i));
            }
        });
    }
}
