// Tag block layout
//
// A tag is stored in one contiguous byte block: the field refs followed by
// the fields' text. All integers are **native-endian**.
//
//    0               1               2               3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +---------------------------------------------------------------+
//   |                      field 0: start (u32)                     |
//   +---------------------------------------------------------------+
//   |                      field 0: len (u32)                       |
//   +---------------------------------------------------------------+
//   |                      field 1: start (u32)                     |
//   +---------------------------------------------------------------+
//   |                      field 1: len (u32)                       |
//   +---------------------------------------------------------------+
//   |                             ...                               |
//   +---------------------------------------------------------------+
//   |    field 0 text    |    field 1 text    |         ...         |  <- text region
//   +---------------------------------------------------------------+
//
// - `start` of a field is relative to the beginning of the text region
// - the text region begins right after the refs region (8 bytes per field)
// - the fields' text is stored back to back, in field order

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Index;
use core::str::FromStr;

mod codec;
mod iter;
mod refer;
mod repr;

pub(crate) use self::codec::impl_tag_codec_conversions;
pub use self::iter::*;
pub use self::refer::*;
use self::repr::{OwnedBlock, TagRepr};
use super::mutable::{TagWriter, WriteTag};
use crate::filter::SingleLetterTag;

/// An immutable and cheaply cloneable tag.
///
/// Cloning the tag doesn't allocate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Tag(TagRepr<OwnedBlock>);

impl Tag {
    /// Get the field at `index`, if exists.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&str> {
        self.0.get(index)
    }

    /// Get tag kind (the first field).
    #[inline]
    pub fn kind(&self) -> &str {
        self.0.get(0).expect("BUG: the tag can't be empty")
    }

    /// Return the **first** tag value (index `1`), if exists.
    #[inline]
    pub fn content(&self) -> Option<&str> {
        self.0.get(1)
    }

    /// Get [`SingleLetterTag`]
    #[inline]
    pub fn single_letter_tag(&self) -> Option<SingleLetterTag> {
        SingleLetterTag::from_str(self.kind()).ok()
    }

    /// How many fields.
    ///
    /// This will never return zero.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over the fields
    #[inline]
    pub fn iter(&self) -> TagIter<'_> {
        TagIter::new(self.0.iter())
    }

    /// Consume the tag and return the array of strings.
    ///
    /// This unpacks the tag and allocates.
    #[inline]
    pub fn to_vec(&self) -> Vec<String> {
        self.iter().map(String::from).collect()
    }

    /// Check if it's a protected event tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/70.md>
    #[inline]
    pub fn is_protected(&self) -> bool {
        self.len() == 1 && self.kind() == "-"
    }
}

impl From<TagRepr<OwnedBlock>> for Tag {
    #[inline]
    fn from(repr: TagRepr<OwnedBlock>) -> Self {
        Self(repr)
    }
}

impl Index<usize> for Tag {
    type Output = str;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("tag field index out of bounds")
    }
}

impl WriteTag for Tag {
    #[inline]
    fn write(self, tx: &mut TagWriter<'_>) {
        tx.reserve(self.len());

        for field in self.0.iter() {
            tx.push_str(field);
        }
    }
}

impl WriteTag for &Tag {
    #[inline]
    fn write(self, tx: &mut TagWriter<'_>) {
        tx.reserve(self.len());

        for field in self.0.iter() {
            tx.push_str(field);
        }
    }
}
