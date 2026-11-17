use alloc::sync::Arc;
use core::num::NonZeroUsize;
use core::str::FromStr;

use super::repr::{BorrowedBlock, TagRepr};
use crate::event::{Tag, TagIter, TagWriter, WriteTag};
use crate::filter::SingleLetterTag;

/// A borrowed reference to a tag
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct TagRef<'a>(TagRepr<BorrowedBlock<'a>>);

impl<'a> TagRef<'a> {
    #[inline]
    pub(crate) fn from_tags_parts(
        block: &'a Arc<[u8]>,
        refs_at: usize,
        text_at: usize,
        n_fields: NonZeroUsize,
    ) -> Self {
        Self(TagRepr::new_borrowed(block, refs_at, text_at, n_fields))
    }

    /// How many fields.
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get the field at `index`, if exists.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&'a str> {
        self.0.get_borrowed(index)
    }

    /// Get tag kind (the first field).
    #[inline]
    pub fn kind(&self) -> &'a str {
        self.0.get_borrowed(0).expect("BUG: the tag can't be empty")
    }

    /// Return the **first** tag value (index `1`), if exists.
    #[inline]
    pub fn content(&self) -> Option<&'a str> {
        self.0.get_borrowed(1)
    }

    /// Iterate over the fields
    #[inline]
    pub fn iter(&self) -> TagIter<'a> {
        TagIter::new(self.0.iter_borrowed())
    }

    /// Get [`SingleLetterTag`]
    #[inline]
    pub fn single_letter_tag(&self) -> Option<SingleLetterTag> {
        SingleLetterTag::from_str(self.kind()).ok()
    }

    /// Check if it's a protected event tag
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/70.md>
    #[inline]
    pub fn is_protected(&self) -> bool {
        self.len() == 1 && self.kind() == "-"
    }

    /// Convert into an owned [`Tag`] without allocating.
    ///
    /// This doesn't allocate, the returned [`Tag`] shares the collection block.
    #[inline]
    pub fn into_owned(self) -> Tag {
        Tag::from(self.0.into_owned())
    }
}

impl PartialEq<Tag> for TagRef<'_> {
    fn eq(&self, other: &Tag) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl PartialEq<TagRef<'_>> for Tag {
    fn eq(&self, other: &TagRef<'_>) -> bool {
        other == self
    }
}

impl WriteTag for TagRef<'_> {
    #[inline]
    fn write(self, tx: &mut TagWriter<'_>) {
        tx.reserve(self.len());

        for field in self.0.iter_borrowed() {
            tx.push_str(field);
        }
    }
}

impl WriteTag for &TagRef<'_> {
    #[inline]
    fn write(self, tx: &mut TagWriter<'_>) {
        tx.reserve(self.len());

        for field in self.0.iter_borrowed() {
            tx.push_str(field);
        }
    }
}
