use alloc::sync::Arc;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::num::NonZeroUsize;
use core::ops::{Index, Range};
use core::{fmt, str};

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use crate::event::tags::TagField;

#[derive(Clone, Copy)]
pub(super) struct BorrowedBlock<'a>(&'a Arc<[u8]>);

impl AsRef<[u8]> for BorrowedBlock<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

#[derive(Clone)]
pub(super) struct OwnedBlock(Arc<[u8]>);

impl AsRef<[u8]> for OwnedBlock {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Clone, Copy)]
pub(super) struct TagRepr<B> {
    block: B,
    // Offset of this tag's field refs inside `block`.
    refs_at: usize,
    // Offset of this tag's text region inside `block`.
    text_at: usize,
    // How many fields.
    n_fields: NonZeroUsize,
}

impl<B> fmt::Debug for TagRepr<B>
where
    B: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<B> PartialEq for TagRepr<B>
where
    B: AsRef<[u8]>,
{
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl<B> Eq for TagRepr<B> where B: AsRef<[u8]> {}

impl<B> PartialOrd for TagRepr<B>
where
    B: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<B> Ord for TagRepr<B>
where
    B: AsRef<[u8]>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let n: usize = self.len().min(other.len());
        for j in 0..n {
            match self[j].cmp(&other[j]) {
                Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        self.len().cmp(&other.len())
    }
}

impl<B> Hash for TagRepr<B>
where
    B: AsRef<[u8]>,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.n_fields.hash(state);
        for field in self.iter() {
            field.hash(state);
        }
    }
}

impl<B> TagRepr<B>
where
    B: AsRef<[u8]>,
{
    #[inline]
    #[allow(clippy::len_without_is_empty)]
    pub(super) fn len(&self) -> usize {
        self.n_fields.get()
    }

    #[inline]
    pub(super) fn get(&self, index: usize) -> Option<&str> {
        if index >= self.n_fields.get() {
            return None;
        }

        get_text(self.block.as_ref(), self.refs_at, self.text_at, index)
    }

    #[inline]
    pub(super) fn iter(&self) -> TagReprIter<'_> {
        TagReprIter::new(
            self.n_fields,
            self.refs_at,
            self.text_at,
            self.block.as_ref(),
        )
    }
}

impl<B> Index<usize> for TagRepr<B>
where
    B: AsRef<[u8]>,
{
    type Output = str;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("field index must be in range")
    }
}

impl<'a> TagRepr<BorrowedBlock<'a>> {
    #[inline]
    pub(crate) fn new_borrowed(
        block: &'a Arc<[u8]>,
        refs_at: usize,
        text_at: usize,
        n_fields: NonZeroUsize,
    ) -> Self {
        Self {
            block: BorrowedBlock(block),
            refs_at,
            text_at,
            n_fields,
        }
    }

    #[inline]
    pub(super) fn get_borrowed(&self, index: usize) -> Option<&'a str> {
        if index >= self.n_fields.get() {
            return None;
        }

        get_text(self.block.0, self.refs_at, self.text_at, index)
    }

    #[inline]
    pub(super) fn iter_borrowed(&self) -> TagReprIter<'a> {
        TagReprIter::new(self.n_fields, self.refs_at, self.text_at, self.block.0)
    }

    #[inline]
    pub(super) fn into_owned(self) -> TagRepr<OwnedBlock> {
        let block: Arc<[u8]> = Arc::clone(self.block.0);

        TagRepr {
            block: OwnedBlock(block),
            refs_at: self.refs_at,
            text_at: self.text_at,
            n_fields: self.n_fields,
        }
    }
}

pub(super) struct TagReprIter<'a> {
    refs_at: usize,
    text_at: usize,
    block: &'a [u8],
    range: Range<usize>,
}

impl<'a> TagReprIter<'a> {
    #[inline]
    fn new(n_fields: NonZeroUsize, refs_at: usize, text_at: usize, block: &'a [u8]) -> Self {
        Self {
            refs_at,
            text_at,
            block,
            range: 0..n_fields.get(),
        }
    }
}

impl<'a> Iterator for TagReprIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let index: usize = self.range.next()?;
        get_text(self.block, self.refs_at, self.text_at, index)
    }
}

fn get_text(block: &[u8], refs_at: usize, text_at: usize, index: usize) -> Option<&str> {
    // Gets the field refs
    let at: usize = refs_at.checked_add(TagField::SIZE * index)?;
    let word: &[u8] = block.get(at..at + TagField::SIZE)?;
    let word: [u8; TagField::SIZE] = word.try_into().ok()?;
    let field: TagField = TagField::from_ne_bytes(word);

    // Get the whole text region
    let text: &str = text(block, text_at)?;

    // Get the tag field text
    text.get(field.region())
}

#[inline]
fn text(block: &[u8], text_at: usize) -> Option<&str> {
    let bytes: &[u8] = block.get(text_at..)?;
    // SAFETY: the text region was written as whole UTF-8 by the packer.
    Some(unsafe { str::from_utf8_unchecked(bytes) })
}

impl<B> Serialize for TagRepr<B>
where
    B: AsRef<[u8]>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for element in self.iter() {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}
