use core::ops::Range;

use crate::event::{Tag, TagRef, Tags};

/// Iterator over the tags of a [`Tags`] collection.
#[derive(Clone, Debug)]
pub struct TagsIter<'a> {
    tags: &'a Tags,
    range: Range<usize>,
}

impl<'a> TagsIter<'a> {
    #[inline]
    pub(super) fn new(tags: &'a Tags) -> Self {
        Self {
            range: 0..tags.len(),
            tags,
        }
    }
}

impl<'a> Iterator for TagsIter<'a> {
    type Item = TagRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let index: usize = self.range.next()?;
        Some(self.tags.get(index).expect("tag index in range"))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }

    fn count(self) -> usize {
        self.range.count()
    }
}

impl DoubleEndedIterator for TagsIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let index: usize = self.range.next_back()?;
        Some(self.tags.get(index).expect("tag index in range"))
    }
}

impl ExactSizeIterator for TagsIter<'_> {
    fn len(&self) -> usize {
        self.range.len()
    }
}

/// Iterator over the tags of a [`Tags`] collection.
#[derive(Clone, Debug)]
pub struct TagsIntoIter {
    tags: Tags,
    range: Range<usize>,
}

impl TagsIntoIter {
    #[inline]
    pub(super) fn new(tags: Tags) -> Self {
        Self {
            range: 0..tags.len(),
            tags,
        }
    }
}

impl Iterator for TagsIntoIter {
    type Item = Tag;

    fn next(&mut self) -> Option<Self::Item> {
        let index: usize = self.range.next()?;
        Some(self.tags.get_owned(index).expect("tag index in range"))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }

    fn count(self) -> usize {
        self.range.count()
    }
}

impl DoubleEndedIterator for TagsIntoIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        let index: usize = self.range.next_back()?;
        Some(self.tags.get_owned(index).expect("tag index in range"))
    }
}

impl ExactSizeIterator for TagsIntoIter {
    fn len(&self) -> usize {
        self.range.len()
    }
}
