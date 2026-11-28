use super::repr::TagReprIter;

/// Tag iterator
pub struct TagIter<'a>(TagReprIter<'a>);

impl<'a> TagIter<'a> {
    #[inline]
    pub(super) fn new(iter: TagReprIter<'a>) -> Self {
        Self(iter)
    }
}

impl<'a> Iterator for TagIter<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}
