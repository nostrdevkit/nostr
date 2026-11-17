use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use core::str;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use super::entry::TagEntry;
use super::field::TagField;
use crate::event::Tags;

/// One decimal-pushing method per integer type, with native-width arithmetic
/// and a buffer sized for that type's worst case.
macro_rules! define_push_uint {
    ($($name:ident($t:ty) => $max_digits:literal;)*) => {
        $(
            #[doc = "Push a tag field with the decimal representation of `value`"]
            pub fn $name(&mut self, value: $t) {
                let mut buf: [u8; $max_digits] = [0; $max_digits];

                if value == 0 {
                    self.push_str("0");
                    return;
                }

                // Extracts digits least-significant first, filling the buffer backwards.
                let mut rest: $t = value;
                let mut start: usize = buf.len();
                while rest > 0 {
                    start -= 1;
                    buf[start] = b'0' + (rest % 10) as u8;
                    rest /= 10;
                }

                // SAFETY: the buffer contains only ASCII digits
                let field: &str = unsafe { str::from_utf8_unchecked(&buf[start..]) };
                self.push_str(field);
            }
        )*
    };
}

/// The writer of the fields of a tag being staged into a [`TagsMut`].
pub struct TagWriter<'a> {
    // The collection the tag is being staged into.
    tags: &'a mut TagsMut,
    // First field index of the tag being staged.
    first_field: u32,
    // How many fields staged so far for this tag.
    n_fields: u32,
}

impl TagWriter<'_> {
    /// Reserves capacity for at least `additional` more fields to be inserted in the tag.
    ///
    /// Does nothing if capacity is already sufficient.
    pub fn reserve(&mut self, additional: usize) {
        self.tags.fields.reserve(additional);
    }

    /// Push a tag field string
    pub fn push_str(&mut self, field: &str) {
        let start: u32 = self.tags.text.len() as u32;
        let len: u32 = field.len() as u32;
        self.tags.fields.push(TagField::new(start, len));
        self.tags.text.push_str(field);
        self.n_fields += 1;
    }

    /// Appends `bytes` as a new field, encoded as lowercase hex.
    pub fn push_hex(&mut self, bytes: &[u8]) {
        let start: u32 = self.tags.text.len() as u32;
        let len: usize = bytes.len() * 2;

        self.tags.text.reserve(len);

        let mut buf: [u8; 64] = [0; 64];

        for chunk in bytes.chunks(32) {
            let n: usize = chunk.len();
            faster_hex::hex_encode(chunk, &mut buf[..n * 2]).expect("buffer size is correct");
            let value: &str = unsafe { str::from_utf8_unchecked(&buf[..n * 2]) };
            self.tags.text.push_str(value);
        }

        self.tags.fields.push(TagField::new(start, len as u32));
        self.n_fields += 1;
    }

    define_push_uint! {
        push_u8(u8)     => 3;  // u8::MAX   = 255
        push_u16(u16)   => 5;  // u16::MAX  = 65_535
        push_u32(u32)   => 10; // u32::MAX  = 4_294_967_295
        push_u64(u64)   => 20; // u64::MAX  = 18_446_744_073_709_551_615
        push_u128(u128) => 39; // u128::MAX = 340_282_366_920_938_463_463_374_607_431_768_211_455
    }

    /// Close the tag being staged.
    ///
    /// Returns `None` if no field was staged (empty tag).
    pub(super) fn end(self) -> Option<TagEntry> {
        let n_fields: NonZeroU32 = NonZeroU32::new(self.n_fields)?;

        let entry: TagEntry = TagEntry {
            first_field: self.first_field,
            n_fields,
        };

        self.tags.entries.push(entry);

        Some(entry)
    }
}

/// A tag that can be written into a [`TagsMut`].
pub trait WriteTag {
    /// Write the fields of the tag, in order, into the writer.
    fn write(self, tx: &mut TagWriter<'_>);
}

impl<I, S> WriteTag for I
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    #[inline]
    fn write(self, tx: &mut TagWriter<'_>) {
        let iter = self.into_iter();

        let (len, _) = iter.size_hint();

        tx.reserve(len);

        for field in iter {
            tx.push_str(field.as_ref());
        }
    }
}

/// A mutable tags collection under construction.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagsMut {
    entries: Vec<TagEntry>,
    fields: Vec<TagField>,
    text: String,
}

impl TagsMut {
    /// Construct a new empty collection.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a new empty collection with at least the specified capacity
    /// (as number of tags).
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            fields: Vec::new(),
            text: String::new(),
        }
    }

    #[inline]
    pub(super) fn from_parts(entries: Vec<TagEntry>, fields: Vec<TagField>, text: String) -> Self {
        Self {
            entries,
            fields,
            text,
        }
    }

    /// How many tags.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the collection is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reserves capacity for at least `additional` more tag to be inserted in the collection.
    ///
    /// Does nothing if capacity is already sufficient.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    /// Removes all the values.
    ///
    /// Note that this method has no effect on the allocated capacity.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.fields.clear();
        self.text.clear();
    }

    #[inline]
    pub(super) fn begin(&mut self) -> TagWriter<'_> {
        TagWriter {
            first_field: self.fields.len() as u32,
            n_fields: 0,
            tags: self,
        }
    }

    /// Write a tag.
    ///
    /// Returns `true` if the tag has been written, otherwise `false` (empty tag).
    #[inline]
    pub fn push<T>(&mut self, tag: T) -> bool
    where
        T: WriteTag,
    {
        let mut tx: TagWriter<'_> = self.begin();
        tag.write(&mut tx);
        tx.end().is_some()
    }

    /// Removes the last added tag.
    pub fn pop(&mut self) {
        let Some(entry) = self.entries.pop() else {
            return;
        };

        let Some(first_field) = self.fields.drain(entry.first_field as usize..).next() else {
            return;
        };

        self.text.truncate(first_field.start());
    }

    /// Freeze the collection into an immutable, cheaply cloneable [`Tags`].
    ///
    /// The collection is not consumed, so it can be efficiently reused for
    /// building other tags, after clearing it with [`TagsMut::clear`].
    #[inline]
    pub fn freeze(&self) -> Tags {
        Tags::from_parts(&self.entries, &self.fields, &self.text)
    }
}

impl<T> From<T> for TagsMut
where
    T: WriteTag,
{
    fn from(tag: T) -> Self {
        let mut tags: TagsMut = TagsMut::with_capacity(1);
        tags.push(tag);
        tags
    }
}

impl<T> Extend<T> for TagsMut
where
    T: WriteTag,
{
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = T>,
    {
        for tag in iter {
            self.push(tag);
        }
    }
}

impl<T> FromIterator<T> for TagsMut
where
    T: WriteTag,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        let mut tags: Self = Self::new();
        tags.extend(iter);
        tags
    }
}

impl Serialize for TagsMut {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        // TODO: remove this freeze
        for tag in self.freeze().iter() {
            seq.serialize_element(&tag)?;
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_pop() {
        let mut tags: TagsMut = TagsMut::new();

        assert!(tags.entries.is_empty());
        assert!(tags.fields.is_empty());
        assert!(tags.text.is_empty());

        tags.push(["t", "nostrdevkit"]);

        assert_eq!(tags.entries.len(), 1);
        assert_eq!(tags.fields.len(), 2);
        assert_eq!(tags.text, "tnostrdevkit");

        tags.push(["t", "rust"]);

        assert_eq!(tags.entries.len(), 2);
        assert_eq!(tags.fields.len(), 4);
        assert_eq!(tags.text, "tnostrdevkittrust");

        tags.pop();

        assert_eq!(tags.entries.len(), 1);
        assert_eq!(tags.fields.len(), 2);
        assert_eq!(tags.text, "tnostrdevkit");

        tags.pop();

        assert!(tags.entries.is_empty());
        assert!(tags.fields.is_empty());
        assert!(tags.text.is_empty());
    }
}
