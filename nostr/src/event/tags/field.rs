use core::mem;
use core::ops::Range;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct TagField {
    pub(super) start: u32,
    len: u32,
}

impl TagField {
    pub(super) const SIZE: usize = size_of::<Self>();

    const _CHECK_SIZE: () = assert!(Self::SIZE == 8);

    #[inline]
    pub(super) fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    #[inline]
    pub(super) fn start(&self) -> usize {
        self.start as usize
    }

    #[inline]
    pub(super) fn region(&self) -> Range<usize> {
        let start: usize = self.start as usize;
        let len: usize = self.len as usize;
        start..start + len
    }

    #[inline]
    pub(super) fn from_ne_bytes(bytes: [u8; Self::SIZE]) -> Self {
        unsafe { mem::transmute(bytes) }
    }
}
