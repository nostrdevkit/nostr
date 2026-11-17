use core::num::NonZeroU32;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct TagEntry {
    // Position of the first field
    pub(super) first_field: u32,
    pub(super) n_fields: NonZeroU32,
}

impl TagEntry {
    pub(super) const SIZE: usize = size_of::<Self>();

    const _CHECK_SIZE: () = assert!(Self::SIZE == 8);

    #[inline]
    pub(super) fn from_ne_bytes(bytes: [u8; Self::SIZE]) -> Option<Self> {
        let first_field: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let n_fields: [u8; 4] = [bytes[4], bytes[5], bytes[6], bytes[7]];

        let first_field: u32 = u32::from_ne_bytes(first_field);
        let n_fields: u32 = u32::from_ne_bytes(n_fields);
        let n_fields: NonZeroU32 = NonZeroU32::new(n_fields)?;

        Some(Self {
            first_field,
            n_fields,
        })
    }
}
