// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

macro_rules! impl_tag_codec_conversions {
    (
        $ty:ty,
        fn parse($tag:ident) $parse_body:block
        fn write($value:ident, $tx:ident) $write_body:block
    ) => {
        impl $ty {
            /// Parse a typed tag from a raw tag representation.
            pub fn parse<I, S>($tag: I) -> Result<Self, $crate::error::Error>
            where
                I: IntoIterator<Item = S>,
                S: AsRef<str>,
            $parse_body
        }

        impl $crate::event::WriteTag for $ty {
            #[inline]
            fn write($value: $ty, $tx: &mut $crate::event::TagWriter<'_>) $write_body
        }

        impl TryFrom<&$crate::event::Tag> for $ty {
            type Error = $crate::error::Error;

            #[inline]
            fn try_from(tag: &$crate::event::Tag) -> Result<Self, Self::Error> {
                <$ty>::parse(tag.iter())
            }
        }

        impl TryFrom<$crate::event::Tag> for $ty {
            type Error = $crate::error::Error;

            #[inline]
            fn try_from(tag: $crate::event::Tag) -> Result<Self, Self::Error> {
                <$ty>::parse(tag.iter())
            }
        }

        impl<'a, 'b> TryFrom<&'a $crate::event::TagRef<'b>> for $ty {
            type Error = $crate::error::Error;

            #[inline]
            fn try_from(tag: &'a $crate::event::TagRef<'b>) -> Result<Self, Self::Error> {
                <$ty>::parse(tag.iter())
            }
        }

        impl<'a> TryFrom<$crate::event::TagRef<'a>> for $ty {
            type Error = $crate::error::Error;

            #[inline]
            fn try_from(tag: $crate::event::TagRef<'a>) -> Result<Self, Self::Error> {
                <$ty>::parse(tag.iter())
            }
        }
    };
}

pub(crate) use impl_tag_codec_conversions;
