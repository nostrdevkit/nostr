// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-30: Custom Emoji
//!
//! <https://github.com/nostr-protocol/nips/blob/master/30.md>

use alloc::string::{String, ToString};

use super::nip01::Coordinate;
use super::util::{
    missing_tag_kind, take_and_parse_from_str, take_and_parse_optional_coordinate, take_string,
    unknown_tag,
};
use crate::error::{Error, ErrorKind};
use crate::event::impl_tag_codec_conversions;
use crate::types::url::Url;

const EMOJI: &str = "emoji";

/// Standardized NIP-30 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/30.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip30Tag {
    /// `emoji` tag
    Emoji {
        /// Emoji shortcode
        shortcode: String,
        /// URL to image
        image_url: Url,
        /// Optional emoji set address
        emoji_set: Option<Coordinate>,
    },
}

impl_tag_codec_conversions! {
    Nip30Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            EMOJI => {
                let (shortcode, image_url, emoji_set) = parse_emoji_tag(iter)?;
                Ok(Self::Emoji {
                    shortcode,
                    image_url,
                    emoji_set,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        let Self::Emoji {
            shortcode,
            image_url,
            emoji_set,
        } = self;

        tx.push_str(EMOJI);
        tx.push_str(&shortcode);
        tx.push_str(image_url.as_str());

        if let Some(emoji_set) = emoji_set {
            tx.push_str(&emoji_set.to_string());
        }
    }
}

fn parse_emoji_tag<T, S>(mut iter: T) -> Result<(String, Url, Option<Coordinate>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let shortcode: String = take_string(&mut iter, "shortcode")?;

    if !is_valid_shortcode(&shortcode) {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "invalid shortcode",
        ));
    }

    let image_url: Url = take_and_parse_from_str(&mut iter, "image URL")?;
    let emoji_set: Option<Coordinate> = take_and_parse_optional_coordinate(&mut iter)?;

    Ok((shortcode, image_url, emoji_set))
}

fn is_valid_shortcode(shortcode: &str) -> bool {
    !shortcode.is_empty()
        && shortcode
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Kind, Tags};
    use crate::key::PublicKey;

    #[test]
    fn test_nip30_emoji_tag() {
        let image_url = Url::parse("https://example.com/emoji.png").unwrap();
        let tag = vec!["emoji", "soapbox", "https://example.com/emoji.png"];
        let parsed = Nip30Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip30Tag::Emoji {
                shortcode: String::from("soapbox"),
                image_url,
                emoji_set: None,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_nip30_emoji_tag_with_set() {
        let image_url = Url::parse("https://example.com/emoji.png").unwrap();
        let emoji_set = Coordinate::new(
            Kind::EmojiSet,
            PublicKey::from_hex("79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6")
                .unwrap(),
        )
        .identifier("blobcats");
        let tag = vec![
            "emoji",
            "soapbox",
            "https://example.com/emoji.png",
            "30030:79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6:blobcats",
        ];
        let parsed = Nip30Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip30Tag::Emoji {
                shortcode: String::from("soapbox"),
                image_url,
                emoji_set: Some(emoji_set),
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_nip30_invalid_shortcode() {
        let tag = vec!["emoji", "soap box", "https://example.com/emoji.png"];
        assert_eq!(
            Nip30Tag::parse(&tag).unwrap_err().kind(),
            ErrorKind::Invalid
        );
    }
}
