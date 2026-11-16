// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-32: Labeling
//!
//! <https://github.com/nostr-protocol/nips/blob/master/32.md>

use alloc::string::String;
use alloc::vec;

use super::util::{missing_tag_kind, take_string, unknown_tag};
use crate::event::{EventBuilder, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions};

/// Label event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label {
    namespace: String,
    value: String,
}

impl Label {
    /// Create a label event.
    pub fn new<S1, S2>(namespace: S1, value: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            namespace: namespace.into(),
            value: value.into(),
        }
    }
}

impl IntoEventBuilder for Label {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::Label).tags([
            Nip32Tag::LabelNamespace(self.namespace.clone()).to_tag(),
            Nip32Tag::Label {
                value: self.value,
                namespace: self.namespace,
            }
            .to_tag(),
        ])
    }
}

/// Standardized NIP-32 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/32.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip32Tag {
    /// `L` tag
    LabelNamespace(String),
    /// `l` tag
    Label {
        /// Label value
        value: String,
        /// Label namespace
        namespace: String,
    },
}

impl_tag_codec_conversions! {
    Nip32Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();

        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            "L" => Ok(Self::LabelNamespace(take_string(
                &mut iter,
                "label namespace",
            )?)),
            "l" => {
                let value: String = take_string(&mut iter, "label")?;
                let namespace: String = take_string(&mut iter, "label namespace")?;

                Ok(Self::Label { value, namespace })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::LabelNamespace(namespace) => Tag::new(vec![String::from("L"), namespace.clone()]),
            Self::Label { value, namespace } => {
                Tag::new(vec![String::from("l"), value.clone(), namespace.clone()])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_label_namespace_tag() {
        let tag = vec!["L", "test"];
        let parsed = Nip32Tag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip32Tag::LabelNamespace(String::from("test")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_label_tag() {
        let tag = vec!["l", "other", "test"];
        let parsed = Nip32Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip32Tag::Label {
                value: String::from("other"),
                namespace: String::from("test")
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn label_event() {
        let builder = Label::new("namespace", "value").into_event_builder();

        assert_eq!(builder.kind, Kind::Label);
        assert_eq!(builder.tags.len(), 2);
        assert_eq!(
            Nip32Tag::try_from(&builder.tags[1]).unwrap(),
            Nip32Tag::Label {
                value: String::from("value"),
                namespace: String::from("namespace"),
            }
        );
    }
}
