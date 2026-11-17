// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-58: Badges
//!
//! <https://github.com/nostr-protocol/nips/blob/master/58.md>

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use super::image::ImageDimensions;
use super::nip01::{Coordinate, Nip01Tag};
use super::util::{
    missing_tag_kind, take_and_parse_from_str, take_and_parse_optional_from_str, take_string,
    unknown_tag,
};
use crate::error::{Error, ErrorKind};
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, TagWriter, Tags,
    impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::{RelayUrl, Url};

const IDENTIFIER: &str = "d";
const NAME: &str = "name";
const DESCRIPTION: &str = "description";
const IMAGE: &str = "image";
const THUMB: &str = "thumb";

/// Badge definition event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BadgeDefinition {
    badge_id: String,
    name: Option<String>,
    description: Option<String>,
    image: Option<(Url, Option<ImageDimensions>)>,
    thumbnails: Vec<(Url, Option<ImageDimensions>)>,
}

impl BadgeDefinition {
    /// Create a badge definition.
    pub fn new<S>(badge_id: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            badge_id: badge_id.into(),
            name: None,
            description: None,
            image: None,
            thumbnails: Vec::new(),
        }
    }

    /// Set the badge name.
    pub fn name<S>(mut self, name: S) -> Self
    where
        S: Into<String>,
    {
        self.name = Some(name.into());
        self
    }

    /// Set the badge description.
    pub fn description<S>(mut self, description: S) -> Self
    where
        S: Into<String>,
    {
        self.description = Some(description.into());
        self
    }

    /// Set the badge image.
    pub fn image(mut self, url: Url, dimensions: Option<ImageDimensions>) -> Self {
        self.image = Some((url, dimensions));
        self
    }

    /// Add a badge thumbnail.
    pub fn thumbnail(mut self, url: Url, dimensions: Option<ImageDimensions>) -> Self {
        self.thumbnails.push((url, dimensions));
        self
    }
}

impl IntoEventBuilder for BadgeDefinition {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::BadgeDefinition)
            .tag(Nip58Tag::Identifier(self.badge_id))
            .tags(self.name.map(Nip58Tag::Name))
            .tags(self.description.map(Nip58Tag::Description))
            .tags(
                self.image
                    .map(|(url, dimensions)| Nip58Tag::Image(url, dimensions)),
            )
            .tags(
                self.thumbnails
                    .into_iter()
                    .map(|(url, dimensions)| Nip58Tag::Thumb(url, dimensions)),
            )
    }
}

/// Badge award event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BadgeAward {
    badge_definition: Coordinate,
    awarded_public_keys: Vec<PublicKey>,
}

impl BadgeAward {
    /// Create a badge award.
    pub fn new<I>(badge_definition: &Event, awarded_public_keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let badge_id = badge_definition.tags.identifier().ok_or_else(|| {
            Error::with_static_message(ErrorKind::Missing, "identifier tag not found")
        })?;

        let badge_definition =
            Coordinate::new(Kind::BadgeDefinition, badge_definition.pubkey).identifier(badge_id);

        Ok(Self {
            badge_definition,
            awarded_public_keys: awarded_public_keys.into_iter().collect(),
        })
    }
}

impl IntoEventBuilder for BadgeAward {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::BadgeAward)
            .tag(Nip01Tag::coordinate(self.badge_definition))
            .tags(
                self.awarded_public_keys
                    .into_iter()
                    .map(Nip01Tag::public_key),
            )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProfileBadge {
    definition: Coordinate,
    definition_relay_hint: Option<RelayUrl>,
    award: EventId,
    award_relay_hint: Option<RelayUrl>,
}

/// Profile badges event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileBadges {
    badges: Vec<ProfileBadge>,
}

impl ProfileBadges {
    /// Create a profile badges event.
    pub fn new(
        badge_definitions: Vec<Event>,
        badge_awards: Vec<Event>,
        awarded_public_key: PublicKey,
    ) -> Result<Self, Error> {
        if badge_definitions.len() != badge_awards.len() {
            return Err(Error::with_static_message(
                ErrorKind::Invalid,
                "invalid length",
            ));
        }

        let badge_awards: Vec<Event> = filter_for_kind(badge_awards, &Kind::BadgeAward);
        if badge_awards.is_empty() {
            return Err(Error::with_static_message(
                ErrorKind::Missing,
                "badge awards are missing",
            ));
        }

        for award in badge_awards.iter() {
            if !award
                .tags
                .public_keys()
                .any(|public_key| public_key == awarded_public_key)
            {
                return Err(Error::with_static_message(
                    ErrorKind::Invalid,
                    "badge award lacks awarded public key",
                ));
            }
        }

        let badge_definitions: Vec<Event> =
            filter_for_kind(badge_definitions, &Kind::BadgeDefinition);
        if badge_definitions.is_empty() {
            return Err(Error::with_static_message(
                ErrorKind::Missing,
                "badge definitions are missing",
            ));
        }

        let definitions = badge_definitions.iter().filter_map(|event| {
            let identifier = event.tags.identifier()?;
            Some((event, identifier))
        });
        let awards = badge_awards.iter().filter_map(|event| {
            let (_, award_relay_hint) =
                extract_awarded_public_key(&event.tags, awarded_public_key)?;
            let (identifier, definition, definition_relay_hint) =
                event
                    .tags
                    .iter()
                    .find_map(|tag| match Nip01Tag::try_from(tag) {
                        Ok(Nip01Tag::Coordinate {
                            coordinate,
                            relay_hint,
                        }) => Some((coordinate.identifier.clone(), coordinate, relay_hint)),
                        _ => None,
                    })?;
            Some((
                event,
                identifier,
                definition,
                definition_relay_hint,
                award_relay_hint,
            ))
        });

        let mut badges: Vec<ProfileBadge> = Vec::new();

        for (definition, award) in core::iter::zip(definitions, awards) {
            match (definition, award) {
                ((_, definition_id), (_, award_id, ..)) if definition_id != award_id => {
                    return Err(Error::with_static_message(
                        ErrorKind::Invalid,
                        "mismatched badge definition or award",
                    ));
                }
                (
                    (_, definition_id),
                    (award_event, award_id, definition, definition_relay_hint, award_relay_hint),
                ) if definition_id == award_id => {
                    badges.push(ProfileBadge {
                        definition,
                        definition_relay_hint,
                        award: award_event.id,
                        award_relay_hint,
                    });
                }
                _ => {}
            }
        }

        Ok(Self { badges })
    }
}

impl IntoEventBuilder for ProfileBadges {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::ProfileBadges);

        builder.tags.reserve(2 * self.badges.len());

        for badge in self.badges {
            builder.tags.push(Nip01Tag::Coordinate {
                coordinate: badge.definition,
                relay_hint: badge.definition_relay_hint,
            });
            builder.tags.push(Nip01Tag::Event {
                id: badge.award,
                relay_hint: badge.award_relay_hint,
                public_key: None,
            });
        }

        builder
    }
}

/// Standardized NIP-58 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/58.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip58Tag {
    /// `d` tag
    Identifier(String),
    /// `name` tag
    Name(String),
    /// `description` tag
    Description(String),
    /// `image` tag
    Image(Url, Option<ImageDimensions>),
    /// `thumb` tag
    Thumb(Url, Option<ImageDimensions>),
}

impl_tag_codec_conversions! {
    Nip58Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            IDENTIFIER => Ok(Self::Identifier(take_string(&mut iter, "identifier")?)),
            NAME => Ok(Self::Name(take_string(&mut iter, "name")?)),
            DESCRIPTION => Ok(Self::Description(take_string(&mut iter, "description")?)),
            IMAGE => {
                let (url, dimensions) = parse_url_and_dimensions_tag(iter, "image URL")?;
                Ok(Self::Image(url, dimensions))
            }
            THUMB => {
                let (url, dimensions) = parse_url_and_dimensions_tag(iter, "thumbnail URL")?;
                Ok(Self::Thumb(url, dimensions))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::Identifier(identifier) => {
                tx.push_str(IDENTIFIER);
                tx.push_str(&identifier);
            }
            Self::Name(name) => {
                tx.push_str(NAME);
                tx.push_str(&name);
            }
            Self::Description(description) => {
                tx.push_str(DESCRIPTION);
                tx.push_str(&description);
            }
            Self::Image(url, dimensions) => {
                to_url_and_dimensions_tag(tx, IMAGE, &url, &dimensions)
            }
            Self::Thumb(url, dimensions) => {
                to_url_and_dimensions_tag(tx, THUMB, &url, &dimensions)
            }
        }
    }
}

fn parse_url_and_dimensions_tag<T, S>(
    mut iter: T,
    missing_error: &'static str,
) -> Result<(Url, Option<ImageDimensions>), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let url: Url = take_and_parse_from_str(&mut iter, missing_error)?;
    let dimensions: Option<ImageDimensions> = take_and_parse_optional_from_str(&mut iter)?;

    Ok((url, dimensions))
}

fn to_url_and_dimensions_tag(
    tx: &mut TagWriter,
    kind: &str,
    url: &Url,
    dimensions: &Option<ImageDimensions>,
) {
    tx.push_str(kind);
    tx.push_str(url.as_str());

    if let Some(dimensions) = dimensions {
        tx.push_str(&dimensions.to_string());
    }
}

/// Helper function to filter events for a specific [`Kind`]
#[inline]
pub(crate) fn filter_for_kind(events: Vec<Event>, kind_needed: &Kind) -> Vec<Event> {
    events
        .into_iter()
        .filter(|e| &e.kind == kind_needed)
        .collect()
}

/// Helper function to extract the awarded public key from an array of PubKey tags
pub(crate) fn extract_awarded_public_key(
    tags: &Tags,
    awarded_public_key: PublicKey,
) -> Option<(PublicKey, Option<RelayUrl>)> {
    tags.iter().find_map(|t| match Nip01Tag::try_from(t) {
        Ok(Nip01Tag::PublicKey {
            public_key,
            relay_hint,
        }) if public_key == awarded_public_key => Some((public_key, relay_hint)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::event::{FinalizeEvent, IntoEventBuilder};
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::key::Keys;

    #[test]
    fn test_identifier_tag() {
        let tag = vec!["d", "bravery"];
        let parsed = Nip58Tag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip58Tag::Identifier(String::from("bravery")));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_name_tag() {
        let tag = vec!["name", "Medal of Bravery"];
        let parsed = Nip58Tag::parse(&tag).unwrap();
        assert_eq!(parsed, Nip58Tag::Name(String::from("Medal of Bravery")));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_description_tag() {
        let tag = vec!["description", "Awarded to users demonstrating bravery"];
        let parsed = Nip58Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip58Tag::Description(String::from("Awarded to users demonstrating bravery"))
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_image_tag() {
        let tag = vec![
            "image",
            "https://nostr.academy/awards/bravery.png",
            "1024x1024",
        ];
        let parsed = Nip58Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip58Tag::Image(
                Url::parse("https://nostr.academy/awards/bravery.png").unwrap(),
                Some(ImageDimensions::new(1024, 1024))
            )
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_thumb_tag() {
        let tag = vec![
            "thumb",
            "https://nostr.academy/awards/bravery_256x256.png",
            "256x256",
        ];
        let parsed = Nip58Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            Nip58Tag::Thumb(
                Url::parse("https://nostr.academy/awards/bravery_256x256.png").unwrap(),
                Some(ImageDimensions::new(256, 256))
            )
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn badge_builders() {
        let definition_builder = BadgeDefinition::new("bravery")
            .name("Bravery")
            .description("A brave soul");
        let generic = definition_builder.clone().into_event_builder();
        let tags: Tags = generic.tags.into();

        assert_eq!(generic.kind, Kind::BadgeDefinition);
        assert_eq!(tags.identifier().as_deref(), Some("bravery"));

        let badge_keys = Keys::generate();
        let definition = definition_builder.finalize(&badge_keys).unwrap();

        let profile_keys = Keys::generate();
        let award = BadgeAward::new(&definition, [profile_keys.public_key()])
            .unwrap()
            .finalize(&badge_keys)
            .unwrap();
        assert_eq!(award.kind, Kind::BadgeAward);

        let profile = ProfileBadges::new(vec![definition], vec![award], profile_keys.public_key())
            .unwrap()
            .finalize(&profile_keys)
            .unwrap();
        assert_eq!(profile.kind, Kind::ProfileBadges);
        assert_eq!(profile.tags.len(), 2);
    }
}
