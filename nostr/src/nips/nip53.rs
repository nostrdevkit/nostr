// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP53: Live Activities
//!
//! <https://github.com/nostr-protocol/nips/blob/master/53.md>

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use secp256k1::schnorr::Signature;

use super::nip01::{Coordinate, Nip01Tag};
use super::util::{
    invalid_value, missing_tag_kind, missing_value, take_and_parse_from_str,
    take_and_parse_optional_from_str, take_and_parse_optional_relay_url, take_coordinate,
    take_event_id, take_optional_string, take_public_key, take_string, take_timestamp, unknown_tag,
};
use crate::error::{Error, ErrorKind};
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions,
};
use crate::key::PublicKey;
use crate::types::Timestamp;
use crate::types::url::{RelayUrl, Url};

const TITLE: &str = "title";
const SUMMARY: &str = "summary";
const IMAGE: &str = "image";
const STREAMING: &str = "streaming";
const RECORDING: &str = "recording";
const STARTS: &str = "starts";
const ENDS: &str = "ends";
const STATUS: &str = "status";
const CURRENT_PARTICIPANTS: &str = "current_participants";
const TOTAL_PARTICIPANTS: &str = "total_participants";
const RELAYS: &str = "relays";
const ROOM: &str = "room";
const SERVICE: &str = "service";
const ENDPOINT: &str = "endpoint";
const PINNED: &str = "pinned";
const HAND: &str = "hand";

#[inline]
fn description_missing() -> Error {
    Error::with_static_message(ErrorKind::Missing, "description missing")
}

/// Live Event Marker
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LiveEventMarker {
    /// Host
    Host,
    /// Speaker
    Speaker,
    /// Participant
    Participant,
    /// Moderator
    Moderator,
    /// Owner
    Owner,
    /// Custom role label
    Custom(String),
}

impl fmt::Display for LiveEventMarker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl LiveEventMarker {
    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::Host => "Host",
            Self::Speaker => "Speaker",
            Self::Participant => "Participant",
            Self::Moderator => "Moderator",
            Self::Owner => "Owner",
            Self::Custom(value) => value.as_str(),
        }
    }
}

impl FromStr for LiveEventMarker {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Host" => Self::Host,
            "Speaker" => Self::Speaker,
            "Participant" => Self::Participant,
            "Moderator" => Self::Moderator,
            "Owner" => Self::Owner,
            other => Self::Custom(other.to_string()),
        })
    }
}

/// Live Event Status
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LiveEventStatus {
    /// Planned
    Planned,
    /// Live
    Live,
    /// Ended
    Ended,
    /// Custom
    Custom(String),
}

impl fmt::Display for LiveEventStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl LiveEventStatus {
    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::Planned => "planned",
            Self::Live => "live",
            Self::Ended => "ended",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl<S> From<S> for LiveEventStatus
where
    S: Into<String>,
{
    fn from(s: S) -> Self {
        let s: String = s.into();
        match s.as_str() {
            "planned" => Self::Planned,
            "live" => Self::Live,
            "ended" => Self::Ended,
            _ => Self::Custom(s),
        }
    }
}

/// Live event participant tag
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveEventParticipant {
    /// Participant public key
    pub public_key: PublicKey,
    /// Participant relay URL
    pub relay_url: Option<RelayUrl>,
    /// Participant role
    pub marker: LiveEventMarker,
    /// Optional proof
    pub proof: Option<Signature>,
}

/// Live event space reference
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveEventSpace {
    /// Coordinate
    pub coordinate: Coordinate,
    /// Optional relay URL
    pub relay_url: Option<RelayUrl>,
    /// Optional marker
    pub marker: Option<String>,
}

/// NIP53 tags
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip53Tag {
    /// Title
    Title(String),
    /// Summary
    Summary(String),
    /// Image
    Image(Url),
    /// Hashtag
    Hashtag(String),
    /// Streaming URL
    Streaming(Url),
    /// Recording URL
    Recording(Url),
    /// Start timestamp
    Starts(Timestamp),
    /// End timestamp
    Ends(Timestamp),
    /// Status
    Status(LiveEventStatus),
    /// Current participants count
    CurrentParticipants(u64),
    /// Total participants count
    TotalParticipants(u64),
    /// Preferred relays
    Relays(Vec<RelayUrl>),
    /// Participant role tag
    Participant(LiveEventParticipant),
    /// Room display name
    Room(String),
    /// Service URL
    Service(Url),
    /// Endpoint URL
    Endpoint(Url),
    /// Pinned event
    Pinned(EventId),
    /// Space reference
    Space(LiveEventSpace),
    /// Hand raised flag
    Hand(bool),
}

impl_tag_codec_conversions! {
    Nip53Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            TITLE => Ok(Self::Title(take_string(&mut iter, "title")?)),
            SUMMARY => Ok(Self::Summary(take_string(&mut iter, "summary")?)),
            IMAGE => {
                let image: Url = take_and_parse_from_str(&mut iter, "image URL")?;
                Ok(Self::Image(image))
            }
            "t" => {
                let hashtag: String = take_string(&mut iter, "hashtag")?;
                if hashtag.chars().any(char::is_uppercase) {
                    return Err(invalid_value("hashtag contains uppercase characters"));
                }

                Ok(Self::Hashtag(hashtag))
            }
            STREAMING => {
                let url: Url = take_and_parse_from_str(&mut iter, "streaming URL")?;
                Ok(Self::Streaming(url))
            }
            RECORDING => {
                let url: Url = take_and_parse_from_str(&mut iter, "recording URL")?;
                Ok(Self::Recording(url))
            }
            STARTS => {
                let timestamp: Timestamp = take_timestamp(&mut iter)?;
                Ok(Self::Starts(timestamp))
            }
            ENDS => {
                let timestamp: Timestamp = take_timestamp(&mut iter)?;
                Ok(Self::Ends(timestamp))
            }
            STATUS => Ok(Self::Status(LiveEventStatus::from(take_string(
                &mut iter, "status",
            )?))),
            CURRENT_PARTICIPANTS => {
                let num: u64 = take_and_parse_from_str(&mut iter, "current participants")?;
                Ok(Self::CurrentParticipants(num))
            }
            TOTAL_PARTICIPANTS => {
                let num: u64 = take_and_parse_from_str(&mut iter, "total participants")?;
                Ok(Self::TotalParticipants(num))
            }
            RELAYS => {
                let mut relays: Vec<RelayUrl> = Vec::new();
                for relay in iter {
                    relays.push(RelayUrl::parse(relay.as_ref())?);
                }
                Ok(Self::Relays(relays))
            }
            "p" => parse_p_tag(iter),
            ROOM => Ok(Self::Room(take_string(&mut iter, "room")?)),
            SERVICE => {
                let url: Url = take_and_parse_from_str(&mut iter, "service URL")?;
                Ok(Self::Service(url))
            }
            ENDPOINT => {
                let url: Url = take_and_parse_from_str(&mut iter, "endpoint URL")?;
                Ok(Self::Endpoint(url))
            }
            PINNED => {
                let event_id: EventId = take_event_id(&mut iter)?;
                Ok(Self::Pinned(event_id))
            }
            "a" => parse_a_tag(iter),
            HAND => parse_hand_tag(iter),
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::Title(title) => Tag::new(vec![String::from(TITLE), title.clone()]),
            Self::Summary(summary) => Tag::new(vec![String::from(SUMMARY), summary.clone()]),
            Self::Image(image) => Tag::new(vec![String::from(IMAGE), image.to_string()]),
            Self::Hashtag(hashtag) => Tag::new(vec![String::from("t"), hashtag.clone()]),
            Self::Streaming(url) => Tag::new(vec![String::from(STREAMING), url.to_string()]),
            Self::Recording(url) => Tag::new(vec![String::from(RECORDING), url.to_string()]),
            Self::Starts(timestamp) => Tag::new(vec![String::from(STARTS), timestamp.to_string()]),
            Self::Ends(timestamp) => Tag::new(vec![String::from(ENDS), timestamp.to_string()]),
            Self::Status(status) => Tag::new(vec![String::from(STATUS), status.to_string()]),
            Self::CurrentParticipants(count) => {
                Tag::new(vec![String::from(CURRENT_PARTICIPANTS), count.to_string()])
            }
            Self::TotalParticipants(count) => {
                Tag::new(vec![String::from(TOTAL_PARTICIPANTS), count.to_string()])
            }
            Self::Relays(relays) => {
                let mut tag: Vec<String> = Vec::with_capacity(1 + relays.len());
                tag.push(String::from(RELAYS));
                tag.extend(relays.iter().map(|relay| relay.to_string()));
                Tag::new(tag)
            }
            Self::Participant(participant) => {
                let mut tag = vec![
                    String::from("p"),
                    participant.public_key.to_string(),
                    participant
                        .relay_url
                        .as_ref()
                        .map(|relay| relay.to_string())
                        .unwrap_or_default(),
                    participant.marker.to_string(),
                ];
                if let Some(proof) = participant.proof {
                    tag.push(proof.to_string());
                }
                Tag::new(tag)
            }
            Self::Room(room) => Tag::new(vec![String::from(ROOM), room.clone()]),
            Self::Service(service) => Tag::new(vec![String::from(SERVICE), service.to_string()]),
            Self::Endpoint(endpoint) => {
                Tag::new(vec![String::from(ENDPOINT), endpoint.to_string()])
            }
            Self::Pinned(event_id) => Tag::new(vec![String::from(PINNED), event_id.to_hex()]),
            Self::Space(space) => {
                let mut tag = vec![String::from("a"), space.coordinate.to_string()];
                if let Some(relay_url) = &space.relay_url {
                    tag.push(relay_url.to_string());
                }
                if let Some(marker) = &space.marker {
                    if space.relay_url.is_none() {
                        tag.push(String::new());
                    }
                    tag.push(marker.clone());
                }
                Tag::new(tag)
            }
            Self::Hand(hand) => Tag::new(vec![
                String::from(HAND),
                if *hand { "1" } else { "0" }.to_string(),
            ]),
        }
    }
}

fn parse_p_tag<T, S>(mut iter: T) -> Result<Nip53Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let public_key: PublicKey = take_public_key(&mut iter)?;
    let relay_url: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;
    let marker: LiveEventMarker = take_and_parse_from_str(&mut iter, "marker")?;
    let proof: Option<Signature> =
        take_and_parse_optional_from_str(&mut iter).map_err(Error::malformed_display)?;

    Ok(Nip53Tag::Participant(LiveEventParticipant {
        public_key,
        relay_url,
        marker,
        proof,
    }))
}

fn parse_a_tag<T, S>(mut iter: T) -> Result<Nip53Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let coordinate = take_coordinate(&mut iter)?;
    let relay_url: Option<RelayUrl> = take_and_parse_optional_relay_url(&mut iter)?;
    let marker: Option<String> = take_optional_string(&mut iter);

    Ok(Nip53Tag::Space(LiveEventSpace {
        coordinate,
        relay_url,
        marker,
    }))
}

fn parse_hand_tag<T, S>(mut iter: T) -> Result<Nip53Tag, Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let hand: S = iter.next().ok_or(missing_value("hand"))?;
    let hand: bool = match hand.as_ref() {
        "1" => true,
        "0" => false,
        _ => return Err(unknown_tag()),
    };

    Ok(Nip53Tag::Hand(hand))
}

/// Live Event Host
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveEventHost {
    /// Host public key
    pub public_key: PublicKey,
    /// Host relay URL
    pub relay_url: Option<RelayUrl>,
    /// Host proof
    pub proof: Option<Signature>,
}

/// Live Event
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveEvent {
    /// Event kind
    pub kind: Kind,
    /// Unique event identifier (`d` tag)
    pub id: String,
    /// Room display name
    pub room: Option<String>,
    /// Parent space reference
    pub space: Option<LiveEventSpace>,
    /// Event title
    pub title: Option<String>,
    /// Event summary
    pub summary: Option<String>,
    /// Event image
    pub image: Option<Url>,
    /// Hashtags
    pub hashtags: Vec<String>,
    /// Streaming URL
    pub streaming: Option<Url>,
    /// Recording URL
    pub recording: Option<Url>,
    /// Service URL
    pub service: Option<Url>,
    /// Endpoint URL
    pub endpoint: Option<Url>,
    /// Starts at
    pub starts: Option<Timestamp>,
    /// Ends at
    pub ends: Option<Timestamp>,
    /// Current status
    pub status: Option<LiveEventStatus>,
    /// Current participants
    pub current_participants: Option<u64>,
    /// Total participants
    pub total_participants: Option<u64>,
    /// Relays
    pub relays: Vec<RelayUrl>,
    /// Pinned live chat messages
    pub pinned: Vec<EventId>,
    /// Host
    pub host: Option<LiveEventHost>,
    /// Owners
    pub owners: Vec<(PublicKey, Option<RelayUrl>)>,
    /// Moderators
    pub moderators: Vec<(PublicKey, Option<RelayUrl>)>,
    /// Speakers
    pub speakers: Vec<(PublicKey, Option<RelayUrl>)>,
    /// Participants
    pub participants: Vec<(PublicKey, Option<RelayUrl>)>,
    /// Hand raised flag for presence events
    pub hand: Option<bool>,
}

/// Live event message builder.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LiveEventMessageBuilder {
    live_event_id: String,
    live_event_host: PublicKey,
    content: String,
    relay_hint: Option<RelayUrl>,
}

impl LiveEventMessageBuilder {
    /// Create a live event message.
    pub fn new<S1, S2>(live_event_id: S1, live_event_host: PublicKey, content: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            live_event_id: live_event_id.into(),
            live_event_host,
            content: content.into(),
            relay_hint: None,
        }
    }

    /// Set the relay hint.
    pub fn relay_hint(mut self, relay_hint: RelayUrl) -> Self {
        self.relay_hint = Some(relay_hint);
        self
    }
}

impl IntoEventBuilder for LiveEventMessageBuilder {
    fn into_event_builder(self) -> EventBuilder {
        let coordinate =
            Coordinate::new(Kind::LiveEvent, self.live_event_host).identifier(self.live_event_id);
        EventBuilder::new(Kind::LiveEventMessage)
            .content(self.content)
            .tag(Nip01Tag::Coordinate {
                coordinate,
                relay_hint: self.relay_hint,
            })
    }
}

impl LiveEvent {
    /// Create a new LiveEvent
    pub fn new<S>(id: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            kind: Kind::LiveEvent,
            id: id.into(),
            room: None,
            space: None,
            title: None,
            summary: None,
            image: None,
            hashtags: Vec::new(),
            streaming: None,
            recording: None,
            service: None,
            endpoint: None,
            starts: None,
            ends: None,
            status: None,
            current_participants: None,
            total_participants: None,
            relays: Vec::new(),
            pinned: Vec::new(),
            host: None,
            owners: Vec::new(),
            moderators: Vec::new(),
            speakers: Vec::new(),
            participants: Vec::new(),
            hand: None,
        }
    }

    /// Parse live-activity data from an [`Event`].
    pub fn from_event(event: &Event) -> Result<Self, Error> {
        let id = if event.kind == Kind::Custom(10312) {
            String::new()
        } else {
            event.tags.identifier().ok_or(description_missing())?
        };

        let mut live_event = Self::new(id);
        live_event.kind = event.kind;

        for tag in event.tags.iter() {
            let parsed = match Nip53Tag::try_from(tag) {
                Ok(tag) => tag,
                Err(e) if e.kind() == ErrorKind::Malformed => continue,
                Err(err) => return Err(err),
            };

            live_event.apply_tag(parsed);
        }

        Ok(live_event)
    }

    fn apply_tag(&mut self, tag: Nip53Tag) {
        match tag {
            Nip53Tag::Title(title) => self.title = Some(title),
            Nip53Tag::Summary(summary) => self.summary = Some(summary),
            Nip53Tag::Image(image) => self.image = Some(image),
            Nip53Tag::Hashtag(hashtag) => self.hashtags.push(hashtag),
            Nip53Tag::Streaming(url) => self.streaming = Some(url),
            Nip53Tag::Recording(url) => self.recording = Some(url),
            Nip53Tag::Starts(starts) => self.starts = Some(starts),
            Nip53Tag::Ends(ends) => self.ends = Some(ends),
            Nip53Tag::Status(status) => self.status = Some(status),
            Nip53Tag::CurrentParticipants(count) => self.current_participants = Some(count),
            Nip53Tag::TotalParticipants(count) => self.total_participants = Some(count),
            Nip53Tag::Relays(mut relays) => self.relays.append(&mut relays),
            Nip53Tag::Participant(participant) => match participant.marker {
                LiveEventMarker::Host => {
                    self.host = Some(LiveEventHost {
                        public_key: participant.public_key,
                        relay_url: participant.relay_url,
                        proof: participant.proof,
                    });
                }
                LiveEventMarker::Owner => {
                    self.owners
                        .push((participant.public_key, participant.relay_url));
                }
                LiveEventMarker::Moderator => {
                    self.moderators
                        .push((participant.public_key, participant.relay_url));
                }
                LiveEventMarker::Speaker => {
                    self.speakers
                        .push((participant.public_key, participant.relay_url));
                }
                LiveEventMarker::Participant | LiveEventMarker::Custom(_) => {
                    self.participants
                        .push((participant.public_key, participant.relay_url));
                }
            },
            Nip53Tag::Room(room) => self.room = Some(room),
            Nip53Tag::Service(service) => self.service = Some(service),
            Nip53Tag::Endpoint(endpoint) => self.endpoint = Some(endpoint),
            Nip53Tag::Pinned(event_id) => self.pinned.push(event_id),
            Nip53Tag::Space(space) => self.space = Some(space),
            Nip53Tag::Hand(hand) => self.hand = Some(hand),
        }
    }
}

impl IntoEventBuilder for LiveEvent {
    fn into_event_builder(self) -> EventBuilder {
        let tags: Vec<Tag> = self.into();
        EventBuilder::new(Kind::LiveEvent).tags(tags)
    }
}

impl From<LiveEvent> for Vec<Tag> {
    fn from(live_event: LiveEvent) -> Self {
        let LiveEvent {
            kind: _,
            id,
            room,
            space,
            title,
            summary,
            image,
            hashtags,
            streaming,
            recording,
            service,
            endpoint,
            starts,
            ends,
            status,
            current_participants,
            total_participants,
            relays,
            pinned,
            host,
            owners,
            moderators,
            speakers,
            participants,
            hand,
        } = live_event;

        let mut tags = Vec::with_capacity(1);

        if !id.is_empty() {
            tags.push(Tag::identifier(id));
        }

        if let Some(room) = room {
            tags.push(Nip53Tag::Room(room).to_tag());
        }

        if let Some(space) = space {
            tags.push(Nip53Tag::Space(space).to_tag());
        }

        if let Some(title) = title {
            tags.push(Nip53Tag::Title(title).to_tag());
        }

        if let Some(summary) = summary {
            tags.push(Nip53Tag::Summary(summary).to_tag());
        }

        if let Some(image) = image {
            tags.push(Nip53Tag::Image(image).to_tag());
        }

        for hashtag in hashtags.into_iter() {
            tags.push(Nip53Tag::Hashtag(hashtag).to_tag());
        }

        if let Some(streaming) = streaming {
            tags.push(Nip53Tag::Streaming(streaming).to_tag());
        }

        if let Some(recording) = recording {
            tags.push(Nip53Tag::Recording(recording).to_tag());
        }

        if let Some(service) = service {
            tags.push(Nip53Tag::Service(service).to_tag());
        }

        if let Some(endpoint) = endpoint {
            tags.push(Nip53Tag::Endpoint(endpoint).to_tag());
        }

        if let Some(starts) = starts {
            tags.push(Nip53Tag::Starts(starts).to_tag());
        }

        if let Some(ends) = ends {
            tags.push(Nip53Tag::Ends(ends).to_tag());
        }

        if let Some(status) = status {
            tags.push(Nip53Tag::Status(status).to_tag());
        }

        if let Some(current_participants) = current_participants {
            tags.push(Nip53Tag::CurrentParticipants(current_participants).to_tag());
        }

        if let Some(total_participants) = total_participants {
            tags.push(Nip53Tag::TotalParticipants(total_participants).to_tag());
        }

        if !relays.is_empty() {
            tags.push(Nip53Tag::Relays(relays).to_tag());
        }

        for event_id in pinned.into_iter() {
            tags.push(Nip53Tag::Pinned(event_id).to_tag());
        }

        if let Some(LiveEventHost {
            public_key,
            relay_url,
            proof,
        }) = host
        {
            tags.push(
                Nip53Tag::Participant(LiveEventParticipant {
                    public_key,
                    relay_url,
                    marker: LiveEventMarker::Host,
                    proof,
                })
                .to_tag(),
            );
        }

        for (public_key, relay_url) in owners.into_iter() {
            tags.push(
                Nip53Tag::Participant(LiveEventParticipant {
                    public_key,
                    relay_url,
                    marker: LiveEventMarker::Owner,
                    proof: None,
                })
                .to_tag(),
            );
        }

        for (public_key, relay_url) in moderators.into_iter() {
            tags.push(
                Nip53Tag::Participant(LiveEventParticipant {
                    public_key,
                    relay_url,
                    marker: LiveEventMarker::Moderator,
                    proof: None,
                })
                .to_tag(),
            );
        }

        for (public_key, relay_url) in speakers.into_iter() {
            tags.push(
                Nip53Tag::Participant(LiveEventParticipant {
                    public_key,
                    relay_url,
                    marker: LiveEventMarker::Speaker,
                    proof: None,
                })
                .to_tag(),
            );
        }

        for (public_key, relay_url) in participants.into_iter() {
            tags.push(
                Nip53Tag::Participant(LiveEventParticipant {
                    public_key,
                    relay_url,
                    marker: LiveEventMarker::Participant,
                    proof: None,
                })
                .to_tag(),
            );
        }

        if let Some(hand) = hand {
            tags.push(Nip53Tag::Hand(hand).to_tag());
        }

        tags
    }
}

impl TryFrom<Vec<Tag>> for LiveEvent {
    type Error = Error;

    fn try_from(tags: Vec<Tag>) -> Result<Self, Self::Error> {
        let id: String = tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .map(|value| value.to_string())
            .ok_or(description_missing())?;

        let mut live_event = LiveEvent::new(id);

        for tag in tags.into_iter() {
            let parsed = match Nip53Tag::try_from(tag) {
                Ok(tag) => tag,
                Err(e) if e.kind() == ErrorKind::Malformed => continue,
                Err(err) => return Err(err),
            };

            live_event.apply_tag(parsed);
        }

        Ok(live_event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_live_event_marker() {
        assert_eq!(
            LiveEventMarker::from_str("Host").unwrap(),
            LiveEventMarker::Host
        );
        assert_eq!(
            LiveEventMarker::from_str("Moderator").unwrap(),
            LiveEventMarker::Moderator
        );
        assert_eq!(
            LiveEventMarker::from_str("Owner").unwrap(),
            LiveEventMarker::Owner
        );
        assert_eq!(
            LiveEventMarker::from_str("Invited").unwrap(),
            LiveEventMarker::Custom(String::from("Invited"))
        );
    }

    #[test]
    fn test_standardized_nip53_tags() {
        let service = Nip53Tag::parse(["service", "https://meet.example.com/room"]).unwrap();
        assert_eq!(
            service,
            Nip53Tag::Service(Url::parse("https://meet.example.com/room").unwrap())
        );

        let pinned_id =
            EventId::from_hex("97aa81798ee6c5637f7b21a411f89e10244e195aa91cb341bf49f718e36c8188")
                .unwrap();
        let pinned = Nip53Tag::parse([
            "pinned",
            "97aa81798ee6c5637f7b21a411f89e10244e195aa91cb341bf49f718e36c8188",
        ])
        .unwrap();
        assert_eq!(pinned, Nip53Tag::Pinned(pinned_id));

        let space = Nip53Tag::parse([
            "a",
            "30312:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:main-conference-room",
            "wss://nostr.example.com",
            "root",
        ])
        .unwrap();
        assert_eq!(
            space,
            Nip53Tag::Space(LiveEventSpace {
                coordinate: Coordinate::new(
                    Kind::Custom(30312),
                    PublicKey::from_hex(
                        "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca",
                    )
                    .unwrap(),
                )
                .identifier("main-conference-room"),
                relay_url: Some(RelayUrl::parse("wss://nostr.example.com").unwrap()),
                marker: Some(String::from("root")),
            })
        );

        let hand = Nip53Tag::parse(["hand", "1"]).unwrap();
        assert_eq!(hand, Nip53Tag::Hand(true));
    }

    #[test]
    fn test_live_event_from_event() {
        let event = Event::from_json(
            r#"{
  "content": "",
  "created_at": 1687286726,
  "id": "97aa81798ee6c5637f7b21a411f89e10244e195aa91cb341bf49f718e36c8188",
  "kind": 30313,
  "pubkey": "3f770d65d3a764a9c5cb503ae123e62ec7598ad035d836e2a810f3877a745b24",
  "sig": "997f62ddfc0827c121043074d50cfce7a528e978c575722748629a4137c45b75bdbc84170bedc723ef0a5a4c3daebf1fef2e93f5e2ddb98e5d685d022c30b622",
  "tags": [
    ["d", "annual-meeting-2025"],
    ["a", "30312:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:main-conference-room", "wss://nostr.example.com"],
    ["title", "Annual Company Meeting 2025"],
    ["summary", "Yearly company-wide meeting"],
    ["image", "https://example.com/meeting.jpg"],
    ["starts", "1676262123"],
    ["ends", "1676269323"],
    ["status", "live"],
    ["total_participants", "180"],
    ["current_participants", "175"],
    ["p", "91cf94e5ca91cf94e5ca91cf94e5ca91cf94e5ca91cf94e5ca91cf94e5ca91cf", "wss://provider1.com/", "Speaker"]
  ]
}"#,
        )
        .unwrap();

        let live_event = LiveEvent::from_event(&event).unwrap();
        assert_eq!(live_event.kind, Kind::Custom(30313));
        assert_eq!(live_event.id, "annual-meeting-2025");
        assert_eq!(
            live_event.space,
            Some(LiveEventSpace {
                coordinate: Coordinate::new(
                    Kind::Custom(30312),
                    PublicKey::from_hex(
                        "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca",
                    )
                    .unwrap(),
                )
                .identifier("main-conference-room"),
                relay_url: Some(RelayUrl::parse("wss://nostr.example.com").unwrap()),
                marker: None,
            })
        );
        assert_eq!(
            live_event.title,
            Some(String::from("Annual Company Meeting 2025"))
        );
        assert_eq!(live_event.status, Some(LiveEventStatus::Live));
        assert_eq!(live_event.total_participants, Some(180));
        assert_eq!(live_event.current_participants, Some(175));
        assert_eq!(live_event.speakers.len(), 1);
    }

    #[test]
    fn test_room_presence_from_event() {
        let event = Event::from_json(
            r#"{
  "content": "",
  "created_at": 1687286726,
  "id": "97aa81798ee6c5637f7b21a411f89e10244e195aa91cb341bf49f718e36c8188",
  "kind": 10312,
  "pubkey": "3f770d65d3a764a9c5cb503ae123e62ec7598ad035d836e2a810f3877a745b24",
  "sig": "997f62ddfc0827c121043074d50cfce7a528e978c575722748629a4137c45b75bdbc84170bedc723ef0a5a4c3daebf1fef2e93f5e2ddb98e5d685d022c30b622",
  "tags": [
    ["a", "30312:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:main-conference-room", "wss://nostr.example.com", "root"],
    ["hand", "1"]
  ]
}"#,
        )
        .unwrap();

        let presence = LiveEvent::from_event(&event).unwrap();
        assert_eq!(presence.kind, Kind::Custom(10312));
        assert!(presence.id.is_empty());
        assert_eq!(presence.hand, Some(true));
        assert_eq!(presence.space.unwrap().marker, Some(String::from("root")));
    }
}
