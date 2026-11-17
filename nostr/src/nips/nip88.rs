// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-88: Polls
//!
//! <https://github.com/nostr-protocol/nips/blob/master/88.md>

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use super::util::{
    missing_tag_kind, take_and_parse_from_str, take_relay_url, take_string, take_timestamp,
    unknown_tag,
};
use crate::error::{Error, ErrorKind};
use crate::event::{
    Event, EventBuilder, EventId, IntoEventBuilder, Kind, impl_tag_codec_conversions,
};
use crate::nips::nip01::Nip01Tag;
use crate::types::{RelayUrl, Timestamp};

const ENDS_AT: &str = "endsAt";
const POLL_TYPE: &str = "polltype";
const POLL_OPTION: &str = "option";
const POLL_RESPONSE: &str = "response";
const RELAY: &str = "relay";

#[inline]
fn unknown_poll_type() -> Error {
    Error::with_static_message(ErrorKind::Unsupported, "unknown poll type")
}

/// Poll type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PollType {
    /// Single choice
    SingleChoice,
    /// Multiple choice
    MultipleChoice,
}

impl fmt::Display for PollType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PollType {
    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::SingleChoice => "singlechoice",
            Self::MultipleChoice => "multiplechoice",
        }
    }
}

impl FromStr for PollType {
    type Err = Error;

    fn from_str(poll_type: &str) -> Result<Self, Self::Err> {
        match poll_type {
            "singlechoice" => Ok(Self::SingleChoice),
            "multiplechoice" => Ok(Self::MultipleChoice),
            _ => Err(unknown_poll_type()),
        }
    }
}

/// Poll option
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PollOption {
    /// Option ID
    pub id: String,
    /// Option label
    pub text: String,
}

/// Standardized NIP-88 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/88.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip88Tag {
    /// Poll option
    PollOption(PollOption),
    /// Poll response
    PollResponse(String),
    /// Poll type
    PollType(PollType),
    /// Relay URL
    Relay(RelayUrl),
    /// Poll expiration timestamp
    PollEndsAt(Timestamp),
}

impl_tag_codec_conversions! {
    Nip88Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            POLL_OPTION => Ok(Self::PollOption(PollOption {
                id: take_string(&mut iter, "poll ID")?,
                text: take_string(&mut iter, "poll option text")?,
            })),
            POLL_RESPONSE => Ok(Self::PollResponse(take_string(&mut iter, "poll response")?)),
            POLL_TYPE => {
                let poll_type: PollType = take_and_parse_from_str(&mut iter, "poll type")?;
                Ok(Self::PollType(poll_type))
            }
            RELAY => {
                let relay: RelayUrl = take_relay_url(&mut iter)?;
                Ok(Self::Relay(relay))
            }
            ENDS_AT => {
                let timestamp: Timestamp = take_timestamp(&mut iter)?;
                Ok(Self::PollEndsAt(timestamp))
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::PollOption(option) => {
                tx.push_str(POLL_OPTION);
                tx.push_str(&option.id);
                tx.push_str(&option.text);
            }
            Self::PollResponse(response) => {
                tx.push_str(POLL_RESPONSE);
                tx.push_str(&response);
            }
            Self::PollType(poll_type) => {
                tx.push_str(POLL_TYPE);
                tx.push_str(poll_type.as_str());
            }
            Self::Relay(relay) => {
                tx.push_str(RELAY);
                tx.push_str(relay.as_str());
            }
            Self::PollEndsAt(timestamp) => {
                tx.push_str(ENDS_AT);
                tx.push_u64(timestamp.as_secs());
            }
        }
    }
}

/// Poll
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Poll {
    /// Poll title
    pub title: String,
    /// Poll type
    pub r#type: PollType,
    /// Poll options
    pub options: Vec<PollOption>,
    /// Relays
    pub relays: Vec<RelayUrl>,
    /// Optionally, when the poll ends
    pub ends_at: Option<Timestamp>,
}

impl Poll {
    /// Parse poll data from an [`Event`].
    pub fn from_event(event: &Event) -> Result<Self, Error> {
        let mut poll_type: PollType = PollType::SingleChoice;
        let mut options: Vec<PollOption> = Vec::new();
        let mut relays: Vec<RelayUrl> = Vec::new();
        let mut ends_at: Option<Timestamp> = None;

        for tag in event.tags.iter() {
            match Nip88Tag::try_from(tag) {
                Ok(Nip88Tag::PollType(value)) => poll_type = value,
                Ok(Nip88Tag::PollOption(option)) => options.push(option),
                Ok(Nip88Tag::Relay(url)) => relays.push(url),
                Ok(Nip88Tag::PollEndsAt(timestamp)) => ends_at = Some(timestamp),
                Ok(Nip88Tag::PollResponse(..)) => (),
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::Invalid
                            | ErrorKind::Missing
                            | ErrorKind::Unsupported
                            | ErrorKind::Malformed
                    ) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(Self {
            title: event.content.clone(),
            r#type: poll_type,
            options,
            relays,
            ends_at,
        })
    }
}

impl IntoEventBuilder for Poll {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::Poll).content(self.title);

        builder
            .tags
            .reserve(1 + self.options.len() + self.relays.len());

        builder.tags.push(Nip88Tag::PollType(self.r#type));

        for option in self.options {
            builder.tags.push(Nip88Tag::PollOption(option));
        }

        for url in self.relays {
            builder.tags.push(Nip88Tag::Relay(url));
        }

        if let Some(timestamp) = self.ends_at {
            builder.tags.push(Nip88Tag::PollEndsAt(timestamp));
        }

        builder
    }
}

/// Poll response
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PollResponse {
    /// Single choice
    SingleChoice {
        /// Event ID of poll event
        poll_id: EventId,
        /// Response
        response: String,
    },
    /// Multiple choice
    MultipleChoice {
        /// Event ID of poll event
        poll_id: EventId,
        /// Responses
        responses: Vec<String>,
    },
}
impl IntoEventBuilder for PollResponse {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::PollResponse);

        match self {
            Self::SingleChoice { poll_id, response } => {
                builder.tags.reserve(2);
                builder.tags.push(Nip01Tag::event(poll_id));
                builder.tags.push(Nip88Tag::PollResponse(response));
            }
            Self::MultipleChoice { poll_id, responses } => {
                builder.tags.reserve(1 + responses.len());

                builder.tags.push(Nip01Tag::event(poll_id));

                for response in responses {
                    builder.tags.push(Nip88Tag::PollResponse(response));
                }
            }
        };

        builder
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::event::Tags;

    #[test]
    fn test_poll_type() {
        // Serialization
        assert_eq!(PollType::SingleChoice.as_str(), "singlechoice");
        assert_eq!(PollType::MultipleChoice.as_str(), "multiplechoice");

        // Deserialization
        assert_eq!(
            PollType::from_str("singlechoice").unwrap(),
            PollType::SingleChoice
        );
        assert_eq!(
            PollType::from_str("multiplechoice").unwrap(),
            PollType::MultipleChoice
        );
        assert!(PollType::from_str("unknown").is_err());
    }

    #[test]
    fn test_standardized_poll_tags() {
        let option = Nip88Tag::parse(["option", "qj518h583", "Yay"]).unwrap();
        assert_eq!(
            option,
            Nip88Tag::PollOption(PollOption {
                id: "qj518h583".to_string(),
                text: "Yay".to_string(),
            })
        );
        assert_eq!(
            Tags::from_iter([option]),
            Tags::parse([["option", "qj518h583", "Yay"]]).unwrap()
        );

        let poll_type = Nip88Tag::parse(["polltype", "multiplechoice"]).unwrap();
        assert_eq!(poll_type, Nip88Tag::PollType(PollType::MultipleChoice));
        assert_eq!(
            Tags::from_iter([poll_type]),
            Tags::parse([["polltype", "multiplechoice"]]).unwrap()
        );

        let relay = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let relay_tag = Nip88Tag::parse(["relay", "wss://relay.damus.io"]).unwrap();
        assert_eq!(relay_tag, Nip88Tag::Relay(relay.clone()));
        assert_eq!(
            Tags::from_iter([relay_tag]),
            Tags::parse([["relay", relay.as_str()]]).unwrap()
        );

        let ends_at = Nip88Tag::parse(["endsAt", "1788888888"]).unwrap();
        assert_eq!(
            ends_at,
            Nip88Tag::PollEndsAt(Timestamp::from_secs(1788888888))
        );
        assert_eq!(
            Tags::from_iter([ends_at]),
            Tags::parse([["endsAt", "1788888888"]]).unwrap()
        );

        let response = Nip88Tag::parse(["response", "qj518h583"]).unwrap();
        assert_eq!(response, Nip88Tag::PollResponse("qj518h583".to_string()));
        assert_eq!(
            Tags::from_iter([response]),
            Tags::parse([["response", "qj518h583"]]).unwrap()
        );
    }

    #[test]
    fn test_poll_from_event() {
        let event = Event::from_json(r#"{
  "content": "Pineapple on pizza",
  "created_at": 1719888496,
  "id": "9d1b6b9562e66f2ecf35eb0a3c2decc736c47fddb13d6fb8f87185a153ea3634",
  "kind": 1068,
  "pubkey": "dee45a23c4f1d93f3a2043650c5081e4ac14a778e0acbef03de3768e4f81ac7b",
  "sig": "7fa93bf3c430eaef784b0dacc217d3cd5eff1c520e7ef5d961381bc0f014dde6286618048d924808e54d1be03f2f2c2f0f8b5c9c2082a4480caf45a565ca9797",
  "tags": [
    ["option", "qj518h583", "Yay"],
    ["option", "gga6cdnqj", "Nay"],
    ["relay", "wss://relay.damus.io"],
    ["relay", "wss://relay.example.com"],
    ["polltype", "multiplechoice"],
    ["endsAt", "1788888888"]
  ]
}"#).unwrap();

        let poll = Poll::from_event(&event).unwrap();
        assert_eq!(poll.title, "Pineapple on pizza");
        assert_eq!(poll.r#type, PollType::MultipleChoice);
        assert_eq!(
            poll.options,
            vec![
                PollOption {
                    id: "qj518h583".to_string(),
                    text: "Yay".to_string(),
                },
                PollOption {
                    id: "gga6cdnqj".to_string(),
                    text: "Nay".to_string(),
                }
            ]
        );
        assert_eq!(
            poll.relays,
            vec![
                RelayUrl::from_str("wss://relay.damus.io").unwrap(),
                RelayUrl::from_str("wss://relay.example.com").unwrap(),
            ]
        );
        assert_eq!(poll.ends_at, Some(Timestamp::from_secs(1788888888)));
    }

    #[test]
    fn test_poll_from_event_without_poll_type() {
        let event = Event::from_json(r#"{
  "content": "Pineapple on pizza",
  "created_at": 1719888496,
  "id": "9d1b6b9562e66f2ecf35eb0a3c2decc736c47fddb13d6fb8f87185a153ea3634",
  "kind": 1068,
  "pubkey": "dee45a23c4f1d93f3a2043650c5081e4ac14a778e0acbef03de3768e4f81ac7b",
  "sig": "7fa93bf3c430eaef784b0dacc217d3cd5eff1c520e7ef5d961381bc0f014dde6286618048d924808e54d1be03f2f2c2f0f8b5c9c2082a4480caf45a565ca9797",
  "tags": [
    ["option", "qj518h583", "Yay"]
  ]
}"#).unwrap();

        let poll = Poll::from_event(&event).unwrap();
        assert_eq!(poll.title, "Pineapple on pizza");
        assert_eq!(poll.r#type, PollType::SingleChoice);
        assert_eq!(
            poll.options,
            vec![PollOption {
                id: "qj518h583".to_string(),
                text: "Yay".to_string(),
            },]
        );
        assert!(poll.relays.is_empty());
        assert!(poll.ends_at.is_none());
    }

    #[test]
    fn test_poll_from_event_with_empty_poll_type() {
        let event = Event::from_json(r#"{
  "content": "Pineapple on pizza",
  "created_at": 1719888496,
  "id": "9d1b6b9562e66f2ecf35eb0a3c2decc736c47fddb13d6fb8f87185a153ea3634",
  "kind": 1068,
  "pubkey": "dee45a23c4f1d93f3a2043650c5081e4ac14a778e0acbef03de3768e4f81ac7b",
  "sig": "7fa93bf3c430eaef784b0dacc217d3cd5eff1c520e7ef5d961381bc0f014dde6286618048d924808e54d1be03f2f2c2f0f8b5c9c2082a4480caf45a565ca9797",
  "tags": [
    ["option", "qj518h583", "Yay"],
    ["polltype", ""]
  ]
}"#).unwrap();

        let poll = Poll::from_event(&event).unwrap();
        assert_eq!(poll.title, "Pineapple on pizza");
        assert_eq!(poll.r#type, PollType::SingleChoice);
        assert_eq!(
            poll.options,
            vec![PollOption {
                id: "qj518h583".to_string(),
                text: "Yay".to_string(),
            },]
        );
        assert!(poll.relays.is_empty());
        assert!(poll.ends_at.is_none());
    }

    #[test]
    fn test_poll_from_event_with_malformed_polltype_tag() {
        let event = Event::from_json(r#"{
  "content": "Pineapple on pizza",
  "created_at": 1719888496,
  "id": "9d1b6b9562e66f2ecf35eb0a3c2decc736c47fddb13d6fb8f87185a153ea3634",
  "kind": 1068,
  "pubkey": "dee45a23c4f1d93f3a2043650c5081e4ac14a778e0acbef03de3768e4f81ac7b",
  "sig": "7fa93bf3c430eaef784b0dacc217d3cd5eff1c520e7ef5d961381bc0f014dde6286618048d924808e54d1be03f2f2c2f0f8b5c9c2082a4480caf45a565ca9797",
  "tags": [
    ["option", "qj518h583", "Yay"],
    ["polltype"]
  ]
}"#).unwrap();

        let poll = Poll::from_event(&event).unwrap();
        assert_eq!(poll.title, "Pineapple on pizza");
        assert_eq!(poll.r#type, PollType::SingleChoice);
        assert_eq!(
            poll.options,
            vec![PollOption {
                id: "qj518h583".to_string(),
                text: "Yay".to_string(),
            },]
        );
        assert!(poll.relays.is_empty());
        assert!(poll.ends_at.is_none());
    }
}
