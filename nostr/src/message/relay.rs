// Copyright (c) 2021 Paul Miller
// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Relay messages

use alloc::borrow::{Cow, ToOwned};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::SubscriptionId;
use crate::event::{Event, EventId};
use crate::nips::nip67::EoseHint;
use crate::util::impl_json_methods;

/// A string that must be exactly one word.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SingleWord<'a>(Cow<'a, str>);

impl<'a> SingleWord<'a> {
    /// Parse a [`SingleWord`] from a string.
    ///
    /// Returns `None` if the `word` is empty or contains any ASCII whitespace.
    pub fn parse<S>(word: S) -> Option<Self>
    where
        S: Into<Cow<'a, str>>,
    {
        let word: Cow<'a, str> = word.into();
        let bytes = word.as_bytes();

        if !is_single_word(bytes) {
            return None;
        }

        Some(Self(word))
    }

    /// Parse a [`SingleWord`] from a static slice string.
    ///
    /// Returns `None` if the `word` is empty or contains any ASCII whitespace.
    pub const fn from_static(word: &'static str) -> Option<SingleWord<'static>> {
        let bytes = word.as_bytes();

        if !is_single_word(bytes) {
            return None;
        }

        Some(SingleWord(Cow::Borrowed(word)))
    }
}

/// Machine-readable prefixes for `OK` and `CLOSED` relay messages
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MachineReadablePrefix {
    /// Duplicate
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Duplicate,
    /// POW
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Pow,
    /// Blocked
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Blocked,
    /// Rate limited
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    RateLimited,
    /// Invalid
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Invalid,
    /// Error
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Error,
    /// Unsupported
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Unsupported,
    /// Authentication required
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/42.md>
    AuthRequired,
    /// Restricted
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/42.md>
    Restricted,
    /// Custom machine-readable prefix
    Custom(SingleWord<'static>),
}

impl fmt::Display for MachineReadablePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl MachineReadablePrefix {
    /// Parse machine-readable prefix
    pub fn parse(message: &str) -> Option<Self> {
        match message {
            m if m.starts_with("duplicate:") => Some(Self::Duplicate),
            m if m.starts_with("pow:") => Some(Self::Pow),
            m if m.starts_with("blocked:") => Some(Self::Blocked),
            m if m.starts_with("rate-limited:") => Some(Self::RateLimited),
            m if m.starts_with("invalid:") => Some(Self::Invalid),
            m if m.starts_with("error:") => Some(Self::Error),
            m if m.starts_with("unsupported:") => Some(Self::Unsupported),
            m if m.starts_with("auth-required:") => Some(Self::AuthRequired),
            m if m.starts_with("restricted:") => Some(Self::Restricted),
            other => {
                let (prefix, ..) = other.split_once(':')?;
                Some(Self::Custom(SingleWord::parse(prefix.to_owned())?))
            }
        }
    }

    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Pow => "pow",
            Self::Blocked => "blocked",
            Self::RateLimited => "rate-limited",
            Self::Invalid => "invalid",
            Self::Error => "error",
            Self::Unsupported => "unsupported",
            Self::AuthRequired => "auth-required",
            Self::Restricted => "restricted",
            Self::Custom(SingleWord(custom)) => custom.as_ref(),
        }
    }
}

/// Messages sent by relays, received by clients
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayMessage<'a> {
    /// Event
    ///
    /// Used to send events requested by clients.
    ///
    /// JSON: `["EVENT", <subscription_id>, <event JSON>]`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Event {
        /// Subscription ID
        subscription_id: Cow<'a, SubscriptionId>,
        /// Event
        event: Cow<'a, Event>,
    },
    /// Ok
    ///
    /// Used to indicate acceptance or denial of an `EVENT` message.
    ///
    /// JSON: `["OK", <event_id>, <true|false>, <message>]`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Ok {
        /// Event ID
        event_id: EventId,
        /// Status
        status: bool,
        /// Message
        message: Cow<'a, str>,
    },
    /// End of stored events
    ///
    /// Used to indicate the end of stored events and the beginning of events newly received in real-time.
    ///
    /// JSON: `["EOSE", <subscription_id>]` or `["EOSE", <subscription_id>, [<hint>, ...]]`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    /// <https://github.com/nostr-protocol/nips/blob/master/67.md>
    EndOfStoredEvents {
        /// Subscription ID to which the hints apply.
        subscription_id: Cow<'a, SubscriptionId>,
        /// Optional completeness hints supplied by the relay.
        ///
        /// `None` means the relay omitted the hint array; `Some` may be empty.
        hints: Option<Vec<EoseHint>>,
    },
    /// Notice
    ///
    /// Used to send human-readable error messages or other things to clients.
    ///
    /// JSON: `["NOTICE", <message>]`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Notice(Cow<'a, str>),
    /// Closed
    ///
    /// Used to indicate that a subscription was ended on the server side.
    ///
    /// JSON: `["CLOSED", <subscription_id>, <message>]`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    Closed {
        /// Subscription ID
        subscription_id: Cow<'a, SubscriptionId>,
        /// Message
        message: Cow<'a, str>,
    },
    /// Auth
    ///
    /// `["AUTH", <challenge-string>]`
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/42.md>
    Auth {
        /// Challenge
        challenge: Cow<'a, str>,
    },
    /// Count
    ///
    /// `["COUNT", <subscription_id>, {"count": <integer>}]`
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/45.md>
    Count {
        /// Subscription ID
        subscription_id: Cow<'a, SubscriptionId>,
        /// Events count
        count: usize,
    },
    /// Negentropy Message
    NegMsg {
        /// Subscription ID
        subscription_id: Cow<'a, SubscriptionId>,
        /// Message
        message: Cow<'a, str>,
    },
    /// Negentropy Error
    NegErr {
        /// Subscription ID
        subscription_id: Cow<'a, SubscriptionId>,
        /// Error message
        message: Cow<'a, str>,
    },
}

impl RelayMessage<'_> {
    /// Create `EVENT` message
    #[inline]
    pub fn event(subscription_id: SubscriptionId, event: Event) -> Self {
        Self::Event {
            subscription_id: Cow::Owned(subscription_id),
            event: Cow::Owned(event),
        }
    }

    /// Create `NOTICE` message
    #[inline]
    pub fn notice<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::Notice(Cow::Owned(message.into()))
    }

    /// Create `CLOSED` message
    #[inline]
    pub fn closed<S>(subscription_id: SubscriptionId, message: S) -> Self
    where
        S: Into<String>,
    {
        Self::Closed {
            subscription_id: Cow::Owned(subscription_id),
            message: Cow::Owned(message.into()),
        }
    }

    /// Create `EOSE` message
    #[inline]
    pub fn eose(subscription_id: SubscriptionId) -> Self {
        Self::EndOfStoredEvents {
            subscription_id: Cow::Owned(subscription_id),
            hints: None,
        }
    }

    /// Create an `EOSE` message with NIP-67 completeness hints.
    #[inline]
    pub fn eose_with_hints(subscription_id: SubscriptionId, hints: Vec<EoseHint>) -> Self {
        Self::EndOfStoredEvents {
            subscription_id: Cow::Owned(subscription_id),
            hints: Some(hints),
        }
    }

    /// Create `OK` message
    #[inline]
    pub fn ok<S>(event_id: EventId, status: bool, message: S) -> Self
    where
        S: Into<String>,
    {
        Self::Ok {
            event_id,
            status,
            message: Cow::Owned(message.into()),
        }
    }

    /// Create `AUTH` message
    #[inline]
    pub fn auth<S>(challenge: S) -> Self
    where
        S: Into<String>,
    {
        Self::Auth {
            challenge: Cow::Owned(challenge.into()),
        }
    }

    /// Create  `EVENT` message
    #[inline]
    pub fn count(subscription_id: SubscriptionId, count: usize) -> Self {
        Self::Count {
            subscription_id: Cow::Owned(subscription_id),
            count,
        }
    }

    /// Number of elements in the JSON array form.
    ///
    /// Matched exhaustively on purpose: a new variant must state its own
    /// length rather than inherit a default that may not fit.
    const fn len(&self) -> usize {
        match self {
            Self::Notice(..) | Self::Auth { .. } => 2,
            Self::EndOfStoredEvents { hints, .. } => 2 + hints.is_some() as usize,
            Self::Event { .. }
            | Self::Closed { .. }
            | Self::Count { .. }
            | Self::NegMsg { .. }
            | Self::NegErr { .. } => 3,
            Self::Ok { .. } => 4,
        }
    }
}

impl Serialize for RelayMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Write the array elements straight to the serializer. Building a
        // `serde_json::Value` first would allocate for every element, and for
        // an `EVENT` message that means the whole event too.
        let mut seq = serializer.serialize_seq(Some(self.len()))?;

        match self {
            Self::Event {
                subscription_id,
                event,
            } => {
                seq.serialize_element("EVENT")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(event)?;
            }
            Self::Notice(message) => {
                seq.serialize_element("NOTICE")?;
                seq.serialize_element(message)?;
            }
            Self::Closed {
                subscription_id,
                message,
            } => {
                seq.serialize_element("CLOSED")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(message)?;
            }
            Self::EndOfStoredEvents {
                subscription_id,
                hints,
            } => {
                seq.serialize_element("EOSE")?;
                seq.serialize_element(subscription_id)?;
                if let Some(hints) = hints {
                    seq.serialize_element(hints)?;
                }
            }
            Self::Ok {
                event_id,
                status,
                message,
            } => {
                seq.serialize_element("OK")?;
                seq.serialize_element(event_id)?;
                seq.serialize_element(status)?;
                seq.serialize_element(message)?;
            }
            Self::Auth { challenge } => {
                seq.serialize_element("AUTH")?;
                seq.serialize_element(challenge)?;
            }
            Self::Count {
                subscription_id,
                count,
            } => {
                seq.serialize_element("COUNT")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(&Count { count: *count })?;
            }
            Self::NegMsg {
                subscription_id,
                message,
            } => {
                seq.serialize_element("NEG-MSG")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(message)?;
            }
            Self::NegErr {
                subscription_id,
                message,
            } => {
                seq.serialize_element("NEG-ERR")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(message)?;
            }
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for RelayMessage<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RelayMessageVisitor)
    }
}

struct RelayMessageVisitor;

impl<'de> Visitor<'de> for RelayMessageVisitor {
    type Value = RelayMessage<'static>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a relay message array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        fn malformed<E>() -> E
        where
            E: de::Error,
        {
            E::custom("invalid message format")
        }

        // Read only the elements each variant defines, then drain the rest.
        // Extra trailing elements are reserved for future extensions and must
        // not be rejected, which the previous `Value::Array` path also allowed.
        macro_rules! next {
            () => {
                seq.next_element()?.ok_or_else(malformed)?
            };
        }

        let message_type: String = next!();

        let message: RelayMessage<'static> = match message_type.as_str() {
            // ["EVENT", <subscription id>, <event JSON>]
            "EVENT" => RelayMessage::Event {
                subscription_id: Cow::Owned(next!()),
                event: Cow::Owned(next!()),
            },
            // ["OK", <event_id>, <true|false>, <message>]
            "OK" => RelayMessage::Ok {
                event_id: next!(),
                status: next!(),
                message: Cow::Owned(next!()),
            },
            // ["EOSE", <subscription_id>, <optional hints>]
            "EOSE" => RelayMessage::EndOfStoredEvents {
                subscription_id: Cow::Owned(next!()),
                hints: seq.next_element()?,
            },
            // ["NOTICE", <message>]
            "NOTICE" => RelayMessage::Notice(Cow::Owned(next!())),
            // ["CLOSED", <subscription_id>, <message>]
            "CLOSED" => RelayMessage::Closed {
                subscription_id: Cow::Owned(next!()),
                message: Cow::Owned(next!()),
            },
            // ["AUTH", <challenge>]
            "AUTH" => RelayMessage::Auth {
                challenge: Cow::Owned(next!()),
            },
            // ["COUNT", <subscription id>, {"count": num}]
            "COUNT" => {
                let subscription_id: SubscriptionId = next!();
                let Count { count } = next!();
                RelayMessage::Count {
                    subscription_id: Cow::Owned(subscription_id),
                    count,
                }
            }
            // ["NEG-MSG", <subscription ID string>, <message, lowercase hex-encoded>]
            "NEG-MSG" => RelayMessage::NegMsg {
                subscription_id: Cow::Owned(next!()),
                message: Cow::Owned(next!()),
            },
            // ["NEG-ERR", <subscription ID string>, <reason-code>]
            "NEG-ERR" => RelayMessage::NegErr {
                subscription_id: Cow::Owned(next!()),
                message: Cow::Owned(next!()),
            },
            _ => return Err(malformed()),
        };

        while seq.next_element::<de::IgnoredAny>()?.is_some() {}

        Ok(message)
    }
}

impl_json_methods!(RelayMessage<'_>);

/// Returns true if the slice is not empty and has no ASCII whitespace
const fn is_single_word(mut bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    while let [b, rest @ ..] = bytes {
        if b.is_ascii_whitespace() {
            return false;
        }
        bytes = rest;
    }

    true
}

#[derive(Serialize, Deserialize)]
struct Count {
    count: usize,
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::error::ErrorKind;
    use crate::event::{Kind, Signature};
    use crate::key::PublicKey;
    use crate::types::Timestamp;

    #[test]
    fn test_handle_valid_notice() {
        let valid_notice_msg = r#"["NOTICE","Invalid event format!"]"#;
        let handled_valid_notice_msg = RelayMessage::notice(String::from("Invalid event format!"));

        assert_eq!(
            RelayMessage::from_json(valid_notice_msg).unwrap(),
            handled_valid_notice_msg
        );
    }
    #[test]
    fn test_handle_invalid_notice() {
        // Missing content
        let invalid_notice_msg = r#"["NOTICE"]"#;
        // The content is not string
        let invalid_notice_msg_content = r#"["NOTICE": 404]"#;

        assert!(RelayMessage::from_json(invalid_notice_msg).is_err(),);
        assert!(RelayMessage::from_json(invalid_notice_msg_content).is_err(),);
    }

    #[test]
    fn test_handle_valid_closed() {
        let valid_closed_msg = r#"["CLOSED","random-subscription-id","reason"]"#;
        let handled_valid_closed_msg =
            RelayMessage::closed(SubscriptionId::new("random-subscription-id"), "reason");

        assert_eq!(
            RelayMessage::from_json(valid_closed_msg).unwrap(),
            handled_valid_closed_msg
        );
    }

    #[test]
    fn test_handle_invalid_closed() {
        // Missing subscription ID
        assert!(RelayMessage::from_json(r#"["CLOSED"]"#).is_err());

        // The subscription ID is not a string
        assert!(RelayMessage::from_json(r#"["CLOSED", 404, "reason"]"#).is_err());

        // The content is not a string
        assert!(RelayMessage::from_json(r#"["CLOSED", "random-subscription-id", 404]"#).is_err())
    }

    #[test]
    fn test_handle_valid_event() {
        let valid_event_msg = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}]"#;

        let id =
            EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                .unwrap();
        let pubkey =
            PublicKey::from_str("379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe")
                .unwrap();
        let created_at = Timestamp::from(1612809991);
        let kind = Kind::TextNote;
        let content = "test";
        let sig = Signature::from_str("273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502").unwrap();

        let handled_event = Event::new(id, pubkey, created_at, kind, [], content, sig);

        assert_eq!(
            RelayMessage::from_json(valid_event_msg).unwrap(),
            RelayMessage::event(SubscriptionId::new("random_string"), handled_event)
        );

        let message = RelayMessage::from_json(r#"["EVENT","bf7da933d6c6d67e5c97f94f17cf8762",{"content":"Think about this.\n\nThe most powerful centralized institutions in the world have been replaced by a protocol that protects the individual. #bitcoin\n\nDo you doubt that we can replace everything else?\n\nBullish on the future of humanity\nnostr:nevent1qqs9ljegkuk2m2ewfjlhxy054n6ld5dfngwzuep0ddhs64gc49q0nmqpzdmhxue69uhhyetvv9ukzcnvv5hx7un8qgsw3mfhnrr0l6ll5zzsrtpeufckv2lazc8k3ru5c3wkjtv8vlwngksrqsqqqqqpttgr27","created_at":1703184271,"id":"38acf9b08d06859e49237688a9fd6558c448766f47457236c2331f93538992c6","kind":1,"pubkey":"e8ed3798c6ffebffa08501ac39e271662bfd160f688f94c45d692d8767dd345a","sig":"f76d5ecc8e7de688ac12b9d19edaacdcffb8f0c8fa2a44c00767363af3f04dbc069542ddc5d2f63c94cb5e6ce701589d538cf2db3b1f1211a96596fabb6ecafe","tags":[["e","5fcb28b72cadab2e4cbf7311f4acf5f6d1a99a1c2e642f6b6f0d5518a940f9ec","","mention"],["p","e8ed3798c6ffebffa08501ac39e271662bfd160f688f94c45d692d8767dd345a","","mention"],["t","bitcoin"],["t","bitcoin"]]}]"#).unwrap();
        if let RelayMessage::Event { event, .. } = message {
            event.verify().unwrap();
        } else {
            panic!("Wrong relay message");
        }
    }

    #[test]
    fn test_handle_invalid_event() {
        // Missing Event field
        let invalid_event_msg = r#"["EVENT", "random_string"]"#;
        // Event JSON with incomplete content
        let invalid_event_msg_content = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe"}]"#;

        assert!(RelayMessage::from_json(invalid_event_msg).is_err());

        assert!(RelayMessage::from_json(invalid_event_msg_content).is_err());
    }

    #[test]
    fn test_handle_valid_eose() {
        let valid_eose_msg = r#"["EOSE","random-subscription-id"]"#;
        let handled_valid_eose_msg =
            RelayMessage::eose(SubscriptionId::new("random-subscription-id"));

        assert_eq!(
            RelayMessage::from_json(valid_eose_msg).unwrap(),
            handled_valid_eose_msg
        );
    }
    #[test]
    fn test_handle_invalid_eose() {
        // Missing subscription ID
        assert!(RelayMessage::from_json(r#"["EOSE"]"#).is_err(),);

        // The subscription ID is not string
        assert!(RelayMessage::from_json(r#"["EOSE", 404]"#).is_err(),);
    }

    #[test]
    fn test_handle_valid_ok() {
        let valid_ok_msg = r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30", true, "pow: difficulty 25>=24"]"#;
        let handled_valid_ok_msg = RelayMessage::ok(
            EventId::from_hex("b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30")
                .unwrap(),
            true,
            "pow: difficulty 25>=24",
        );

        assert_eq!(
            RelayMessage::from_json(valid_ok_msg).unwrap(),
            handled_valid_ok_msg
        );
    }
    #[test]
    fn test_handle_invalid_ok() {
        // Missing params
        assert!(
            RelayMessage::from_json(
                r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30"]"#
            )
            .is_err()
        );

        // Invalid event_id
        assert!(
            RelayMessage::from_json(
                r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7dde", true, ""]"#
            )
            .is_err()
        );

        // Invalid status
        assert!(
            RelayMessage::from_json(r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30", hello, ""]"#).is_err(),
        );

        // Invalid message
        assert!(
            RelayMessage::from_json(r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30", hello, 404]"#).is_err()
        );
    }

    #[test]
    fn parse_message() {
        // Got this fresh off the wire
        pub const SAMPLE_EVENT: &str = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}]"#;

        // Hand parsed version as a sanity check
        let id =
            EventId::from_hex("70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5")
                .unwrap();
        let pubkey =
            PublicKey::from_str("379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe")
                .unwrap();
        let created_at = Timestamp::from(1612809991);
        let kind = Kind::TextNote;
        let content = "test";
        let sig = Signature::from_str("273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502").unwrap();

        let event = Event::new(id, pubkey, created_at, kind, [], content, sig);

        let parsed_event = RelayMessage::from_json(SAMPLE_EVENT).expect("Failed to parse event");

        assert_eq!(
            parsed_event,
            RelayMessage::event(SubscriptionId::new("random_string"), event)
        );
    }

    #[test]
    fn parse_nip67() {
        let cases: [(&str, Option<Vec<EoseHint>>); 5] = [
            (r#"["EOSE","sub"]"#, None),
            (r#"["EOSE","sub",[]]"#, Some(vec![])),
            (r#"["EOSE","sub",["finish"]]"#, Some(vec![EoseHint::Finish])),
            (
                r#"["EOSE","sub",["more","auth"]]"#,
                Some(vec![EoseHint::More, EoseHint::Auth]),
            ),
            (
                r#"["EOSE","sub",["Finish","future"]]"#,
                Some(vec![
                    EoseHint::Unknown(String::from("Finish")),
                    EoseHint::Unknown(String::from("future")),
                ]),
            ),
        ];

        for (json, hints) in cases {
            let expected: RelayMessage = match hints {
                Some(hints) => RelayMessage::eose_with_hints(SubscriptionId::new("sub"), hints),
                None => RelayMessage::eose(SubscriptionId::new("sub")),
            };
            assert_eq!(RelayMessage::from_json(json).unwrap(), expected, "{json}");
        }
    }

    #[test]
    fn nip67_round_trip_preserves_hints() {
        for json in [
            r#"["EOSE","sub"]"#,
            r#"["EOSE","sub",[]]"#,
            r#"["EOSE","sub",["finish"]]"#,
            r#"["EOSE","sub",["more"]]"#,
            r#"["EOSE","sub",["auth","finish"]]"#,
            r#"["EOSE","sub",["future","more","more",""]]"#,
            r#"["EOSE","sub",["hint-\"quoted\"-雪"]]"#,
        ] {
            let message: RelayMessage = RelayMessage::from_json(json).unwrap();
            let expected: serde_json::Value = serde_json::from_str(json).unwrap();
            let actual: serde_json::Value = serde_json::from_str(&message.as_json()).unwrap();
            assert_eq!(actual, expected, "{json}");
        }
    }

    #[test]
    fn nip67_rejects_malformed_hints() {
        for json in [
            r#"["EOSE","sub",null]"#,
            r#"["EOSE","sub","finish"]"#,
            r#"["EOSE","sub",{}]"#,
            r#"["EOSE","sub",[1]]"#,
            r#"["EOSE","sub",["finish",null]]"#,
            r#"["EOSE","sub",[["more"]]]"#,
        ] {
            assert!(RelayMessage::from_json(json).is_err(), "{json}");
        }
    }

    /// Trailing elements are reserved for future extensions, so every variant
    /// must ignore them rather than reject the message.
    #[test]
    fn parse_trailing_elements() {
        let cases: [(&str, RelayMessage); 5] = [
            (r#"["NOTICE","hi","extra"]"#, RelayMessage::notice("hi")),
            (
                r#"["CLOSED","sub","reason",{"a":1}]"#,
                RelayMessage::closed(SubscriptionId::new("sub"), "reason"),
            ),
            (
                r#"["COUNT","sub",{"count":7},"extra"]"#,
                RelayMessage::count(SubscriptionId::new("sub"), 7),
            ),
            (
                r#"["AUTH","challenge",1,2,3]"#,
                RelayMessage::auth("challenge"),
            ),
            (
                r#"["EOSE","sub",["finish"],{"future":true}]"#,
                RelayMessage::eose_with_hints(SubscriptionId::new("sub"), vec![EoseHint::Finish]),
            ),
        ];

        for (json, expected) in cases {
            assert_eq!(RelayMessage::from_json(json).unwrap(), expected, "{json}");
        }
    }

    /// Every variant must survive a serialize and parse cycle. The suite only
    /// ever parsed messages, so the serialized form of most variants had no
    /// coverage at all.
    #[test]
    fn round_trip_every_variant() {
        let event: Event = Event::from_json(
            r#"{"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}"#,
        )
        .unwrap();
        let id: EventId = event.id;
        let sub = || SubscriptionId::new("sub");

        let messages: [RelayMessage; 10] = [
            RelayMessage::event(sub(), event),
            RelayMessage::notice("a \"quoted\" notice"),
            RelayMessage::closed(sub(), "duplicate: have this already"),
            RelayMessage::eose(sub()),
            RelayMessage::ok(id, true, ""),
            RelayMessage::ok(id, false, "blocked: no"),
            RelayMessage::auth("challenge"),
            RelayMessage::count(sub(), 42),
            RelayMessage::NegMsg {
                subscription_id: Cow::Owned(sub()),
                message: Cow::Borrowed("deadbeef"),
            },
            RelayMessage::NegErr {
                subscription_id: Cow::Owned(sub()),
                message: Cow::Borrowed("RESULTS_TOO_BIG"),
            },
        ];

        for message in messages {
            let json: String = message.as_json();
            assert_eq!(RelayMessage::from_json(&json).unwrap(), message, "{json}");
        }
    }

    #[test]
    fn parse_rejects_unknown_type_and_non_array() {
        for json in [
            r#"["NOT-A-REAL-TYPE","x"]"#,
            r#"{"type":"NOTICE"}"#,
            r#""NOTICE""#,
            r#"[]"#,
        ] {
            let err = RelayMessage::from_json(json).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Malformed, "{json}");
        }
    }

    /// An `EVENT` message must embed the event exactly as the event serializes
    /// on its own. Round-tripping through `serde_json::Value` used to reorder
    /// the event's keys alphabetically.
    #[test]
    fn event_message_embeds_canonical_event() {
        let event: Event = Event::from_json(
            r#"{"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1707161500,"kind":1,"tags":[],"content":"test","sig":"0e57f2c4b6b7b4cc7cbb0e1d0b0e0c9f24b8bde9f0d51c3d9f22a5cd94e0e4d8b0e6b1dfa1e0dd5e0cd0b8b7c9c3e1e8b1b7e4f8b0d1e7c0d6b1e4a7e3b2c1d0"}"#,
        )
        .unwrap();

        let message: RelayMessage = RelayMessage::event(SubscriptionId::new("sub"), event.clone());
        let json: String = message.as_json();

        assert!(
            json.contains(&event.as_json()),
            "event was not embedded verbatim: {json}"
        );
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    #[bench]
    fn bench_parse_machine_readable_prefix(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(MachineReadablePrefix::parse(
                "blocked: you are banned from posting here",
            ));
        })
    }

    #[bench]
    pub fn parse_ok_relay_message(bh: &mut Bencher) {
        let json: &str = r#"["OK", "70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5", true, "pow: difficulty 25>=24"]"#;
        bh.iter(|| {
            black_box(RelayMessage::from_json(&json)).unwrap();
        });
    }

    #[bench]
    pub fn parse_event_relay_message(bh: &mut Bencher) {
        let json: &str = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}]"#;
        bh.iter(|| {
            black_box(RelayMessage::from_json(&json)).unwrap();
        });
    }
}
