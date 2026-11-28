// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-56: Reporting
//!
//! <https://github.com/nostr-protocol/nips/blob/master/56.md>

use core::fmt;
use core::str::FromStr;

use super::util::{
    missing_tag_kind, take_and_parse_from_str, take_event_id, take_public_key, unknown_tag,
};
use crate::error::{Error, ErrorKind};
use crate::event::{EventId, impl_tag_codec_conversions};
use crate::key::PublicKey;

#[inline]
fn unknown_report_type() -> Error {
    Error::with_static_message(ErrorKind::Unsupported, "unknown report type")
}

/// Report
///
/// <https://github.com/nostr-protocol/nips/blob/master/56.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Report {
    /// Depictions of nudity, porn, etc
    Nudity,
    /// Virus, trojan horse, worm, robot, spyware, adware, back door, ransomware, rootkit, kidnapper, etc.
    Malware,
    /// Profanity, hateful speech, etc.
    Profanity,
    /// Something which may be illegal in some jurisdiction
    Illegal,
    /// Spam
    Spam,
    /// Someone pretending to be someone else
    Impersonation,
    ///  Reports that don't fit in the above categories
    Other,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Report {
    /// Get as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::Nudity => "nudity",
            Self::Malware => "malware",
            Self::Profanity => "profanity",
            Self::Illegal => "illegal",
            Self::Spam => "spam",
            Self::Impersonation => "impersonation",
            Self::Other => "other",
        }
    }
}

impl FromStr for Report {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "nudity" => Ok(Self::Nudity),
            "malware" => Ok(Self::Malware),
            "profanity" => Ok(Self::Profanity),
            "illegal" => Ok(Self::Illegal),
            "spam" => Ok(Self::Spam),
            "impersonation" => Ok(Self::Impersonation),
            "other" => Ok(Self::Other),
            _ => Err(unknown_report_type()),
        }
    }
}

/// Standardized NIP-56 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/56.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip56Tag {
    /// `e` tag
    Event {
        /// Event ID
        id: EventId,
        /// Report
        report: Report,
    },
    /// `p` tag
    PublicKey {
        /// Public key
        public_key: PublicKey,
        /// Report
        report: Report,
    },
}

impl_tag_codec_conversions! {
    Nip56Tag,
    fn parse(tag) {
        // Take iterator
        let mut iter = tag.into_iter();

        // Extract first value
        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        // Match kind
        match kind.as_ref() {
            "e" => {
                let (id, report) = parse_e_tag(iter)?;
                Ok(Self::Event { id, report })
            }
            "p" => {
                let (public_key, report) = parse_p_tag(iter)?;
                Ok(Self::PublicKey { public_key, report })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::Event { id, report } => {
                tx.push_str("e");
                tx.push_hex(id.as_bytes());
                tx.push_str(report.as_str());
            }
            Self::PublicKey { public_key, report } => {
                tx.push_str("p");
                tx.push_hex(public_key.as_bytes());
                tx.push_str(report.as_str());
            }
        }
    }
}

fn parse_e_tag<T, S>(mut iter: T) -> Result<(EventId, Report), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let id: EventId = take_event_id(&mut iter)?;
    let report: Report = take_and_parse_from_str(&mut iter, "report")?;

    Ok((id, report))
}

fn parse_p_tag<T, S>(mut iter: T) -> Result<(PublicKey, Report), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let public_key: PublicKey = take_public_key(&mut iter)?;
    let report: Report = take_and_parse_from_str(&mut iter, "report")?;

    Ok((public_key, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Tags;

    #[test]
    fn test_report_e_tag() {
        let tag = vec![
            "e",
            "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
            "nudity",
        ];
        let parsed = Nip56Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip56Tag::Event {
                id: EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )
                .unwrap(),
                report: Report::Nudity,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_report_p_tag() {
        let tag = vec![
            "p",
            "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
            "impersonation",
        ];
        let parsed = Nip56Tag::parse(&tag).unwrap();

        assert_eq!(
            parsed,
            Nip56Tag::PublicKey {
                public_key: PublicKey::from_hex(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )
                .unwrap(),
                report: Report::Impersonation,
            }
        );
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_missing_report() {
        let tag = vec![
            "p",
            "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
        ];
        assert_eq!(
            Nip56Tag::parse(&tag).unwrap_err().kind(),
            ErrorKind::Missing
        );

        let tag = vec![
            "e",
            "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
        ];
        assert_eq!(
            Nip56Tag::parse(&tag).unwrap_err().kind(),
            ErrorKind::Missing
        );
    }

    #[test]
    fn test_empty_report() {
        let tag = vec![
            "p",
            "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
            "",
        ];
        assert_eq!(
            Nip56Tag::parse(&tag).unwrap_err().kind(),
            ErrorKind::Malformed
        );

        let tag = vec![
            "e",
            "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
            "",
        ];
        assert_eq!(
            Nip56Tag::parse(&tag).unwrap_err().kind(),
            ErrorKind::Malformed
        );
    }
}
