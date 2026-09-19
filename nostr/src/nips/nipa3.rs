// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-A3: payto: Payment Targets
//!
//! <https://github.com/nostr-protocol/nips/blob/master/A3.md>

use alloc::string::String;

use crate::error::Error;
use crate::event::{Tag, impl_tag_codec_conversions};
use crate::nips::util::{missing_tag_kind, missing_value, take_and_parse_from_str, unknown_tag};

const PAYTO: &str = "payto";

/// Standardized NIP-A3 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/A3.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NipA3Tag {
    /// `payto` tag
    Payto {
        /// payment `type` (e.g., `"bitcoin"`, `"lightning"`), always lowercase.
        payment_type: String,
        /// `address` (e.g., address, username)
        payment_address: String,
    },
}

impl NipA3Tag {
    /// Returns the payment URI for the `payto` tag when the payment type is
    /// supported. For unrecognized types, a standard `payto` URI is produced
    /// per RFC 8905.
    ///
    /// Supported types: bitcoin, monero, lightning, litecoin, ethereum. For
    /// these, the URI is formatted as `<type>:<address>`. For any other type,
    /// the URI is formatted as `payto://<type>/<address>`.
    ///
    /// Returns `None` only if the tag is not `payto`.
    pub fn to_uri(&self) -> Option<String> {
        #[allow(irrefutable_let_patterns)]
        let Self::Payto {
            payment_type,
            payment_address,
        } = self
        else {
            return None;
        };

        match payment_type.as_str() {
            "bitcoin" | "monero" | "lightning" | "litecoin" | "ethereum" => {
                Some(format!("{payment_type}:{payment_address}"))
            }
            _ => Some(format!("payto://{payment_type}/{payment_address}")),
        }
    }
}

impl_tag_codec_conversions! {
    NipA3Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();

        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            PAYTO => {
                let (payment_type, payment_address) = parse_payto_tag(iter)?;
                Ok(Self::Payto {
                    payment_type,
                    payment_address,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::Payto {
                payment_type,
                payment_address,
            } => Tag::new(vec![
                String::from(PAYTO),
                payment_type.clone(),
                payment_address.clone(),
            ]),
        }
    }
}

/// Parse `payto` tag
#[inline]
fn parse_payto_tag<T, S>(mut iter: T) -> Result<(String, String), Error>
where
    T: Iterator<Item = S>,
    S: AsRef<str>,
{
    let payment_type = iter
        .next()
        .ok_or_else(|| missing_value("payment type"))?
        .as_ref()
        .to_lowercase();
    let payment_address = take_and_parse_from_str(&mut iter, "payment address")?;

    Ok((payment_type, payment_address))
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn test_parse_unknown_tag() {
        let tag = vec!["unknown"];
        assert_eq!(
            NipA3Tag::parse(tag).unwrap_err().kind(),
            ErrorKind::Malformed
        )
    }

    #[test]
    fn test_parse_payto_tag() {
        let tag = vec!["payto", "bitcoin", "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"];
        let parsed = NipA3Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            NipA3Tag::Payto {
                payment_type: tag[1].to_string(),
                payment_address: tag[2].to_string()
            }
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_payto_tag_missing_type() {
        let tag = vec!["payto"];
        assert_eq!(NipA3Tag::parse(tag).unwrap_err().kind(), ErrorKind::Missing)
    }

    #[test]
    fn test_parse_payto_tag_missing_address() {
        let tag = vec!["payto", "monero"];
        assert_eq!(NipA3Tag::parse(tag).unwrap_err().kind(), ErrorKind::Missing)
    }

    #[test]
    fn test_parse_payto_tag_lowercase_type() {
        let tag = vec![
            "payto",
            "Monero", // This is invalid. It should be lowercase
            "4AcQxuMBUfJM7uAWpZP1Vs1BzQLC1QR6zZL3sMYdBuayWmpZHmaVYo7EQ3cSneyHYf2LRKJnRtrGz5ogZzjmmGygAyusEcJ",
        ];
        let NipA3Tag::Payto { payment_type, .. } = NipA3Tag::parse(&tag).unwrap();
        assert_eq!(payment_type, "monero");
    }

    #[test]
    fn test_payto_tag_to_uri() {
        assert_eq!(
            NipA3Tag::Payto {
                payment_type: "bitcoin".to_string(),
                payment_address: "0".to_string()
            }
            .to_uri()
            .unwrap(),
            "bitcoin:0"
        );
        assert_eq!(
            NipA3Tag::Payto {
                payment_type: "monero".to_string(),
                payment_address: "0".to_string()
            }
            .to_uri()
            .unwrap(),
            "monero:0"
        );
        assert_eq!(
            NipA3Tag::Payto {
                payment_type: "lightning".to_string(),
                payment_address: "0".to_string()
            }
            .to_uri()
            .unwrap(),
            "lightning:0"
        );
        assert_eq!(
            NipA3Tag::Payto {
                payment_type: "litecoin".to_string(),
                payment_address: "0".to_string()
            }
            .to_uri()
            .unwrap(),
            "litecoin:0"
        );
        assert_eq!(
            NipA3Tag::Payto {
                payment_type: "ethereum".to_string(),
                payment_address: "0".to_string()
            }
            .to_uri()
            .unwrap(),
            "ethereum:0"
        );
        assert_eq!(
            NipA3Tag::Payto {
                payment_type: "unknowntype".to_string(),
                payment_address: "0".to_string()
            }
            .to_uri()
            .unwrap(),
            "payto://unknowntype/0"
        );
    }
}
