//! NIP-60: Cashu Wallets
//!
//! <https://github.com/nostr-protocol/nips/blob/master/60.md>

use alloc::string::String;
#[cfg(all(feature = "std", feature = "os-rng"))]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use super::nip44;
use crate::error::{Error, ErrorKind};
use crate::event::EventId;
#[cfg(feature = "std")]
use crate::event::{Event, Kind};
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::event::{EventBuilder, IntoEventBuilder};
#[cfg(feature = "std")]
use crate::key::{PublicKey, SecretKey};
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::nips::nip40::Nip40Tag;
use crate::types::time::Timestamp;
use crate::types::url::Url;
#[cfg(feature = "std")]
use crate::util::parse_json;

#[cfg(feature = "std")]
const E_TAG_STR: &str = "e";
#[cfg(feature = "std")]
const PRIVKEY: &str = "privkey";
#[cfg(feature = "std")]
const MINT: &str = "mint";
#[cfg(feature = "std")]
const DIRECTION: &str = "direction";
#[cfg(feature = "std")]
const AMOUNT: &str = "amount";
#[cfg(feature = "std")]
const EVENT_MARKER_CREATED: &str = "created";
#[cfg(feature = "std")]
const EVENT_MARKER_DESTROYED: &str = "destroyed";
#[cfg(feature = "std")]
const EVENT_MARKER_REDEEMED: &str = "redeemed";

#[inline]
#[cfg(feature = "std")]
fn found_multiple_priv_keys() -> Error {
    Error::with_static_message(ErrorKind::Invalid, "found multiple private keys")
}

#[cfg(feature = "std")]
fn missing_field(field: &'static str) -> Error {
    Error::with_static_message(ErrorKind::Missing, field)
}

#[cfg(feature = "std")]
fn validate_wallet_event(
    wallet_public_key: &PublicKey,
    event: &Event,
    expected_kind: Kind,
) -> Result<(), Error> {
    // ECDH authenticates the supplied peer, so bind that peer to the trusted wallet first.
    if event.pubkey != *wallet_public_key {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "wallet event author mismatch",
        ));
    }

    if event.kind != expected_kind {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "invalid wallet event kind",
        ));
    }

    if !event.verify_id() {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "invalid wallet event ID",
        ));
    }

    if !event.verify_signature() {
        return Err(Error::with_static_message(
            ErrorKind::Invalid,
            "invalid wallet event signature",
        ));
    }

    Ok(())
}

/// Cashu proof
///
/// <https://github.com/nostr-protocol/nips/blob/master/60.md>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CashuProof {
    /// Proof ID
    pub id: String,
    /// Amount in sats
    pub amount: u64,
    /// Secret
    pub secret: String,
    /// C value
    pub c: String,
}

impl fmt::Debug for CashuProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CashuProof")
            .field("id", &self.id)
            .field("amount", &self.amount)
            .field("secret", &"[REDACTED]")
            .field("c", &self.c)
            .finish()
    }
}

/// Wallet event
///
/// <https://github.com/nostr-protocol/nips/blob/master/60.md>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalletEvent {
    /// Private key used to unlock P2PK ecash
    pub privkey: String,
    /// Mint URLs this wallet uses
    pub mints: Vec<Url>,
}

impl fmt::Debug for WalletEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletEvent")
            .field("privkey", &"[REDACTED]")
            .field("mints", &self.mints)
            .finish()
    }
}

impl WalletEvent {
    /// Create new wallet event
    pub fn new<S>(privkey: S, mints: Vec<Url>) -> Self
    where
        S: Into<String>,
    {
        Self {
            privkey: privkey.into(),
            mints,
        }
    }

    /// Parse from wallet event.
    ///
    /// `wallet_public_key` must be the trusted public key of the wallet author.
    #[cfg(feature = "std")]
    pub fn from_wallet_event(
        secret_key: &SecretKey,
        wallet_public_key: &PublicKey,
        event: &Event,
    ) -> Result<Self, Error> {
        validate_wallet_event(wallet_public_key, event, Kind::CashuWallet)?;

        let decrypted: String = nip44::decrypt(secret_key, wallet_public_key, &event.content)?;
        let wallet_data: Vec<Vec<String>> = parse_json(&decrypted)?;

        let mut privkey: String = String::new();
        let mut mints: Vec<Url> = Vec::new();

        for item in wallet_data.into_iter() {
            let mut iter = item.into_iter();

            if let (Some(key), Some(value)) = (iter.next(), iter.next()) {
                match key.as_str() {
                    PRIVKEY => {
                        if privkey.is_empty() {
                            privkey = value
                        } else {
                            return Err(found_multiple_priv_keys());
                        }
                    }
                    MINT => {
                        if let Ok(mint_url) = Url::parse(&value) {
                            mints.push(mint_url);
                        }
                    }
                    _ => {}
                }
            }
        }

        if privkey.is_empty() {
            return Err(missing_field(PRIVKEY));
        }

        if mints.is_empty() {
            return Err(missing_field(MINT));
        }

        Ok(Self { privkey, mints })
    }

    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn to_encrypted_content(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<String, Error> {
        let mut wallet_data: Vec<Vec<&str>> = vec![vec![PRIVKEY, &self.privkey]];

        // Add each mint URL as a separate entry
        for mint in self.mints.iter() {
            wallet_data.push(vec![MINT, mint.as_str()]);
        }

        let json: String = serde_json::to_string(&wallet_data).map_err(Error::malformed)?;

        nip44::encrypt(secret_key, public_key, json, nip44::Version::V2)
    }

    /// Encrypt and prepare the wallet event.
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn prepare(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<PreparedWalletEvent, Error> {
        Ok(PreparedWalletEvent {
            content: self.to_encrypted_content(secret_key, public_key)?,
        })
    }
}

/// Token event
///
/// <https://github.com/nostr-protocol/nips/blob/master/60.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TokenEvent {
    /// Mint URL
    pub mint: Url,
    /// Unspent proofs
    pub proofs: Vec<CashuProof>,
    /// Token event IDs that were destroyed
    pub del: Vec<String>,
}

impl TokenEvent {
    /// Create new token event data
    pub fn new(mint: Url, proofs: Vec<CashuProof>) -> Self {
        Self {
            mint,
            proofs,
            del: Vec::new(),
        }
    }

    /// Parse from token event.
    ///
    /// `wallet_public_key` must be the trusted public key of the wallet author.
    #[cfg(feature = "std")]
    pub fn from_token_event(
        secret_key: &SecretKey,
        wallet_public_key: &PublicKey,
        event: &Event,
    ) -> Result<Self, Error> {
        validate_wallet_event(wallet_public_key, event, Kind::CashuWalletUnspentProof)?;

        let decrypted: String = nip44::decrypt(secret_key, wallet_public_key, &event.content)?;
        parse_json(&decrypted)
    }

    /// Add destroyed token event ID
    pub fn destroyed(mut self, event_id: String) -> Self {
        self.del.push(event_id);
        self
    }

    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn to_encrypted_content(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<String, Error> {
        let json: String = serde_json::to_string(self).map_err(Error::malformed)?;
        nip44::encrypt(secret_key, public_key, json, nip44::Version::V2)
    }

    /// Encrypt and prepare the unspent token event.
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn prepare(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<PreparedTokenEvent, Error> {
        Ok(PreparedTokenEvent {
            content: self.to_encrypted_content(secret_key, public_key)?,
        })
    }
}

/// Transaction direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionDirection {
    /// Received funds
    In,
    /// Sent funds
    Out,
}

impl fmt::Display for TransactionDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TransactionDirection {
    /// Get as `&str`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

impl FromStr for TransactionDirection {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "in" => Ok(Self::In),
            "out" => Ok(Self::Out),
            _ => Err(Error::with_static_message(
                ErrorKind::Invalid,
                "invalid direction",
            )),
        }
    }
}

/// Spending history event data (kind: 7376)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingHistory {
    /// Transaction direction
    pub direction: TransactionDirection,
    /// Amount in sats
    pub amount: u64,
    /// Created event IDs
    pub created: Vec<EventId>,
    /// Destroyed event IDs
    pub destroyed: Vec<EventId>,
    /// Redeemed event IDs
    pub redeemed: Vec<EventId>,
}

impl SpendingHistory {
    /// Create new spending history data
    pub fn new(direction: TransactionDirection, amount: u64) -> Self {
        Self {
            direction,
            amount,
            created: Vec::new(),
            destroyed: Vec::new(),
            redeemed: Vec::new(),
        }
    }

    /// Parse from spending history event.
    ///
    /// `wallet_public_key` must be the trusted public key of the wallet author.
    #[cfg(feature = "std")]
    pub fn from_spending_history_event(
        secret_key: &SecretKey,
        wallet_public_key: &PublicKey,
        event: &Event,
    ) -> Result<Self, Error> {
        validate_wallet_event(wallet_public_key, event, Kind::CashuWalletSpendingHistory)?;

        let decrypted: String = nip44::decrypt(secret_key, wallet_public_key, &event.content)?;
        let data: Vec<Vec<String>> = parse_json(&decrypted)?;

        let mut direction = None;
        let mut amount = None;
        let mut created: Vec<EventId> = Vec::new();
        let mut destroyed: Vec<EventId> = Vec::new();
        let mut redeemed: Vec<EventId> = Vec::new();

        // Parse encrypted content for created/destroyed events
        for item in data {
            if item.len() >= 2 {
                match item[0].as_str() {
                    DIRECTION => {
                        direction = Some(TransactionDirection::from_str(&item[1])?);
                    }
                    AMOUNT => {
                        amount = Some(item[1].parse().map_err(|_| {
                            Error::with_static_message(ErrorKind::Invalid, "invalid amount")
                        })?);
                    }
                    E_TAG_STR if item.len() >= 4 => {
                        let event_id: EventId = EventId::from_hex(&item[1])?;
                        let marker: &str = &item[3];
                        match marker {
                            EVENT_MARKER_CREATED => created.push(event_id),
                            EVENT_MARKER_DESTROYED => destroyed.push(event_id),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check unencrypted e tags for redeemed events
        for tag in event.tags.iter() {
            if tag.len() >= 4
                && tag.get(0) == Some(E_TAG_STR)
                && tag.get(3) == Some(EVENT_MARKER_REDEEMED)
            {
                if let Some(id) = tag.get(1) {
                    redeemed.push(EventId::from_hex(id)?);
                }
            }
        }

        let direction: TransactionDirection = direction.ok_or_else(|| missing_field(DIRECTION))?;
        let amount: u64 = amount.ok_or_else(|| missing_field(AMOUNT))?;

        Ok(Self {
            direction,
            amount,
            created,
            destroyed,
            redeemed,
        })
    }

    /// Add created event ID
    pub fn add_created(mut self, id: EventId) -> Self {
        self.created.push(id);
        self
    }

    /// Add destroyed event ID
    pub fn add_destroyed(mut self, id: EventId) -> Self {
        self.destroyed.push(id);
        self
    }

    /// Add redeemed event ID
    pub fn add_redeemed(mut self, id: EventId) -> Self {
        self.redeemed.push(id);
        self
    }

    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn to_encrypted_content(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<String, Error> {
        let mut data: Vec<Vec<String>> = vec![
            vec![DIRECTION.to_string(), self.direction.to_string()],
            vec![AMOUNT.to_string(), self.amount.to_string()],
        ];

        // Add created event references (encrypted)
        for event_id in &self.created {
            data.push(vec![
                String::from("e"),
                event_id.to_hex(),
                String::new(),
                EVENT_MARKER_CREATED.to_string(),
            ]);
        }

        // Add destroyed event references (encrypted)
        for event_id in &self.destroyed {
            data.push(vec![
                String::from("e"),
                event_id.to_hex(),
                String::new(),
                EVENT_MARKER_DESTROYED.to_string(),
            ]);
        }

        let json: String = serde_json::to_string(&data).map_err(Error::malformed)?;

        nip44::encrypt(secret_key, public_key, json, nip44::Version::V2)
    }

    /// Encrypt and prepare the spending history event.
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn prepare(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<PreparedSpendingHistoryEvent, Error> {
        Ok(PreparedSpendingHistoryEvent {
            content: self.to_encrypted_content(secret_key, public_key)?,
            redeemed: self.redeemed.clone(),
        })
    }
}

/// Quote event
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuoteEvent {
    /// Quote ID
    pub quote_id: String,
    /// Mint URL
    pub mint: Url,
    /// Expiration timestamp
    pub expiration: Option<Timestamp>,
}

impl fmt::Debug for QuoteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuoteEvent")
            .field("quote_id", &"[REDACTED]")
            .field("mint", &self.mint)
            .field("expiration", &self.expiration)
            .finish()
    }
}

impl QuoteEvent {
    /// Create new quote event data
    pub fn new<S>(quote_id: S, mint: Url) -> Self
    where
        S: Into<String>,
    {
        Self {
            quote_id: quote_id.into(),
            mint,
            expiration: None,
        }
    }

    /// Parse from quote event.
    ///
    /// `wallet_public_key` must be the trusted public key of the wallet author.
    #[cfg(feature = "std")]
    pub fn from_quote_event(
        secret_key: &SecretKey,
        wallet_public_key: &PublicKey,
        event: &Event,
    ) -> Result<Self, Error> {
        validate_wallet_event(wallet_public_key, event, Kind::CashuWalletQuote)?;

        let quote_id: String = nip44::decrypt(secret_key, wallet_public_key, &event.content)?;

        // Extract mint URL from tags
        let mint: Url = event
            .tags
            .iter()
            .find(|t| t.kind() == MINT)
            .and_then(|tag| tag.content())
            .ok_or_else(|| Error::with_static_message(ErrorKind::Missing, "missing mint tag"))?
            .parse()
            .map_err(|_| Error::with_static_message(ErrorKind::Invalid, "invalid mint URL"))?;

        // Extract NIP-40 expiration from tags if present
        let expiration: Option<Timestamp> = event.tags.expiration();

        Ok(Self {
            quote_id,
            mint,
            expiration,
        })
    }

    /// Set expiration timestamp
    pub fn expiration(mut self, expiration: Timestamp) -> Self {
        self.expiration = Some(expiration);
        self
    }

    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn to_encrypted_content(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<String, Error> {
        nip44::encrypt(secret_key, public_key, &self.quote_id, nip44::Version::V2)
    }

    /// Encrypt and prepare the quote event.
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn prepare(
        &self,
        secret_key: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<PreparedQuoteEvent, Error> {
        Ok(PreparedQuoteEvent {
            content: self.to_encrypted_content(secret_key, public_key)?,
            mint: self.mint.clone(),
        })
    }
}

/// Prepared wallet event.
#[cfg(all(feature = "std", feature = "os-rng"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreparedWalletEvent {
    content: String,
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl IntoEventBuilder for PreparedWalletEvent {
    #[inline]
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::CashuWallet).content(self.content)
    }
}

/// Prepared unspent token event.
#[cfg(all(feature = "std", feature = "os-rng"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreparedTokenEvent {
    content: String,
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl IntoEventBuilder for PreparedTokenEvent {
    #[inline]
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::CashuWalletUnspentProof).content(self.content)
    }
}

/// Prepared spending history event.
#[cfg(all(feature = "std", feature = "os-rng"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreparedSpendingHistoryEvent {
    content: String,
    redeemed: Vec<EventId>,
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl IntoEventBuilder for PreparedSpendingHistoryEvent {
    fn into_event_builder(self) -> EventBuilder {
        let tags = self.redeemed.into_iter().map(|event_id| {
            vec![
                String::from("e"),
                event_id.to_hex(),
                String::new(),
                String::from(EVENT_MARKER_REDEEMED),
            ]
        });
        EventBuilder::new(Kind::CashuWalletSpendingHistory)
            .content(self.content)
            .tags(tags)
    }
}

/// Prepared wallet quote event.
#[cfg(all(feature = "std", feature = "os-rng"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreparedQuoteEvent {
    content: String,
    mint: Url,
}

#[cfg(all(feature = "std", feature = "os-rng"))]
impl IntoEventBuilder for PreparedQuoteEvent {
    fn into_event_builder(self) -> EventBuilder {
        let expiration = Timestamp::now() + 14 * 24 * 60 * 60;
        EventBuilder::new(Kind::CashuWalletQuote)
            .content(self.content)
            .tag([MINT, self.mint.as_str()])
            .tag(Nip40Tag::Expiration(expiration))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::event::FinalizeEvent;
    #[cfg(all(feature = "std", feature = "os-rng"))]
    use crate::key::Keys;

    #[test]
    fn test_transaction_direction() {
        assert_eq!(TransactionDirection::In.to_string(), "in");
        assert_eq!(TransactionDirection::Out.to_string(), "out");

        assert_eq!(
            TransactionDirection::from_str("in").unwrap(),
            TransactionDirection::In
        );
        assert_eq!(
            TransactionDirection::from_str("out").unwrap(),
            TransactionDirection::Out
        );
        assert!(TransactionDirection::from_str("invalid").is_err());
    }

    #[test]
    fn test_wallet_event() {
        let mint_url = Url::parse("https://example.com").unwrap();
        let wallet = WalletEvent::new("test_privkey", vec![mint_url.clone()]);

        assert_eq!(wallet.privkey, "test_privkey");
        assert_eq!(wallet.mints.len(), 1);
        assert_eq!(wallet.mints[0], mint_url);
    }

    #[test]
    fn test_token_event_data() {
        let mint_url = Url::parse("https://example.com").unwrap();
        let proof = CashuProof {
            id: String::from("test_id"),
            amount: 100,
            secret: String::from("test_secret"),
            c: String::from("test_c"),
        };

        let token_data = TokenEvent::new(mint_url.clone(), vec![proof.clone()]);

        assert_eq!(token_data.mint, mint_url);
        assert_eq!(token_data.proofs.len(), 1);
        assert_eq!(token_data.proofs[0], proof);
        assert!(token_data.del.is_empty());
    }

    #[test]
    fn test_spending_history_data() {
        let history = SpendingHistory::new(TransactionDirection::In, 50);

        assert_eq!(history.direction, TransactionDirection::In);
        assert_eq!(history.amount, 50);
        assert!(history.created.is_empty());
        assert!(history.destroyed.is_empty());
        assert!(history.redeemed.is_empty());
    }

    #[test]
    fn test_spending_history_with_references() {
        let id1 = EventId::all_zeros();
        let id2 = EventId::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap();
        let id3 = EventId::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ])
        .unwrap();

        let history = SpendingHistory::new(TransactionDirection::In, 50)
            .add_created(id1)
            .add_destroyed(id2)
            .add_redeemed(id3);

        assert_eq!(history.direction, TransactionDirection::In);
        assert_eq!(history.amount, 50);
        assert_eq!(history.created.len(), 1);
        assert_eq!(history.destroyed.len(), 1);
        assert_eq!(history.redeemed.len(), 1);
        assert_eq!(history.created[0], id1);
        assert_eq!(history.destroyed[0], id2);
        assert_eq!(history.redeemed[0], id3);
    }

    #[test]
    fn test_quote_event_data() {
        let mint_url = Url::parse("https://example.com").unwrap();
        let quote = QuoteEvent::new("test_quote_id", mint_url.clone());

        assert_eq!(quote.quote_id, "test_quote_id");
        assert_eq!(quote.mint, mint_url);
        assert!(quote.expiration.is_none());
    }

    #[test]
    fn debug_redacts_wallet_credentials() {
        let mint = Url::parse("https://example.com").unwrap();
        let wallet = WalletEvent::new("wallet-private-key", vec![mint.clone()]);
        let proof = CashuProof {
            id: String::from("proof-id"),
            amount: 100,
            secret: String::from("cashu-bearer-secret"),
            c: String::from("proof-signature"),
        };
        let token = TokenEvent::new(mint.clone(), vec![proof]);
        let quote = QuoteEvent::new("quote-capability", mint);

        let debug = format!("{wallet:?} {token:?} {quote:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("wallet-private-key"));
        assert!(!debug.contains("cashu-bearer-secret"));
        assert!(!debug.contains("quote-capability"));
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn prepared_wallet_builder_round_trip() {
        let keys = Keys::generate();
        let public_key = keys.public_key();
        let wallet = WalletEvent::new(
            "test_privkey",
            vec![Url::parse("https://mint.example.com").unwrap()],
        );

        let event = wallet
            .prepare(keys.secret_key(), &public_key)
            .unwrap()
            .finalize(&keys)
            .unwrap();
        let decoded =
            WalletEvent::from_wallet_event(keys.secret_key(), &public_key, &event).unwrap();

        assert_eq!(decoded, wallet);
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn wallet_event_requires_the_trusted_author() {
        let wallet_keys = Keys::generate();
        let attacker_keys = Keys::generate();
        let wallet = WalletEvent::new(
            "attacker-controlled-key",
            vec![Url::parse("https://mint.example.com").unwrap()],
        );
        let event = wallet
            .prepare(attacker_keys.secret_key(), &wallet_keys.public_key())
            .unwrap()
            .finalize(&attacker_keys)
            .unwrap();

        let error = WalletEvent::from_wallet_event(
            wallet_keys.secret_key(),
            &wallet_keys.public_key(),
            &event,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "wallet event author mismatch");
    }

    #[test]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    fn wallet_event_requires_a_valid_signature() {
        let wallet_keys = Keys::generate();
        let wallet = WalletEvent::new(
            "wallet-key",
            vec![Url::parse("https://mint.example.com").unwrap()],
        );
        let mut event = wallet
            .prepare(wallet_keys.secret_key(), &wallet_keys.public_key())
            .unwrap()
            .finalize(&wallet_keys)
            .unwrap();
        event.sig = EventBuilder::new(Kind::TextNote)
            .content("invalid")
            .finalize(&Keys::generate())
            .unwrap()
            .sig;

        let error = WalletEvent::from_wallet_event(
            wallet_keys.secret_key(),
            &wallet_keys.public_key(),
            &event,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid wallet event signature");
    }
}
