// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! Kind

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Add, Range};
use core::str::FromStr;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use crate::error::Error;

/// Regular range
pub const REGULAR_RANGE: Range<u16> = 1_000..10_000;
/// Replaceable range
pub const REPLACEABLE_RANGE: Range<u16> = 10_000..20_000;
/// Ephemeral range
pub const EPHEMERAL_RANGE: Range<u16> = 20_000..30_000;
/// Addressable range
pub const ADDRESSABLE_RANGE: Range<u16> = 30_000..40_000;

macro_rules! kind_variants {
    ($($name:ident => $value:expr, $doc0:expr, $doc1:expr),* $(,)?) => {
        /// Event kind
        ///
        /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
        #[derive(Debug, Clone, Copy)]
        pub enum Kind {
            $(
                #[doc = concat!($doc0, " (kind: ", stringify!($value), ")")]
                #[doc = ""]
                #[doc = $doc1]
                $name,
            )*
            /// Represents a custom event.
            Custom(u16),
        }

        impl Kind {
            /// Construct from 16-bit unsigned integer
            pub const fn from_u16(kind: u16) -> Self {
                match kind {
                    $(
                        $value => Self::$name,
                    )*
                    x => Self::Custom(x),
                }
            }

            /// Get as 16-bit unsigned integer
            #[inline]
            pub const fn as_u16(&self) -> u16 {
                match self {
                    $(
                        Self::$name => $value,
                    )*
                    Self::Custom(u) => *u,
                }
            }
        }
    };
}

kind_variants! {
    Metadata => 0, "Metadata", "<https://github.com/nostr-protocol/nips/blob/master/01.md> and <https://github.com/nostr-protocol/nips/blob/master/05.md>",
    TextNote => 1, "Short Text Note", "<https://github.com/nostr-protocol/nips/blob/master/32.md>",
    RecommendRelay => 2, "Recommend Relay (deprecated)", "",
    ContactList => 3, "Contacts", "<https://github.com/nostr-protocol/nips/blob/master/02.md>",
    OpenTimestamps => 1040, "OpenTimestamps Attestations", "<https://github.com/nostr-protocol/nips/blob/master/03.md>",
    EncryptedDirectMessage => 4, "Encrypted Direct Messages", "<https://github.com/nostr-protocol/nips/blob/master/04.md>",
    EventDeletion => 5, "Event Deletion", "<https://github.com/nostr-protocol/nips/blob/master/09.md>",
    Repost => 6, "Repos", "<https://github.com/nostr-protocol/nips/blob/master/18.md>",
    GenericRepost => 16, "Generic Repos", "<https://github.com/nostr-protocol/nips/blob/master/18.md>",
    Comment => 1111, "Comment", "<https://github.com/nostr-protocol/nips/blob/master/22.md>",
    DoubleRatchetMessage => 1060, "Double Ratchet Message", "<https://github.com/nostr-protocol/nips/pull/1813>",
    Reaction => 7, "Reaction", "<https://github.com/nostr-protocol/nips/blob/master/25.md>",
    BadgeAward => 8, "Badge Award", "<https://github.com/nostr-protocol/nips/blob/master/58.md>",
    ChannelCreation => 40, "Channel Creation", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    ChannelMetadata => 41, "Channel Metadata", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    ChannelMessage => 42, "Channel Message", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    ChannelHideMessage => 43, "Channel Hide Message", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    ChannelMuteUser => 44, "Channel Mute User", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    PublicChatReserved45 => 45, "Public Chat Reserved", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    PublicChatReserved46 => 46, "Public Chat Reserved", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    PublicChatReserved47 => 47, "Public Chat Reserved", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    PublicChatReserved48 => 48, "Public Chat Reserved", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    PublicChatReserved49 => 49, "Public Chat Reserved", "<https://github.com/nostr-protocol/nips/blob/master/28.md>",
    MlsKeyPackage => 443, "MLS Key Package", "<https://github.com/nostr-protocol/nips/blob/master/104.md>",
    MlsWelcome => 444, "MLS Welcome", "<https://github.com/nostr-protocol/nips/blob/master/104.md>",
    MlsGroupMessage => 445, "MLS Group Message", "<https://github.com/nostr-protocol/nips/blob/master/104.md>",
    RepoState => 30618, "Repository state announcements", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitPatch => 1617, "Git Patch", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitPullRequest => 1618, "Git Pull Request", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitPullRequestUpdate => 1619, "Git Pull Request Update", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitIssue => 1621, "Git Issue", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitReply => 1622, "Git Reply", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitStatusOpen => 1630, "Open Status of Git Patch or Issue", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitStatusApplied => 1631, "Applied / Merged Status of Git Patch or Resolved Status of Git Issue", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitStatusClosed => 1632, "Closed Status of Git Patch or Issue", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    GitStatusDraft => 1633, "Draft Status of Git Patch or Issue", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    WalletConnectInfo => 13194, "Wallet Service Info", "<https://github.com/nostr-protocol/nips/blob/master/47.md>",
    Reporting => 1984, "Reporting", "<https://github.com/nostr-protocol/nips/blob/master/56.md>",
    Label => 1985, "Label", "<https://github.com/nostr-protocol/nips/blob/master/32.md>",
    GroupPutUser => 9000, "Put User", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupRemoveUser => 9001, "Remove User", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupEditMetadata => 9002, "Edit Metadata", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupDeleteEvent => 9005, "Delete Event", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupCreateGroup => 9007, "Create Group", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupDeleteGroup => 9008, "Delete Group", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupCreateInvite => 9009, "Create Invite", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupJoinRequest => 9021, "Join Request", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupLeaveRequest => 9022, "Leave Request", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupMetadata => 39000, "Group Metadata", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupAdmins => 39001, "Group Admins", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupMembers => 39002, "Group Members", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupRoles => 39003, "Group Roles", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    GroupLivekitParticipants => 39004, "Livekit Participants", "<https://github.com/nostr-protocol/nips/blob/master/29.md>",
    ZapPrivateMessage => 9733, "Zap Private Message", "<https://github.com/nostr-protocol/nips/blob/master/57.md>",
    ZapRequest => 9734, "Zap Request", "<https://github.com/nostr-protocol/nips/blob/master/57.md>",
    ZapReceipt => 9735, "Zap Receipt", "<https://github.com/nostr-protocol/nips/blob/master/57.md>",
    Highlight => 9802, "Highlights", "<https://github.com/nostr-protocol/nips/blob/master/84.md>",
    MuteList => 10000, "Mute List", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    PinList => 10001, "Pin List", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    RelayList => 10002, "Relay List Metadata", "<https://github.com/nostr-protocol/nips/blob/master/65.md>",
    Bookmarks => 10003, "Bookmarks", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    Communities => 10004, "Communities", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    PublicChats => 10005, "Public Chats", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    BlockedRelays => 10006, "Blocked Relays", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    SearchRelays => 10007, "Search Relays", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    SimpleGroups => 10009, "Simple Groups", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    Interests => 10015, "Interests", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    Emojis => 10030, "Emojis", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    InboxRelays => 10050, "Inbox Relays", "<https://github.com/nostr-protocol/nips/blob/master/17.md>",
    MlsKeyPackageRelays => 10051, "MLS Key Package Relays", "<https://github.com/nostr-protocol/nips/blob/master/104.md>",
    BlossomServerList => 10063, "Blossom Server List", "<https://github.com/nostr-protocol/nips/blob/master/B7.md>",
    Authentication => 22242, "Client Authentication", "<https://github.com/nostr-protocol/nips/blob/master/42.md>",
    WalletConnectRequest => 23194, "Wallet Connect Request", "<https://github.com/nostr-protocol/nips/blob/master/47.md>",
    WalletConnectResponse => 23195, "Wallet Connect Response", "<https://github.com/nostr-protocol/nips/blob/master/47.md>",
    WalletConnectNotification => 23196, "Wallet Connect Notification", "<https://github.com/nostr-protocol/nips/blob/master/47.md>",
    WalletConnectNotificationNip44V2 => 23197, "Wallet Connect Notification encrypted using nip44_v2", "<https://github.com/nostr-protocol/nips/blob/master/47.md>",
    NostrConnect => 24133, "Nostr Connect", "<https://github.com/nostr-protocol/nips/blob/master/47.md>",
    LiveEvent => 30311, "Live Event", "<https://github.com/nostr-protocol/nips/blob/master/53.md>",
    LiveEventMessage => 1311, "Live Event Message", "<https://github.com/nostr-protocol/nips/blob/master/53.md>",
    ProfileBadges => 10008, "Profile Badges", "<https://github.com/nostr-protocol/nips/blob/master/58.md>",
    BadgeSet => 30008, "Badge Set", "<https://github.com/nostr-protocol/nips/blob/master/58.md>",
    BadgeDefinition => 30009, "Badge Definition", "<https://github.com/nostr-protocol/nips/blob/master/58.md>",
    Seal => 13, "Seal", "<https://github.com/nostr-protocol/nips/blob/master/59.md>",
    GiftWrap => 1059, "Gift Wrap", "<https://github.com/nostr-protocol/nips/blob/master/59.md>",
    PrivateDirectMessage => 14, "Private Direct message", "<https://github.com/nostr-protocol/nips/blob/master/17.md>",
    SetStall => 30017, "Set stall", "<https://github.com/nostr-protocol/nips/blob/master/15.md>",
    SetProduct => 30018, "Set product", "<https://github.com/nostr-protocol/nips/blob/master/15.md>",
    JobFeedback => 7000, "Job Feedback", "<https://github.com/nostr-protocol/nips/blob/master/90.md>",
    FollowSet => 30000, "Follow Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    RelaySet => 30002, "Relay Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    BookmarkSet => 30003, "Bookmark Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    ArticlesCurationSet => 30004, "Articles Curation Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    VideosCurationSet => 30005, "Videos Curation Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    InterestSet => 30015, "Interest Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    EmojiSet => 30030, "Emoji Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    ReleaseArtifactSet => 30063, "Release Artifact Set", "<https://github.com/nostr-protocol/nips/blob/master/51.md>",
    LongFormTextNote => 30023, "Long-form Text Note", "<https://github.com/nostr-protocol/nips/blob/master/23.md>",
    GitRepoAnnouncement => 30617, "Git Repository Announcement", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    FileMetadata => 1063, "File Metadata", "<https://github.com/nostr-protocol/nips/blob/master/94.md>",
    BlossomAuth => 24242, "Blossom Authorization", "<https://github.com/hzrd149/blossom/blob/master/buds/01.md>",
    HttpAuth => 27235, "HTTP Auth", "<https://github.com/nostr-protocol/nips/blob/master/98.md>",
    ApplicationSpecificData => 30078, "Application-specific Data", "<https://github.com/nostr-protocol/nips/blob/master/78.md>",
    Torrent => 2003, "Torrent", "<https://github.com/nostr-protocol/nips/blob/master/35.md>",
    TorrentComment => 2004, "Torrent Comment", "<https://github.com/nostr-protocol/nips/blob/master/35.md>",
    PeerToPeerOrder => 38383, "Peer-to-peer Order events", "<https://github.com/nostr-protocol/nips/blob/master/69.md>",
    RequestToVanish => 62, "Request to Vanish", "<https://github.com/nostr-protocol/nips/blob/master/62.md>",
    UserStatus => 30315, "User Status", "<https://github.com/nostr-protocol/nips/blob/master/38.md>",
    VoiceMessage => 1222, "Voice Message", "<https://github.com/nostr-protocol/nips/blob/master/A0.md>",
    VoiceMessageReply => 1244, "Voice Message Reply", "<https://github.com/nostr-protocol/nips/blob/master/A0.md>",
    CashuWallet => 17375, "Cashu Wallet", "<https://github.com/nostr-protocol/nips/blob/master/60.md>",
    CashuWalletUnspentProof => 7375, "Cashu Wallet Unspent Proof", "<https://github.com/nostr-protocol/nips/blob/master/60.md>",
    CashuWalletSpendingHistory => 7376, "Cashu Wallet Spending History", "<https://github.com/nostr-protocol/nips/blob/master/60.md>",
    CashuWalletQuote => 7374, "Cashu Wallet Redeeming a quote", "<https://github.com/nostr-protocol/nips/blob/master/60.md>",
    CashuNutZapInfo => 10019, "Cashu Nut Zap informational event", "<https://github.com/nostr-protocol/nips/blob/master/61.md>",
    GitUserGraspList => 10317, "User Grasp List", "<https://github.com/nostr-protocol/nips/blob/master/34.md>",
    CashuNutZap => 9321, "Cashu Nut Zap", "<https://github.com/nostr-protocol/nips/blob/master/61.md>",
    CodeSnippet => 1337, "Code Snippets", "<https://github.com/nostr-protocol/nips/blob/master/C0.md>",
    Poll => 1068, "Poll", "<https://github.com/nostr-protocol/nips/blob/master/88.md>",
    PollResponse => 1018, "Poll response", "<https://github.com/nostr-protocol/nips/blob/master/88.md>",
    ChatMessage => 9, "Chat Message", "<https://github.com/nostr-protocol/nips/blob/master/C7.md>",
    Thread => 11, "Thread", "<https://github.com/nostr-protocol/nips/blob/master/7D.md>",
    WebBookmark => 39701, "Web Bookmark", "<https://github.com/nostr-protocol/nips/blob/master/B0.md>",
    RelayMonitor => 10166, "Relay Monitor", "<https://github.com/nostr-protocol/nips/blob/master/66.md>",
    RelayDiscovery => 30166, "Relay Discovery", "<https://github.com/nostr-protocol/nips/blob/master/66.md>",
}

impl PartialEq for Kind {
    fn eq(&self, other: &Kind) -> bool {
        self.as_u16() == other.as_u16()
    }
}

impl Eq for Kind {}

impl PartialOrd for Kind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Kind {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_u16().cmp(&other.as_u16())
    }
}

impl Hash for Kind {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.as_u16().hash(state);
    }
}

impl Kind {
    /// Check if it's regular
    ///
    /// Regular means that event is expected to be stored by relays.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    pub fn is_regular(&self) -> bool {
        let kind: u16 = self.as_u16();

        // Exclude ALL param replaceable and ephemeral
        // Exclude PARTIALLY the replaceable
        if kind > 10_000 {
            return false;
        }

        REGULAR_RANGE.contains(&kind) || !self.is_replaceable()
    }

    /// Check if it's replaceable
    ///
    /// Replaceable means that, for each combination of `pubkey` and `kind`,
    /// only the latest event MUST be stored by relays, older versions MAY be discarded.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn is_replaceable(&self) -> bool {
        matches!(self, Kind::Metadata)
            || matches!(self, Kind::ContactList)
            || matches!(self, Kind::ChannelMetadata)
            || REPLACEABLE_RANGE.contains(&self.as_u16())
    }

    /// Check if it's ephemeral
    ///
    /// Ephemeral means that event is not expected to be stored by relays.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn is_ephemeral(&self) -> bool {
        EPHEMERAL_RANGE.contains(&self.as_u16())
    }

    /// Check if it's addressable
    ///
    /// Addressable means that,
    /// for each combination of `pubkey`, `kind` and the `d` tag's first value,
    /// only the latest event MUST be stored by relays, older versions MAY be discarded.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
    #[inline]
    pub fn is_addressable(&self) -> bool {
        ADDRESSABLE_RANGE.contains(&self.as_u16())
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_u16())
    }
}

impl FromStr for Kind {
    type Err = Error;

    fn from_str(kind: &str) -> Result<Self, Self::Err> {
        let kind: u16 = kind.parse().map_err(Error::malformed)?;
        Ok(Self::from_u16(kind))
    }
}

impl From<u16> for Kind {
    fn from(kind: u16) -> Self {
        Self::from_u16(kind)
    }
}

impl From<Kind> for u16 {
    fn from(kind: Kind) -> u16 {
        kind.as_u16()
    }
}

// Currently, this is needed for NIP-90
impl Add<u16> for Kind {
    type Output = Self;

    fn add(self, rhs: u16) -> Self::Output {
        let kind: u16 = self.as_u16();
        let sum: u16 = kind.saturating_add(rhs);
        Kind::from_u16(sum)
    }
}

impl Serialize for Kind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.as_u16())
    }
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let kind: u16 = Deserialize::deserialize(deserializer)?;
        Ok(Self::from_u16(kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct TestKind {
        kind: Kind,
    }

    #[test]
    fn test_equal_kind() {
        assert_eq!(Kind::Custom(20100), Kind::from_u16(20100));
        assert_eq!(Kind::TextNote, Kind::Custom(1));
        assert_eq!(Kind::Custom(30017), Kind::SetStall);
        assert_eq!(Kind::Custom(30018), Kind::SetProduct);
    }

    #[test]
    fn test_not_equal_kind() {
        assert_ne!(Kind::Custom(20100), Kind::Custom(2000));
        assert_ne!(Kind::Authentication, Kind::EncryptedDirectMessage);
        assert_ne!(Kind::TextNote, Kind::Custom(2));
    }

    #[test]
    fn test_kind_is_addressable() {
        assert!(Kind::Custom(32122).is_addressable());
        assert!(!Kind::TextNote.is_addressable());
    }

    #[test]
    fn test_kind_from_str() {
        assert_eq!(Kind::from_str("0").unwrap(), Kind::Metadata);
        assert_eq!(Kind::from_str("1").unwrap(), Kind::TextNote);
        assert_eq!(Kind::from_str("1621").unwrap(), Kind::Custom(1621));
        assert_eq!(Kind::from_str("20100").unwrap(), Kind::Custom(20100));
    }

    #[test]
    fn test_kind_deserialize() {
        let json: &str = r#"{"kind": 1621}"#;
        let TestKind { kind } = serde_json::from_str(json).unwrap();

        assert_eq!(kind, Kind::Custom(1621));
    }

    #[test]
    fn test_kind_serialize() {
        let kind = TestKind {
            kind: Kind::Metadata,
        };
        let json = serde_json::to_string(&kind).unwrap();
        let expected_json: &str = r#"{"kind":0}"#;

        assert_eq!(json, expected_json);
    }

    #[test]
    fn test_kind_serialize_deserialize_round_trip() {
        let kind = Kind::Custom(20100);
        let json = serde_json::to_string(&kind).unwrap();
        let deserialized_kind: Kind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, deserialized_kind);
    }

    #[test]
    fn test_kind_add() {
        let kind = Kind::TextNote + 100;
        assert_eq!(kind, Kind::Custom(101));

        let kind = Kind::Custom(20100) + 100;
        assert_eq!(kind, Kind::Custom(20200));
    }

    #[test]
    fn test_kind_add_overflow() {
        // MUST NOT overflow
        let kind = Kind::Custom(u16::MAX - 1) + 10;
        assert_eq!(kind, Kind::Custom(u16::MAX));
    }
}

#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};

    use super::*;

    #[bench]
    pub fn parse_ephemeral_kind(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(Kind::from(29_999));
        });
    }

    #[bench]
    pub fn parse_kind(bh: &mut Bencher) {
        bh.iter(|| {
            black_box(Kind::from(0));
        });
    }
}
