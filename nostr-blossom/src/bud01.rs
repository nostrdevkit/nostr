//! Implements data structures specific to BUD-01

use std::fmt;

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use nostr::event::{EventBuilder, IntoEventBuilder, Kind};
use nostr::nips::nip40::Nip40Tag;
use nostr::types::{Timestamp, Url};

/// Represents the authorization data for accessing a Blossom server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlossomAuthorization {
    /// A human readable string explaining to the user what the events intended use is
    pub content: String,
    /// A UNIX timestamp (in seconds) indicating when the authorization should be expired
    pub expiration: Timestamp,
    /// The type of action authorized by the user
    pub action: BlossomAuthorizationVerb,
    /// The scope of the authorization
    pub scope: BlossomAuthorizationScope,
}

impl BlossomAuthorization {
    /// Constructor for creating a new BlossomAuthorization
    pub fn new(
        content: String,
        expiration: Timestamp,
        action: BlossomAuthorizationVerb,
        scope: BlossomAuthorizationScope,
    ) -> Self {
        Self {
            content,
            expiration,
            action,
            scope,
        }
    }
}

/// The scope of a Blossom authorization event
///
/// MUST contain either a server tag containing the full URL to the server or MUST contain at least one x tag matching the sha256 hash of the blob being retrieved
///
/// <https://github.com/hzrd149/blossom/blob/master/buds/01.md>
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlossomAuthorizationScope {
    /// Authorizes access to blobs with the given SHA256 hashes.
    BlobSha256Hashes(Vec<Sha256Hash>),
    /// Authorizes access to the given server URL.
    ServerUrl(Url),
    /// Authorizes access to the given server domains.
    ServerDomains(Vec<String>),
    /// Authorizes access to the given hashes on the given server domains.
    ServerDomainsAndBlobSha256Hashes {
        /// Lowercase server domain names.
        domains: Vec<String>,
        /// SHA256 hashes of the authorized blobs.
        hashes: Vec<Sha256Hash>,
    },
}

/// Represents the possible actions that can be authorized by a Blossom authorization event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlossomAuthorizationVerb {
    /// Authorizes the retrieval of a blob.
    Get,
    /// Authorizes the upload of a blob.
    Upload,
    /// Authorizes the listing of blobs.
    List,
    /// Authorizes the deletion of a blob.
    Delete,
    /// Authorizes media processing.
    Media,
}

impl fmt::Display for BlossomAuthorizationVerb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl BlossomAuthorizationVerb {
    /// Converts the authorization verb into a string
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "get",
            Self::Upload => "upload",
            Self::List => "list",
            Self::Delete => "delete",
            Self::Media => "media",
        }
    }
}

impl IntoEventBuilder for BlossomAuthorization {
    /// Blossom authorization event
    ///
    /// <https://github.com/hzrd149/blossom/blob/master/buds/01.md>
    fn into_event_builder(self) -> EventBuilder {
        let mut builder: EventBuilder = EventBuilder::new(Kind::BlossomAuth).content(self.content);

        match self.scope {
            BlossomAuthorizationScope::BlobSha256Hashes(hashes) => {
                for hash in hashes.into_iter() {
                    builder.tags.push(["x", hash.to_string().as_str()]);
                }
            }
            BlossomAuthorizationScope::ServerUrl(url) => {
                if let Some(domain) = url.host_str() {
                    builder.tags.push(["server", domain]);
                }
            }
            BlossomAuthorizationScope::ServerDomains(domains) => {
                for domain in domains {
                    builder
                        .tags
                        .push(["server", domain.to_ascii_lowercase().as_str()]);
                }
            }
            BlossomAuthorizationScope::ServerDomainsAndBlobSha256Hashes { domains, hashes } => {
                for domain in domains {
                    builder
                        .tags
                        .push(["server", domain.to_ascii_lowercase().as_str()]);
                }
                for hash in hashes {
                    builder.tags.push(["x", hash.to_string().as_str()]);
                }
            }
        }

        builder.tags.push(Nip40Tag::Expiration(self.expiration));

        // Add the 't' tag to say what this auth is for
        builder.tags.push(["t", self.action.to_string().as_str()]);

        builder
    }
}

#[cfg(test)]
mod tests {
    use nostr::event::{IntoEventBuilder, Tags};

    use super::*;

    #[test]
    fn authorization_uses_domain_scopes_and_media_verb() {
        let authorization = BlossomAuthorization::new(
            "Optimize media".to_owned(),
            Timestamp::from_secs(1_800_000_000),
            BlossomAuthorizationVerb::Media,
            BlossomAuthorizationScope::ServerUrl(
                Url::parse("https://CDN.EXAMPLE.COM/some/path").unwrap(),
            ),
        );

        let builder = authorization.into_event_builder();
        let tags: Tags = builder.tags.freeze();

        assert!(
            tags.iter()
                .any(|t| t.kind() == "server" && t.content() == Some("cdn.example.com"))
        );
        assert!(
            tags.iter()
                .any(|t| t.kind() == "t" && t.content() == Some("media"))
        );
        assert!(
            !tags
                .iter()
                .any(|tag| tag.get(1).is_some_and(|value| value.contains("://")))
        );
    }
}
