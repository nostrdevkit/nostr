// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP34: git stuff
//!
//! <https://github.com/nostr-protocol/nips/blob/master/34.md>

#![allow(clippy::wrong_self_convention)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use bitcoin_hashes::sha1::Hash as Sha1Hash;

use super::nip01::{Coordinate, Nip01Tag};
use super::nip22::Nip22Tag;
use super::nip51::Nip51Tag;
use super::util::{
    missing_tag_kind, missing_value, take_and_parse_from_str, take_string, unknown_tag,
};
use crate::error::{Error, ErrorKind};
use crate::event::{EventBuilder, EventId, IntoEventBuilder, Kind, impl_tag_codec_conversions};
use crate::key::PublicKey;
use crate::types::url::Url;
use crate::types::{RelayUrl, Timestamp};

const EUC: &str = "euc";
const APPLIED_AS_COMMITS: &str = "applied-as-commits";
const BRANCH_NAME: &str = "branch-name";
const CLONE: &str = "clone";
const COMMIT: &str = "commit";
const COMMIT_PGP_SIG: &str = "commit-pgp-sig";
const COMMITTER: &str = "committer";
const CURRENT_COMMIT: &str = "c";
const DESCRIPTION: &str = "description";
const GRASP: &str = "g";
const HEAD: &str = "HEAD";
const MAINTAINERS: &str = "maintainers";
const MERGE_BASE: &str = "merge-base";
const MERGE_COMMIT: &str = "merge-commit";
const NAME: &str = "name";
const PARENT_COMMIT: &str = "parent-commit";
const REFERENCE: &str = "r";
const REFS_HEADS: &str = "refs/heads/";
const REFS_TAGS: &str = "refs/tags/";
const SUBJECT: &str = "subject";
const WEB: &str = "web";
const RELAYS: &str = "relays";

/// Standardized NIP-34 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/34.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Nip34Tag {
    /// `applied-as-commits` tag
    AppliedAsCommits(Vec<Sha1Hash>),
    /// `branch-name` tag
    BranchName(String),
    /// `clone` tag
    Clone(Vec<Url>),
    /// `commit` tag
    Commit(Sha1Hash),
    /// `commit-pgp-sig` tag
    CommitPgpSig(String),
    /// `committer` tag
    Committer {
        /// Name
        name: String,
        /// Email
        email: String,
        /// Timestamp
        timestamp: Timestamp,
        /// Timezone offset in minutes
        offset_minutes: i32,
    },
    /// `c` tag
    CurrentCommit(Sha1Hash),
    /// `description` tag
    Description(String),
    /// `r` tag with `euc` marker
    EarliestUniqueCommitId(Sha1Hash),
    /// `g` tag
    Grasp(RelayUrl),
    /// `HEAD` tag
    Head(String),
    /// `maintainers` tag
    Maintainers(Vec<PublicKey>),
    /// `merge-base` tag
    MergeBase(Sha1Hash),
    /// `merge-commit` tag
    MergeCommit(Sha1Hash),
    /// `name` tag
    Name(String),
    /// `parent-commit` tag
    ParentCommit(Sha1Hash),
    /// `r` tag
    Reference(Sha1Hash),
    /// `refs/heads/<branch>` tag
    RefHead {
        /// Branch name
        branch: String,
        /// Commit ID
        commit: Sha1Hash,
    },
    /// `refs/tags/<tag>` tag
    RefTag {
        /// Tag name
        name: String,
        /// Commit ID
        commit: Sha1Hash,
    },
    /// `relays` tag
    Relays(Vec<RelayUrl>),
    /// `subject` tag
    Subject(String),
    /// `web` tag
    Web(Vec<Url>),
}

impl_tag_codec_conversions! {
    Nip34Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();
        let kind: S = iter.next().ok_or(missing_tag_kind())?;
        let kind: &str = kind.as_ref();

        match kind {
            APPLIED_AS_COMMITS => Ok(Self::AppliedAsCommits(parse_commit_list(iter)?)),
            BRANCH_NAME => Ok(Self::BranchName(take_string(&mut iter, "branch name")?)),
            CLONE => Ok(Self::Clone(parse_url_list(iter)?)),
            COMMIT => {
                let commit: Sha1Hash = take_and_parse_from_str(&mut iter, "commit ID")?;
                Ok(Self::Commit(commit))
            }
            COMMIT_PGP_SIG => Ok(Self::CommitPgpSig(take_string(
                &mut iter,
                "commit pgp signature",
            )?)),
            COMMITTER => {
                let name: String = iter
                    .next()
                    .map(|value| value.as_ref().to_string())
                    .unwrap_or_default();
                let email: String = iter
                    .next()
                    .map(|value| value.as_ref().to_string())
                    .unwrap_or_default();
                let timestamp: Timestamp =
                    take_and_parse_from_str(&mut iter, "committer timestamp")?;
                let offset_minutes: i32 = take_and_parse_from_str(&mut iter, "committer offset")?;

                Ok(Self::Committer {
                    name,
                    email,
                    timestamp,
                    offset_minutes,
                })
            }
            CURRENT_COMMIT => {
                let commit: Sha1Hash = take_and_parse_from_str(&mut iter, "current commit ID")?;
                Ok(Self::CurrentCommit(commit))
            }
            DESCRIPTION => Ok(Self::Description(take_string(&mut iter, "description")?)),
            GRASP => {
                let relay: RelayUrl = take_and_parse_from_str(&mut iter, "grasp relay URL")?;
                Ok(Self::Grasp(relay))
            }
            HEAD => {
                let head: S = iter.next().ok_or(missing_value("head"))?;
                let branch: &str =
                    head.as_ref()
                        .strip_prefix("ref: refs/heads/")
                        .ok_or_else(|| {
                            Error::with_static_message(ErrorKind::Invalid, "invalid head tag")
                        })?;
                Ok(Self::Head(branch.to_string()))
            }
            MAINTAINERS => Ok(Self::Maintainers(parse_public_keys(iter)?)),
            MERGE_BASE => {
                let commit: Sha1Hash = take_and_parse_from_str(&mut iter, "merge base")?;
                Ok(Self::MergeBase(commit))
            }
            MERGE_COMMIT => {
                let commit: Sha1Hash = take_and_parse_from_str(&mut iter, "merge commit ID")?;
                Ok(Self::MergeCommit(commit))
            }
            NAME => Ok(Self::Name(take_string(&mut iter, "name")?)),
            PARENT_COMMIT => {
                let commit: Sha1Hash = take_and_parse_from_str(&mut iter, "parent commit ID")?;
                Ok(Self::ParentCommit(commit))
            }
            REFERENCE => {
                let commit: Sha1Hash = take_and_parse_from_str(&mut iter, "reference commit ID")?;
                match iter.next() {
                    Some(marker) if marker.as_ref() == EUC => {
                        Ok(Self::EarliestUniqueCommitId(commit))
                    }
                    Some(_) => Err(unknown_tag()),
                    None => Ok(Self::Reference(commit)),
                }
            }
            SUBJECT => Ok(Self::Subject(take_string(&mut iter, "subject")?)),
            WEB => Ok(Self::Web(parse_url_list(iter)?)),
            RELAYS => Ok(Self::Relays(parse_relay_urls(iter)?)),
            _ if kind.starts_with(REFS_HEADS) => {
                let commit: S = iter.next().ok_or(missing_value("commit id"))?;
                Ok(Self::RefHead {
                    branch: kind.trim_start_matches(REFS_HEADS).to_string(),
                    commit: Sha1Hash::from_str(commit.as_ref())
                        .map_err(Error::malformed_display)?,
                })
            }
            _ if kind.starts_with(REFS_TAGS) => {
                let commit: S = iter.next().ok_or(missing_value("commit id"))?;
                Ok(Self::RefTag {
                    name: kind.trim_start_matches(REFS_TAGS).to_string(),
                    commit: Sha1Hash::from_str(commit.as_ref())
                        .map_err(Error::malformed_display)?,
                })
            }
            _ => Err(unknown_tag()),
        }
    }

    fn write(self, tx) {
        match self {
            Self::AppliedAsCommits(commits) => {
                tx.push_str(APPLIED_AS_COMMITS);

                for commit in &commits {
                    tx.push_hex(commit.as_byte_array());
                }
            }
            Self::BranchName(name) => {
                tx.push_str(BRANCH_NAME);
                tx.push_str(&name);
            }
            Self::Clone(urls) => {
                tx.push_str(CLONE);

                for url in &urls {
                    tx.push_str(url.as_str());
                }
            }
            Self::Commit(commit) => {
                tx.push_str(COMMIT);
                tx.push_hex(commit.as_byte_array());
            }
            Self::CommitPgpSig(signature) => {
                tx.push_str(COMMIT_PGP_SIG);
                tx.push_str(&signature);
            }
            Self::Committer {
                name,
                email,
                timestamp,
                offset_minutes,
            } => {
                tx.push_str(COMMITTER);
                tx.push_str(&name);
                tx.push_str(&email);
                tx.push_u64(timestamp.as_secs());
                tx.push_str(&offset_minutes.to_string());
            }
            Self::CurrentCommit(commit) => {
                tx.push_str(CURRENT_COMMIT);
                tx.push_hex(commit.as_byte_array());
            }
            Self::Description(description) => {
                tx.push_str(DESCRIPTION);
                tx.push_str(&description);
            }
            Self::EarliestUniqueCommitId(commit) => {
                tx.push_str(REFERENCE);
                tx.push_hex(commit.as_byte_array());
                tx.push_str(EUC);
            }
            Self::Grasp(relay) => {
                tx.push_str(GRASP);
                tx.push_str(relay.as_str());
            }
            Self::Head(branch) => {
                tx.push_str(HEAD);
                tx.push_str(&format!("ref: refs/heads/{branch}"));
            }
            Self::Maintainers(public_keys) => {
                tx.push_str(MAINTAINERS);

                for public_key in &public_keys {
                    tx.push_hex(public_key.as_bytes());
                }
            }
            Self::MergeBase(commit) => {
                tx.push_str(MERGE_BASE);
                tx.push_hex(commit.as_byte_array());
            }
            Self::MergeCommit(commit) => {
                tx.push_str(MERGE_COMMIT);
                tx.push_hex(commit.as_byte_array());
            }
            Self::Name(name) => {
                tx.push_str(NAME);
                tx.push_str(&name);
            }
            Self::ParentCommit(commit) => {
                tx.push_str(PARENT_COMMIT);
                tx.push_hex(commit.as_byte_array());
            }
            Self::Reference(commit) => {
                tx.push_str(REFERENCE);
                tx.push_hex(commit.as_byte_array());
            }
            Self::RefHead { branch, commit } => {
                tx.push_str(&format!("{REFS_HEADS}{branch}"));
                tx.push_hex(commit.as_byte_array());
            }
            Self::RefTag { name, commit } => {
                tx.push_str(&format!("{REFS_TAGS}{name}"));
                tx.push_hex(commit.as_byte_array());
            }
            Self::Relays(relays) => {
                tx.push_str(RELAYS);

                for relay in &relays {
                    tx.push_str(relay.as_str());
                }
            }
            Self::Subject(subject) => {
                tx.push_str(SUBJECT);
                tx.push_str(&subject);
            }
            Self::Web(urls) => {
                tx.push_str(WEB);

                for url in &urls {
                    tx.push_str(url.as_str());
                }
            }
        }
    }
}

fn parse_commit_list<I, S>(iter: I) -> Result<Vec<Sha1Hash>, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values: Vec<Sha1Hash> = iter
        .into_iter()
        .map(|value| Sha1Hash::from_str(value.as_ref()))
        .collect::<Result<_, _>>()
        .map_err(Error::malformed_display)?;

    if values.is_empty() {
        return Err(missing_value("commits"));
    }

    Ok(values)
}

fn parse_public_keys<I, S>(iter: I) -> Result<Vec<PublicKey>, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values: Vec<PublicKey> = iter
        .into_iter()
        .map(|value| PublicKey::from_hex(value.as_ref()))
        .collect::<Result<_, _>>()?;

    if values.is_empty() {
        return Err(missing_value("public keys"));
    }

    Ok(values)
}

fn parse_relay_urls<I, S>(iter: I) -> Result<Vec<RelayUrl>, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values: Vec<RelayUrl> = iter
        .into_iter()
        .map(|value| RelayUrl::parse(value.as_ref()))
        .collect::<Result<_, _>>()?;

    if values.is_empty() {
        return Err(missing_value("relay URLs"));
    }

    Ok(values)
}

fn parse_url_list<I, S>(iter: I) -> Result<Vec<Url>, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let values: Vec<Url> = iter
        .into_iter()
        .map(|value| Url::parse(value.as_ref()))
        .collect::<Result<_, _>>()
        .map_err(Error::malformed)?;

    if values.is_empty() {
        return Err(missing_value("URLs"));
    }

    Ok(values)
}

/// Git Repository Announcement
///
/// Git repositories are hosted in Git-enabled servers, but their existence can be announced using Nostr events,
/// as well as their willingness to receive patches, bug reports and comments in general.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitRepositoryAnnouncement {
    /// Repository ID (usually kebab-case short name)
    pub id: String,
    /// Human-readable project name
    pub name: Option<String>,
    /// Brief human-readable project description
    pub description: Option<String>,
    /// Webpage urls, if the git server being used provides such a thing
    pub web: Vec<Url>,
    /// Urls for git-cloning
    pub clone: Vec<Url>,
    /// Relays that this repository will monitor for patches and issues
    pub relays: Vec<RelayUrl>,
    /// Earliest unique commit ID
    ///
    /// `euc` marker should be the commit ID of the earliest unique commit of this repo,
    /// made to identify it among forks and group it with other repositories hosted elsewhere that may represent essentially the same project.
    /// In most cases it will be the root commit of a repository.
    /// In case of a permanent fork between two projects, then the first commit after the fork should be used.
    pub euc: Option<Sha1Hash>,
    /// Other recognized maintainers
    pub maintainers: Vec<PublicKey>,
}

impl IntoEventBuilder for GitRepositoryAnnouncement {
    fn into_event_builder(self) -> EventBuilder {
        let mut builder = EventBuilder::new(Kind::GitRepoAnnouncement);

        // Add repo ID
        builder.tags.push(Nip01Tag::identifier(self.id));

        // Add name
        if let Some(name) = self.name {
            builder.tags.push(Nip34Tag::Name(name));
        }

        // Add description
        if let Some(description) = self.description {
            builder.tags.push(Nip34Tag::Description(description));
        }

        // Add web
        if !self.web.is_empty() {
            builder.tags.push(Nip34Tag::Web(self.web));
        }

        // Add clone
        if !self.clone.is_empty() {
            builder.tags.push(Nip34Tag::Clone(self.clone));
        }

        // Add relays
        if !self.relays.is_empty() {
            builder.tags.push(Nip34Tag::Relays(self.relays));
        }

        // Add EUC
        if let Some(commit) = self.euc {
            builder.tags.push(Nip34Tag::EarliestUniqueCommitId(commit));
        }

        // Add maintainers
        if !self.maintainers.is_empty() {
            builder.tags.push(Nip34Tag::Maintainers(self.maintainers));
        }

        // Build
        builder
    }
}

/// Git Issue
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitIssue {
    /// The repository address
    pub repository: Coordinate,
    /// The issue content (markdown)
    pub content: String,
    /// Subject
    pub subject: Option<String>,
    /// Labels
    pub labels: Vec<String>,
}

impl IntoEventBuilder for GitIssue {
    /// Based on <https://github.com/nostr-protocol/nips/blob/ea36ec9ed7596e49bf7f217b05954c1fecacad88/34.md> revision.
    fn into_event_builder(self) -> EventBuilder {
        let owner_public_key: PublicKey = self.repository.public_key;

        let mut builder: EventBuilder = EventBuilder::new(Kind::GitIssue).content(self.content);

        builder.tags.reserve(2 + self.labels.len());

        // Add coordinate
        builder.tags.push(Nip01Tag::coordinate(self.repository));

        // Add owner public key
        builder.tags.push(Nip01Tag::public_key(owner_public_key));

        // Add subject
        if let Some(subject) = self.subject {
            builder.tags.push(Nip34Tag::Subject(subject));
        }

        // Add labels
        builder
            .tags
            .extend(self.labels.into_iter().map(Nip51Tag::Hashtag));

        builder
    }
}

/// Git Patch Committer
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitPatchCommitter {
    /// Name
    pub name: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Timestamp
    pub timestamp: Timestamp,
    /// Timezone offset in minutes
    pub offset_minutes: i32,
}

/// Git Patch Content
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GitPatchContent {
    /// Cover letter
    CoverLetter {
        /// Title
        title: String,
        /// Description
        description: String,
        /// Last commit
        last_commit: Sha1Hash,
        /// Number of commits
        commits_len: usize,
    },
    /// Patch
    Patch {
        /// Patch content
        content: String,
        /// Commit hash
        commit: Sha1Hash,
        /// Parent commit
        parent_commit: Sha1Hash,
        /// PGP signature of commit
        commit_pgp_sig: Option<String>,
        /// Committer
        committer: GitPatchCommitter,
    },
}

impl fmt::Display for GitPatchContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoverLetter {
                title,
                description,
                last_commit,
                commits_len,
            } => {
                write!(
                    f,
                    "From {last_commit} Mon Sep 17 00:00:00 2001\nSubject: [PATCH 0/{commits_len}] {title}\n\n{description}"
                )
            }
            Self::Patch { content, .. } => write!(f, "{content}"),
        }
    }
}

/// Git Patch
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitPatch {
    /// Repository ID
    pub repository: Coordinate,
    /// Patch
    pub content: GitPatchContent,
    /// Earliest unique commit ID of repo
    pub euc: Sha1Hash,
    /// Labels
    pub labels: Vec<String>,
}

impl IntoEventBuilder for GitPatch {
    fn into_event_builder(self) -> EventBuilder {
        let owner_public_key: PublicKey = self.repository.public_key;

        let content: String = self.content.to_string();
        let mut builder: EventBuilder = EventBuilder::new(Kind::GitPatch).content(content);

        builder.tags.reserve(3 + 5 + self.labels.len());

        // Push coordinate
        builder.tags.push(Nip01Tag::coordinate(self.repository));

        // Tag repo owner
        builder.tags.push(Nip01Tag::public_key(owner_public_key));

        // Add EUC (without `euc` marker)
        builder.tags.push(Nip34Tag::Reference(self.euc));

        // Handle patch content
        match self.content {
            GitPatchContent::CoverLetter { .. } => {
                // Add cover letter hashtag
                builder
                    .tags
                    .push(Nip51Tag::Hashtag(String::from("cover-letter")));
            }
            GitPatchContent::Patch {
                commit,
                parent_commit,
                commit_pgp_sig,
                committer,
                ..
            } => {
                builder.tags.push(Nip34Tag::Reference(commit));
                builder.tags.push(Nip34Tag::Commit(commit));
                builder.tags.push(Nip34Tag::ParentCommit(parent_commit));
                builder
                    .tags
                    .push(Nip34Tag::CommitPgpSig(commit_pgp_sig.unwrap_or_default()));
                builder.tags.push(Nip34Tag::Committer {
                    name: committer.name.unwrap_or_default(),
                    email: committer.email.unwrap_or_default(),
                    timestamp: committer.timestamp,
                    offset_minutes: committer.offset_minutes,
                });
            }
        }

        // Add labels
        builder
            .tags
            .extend(self.labels.into_iter().map(Nip51Tag::Hashtag));

        builder
    }
}

/// Git Pull Request
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitPullRequest {
    /// Repository coordinate
    pub repository: Coordinate,
    /// Pull request content (markdown)
    pub content: String,
    /// Subject
    pub subject: Option<String>,
    /// Labels
    pub labels: Vec<String>,
    /// Current commit ID (tip of the PR branch)
    pub current_commit: Sha1Hash,
    /// Git clone URLs where commit can be downloaded
    pub clone: Vec<Url>,
    /// Recommended branch name
    pub branch_name: Option<String>,
    /// Optional root patch event ID (indicates PR is a revision of an existing patch)
    pub root_patch_event: Option<EventId>,
    /// Merge base commit (the most recent common ancestor with the target branch)
    pub merge_base: Option<Sha1Hash>,
}

impl IntoEventBuilder for GitPullRequest {
    fn into_event_builder(self) -> EventBuilder {
        let owner_public_key: PublicKey = self.repository.public_key;

        let mut builder: EventBuilder =
            EventBuilder::new(Kind::GitPullRequest).content(self.content);

        builder.tags.reserve(2 + 6 + self.labels.len());

        // Add coordinate
        builder.tags.push(Nip01Tag::coordinate(self.repository));

        // Add repository owner public key
        builder.tags.push(Nip01Tag::public_key(owner_public_key));

        // Add subject
        if let Some(subject) = self.subject {
            builder.tags.push(Nip34Tag::Subject(subject));
        }

        // Add labels
        builder
            .tags
            .extend(self.labels.into_iter().map(Nip51Tag::Hashtag));

        // Add current commit
        builder
            .tags
            .push(Nip34Tag::CurrentCommit(self.current_commit));

        // Add clone URLs
        if !self.clone.is_empty() {
            builder.tags.push(Nip34Tag::Clone(self.clone));
        }

        // Add branch name
        if let Some(branch_name) = self.branch_name {
            builder.tags.push(Nip34Tag::BranchName(branch_name));
        }

        // Add root patch event (if this is a revision)
        if let Some(root_patch) = self.root_patch_event {
            builder.tags.push(Nip01Tag::event(root_patch));
        }

        // Add merge base
        if let Some(merge_base) = self.merge_base {
            builder.tags.push(Nip34Tag::MergeBase(merge_base));
        }

        builder
    }
}

/// Git Pull Request Update
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitPullRequestUpdate {
    /// Repository coordinate
    pub repository: Coordinate,
    /// The pull request event ID being updated
    pub pull_request_event: EventId,
    /// The pull request author
    pub pull_request_author: PublicKey,
    /// Updated current commit ID
    pub current_commit: Sha1Hash,
    /// Git clone URLs where commit can be downloaded
    pub clone: Vec<Url>,
    /// Merge base commit (the most recent common ancestor with the target branch)
    pub merge_base: Option<Sha1Hash>,
}

impl IntoEventBuilder for GitPullRequestUpdate {
    fn into_event_builder(self) -> EventBuilder {
        let owner_public_key: PublicKey = self.repository.public_key;

        let mut builder: EventBuilder = EventBuilder::new(Kind::GitPullRequestUpdate);

        builder.tags.reserve(7);

        // Add coordinate
        builder.tags.push(Nip01Tag::coordinate(self.repository));

        // Add repository owner public key
        builder.tags.push(Nip01Tag::public_key(owner_public_key));

        // Add NIP-22 builder.tags for the pull request being updated
        builder.tags.push(Nip22Tag::Event {
            id: self.pull_request_event,
            relay_hint: None,
            public_key: None,
            uppercase: true,
        });
        builder.tags.push(Nip22Tag::PublicKey {
            public_key: self.pull_request_author,
            relay_hint: None,
            uppercase: true,
        });

        // Add updated current commit
        builder
            .tags
            .push(Nip34Tag::CurrentCommit(self.current_commit));

        // Add clone URLs
        if !self.clone.is_empty() {
            builder.tags.push(Nip34Tag::Clone(self.clone));
        }

        // Add merge base
        if let Some(merge_base) = self.merge_base {
            builder.tags.push(Nip34Tag::MergeBase(merge_base));
        }

        builder
    }
}

/// Git User Grasp List
///
/// List of grasp servers the user generally wishes to use for NIP-34 related activity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitUserGraspList {
    /// Grasp service websocket URLs in order of preference
    pub grasp_servers: Vec<RelayUrl>,
}

impl IntoEventBuilder for GitUserGraspList {
    fn into_event_builder(self) -> EventBuilder {
        EventBuilder::new(Kind::GitUserGraspList)
            .tags(self.grasp_servers.into_iter().map(Nip34Tag::Grasp))
    }
}

#[cfg(all(test, feature = "std", feature = "os-rng"))]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::event::{Event, FinalizeEvent, Tags};
    use crate::key::Keys;

    #[test]
    fn test_git_repo_announcement() {
        let repo = GitRepositoryAnnouncement {
            id: String::from("test"),
            name: Some(String::from("Test nostr repository")),
            description: Some(String::from("Long desc")),
            web: Vec::new(),
            clone: vec![Url::parse("https://github.com/nostrdevkit/nostr.git").unwrap()],
            relays: vec![
                RelayUrl::parse("wss://example.com").unwrap(),
                RelayUrl::parse("wss://example.org").unwrap(),
            ],
            euc: Some(Sha1Hash::from_str("aa231c4c6a5777dc89b42207b499891a344add5c").unwrap()),
            maintainers: vec![
                PublicKey::parse("npub1drvpzev3syqt0kjrls50050uzf25gehpz9vgdw08hvex7e0vgfeq0eseet")
                    .unwrap(),
            ],
        };

        let keys = Keys::generate();
        let event: Event = repo.finalize(&keys).unwrap();

        assert_eq!(event.kind, Kind::GitRepoAnnouncement);
        assert!(event.content.is_empty());

        let tags = Tags::parse([
            vec!["d", "test"],
            vec!["name", "Test nostr repository"],
            vec!["description", "Long desc"],
            vec!["clone", "https://github.com/nostrdevkit/nostr.git"],
            vec!["relays", "wss://example.com", "wss://example.org"],
            vec!["r", "aa231c4c6a5777dc89b42207b499891a344add5c", "euc"],
            vec![
                "maintainers",
                "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
            ],
        ])
        .unwrap();
        assert_eq!(event.tags, tags);
    }

    #[test]
    fn test_standardized_git_head_tag() {
        let tag = vec![String::from("HEAD"), String::from("ref: refs/heads/main")];
        let parsed = Nip34Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip34Tag::Head(String::from("main")));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_standardized_applied_as_commits_tag() {
        let commit_1 = Sha1Hash::from_str("59429cfc6cb35b0a1ddace73b5a5c5ed57b8f5ca").unwrap();
        let commit_2 = Sha1Hash::from_str("b1fa697b5cd42fbb6ec9fef9009609200387e0b4").unwrap();
        let tag = vec![
            String::from("applied-as-commits"),
            commit_1.to_string(),
            commit_2.to_string(),
        ];
        let parsed = Nip34Tag::parse(&tag).unwrap();

        assert_eq!(parsed, Nip34Tag::AppliedAsCommits(vec![commit_1, commit_2]));
        assert_eq!(Tags::from_iter([parsed]), Tags::parse([tag]).unwrap());
    }

    #[test]
    fn test_git_issue() {
        let pk =
            PublicKey::parse("npub1drvpzev3syqt0kjrls50050uzf25gehpz9vgdw08hvex7e0vgfeq0eseet")
                .unwrap();
        let repository = Coordinate::new(Kind::GitRepoAnnouncement, pk).identifier("rust-nostr");

        let repo = GitIssue {
            repository,
            content: String::from("My issue content"),
            subject: Some(String::from("My issue subject")),
            labels: vec![String::from("bug")],
        };

        let keys = Keys::generate();
        let event: Event = repo.finalize(&keys).unwrap();

        assert_eq!(event.kind, Kind::GitIssue);
        assert_eq!(event.content, "My issue content");

        let tags = Tags::parse([
            vec![
                "a",
                "30617:68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272:rust-nostr",
            ],
            vec![
                "p",
                "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
            ],
            vec!["subject", "My issue subject"],
            vec!["t", "bug"],
        ])
        .unwrap();
        assert_eq!(event.tags, tags);
    }

    #[test]
    fn test_git_patch() {
        let pk =
            PublicKey::parse("npub1drvpzev3syqt0kjrls50050uzf25gehpz9vgdw08hvex7e0vgfeq0eseet")
                .unwrap();
        let repository = Coordinate::new(Kind::GitRepoAnnouncement, pk).identifier("rust-nostr");

        let repo = GitPatch {
            repository,
            content: GitPatchContent::Patch {
                content: String::from("<patch>"),
                commit: Sha1Hash::from_str("b1fa697b5cd42fbb6ec9fef9009609200387e0b4").unwrap(),
                parent_commit: Sha1Hash::from_str("c88d901b42ff8389330d6d5d4044cf1d196696f3")
                    .unwrap(),
                committer: GitPatchCommitter {
                    name: Some(String::from("Yuki Kishimoto")),
                    email: Some(String::from("yukikishimoto@protonmail.com")),
                    timestamp: Timestamp::from_secs(1739794763),
                    offset_minutes: 0,
                },
                commit_pgp_sig: None,
            },
            euc: Sha1Hash::from_str("59429cfc6cb35b0a1ddace73b5a5c5ed57b8f5ca").unwrap(),
            labels: vec![String::from("root")],
        };

        let keys = Keys::generate();
        let event: Event = repo.finalize(&keys).unwrap();

        assert_eq!(event.kind, Kind::GitPatch);
        assert_eq!(event.content, "<patch>");

        let tags = Tags::parse([
            vec![
                "a",
                "30617:68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272:rust-nostr",
            ],
            vec![
                "p",
                "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
            ],
            vec!["r", "59429cfc6cb35b0a1ddace73b5a5c5ed57b8f5ca"],
            vec!["r", "b1fa697b5cd42fbb6ec9fef9009609200387e0b4"],
            vec!["commit", "b1fa697b5cd42fbb6ec9fef9009609200387e0b4"],
            vec!["parent-commit", "c88d901b42ff8389330d6d5d4044cf1d196696f3"],
            vec!["commit-pgp-sig", ""],
            vec![
                "committer",
                "Yuki Kishimoto",
                "yukikishimoto@protonmail.com",
                "1739794763",
                "0",
            ],
            vec!["t", "root"],
        ])
        .unwrap();
        assert_eq!(event.tags, tags);
    }

    #[test]
    fn test_git_pull_request_update() {
        let pk =
            PublicKey::parse("npub1drvpzev3syqt0kjrls50050uzf25gehpz9vgdw08hvex7e0vgfeq0eseet")
                .unwrap();
        let repository = Coordinate::new(Kind::GitRepoAnnouncement, pk).identifier("rust-nostr");
        let pull_request_event =
            EventId::from_hex("70b09cb6f4f6b2b8c3d2b6f0bbf8f4f6ca1d9c1df4d5f85f0dbb2a7a9c7c4f21")
                .unwrap();
        let pull_request_author =
            PublicKey::from_hex("68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272")
                .unwrap();

        let update = GitPullRequestUpdate {
            repository,
            pull_request_event,
            pull_request_author,
            current_commit: Sha1Hash::from_str("b1fa697b5cd42fbb6ec9fef9009609200387e0b4").unwrap(),
            clone: vec![Url::parse("https://github.com/nostrdevkit/nostr.git").unwrap()],
            merge_base: Some(
                Sha1Hash::from_str("c88d901b42ff8389330d6d5d4044cf1d196696f3").unwrap(),
            ),
        };

        let keys = Keys::generate();
        let event: Event = update.finalize(&keys).unwrap();

        assert_eq!(event.kind, Kind::GitPullRequestUpdate);
        assert!(event.content.is_empty());

        let tags = Tags::parse([
            vec![
                "a",
                "30617:68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272:rust-nostr",
            ],
            vec![
                "p",
                "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
            ],
            vec![
                "E",
                "70b09cb6f4f6b2b8c3d2b6f0bbf8f4f6ca1d9c1df4d5f85f0dbb2a7a9c7c4f21",
            ],
            vec![
                "P",
                "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
            ],
            vec!["c", "b1fa697b5cd42fbb6ec9fef9009609200387e0b4"],
            vec!["clone", "https://github.com/nostrdevkit/nostr.git"],
            vec!["merge-base", "c88d901b42ff8389330d6d5d4044cf1d196696f3"],
        ])
        .unwrap();
        assert_eq!(event.tags, tags);
    }
}
