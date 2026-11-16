// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP-C0: Code Snippets
//!
//! <https://github.com/nostr-protocol/nips/blob/master/C0.md>

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::util::{missing_tag_kind, take_string, unknown_tag};
use crate::event::{EventBuilder, IntoEventBuilder, Kind, Tag, impl_tag_codec_conversions};

const LANGUAGE: &str = "l";
const NAME: &str = "name";
const EXTENSION: &str = "extension";
const DESCRIPTION: &str = "description";
const RUNTIME: &str = "runtime";
const LICENSE: &str = "license";
const DEPENDENCY: &str = "dep";
const REPOSITORY: &str = "repo";

/// Standardized NIP-C0 tags
///
/// <https://github.com/nostr-protocol/nips/blob/master/C0.md>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NipC0Tag {
    /// `l` tag used as programming language
    Language(String),
    /// `name` tag
    Name(String),
    /// `extension` tag
    Extension(String),
    /// `description` tag
    Description(String),
    /// `runtime` tag
    Runtime(String),
    /// `license` tag
    License(String),
    /// `dep` tag
    Dependency(String),
    /// `repo` tag
    Repository(String),
}

impl_tag_codec_conversions! {
    NipC0Tag,
    fn parse(tag) {
        let mut iter = tag.into_iter();

        let kind: S = iter.next().ok_or(missing_tag_kind())?;

        match kind.as_ref() {
            LANGUAGE => Ok(Self::Language(
                take_string(&mut iter, "language")?.to_lowercase(),
            )),
            NAME => Ok(Self::Name(take_string(&mut iter, "name")?)),
            EXTENSION => Ok(Self::Extension(take_string(&mut iter, "extension")?)),
            DESCRIPTION => Ok(Self::Description(take_string(&mut iter, "description")?)),
            RUNTIME => Ok(Self::Runtime(take_string(&mut iter, "runtime")?)),
            LICENSE => Ok(Self::License(take_string(&mut iter, "license")?)),
            DEPENDENCY => Ok(Self::Dependency(take_string(&mut iter, "dependency")?)),
            REPOSITORY => Ok(Self::Repository(take_string(&mut iter, "repository")?)),
            _ => Err(unknown_tag()),
        }
    }

    fn to_tag(&self) {
        match self {
            Self::Language(language) => {
                Tag::new(vec![String::from(LANGUAGE), language.to_lowercase()])
            }
            Self::Name(name) => Tag::new(vec![String::from(NAME), name.clone()]),
            Self::Extension(extension) => {
                Tag::new(vec![String::from(EXTENSION), extension.clone()])
            }
            Self::Description(description) => {
                Tag::new(vec![String::from(DESCRIPTION), description.clone()])
            }
            Self::Runtime(runtime) => Tag::new(vec![String::from(RUNTIME), runtime.clone()]),
            Self::License(license) => Tag::new(vec![String::from(LICENSE), license.clone()]),
            Self::Dependency(dependency) => {
                Tag::new(vec![String::from(DEPENDENCY), dependency.clone()])
            }
            Self::Repository(repository) => {
                Tag::new(vec![String::from(REPOSITORY), repository.clone()])
            }
        }
    }
}

/// Code snippet
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeSnippet {
    /// The code snippet.
    pub snippet: String,
    /// Programming language name.
    /// Examples: "javascript", "python", "rust"
    pub language: Option<String>,
    /// Name of the code snippet, commonly a filename.
    /// Examples: "hello-world.js", "quick-sort.py"
    pub name: Option<String>,
    /// File extension (without the dot).
    /// Examples: "js", "py", "rs"
    pub extension: Option<String>,
    /// Brief description of what the code does
    pub description: Option<String>,
    /// Runtime or environment specification.
    /// Example: "node v18.15.0", "python 3.11"
    pub runtime: Option<String>,
    /// License under which the code is shared.
    /// Example: "MIT", "GPL-3.0", "Apache-2.0"
    pub license: Option<String>,
    /// Dependencies required for the code to run.
    pub dependencies: Vec<String>,
    /// Reference to a repository where this code originates.
    pub repo: Option<String>,
}

impl CodeSnippet {
    /// Create a new code snippet
    #[inline]
    pub fn new<T>(snippet: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            snippet: snippet.into(),
            ..Default::default()
        }
    }

    /// Set the programming language name (e.g. "javascript", "python", "rust").
    #[inline]
    pub fn language<T>(mut self, lang: T) -> Self
    where
        T: AsRef<str>,
    {
        self.language = Some(lang.as_ref().to_lowercase());
        self
    }

    /// Set the name of the code snippet, commonly a filename.
    #[inline]
    pub fn name<T>(mut self, name: T) -> Self
    where
        T: Into<String>,
    {
        self.name = Some(name.into());
        self
    }

    /// Set the file extension (without the dot).
    #[inline]
    pub fn extension<T>(mut self, extension: T) -> Self
    where
        T: Into<String>,
    {
        self.extension = Some(extension.into());
        self
    }

    /// Set a brief description of what the code does
    #[inline]
    pub fn description<T>(mut self, description: T) -> Self
    where
        T: Into<String>,
    {
        self.description = Some(description.into());
        self
    }

    /// Set the runtime or environment specification (e.g. "node v18.15.0", "python 3.11").
    #[inline]
    pub fn runtime<T>(mut self, runtime: T) -> Self
    where
        T: Into<String>,
    {
        self.runtime = Some(runtime.into());
        self
    }

    /// Set the license under which the code is shared (e.g. "MIT", "GPL-3.0", "Apache-2.0").
    #[inline]
    pub fn license<T>(mut self, license: T) -> Self
    where
        T: Into<String>,
    {
        self.license = Some(license.into());
        self
    }

    /// Add a dependency required for the code to run.
    pub fn dependencies<T>(mut self, dep: T) -> Self
    where
        T: Into<String>,
    {
        let dep = dep.into();
        if !self.dependencies.contains(&dep) {
            self.dependencies.push(dep);
        }
        self
    }

    /// Set the repository where this code originates.
    #[inline]
    pub fn repo<T>(mut self, repo: T) -> Self
    where
        T: Into<String>,
    {
        self.repo = Some(repo.into());
        self
    }
}

impl IntoEventBuilder for CodeSnippet {
    fn into_event_builder(self) -> EventBuilder {
        let mut tags: Vec<Tag> = Vec::new();

        let mut add_if_some = |tag: Option<NipC0Tag>| {
            if let Some(tag) = tag {
                tags.push(tag.into());
            }
        };

        add_if_some(self.language.map(NipC0Tag::Language));
        add_if_some(self.name.map(NipC0Tag::Name));
        add_if_some(self.extension.map(NipC0Tag::Extension));
        add_if_some(self.description.map(NipC0Tag::Description));
        add_if_some(self.runtime.map(NipC0Tag::Runtime));
        add_if_some(self.license.map(NipC0Tag::License));
        add_if_some(self.repo.map(NipC0Tag::Repository));

        for dep in self.dependencies.into_iter() {
            tags.push(NipC0Tag::Dependency(dep).into());
        }

        EventBuilder::new(Kind::CodeSnippet)
            .content(self.snippet)
            .tags(tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_language_tag() {
        let tag = vec!["l", "Rust"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipC0Tag::Language(String::from("rust")));
        assert_eq!(parsed.to_tag(), Tag::parse(vec!["l", "rust"]).unwrap());
    }

    #[test]
    fn test_parse_name_tag() {
        let tag = vec!["name", "hello-world.rs"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipC0Tag::Name(String::from("hello-world.rs")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_extension_tag() {
        let tag = vec!["extension", "rs"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipC0Tag::Extension(String::from("rs")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_description_tag() {
        let tag = vec!["description", "Prints Hello, Nostr!"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            NipC0Tag::Description(String::from("Prints Hello, Nostr!"))
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_runtime_tag() {
        let tag = vec!["runtime", "rustc 1.70.0"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipC0Tag::Runtime(String::from("rustc 1.70.0")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_license_tag() {
        let tag = vec!["license", "MIT"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipC0Tag::License(String::from("MIT")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_dependency_tag() {
        let tag = vec!["dep", "serde"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(parsed, NipC0Tag::Dependency(String::from("serde")));
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }

    #[test]
    fn test_parse_repository_tag() {
        let tag = vec!["repo", "https://github.com/nostr-protocol/nostr"];
        let parsed = NipC0Tag::parse(&tag).unwrap();
        assert_eq!(
            parsed,
            NipC0Tag::Repository(String::from("https://github.com/nostr-protocol/nostr"))
        );
        assert_eq!(parsed.to_tag(), Tag::parse(tag).unwrap());
    }
}
