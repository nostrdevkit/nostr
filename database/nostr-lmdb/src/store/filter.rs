// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::collections::{BTreeMap, BTreeSet, HashSet};

use nostr::filter::{Filter, SingleLetterTag};
use nostr::types::Timestamp;

use super::event::DatabaseEvent;

const TITLE: &str = "title";
const DESCRIPTION: &str = "description";
const SUBJECT: &str = "subject";
const NAME: &str = "name";

pub(crate) struct DatabaseFilter {
    pub(crate) ids: HashSet<[u8; 32]>,
    pub(crate) authors: HashSet<[u8; 32]>,
    pub(crate) kinds: HashSet<u16>,
    // THIS IS LOWERCASE
    pub(crate) search: Option<String>,
    pub(crate) since: Option<Timestamp>,
    pub(crate) until: Option<Timestamp>,
    pub(crate) generic_tags: BTreeMap<SingleLetterTag, BTreeSet<String>>,
}

impl DatabaseFilter {
    #[inline]
    fn ids_match(&self, event: &DatabaseEvent) -> bool {
        self.ids.is_empty() || self.ids.contains(event.id)
    }

    #[inline]
    fn authors_match(&self, event: &DatabaseEvent) -> bool {
        self.authors.is_empty() || self.authors.contains(event.pubkey)
    }

    #[inline]
    fn tag_match(&self, event: &DatabaseEvent) -> bool {
        if self.generic_tags.is_empty() {
            return true;
        }

        if event.tags.is_empty() {
            return false;
        }

        let mut missing: usize = self.generic_tags.len();
        let mut done: u64 = 0;

        for t in event.tags.iter() {
            let Some((letter, val)) = t.extract() else {
                continue;
            };

            let bit: u32 = letter_bit(letter);

            // If already done, immediately skip, avoiding the BTreeSet lookup
            if done & (1u64 << bit) != 0 {
                continue;
            }

            let Some(set) = self.generic_tags.get(&letter) else {
                continue;
            };

            if set.contains(val) {
                done |= 1u64 << bit;

                missing -= 1;

                if missing == 0 {
                    return true;
                }
            }
        }

        missing == 0
    }

    #[inline]
    fn kind_match(&self, event: &DatabaseEvent) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&event.kind)
    }

    #[inline]
    fn search_match(&self, event: &DatabaseEvent) -> bool {
        match &self.search {
            Some(query) => {
                // NOTE: `query` was already converted to lowercase
                let query: &[u8] = query.as_bytes();

                // Match content - early return on match
                if match_content(query, event.content.as_bytes()) {
                    return true;
                }

                // Match tags - only if content didn't match
                for (kind, content) in event
                    .tags
                    .iter()
                    .filter_map(|t| Some((t.kind(), t.content()?)))
                {
                    if is_allowed_tag_kind(kind) && match_content(query, content.as_bytes()) {
                        return true;
                    }
                }

                false
            }
            None => true,
        }
    }

    #[inline]
    pub(crate) fn match_event(&self, event: &DatabaseEvent) -> bool {
        self.ids_match(event)
            && self.authors_match(event)
            && self.kind_match(event)
            && self.since.is_none_or(|t| event.created_at >= t)
            && self.until.is_none_or(|t| event.created_at <= t)
            && self.tag_match(event)
            && self.search_match(event)
    }
}

/// 'a'..'z' -> 0..25, 'A'..'Z' -> 26..51
#[inline]
fn letter_bit(letter: SingleLetterTag) -> u32 {
    let c: char = letter.as_char();
    let base: u32 = (c.to_ascii_lowercase() as u32) - ('a' as u32);
    if c.is_ascii_lowercase() {
        base
    } else {
        base + 26
    }
}

#[inline]
fn match_content(query: &[u8], content: &[u8]) -> bool {
    // Early exit if query is empty
    if query.is_empty() {
        return false;
    }

    // Early exit for impossible matches
    if query.len() > content.len() {
        return false;
    }

    // Fast path for single-byte searches (common case)
    if query.len() == 1 {
        let query_byte = query[0];
        return content
            .iter()
            .any(|&b| b.to_ascii_lowercase() == query_byte);
    }

    content
        .windows(query.len())
        .any(|window| window.eq_ignore_ascii_case(query))
}

#[inline]
fn is_allowed_tag_kind(kind: &str) -> bool {
    matches!(kind, TITLE | DESCRIPTION | SUBJECT | NAME)
}

impl From<Filter> for DatabaseFilter {
    fn from(filter: Filter) -> Self {
        Self {
            ids: filter
                .ids
                .map(|ids| ids.into_iter().map(|id| id.to_bytes()).collect())
                .unwrap_or_default(),
            authors: filter
                .authors
                .map(|authors| {
                    authors
                        .into_iter()
                        .map(|pubkey| pubkey.to_bytes())
                        .collect()
                })
                .unwrap_or_default(),
            kinds: filter
                .kinds
                .map(|kinds| kinds.into_iter().map(|id| id.as_u16()).collect())
                .unwrap_or_default(),
            search: filter.search.map(|mut s| {
                // Convert to lowercase
                s.make_ascii_lowercase();
                s
            }),
            since: filter.since,
            until: filter.until,
            generic_tags: filter.generic_tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use nostr::prelude::*;

    use super::*;

    fn create_test_event(content: &str) -> Event {
        let keys = Keys::generate();
        EventBuilder::new(Kind::TextNote)
            .content(content)
            .finalize(&keys)
            .unwrap()
    }

    #[test]
    fn test_search_match_in_content() {
        let event = create_test_event("Hello World");
        let event: DatabaseEvent = (&event).into();

        let mut filter = DatabaseFilter::from(Filter::new());

        // Case insensitive match
        filter.search = Some("hello".to_string());
        assert!(filter.match_event(&event));

        filter.search = Some("world".to_string());
        assert!(filter.match_event(&event));

        // No match
        filter.search = Some("rust".to_string());
        assert!(!filter.match_event(&event));
    }

    #[test]
    fn test_search_match_in_tags() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote)
            .content("content")
            .tag(["title", "Search userfacing tags"])
            .finalize(&keys)
            .unwrap();
        let event: DatabaseEvent = (&event).into();

        let mut filter = DatabaseFilter::from(Filter::new());

        filter.search = Some("userfacing".to_string());
        assert!(filter.match_event(&event));

        filter.search = Some("bitcoin".to_string());
        assert!(!filter.match_event(&event));
    }

    #[test]
    fn test_search_empty_query() {
        let event = create_test_event("test");
        let event: DatabaseEvent = (&event).into();
        let mut filter = DatabaseFilter::from(Filter::new());

        filter.search = Some("".to_string());
        assert!(!filter.match_event(&event));
    }

    #[test]
    fn test_search_no_query() {
        let event = create_test_event("test");
        let event: DatabaseEvent = (&event).into();
        let filter = DatabaseFilter::from(Filter::new());

        assert!(filter.match_event(&event));
    }

    #[test]
    fn test_search_partial_match() {
        let event = create_test_event("nostr protocol");
        let event: DatabaseEvent = (&event).into();
        let mut filter = DatabaseFilter::from(Filter::new());

        filter.search = Some("proto".to_string());
        assert!(filter.match_event(&event));
    }
}
