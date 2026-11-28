//! Client helpers for BUD-03 user server lists.

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use nostr::event::Event;
use nostr::types::Url;

/// Returns the ordered server URLs in a kind `10063` server-list event.
pub fn server_urls(event: &Event) -> Vec<Url> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            (tag.kind() == "server")
                .then(|| tag.content())
                .flatten()
                .and_then(|url| Url::parse(url).ok())
        })
        .collect()
}

/// Extracts the last 64-character hexadecimal SHA256 occurrence from a URL.
pub fn extract_sha256(url: &str) -> Option<Sha256Hash> {
    url.as_bytes()
        .windows(64)
        .rposition(|window| window.iter().all(u8::is_ascii_hexdigit))
        .and_then(|position| url.get(position..position + 64))
        .and_then(|hash| hash.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_last_hash_from_non_blossom_url() {
        let first = "ec4425ff5e9446080d2f70440188e3ca5d6da8713db7bdeef73d0ed54d9093f0";
        let last = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
        let url = format!("https://cdn.example/{first}/media/{last}.pdf");

        assert_eq!(extract_sha256(&url).unwrap().to_string(), last);
    }
}
