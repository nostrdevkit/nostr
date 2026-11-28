//! Implements data structures specific to BUD-02

use bitcoin_hashes::sha256::Hash as Sha256Hash;
use nostr::event::Tags;
use nostr::types::{Timestamp, Url};
use serde::{Deserialize, Serialize};

/// A descriptor for the blob
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobDescriptor {
    /// The URL at which the blob/file can be accessed
    pub url: Url,
    /// The SHA256 hash of the contents in the blob
    pub sha256: Sha256Hash,
    /// The size of the blob/file, in bytes
    pub size: u64,
    #[serde(rename = "type")]
    /// Mime type of the blob/file
    pub mime_type: String,
    /// The date at which the blob was uploaded, as a UNIX timestamp (in seconds)
    pub uploaded: Timestamp,
    /// Optional NIP-94 file metadata tags returned according to BUD-08.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip94: Option<Tags>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_large_descriptor_with_nip94_tags() {
        let descriptor: BlobDescriptor = serde_json::from_str(
            r#"{
                "url":"https://cdn.example.com/b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553.bin",
                "sha256":"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553",
                "size":4294967296,
                "type":"application/octet-stream",
                "uploaded":1725909682,
                "nip94":[["m","application/octet-stream"]]
            }"#,
        )
        .unwrap();

        assert_eq!(descriptor.size, u64::from(u32::MAX) + 1);
        assert_eq!(descriptor.mime_type, "application/octet-stream");
        assert_eq!(descriptor.nip94.unwrap().len(), 1);
    }

    #[test]
    fn rejects_descriptor_without_required_mime_type() {
        let result = serde_json::from_str::<BlobDescriptor>(
            r#"{
                "url":"https://cdn.example.com/b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553.bin",
                "sha256":"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553",
                "size":1,
                "uploaded":1725909682
            }"#,
        );

        assert!(result.is_err());
    }
}
