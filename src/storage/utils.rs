//! UHRP (Universal Hash Resolution Protocol) URL utilities.
//!
//! UHRP URLs are content-addressed identifiers for files stored on the overlay network.
//! They encode a SHA-256 hash using Base58Check format with a specific prefix.
//!
//! # URL Format
//!
//! ```text
//! uhrp://<base58check_encoded_hash>
//! ```
//!
//! Where the Base58Check encoding uses:
//! - Prefix: `0xce00` (2 bytes)
//! - Payload: SHA-256 hash (32 bytes)
//! - Checksum: First 4 bytes of SHA256(SHA256(prefix || payload))

use crate::primitives::hash::{sha256, sha256d};
use crate::primitives::{from_base58, to_base58};
use crate::Result;
use crate::Error;

/// UHRP URL prefix.
pub const UHRP_PREFIX: &str = "uhrp://";

/// Web+UHRP URL prefix (alternative format).
pub const WEB_UHRP_PREFIX: &str = "web+uhrp://";

/// Base58Check version prefix for UHRP URLs (0xce, 0x00).
const UHRP_VERSION_PREFIX: [u8; 2] = [0xce, 0x00];

/// Minimum hash length in bytes (SHA-256).
const MIN_HASH_LENGTH: usize = 32;

/// Normalize a UHRP URL by removing any prefix.
///
/// Handles both `uhrp://` and `web+uhrp://` prefixes.
///
/// # Arguments
///
/// * `url` - The UHRP URL to normalize
///
/// # Returns
///
/// The URL with prefix removed (Base58Check encoded hash).
///
/// # Example
///
/// ```rust
/// use bsv_sdk::storage::normalize_url;
///
/// let normalized = normalize_url("uhrp://5P3xLaNMFwAQGpDxgwvkGDHCw8o8rvbFQ9c2W1wMxwNHX1hm");
/// assert!(!normalized.starts_with("uhrp://"));
/// ```
pub fn normalize_url(url: &str) -> String {
    let lower = url.to_lowercase();
    if lower.starts_with(WEB_UHRP_PREFIX) {
        url[WEB_UHRP_PREFIX.len()..].to_string()
    } else if lower.starts_with(UHRP_PREFIX) {
        url[UHRP_PREFIX.len()..].to_string()
    } else if lower.starts_with("uhrp:") {
        // Handle "uhrp:" without double slashes
        let rest = &url[5..];
        if let Some(stripped) = rest.strip_prefix("//") {
            stripped.to_string()
        } else {
            rest.to_string()
        }
    } else {
        url.to_string()
    }
}

/// Generate a UHRP URL from a SHA-256 hash.
///
/// Uses Base58Check encoding with the UHRP version prefix (`0xce00`).
///
/// # Arguments
///
/// * `hash` - 32-byte SHA-256 hash
///
/// # Returns
///
/// The UHRP URL string.
///
/// # Errors
///
/// Returns an error if the hash is not exactly 32 bytes.
///
/// # Example
///
/// ```rust
/// use bsv_sdk::storage::get_url_for_hash;
/// use bsv_sdk::primitives::hash::sha256;
///
/// let hash = sha256(b"hello world");
/// let url = get_url_for_hash(&hash).unwrap();
/// assert!(url.starts_with("uhrp://"));
/// ```
pub fn get_url_for_hash(hash: &[u8]) -> Result<String> {
    if hash.len() != MIN_HASH_LENGTH {
        return Err(Error::InvalidDataLength {
            expected: MIN_HASH_LENGTH,
            actual: hash.len(),
        });
    }

    // Build payload: version prefix + hash
    let mut payload = Vec::with_capacity(2 + 32 + 4);
    payload.extend_from_slice(&UHRP_VERSION_PREFIX);
    payload.extend_from_slice(hash);

    // Calculate checksum: first 4 bytes of double SHA-256
    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..4]);

    // Encode with Base58
    let encoded = to_base58(&payload);
    Ok(format!("{}{}", UHRP_PREFIX, encoded))
}

/// Generate a UHRP URL for file content.
///
/// Computes the SHA-256 hash of the file and generates the URL.
///
/// # Arguments
///
/// * `data` - File content as bytes
///
/// # Returns
///
/// The UHRP URL string.
///
/// # Example
///
/// ```rust
/// use bsv_sdk::storage::get_url_for_file;
///
/// let url = get_url_for_file(b"hello world").unwrap();
/// assert!(url.starts_with("uhrp://"));
/// ```
pub fn get_url_for_file(data: &[u8]) -> Result<String> {
    let hash = sha256(data);
    get_url_for_hash(&hash)
}

/// Extract the SHA-256 hash from a UHRP URL.
///
/// Decodes the Base58Check encoded URL and validates the checksum.
///
/// # Arguments
///
/// * `url` - The UHRP URL to parse
///
/// # Returns
///
/// The 32-byte SHA-256 hash.
///
/// # Errors
///
/// Returns an error if:
/// - The URL is not valid Base58
/// - The decoded data is too short
/// - The version prefix is incorrect
/// - The checksum is invalid
///
/// # Example
///
/// ```rust
/// use bsv_sdk::storage::{get_url_for_file, get_hash_from_url};
///
/// let url = get_url_for_file(b"hello world").unwrap();
/// let hash = get_hash_from_url(&url).unwrap();
/// assert_eq!(hash.len(), 32);
/// ```
pub fn get_hash_from_url(url: &str) -> Result<[u8; 32]> {
    let normalized = normalize_url(url);

    // Decode Base58
    let decoded = from_base58(&normalized)?;

    // Minimum length: 2 (prefix) + 32 (hash) + 4 (checksum) = 38 bytes
    if decoded.len() < 38 {
        return Err(Error::InvalidDataLength {
            expected: 38,
            actual: decoded.len(),
        });
    }

    // Extract components
    let prefix = &decoded[..2];
    let hash = &decoded[2..34];
    let checksum = &decoded[34..38];

    // Verify prefix
    if prefix != UHRP_VERSION_PREFIX {
        return Err(Error::InvalidBase58(format!(
            "Bad prefix: expected {:02x}{:02x}, got {:02x}{:02x}",
            UHRP_VERSION_PREFIX[0], UHRP_VERSION_PREFIX[1],
            prefix[0], prefix[1]
        )));
    }

    // Verify checksum
    let data_for_checksum = &decoded[..34]; // prefix + hash
    let expected_checksum = sha256d(data_for_checksum);
    if checksum != &expected_checksum[..4] {
        return Err(Error::InvalidChecksum);
    }

    // Extract hash
    let mut result = [0u8; 32];
    result.copy_from_slice(hash);
    Ok(result)
}

/// Check if a URL is a valid UHRP URL.
///
/// Validates the format, prefix, and checksum.
///
/// # Arguments
///
/// * `url` - The URL to validate
///
/// # Returns
///
/// `true` if the URL is a valid UHRP URL, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use bsv_sdk::storage::{is_valid_url, get_url_for_file};
///
/// let url = get_url_for_file(b"hello").unwrap();
/// assert!(is_valid_url(&url));
/// assert!(!is_valid_url("https://example.com"));
/// ```
pub fn is_valid_url(url: &str) -> bool {
    get_hash_from_url(url).is_ok()
}

/// Get the hash as a hex string from a UHRP URL.
///
/// Convenience function for getting the hash in hex format.
///
/// # Arguments
///
/// * `url` - The UHRP URL to parse
///
/// # Returns
///
/// The SHA-256 hash as a hex string.
///
/// # Example
///
/// ```rust
/// use bsv_sdk::storage::{get_url_for_file, get_hash_hex_from_url};
///
/// let url = get_url_for_file(b"hello").unwrap();
/// let hash_hex = get_hash_hex_from_url(&url).unwrap();
/// assert_eq!(hash_hex.len(), 64); // 32 bytes * 2 hex chars
/// ```
pub fn get_hash_hex_from_url(url: &str) -> Result<String> {
    let hash = get_hash_from_url(url)?;
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::sha256;

    #[test]
    fn test_normalize_url_with_uhrp_prefix() {
        let url = "uhrp://abc123";
        assert_eq!(normalize_url(url), "abc123");
    }

    #[test]
    fn test_normalize_url_with_web_prefix() {
        let url = "web+uhrp://abc123";
        assert_eq!(normalize_url(url), "abc123");
    }

    #[test]
    fn test_normalize_url_without_prefix() {
        let url = "abc123";
        assert_eq!(normalize_url(url), "abc123");
    }

    #[test]
    fn test_normalize_url_case_insensitive() {
        let url = "UHRP://ABC123";
        assert_eq!(normalize_url(url), "ABC123");
    }

    #[test]
    fn test_get_url_for_hash_valid() {
        let hash = sha256(b"hello world");
        let url = get_url_for_hash(&hash).unwrap();
        assert!(url.starts_with(UHRP_PREFIX));
    }

    #[test]
    fn test_get_url_for_hash_invalid_length() {
        let short_hash = vec![0u8; 16];
        let result = get_url_for_hash(&short_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_url_for_file() {
        let data = b"hello world";
        let url = get_url_for_file(data).unwrap();
        assert!(url.starts_with(UHRP_PREFIX));

        // Verify the hash matches
        let hash = get_hash_from_url(&url).unwrap();
        assert_eq!(hash, sha256(data));
    }

    #[test]
    fn test_get_url_for_empty_file() {
        let data = b"";
        let url = get_url_for_file(data).unwrap();
        assert!(url.starts_with(UHRP_PREFIX));

        // SHA-256 of empty string
        let hash = get_hash_from_url(&url).unwrap();
        let expected = sha256(b"");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_roundtrip() {
        let data = b"test file content";
        let url = get_url_for_file(data).unwrap();
        let hash = get_hash_from_url(&url).unwrap();
        assert_eq!(hash, sha256(data));
    }

    #[test]
    fn test_get_hash_from_url_invalid_prefix() {
        // Create a URL with wrong prefix
        let hash = sha256(b"test");
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00]); // Wrong prefix
        payload.extend_from_slice(&hash);
        let checksum = sha256d(&payload);
        payload.extend_from_slice(&checksum[..4]);
        let encoded = to_base58(&payload);
        let url = format!("{}{}", UHRP_PREFIX, encoded);

        let result = get_hash_from_url(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_hash_from_url_invalid_checksum() {
        // Create a URL with wrong checksum
        let hash = sha256(b"test");
        let mut payload = Vec::new();
        payload.extend_from_slice(&UHRP_VERSION_PREFIX);
        payload.extend_from_slice(&hash);
        payload.extend_from_slice(&[0, 0, 0, 0]); // Wrong checksum
        let encoded = to_base58(&payload);
        let url = format!("{}{}", UHRP_PREFIX, encoded);

        let result = get_hash_from_url(&url);
        assert!(matches!(result, Err(Error::InvalidChecksum)));
    }

    #[test]
    fn test_get_hash_from_url_too_short() {
        let url = "uhrp://short";
        let result = get_hash_from_url(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_url() {
        let valid_url = get_url_for_file(b"test").unwrap();
        assert!(is_valid_url(&valid_url));

        assert!(!is_valid_url("https://example.com"));
        assert!(!is_valid_url("uhrp://tooshort"));
        assert!(!is_valid_url("invalid"));
    }

    #[test]
    fn test_get_hash_hex_from_url() {
        let data = b"hello";
        let url = get_url_for_file(data).unwrap();
        let hash_hex = get_hash_hex_from_url(&url).unwrap();

        assert_eq!(hash_hex.len(), 64);
        assert_eq!(hash_hex, hex::encode(sha256(data)));
    }

    #[test]
    fn test_cross_sdk_compatibility() {
        // Test that our implementation produces the same URLs as TypeScript/Go SDKs
        // This verifies the Base58Check encoding with prefix 0xce00

        // Empty string has a known SHA-256 hash
        let empty_hash = sha256(b"");
        assert_eq!(
            hex::encode(empty_hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Generate URL and verify it can be round-tripped
        let url = get_url_for_hash(&empty_hash).unwrap();
        let recovered = get_hash_from_url(&url).unwrap();
        assert_eq!(recovered, empty_hash);
    }

    #[test]
    fn test_url_with_web_prefix_roundtrip() {
        let data = b"test";
        let url = get_url_for_file(data).unwrap();

        // Replace uhrp:// with web+uhrp://
        let web_url = url.replace("uhrp://", "web+uhrp://");

        // Should still be parseable
        let hash = get_hash_from_url(&web_url).unwrap();
        assert_eq!(hash, sha256(data));
    }

    // =========================================================================
    // Cross-SDK compatibility tests with known test vectors from TypeScript SDK
    // =========================================================================

    /// TypeScript SDK test vector - known hash
    const TS_EXAMPLE_HASH_HEX: &str = "1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca";
    /// TypeScript SDK test vector - known file content
    const TS_EXAMPLE_FILE_HEX: &str = "687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db";
    /// TypeScript SDK test vector - expected URL (without uhrp:// prefix)
    const TS_EXAMPLE_URL_BASE58: &str = "XUT6PqWb3GP3LR7dmBMCJwZ3oo5g1iGCF3CrpzyuJCemkGu1WGoq";

    #[test]
    fn test_cross_sdk_vector_hash_to_url() {
        // Verify: getURLForHash(exampleHash) produces the expected URL
        let hash = hex::decode(TS_EXAMPLE_HASH_HEX).unwrap();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);

        let url = get_url_for_hash(&hash_array).unwrap();

        // Our URL has uhrp:// prefix, TypeScript doesn't include it
        // Normalize to compare just the Base58Check part
        let normalized = normalize_url(&url);
        assert_eq!(normalized, TS_EXAMPLE_URL_BASE58);
    }

    #[test]
    fn test_cross_sdk_vector_file_to_url() {
        // Verify: getURLForFile(exampleFile) produces the expected URL
        // This also verifies that SHA256(exampleFile) == exampleHash
        let file = hex::decode(TS_EXAMPLE_FILE_HEX).unwrap();

        let url = get_url_for_file(&file).unwrap();
        let normalized = normalize_url(&url);
        assert_eq!(normalized, TS_EXAMPLE_URL_BASE58);
    }

    #[test]
    fn test_cross_sdk_vector_url_to_hash() {
        // Verify: getHashFromURL(exampleURL) returns the expected hash
        // Test with just the Base58Check string (TypeScript format)
        let hash = get_hash_from_url(TS_EXAMPLE_URL_BASE58).unwrap();
        assert_eq!(hex::encode(hash), TS_EXAMPLE_HASH_HEX);

        // Test with uhrp:// prefix (Go format)
        let url_with_prefix = format!("uhrp://{}", TS_EXAMPLE_URL_BASE58);
        let hash2 = get_hash_from_url(&url_with_prefix).unwrap();
        assert_eq!(hex::encode(hash2), TS_EXAMPLE_HASH_HEX);
    }

    #[test]
    fn test_cross_sdk_vector_file_hash_matches() {
        // Verify: SHA256(exampleFile) == exampleHash
        let file = hex::decode(TS_EXAMPLE_FILE_HEX).unwrap();
        let computed_hash = sha256(&file);
        assert_eq!(hex::encode(computed_hash), TS_EXAMPLE_HASH_HEX);
    }

    #[test]
    fn test_cross_sdk_vector_is_valid() {
        // Verify: isValidURL returns true for valid URLs
        assert!(is_valid_url(TS_EXAMPLE_URL_BASE58));
        assert!(is_valid_url(&format!("uhrp://{}", TS_EXAMPLE_URL_BASE58)));
        assert!(is_valid_url(&format!("web+uhrp://{}", TS_EXAMPLE_URL_BASE58)));

        // Known bad URL from TypeScript tests (invalid checksum)
        let bad_url = "XUU7cTfy6fA6q2neLDmzPqJnGB6o18PXKoGaWLPrH1SeWLKgdCKq";
        assert!(!is_valid_url(bad_url));
    }
}
