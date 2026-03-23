//! BIP-276 script encoding for typed bitcoin-related data.
//!
//! BIP-276 proposes a scheme for encoding typed bitcoin related data in a user-friendly way.
//! See <https://github.com/moneybutton/bips/blob/master/bip-0276.mediawiki>
//!
//! # Format
//!
//! ```text
//! bitcoin-script:<network_hex><script_type_hex><script_hex><checksum_hex>
//! ```
//!
//! Where:
//! - `bitcoin-script` is the fixed prefix
//! - `network_hex` is the network byte as 2-char lowercase hex (e.g., `01` for mainnet)
//! - `script_type_hex` is the script type byte as 2-char lowercase hex (e.g., `01` for version 1)
//! - `script_hex` is the script data as lowercase hex
//! - `checksum_hex` is the first 4 bytes of SHA256d of the payload (everything before the checksum),
//!   encoded as 8-char lowercase hex
//!
//! # Example
//!
//! ```rust
//! use bsv_rs::script::bip276::{encode_bip276, decode_bip276, NETWORK_MAINNET, NETWORK_TESTNET};
//!
//! let encoded = encode_bip276(NETWORK_MAINNET, 1, b"fake script");
//! assert_eq!(encoded, "bitcoin-script:010166616b65207363726970746f0cd86a");
//!
//! let (network, script_type, data) = decode_bip276(&encoded).unwrap();
//! assert_eq!(network, NETWORK_MAINNET);
//! assert_eq!(script_type, 1);
//! assert_eq!(data, b"fake script");
//! ```

use crate::primitives::{from_hex, sha256d, to_hex};
use crate::{Error, Result};

/// The standard BIP-276 prefix for bitcoin scripts.
pub const BIP276_PREFIX: &str = "bitcoin-script";

/// Network byte for mainnet.
pub const NETWORK_MAINNET: u8 = 1;

/// Network byte for testnet.
pub const NETWORK_TESTNET: u8 = 2;

/// Encode script data in BIP-276 format.
///
/// The format is: `bitcoin-script:<network_hex><script_type_hex><script_hex><checksum_hex>`
///
/// The checksum is the first 4 bytes of the double-SHA256 hash of the payload
/// (everything before the checksum), encoded as lowercase hex.
///
/// # Arguments
///
/// * `network` - Network byte (e.g., `NETWORK_MAINNET` or `NETWORK_TESTNET`)
/// * `script_type` - Script type byte (e.g., `1` for current version)
/// * `script` - Raw script bytes to encode
///
/// # Returns
///
/// The BIP-276 encoded string.
///
/// # Example
///
/// ```rust
/// use bsv_rs::script::bip276::{encode_bip276, NETWORK_MAINNET};
///
/// let encoded = encode_bip276(NETWORK_MAINNET, 1, b"fake script");
/// assert_eq!(encoded, "bitcoin-script:010166616b65207363726970746f0cd86a");
/// ```
pub fn encode_bip276(network: u8, script_type: u8, script: &[u8]) -> String {
    let payload = format!(
        "{}:{:02x}{:02x}{}",
        BIP276_PREFIX,
        network,
        script_type,
        to_hex(script)
    );
    let checksum = sha256d(payload.as_bytes());
    let checksum_hex = to_hex(&checksum[..4]);
    format!("{}{}", payload, checksum_hex)
}

/// Decode a BIP-276 encoded string.
///
/// Validates that the string starts with the `bitcoin-script:` prefix and that
/// the checksum is correct.
///
/// # Arguments
///
/// * `encoded` - The BIP-276 encoded string
///
/// # Returns
///
/// A tuple of `(network, script_type, script_bytes)` on success.
///
/// # Errors
///
/// Returns an error if:
/// - The string is too short or does not contain the expected prefix
/// - The hex data is invalid
/// - The checksum does not match
///
/// # Example
///
/// ```rust
/// use bsv_rs::script::bip276::{decode_bip276, NETWORK_MAINNET};
///
/// let (network, script_type, data) = decode_bip276(
///     "bitcoin-script:010166616b65207363726970746f0cd86a"
/// ).unwrap();
/// assert_eq!(network, NETWORK_MAINNET);
/// assert_eq!(script_type, 1);
/// assert_eq!(data, b"fake script");
/// ```
pub fn decode_bip276(encoded: &str) -> Result<(u8, u8, Vec<u8>)> {
    // Check for the prefix followed by ':'
    let prefix_with_colon = format!("{}:", BIP276_PREFIX);
    if !encoded.starts_with(&prefix_with_colon) {
        return Err(Error::Bip276Error(format!(
            "invalid prefix: expected '{}'",
            BIP276_PREFIX
        )));
    }

    let after_prefix = &encoded[prefix_with_colon.len()..];

    // We need at least 4 hex chars (network + script_type) + 8 hex chars (checksum) = 12 chars
    if after_prefix.len() < 12 {
        return Err(Error::Bip276Error("input too short".to_string()));
    }

    // Parse network byte (first 2 hex chars after prefix)
    let network_hex = &after_prefix[..2];
    let network_bytes = from_hex(network_hex)
        .map_err(|_| Error::Bip276Error(format!("invalid network hex: '{}'", network_hex)))?;
    let network = network_bytes[0];

    // Parse script_type byte (next 2 hex chars)
    let script_type_hex = &after_prefix[2..4];
    let script_type_bytes = from_hex(script_type_hex).map_err(|_| {
        Error::Bip276Error(format!("invalid script type hex: '{}'", script_type_hex))
    })?;
    let script_type = script_type_bytes[0];

    // The remaining data is script_hex + 8-char checksum
    let data_and_checksum = &after_prefix[4..];
    if data_and_checksum.len() < 8 {
        return Err(Error::Bip276Error(
            "input too short for checksum".to_string(),
        ));
    }

    let script_hex = &data_and_checksum[..data_and_checksum.len() - 8];
    let provided_checksum = &data_and_checksum[data_and_checksum.len() - 8..];

    // Decode script data
    let script_data = from_hex(script_hex)
        .map_err(|_| Error::Bip276Error(format!("invalid script hex: '{}'", script_hex)))?;

    // Compute expected checksum: SHA256d of the payload (everything before the checksum)
    let payload = &encoded[..encoded.len() - 8];
    let checksum = sha256d(payload.as_bytes());
    let expected_checksum = to_hex(&checksum[..4]);

    if provided_checksum != expected_checksum {
        return Err(Error::Bip276Error("invalid checksum".to_string()));
    }

    Ok((network, script_type, script_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_mainnet() {
        let encoded = encode_bip276(NETWORK_MAINNET, 1, b"fake script");
        assert_eq!(encoded, "bitcoin-script:010166616b65207363726970746f0cd86a");
    }

    #[test]
    fn test_encode_testnet() {
        let encoded = encode_bip276(NETWORK_TESTNET, 1, b"fake script");
        assert_eq!(encoded, "bitcoin-script:020166616b65207363726970742577a444");
    }

    #[test]
    fn test_decode_valid() {
        let (network, script_type, data) =
            decode_bip276("bitcoin-script:010166616b65207363726970746f0cd86a").unwrap();
        assert_eq!(network, NETWORK_MAINNET);
        assert_eq!(script_type, 1);
        assert_eq!(data, b"fake script");
    }

    #[test]
    fn test_roundtrip() {
        let original_data = b"hello world script data";
        let encoded = encode_bip276(NETWORK_MAINNET, 1, original_data);
        let (network, script_type, data) = decode_bip276(&encoded).unwrap();
        assert_eq!(network, NETWORK_MAINNET);
        assert_eq!(script_type, 1);
        assert_eq!(data, original_data);
    }

    #[test]
    fn test_roundtrip_testnet() {
        let original_data = b"\x76\xa9\x14";
        let encoded = encode_bip276(NETWORK_TESTNET, 2, original_data);
        let (network, script_type, data) = decode_bip276(&encoded).unwrap();
        assert_eq!(network, NETWORK_TESTNET);
        assert_eq!(script_type, 2);
        assert_eq!(data, original_data);
    }

    #[test]
    fn test_decode_invalid_prefix() {
        let result = decode_bip276("invalid-prefix:010166616b65207363726970746f0cd86a");
        assert!(result.is_err());
        match result {
            Err(Error::Bip276Error(msg)) => {
                assert!(msg.contains("invalid prefix"));
            }
            _ => panic!("expected Bip276Error"),
        }
    }

    #[test]
    fn test_decode_invalid_checksum() {
        // Valid format but wrong checksum (last 8 chars changed)
        let result = decode_bip276("bitcoin-script:010166616b65207363726970746f0cd8");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_too_short() {
        let result = decode_bip276("bitcoin-script:01");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_empty_script() {
        // Encode empty script and verify roundtrip
        let encoded = encode_bip276(NETWORK_MAINNET, 1, b"");
        let (network, script_type, data) = decode_bip276(&encoded).unwrap();
        assert_eq!(network, NETWORK_MAINNET);
        assert_eq!(script_type, 1);
        assert!(data.is_empty());
    }

    #[test]
    fn test_roundtrip_various_data() {
        // Test with binary data
        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode_bip276(NETWORK_MAINNET, 1, &data);
        let (network, script_type, decoded) = decode_bip276(&encoded).unwrap();
        assert_eq!(network, NETWORK_MAINNET);
        assert_eq!(script_type, 1);
        assert_eq!(decoded, data);
    }
}
