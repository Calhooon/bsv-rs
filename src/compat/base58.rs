//! Base58 encoding compatibility module.
//!
//! This module provides a convenience wrapper over the existing Base58 encoding
//! functions in `primitives::encoding`, matching the Go SDK's `compat/base58` API.
//!
//! # Examples
//!
//! ```rust
//! use bsv_sdk::compat::base58;
//!
//! // Encode bytes to Base58
//! let encoded = base58::encode(&[0x00, 0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]);
//! assert_eq!(encoded, "111233QC4");
//!
//! // Decode Base58 string to bytes
//! let decoded = base58::decode("111233QC4").unwrap();
//! assert_eq!(decoded, vec![0x00, 0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]);
//! ```

use crate::error::Result;
use crate::primitives::encoding::{from_base58, to_base58};

/// Encodes a byte slice to a Base58 string using the Bitcoin alphabet.
///
/// Leading zero bytes are encoded as '1' characters.
///
/// # Arguments
///
/// * `data` - The bytes to encode
///
/// # Returns
///
/// A Base58 encoded string
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::base58;
///
/// assert_eq!(base58::encode(&[0x00]), "1");
/// assert_eq!(base58::encode(&[0x00, 0x00, 0x00]), "111");
/// ```
pub fn encode(data: &[u8]) -> String {
    to_base58(data)
}

/// Decodes a Base58 string to bytes using the Bitcoin alphabet.
///
/// Leading '1' characters are decoded as zero bytes.
///
/// # Arguments
///
/// * `s` - The Base58 string to decode
///
/// # Returns
///
/// The decoded bytes, or an error if the string contains invalid characters
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::base58;
///
/// assert_eq!(base58::decode("111").unwrap(), vec![0x00, 0x00, 0x00]);
/// assert!(base58::decode("0OIl").is_err()); // Invalid characters
/// ```
pub fn decode(s: &str) -> Result<Vec<u8>> {
    from_base58(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::encoding::from_hex;

    #[test]
    fn test_encode_leading_zeros() {
        assert_eq!(encode(&[0x00]), "1");
        assert_eq!(encode(&[0x00, 0x00, 0x00]), "111");
    }

    #[test]
    fn test_encode_known_values() {
        let bytes = from_hex("0123456789ABCDEF").unwrap();
        assert_eq!(encode(&bytes), "C3CPq7c8PY");

        let bytes = from_hex("000000287FB4CD").unwrap();
        assert_eq!(encode(&bytes), "111233QC4");

        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0, 0, 0, 0]), "1111");
        assert_eq!(encode(&[255, 255, 255, 255]), "7YXq9G");
    }

    #[test]
    fn test_decode_leading_ones() {
        assert_eq!(decode("1").unwrap(), vec![0x00]);
        assert_eq!(decode("111").unwrap(), vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_decode_known_values() {
        let decoded = decode("C3CPq7c8PY").unwrap();
        assert_eq!(decoded, from_hex("0123456789abcdef").unwrap());

        let decoded = decode("111233QC4").unwrap();
        assert_eq!(decoded, from_hex("000000287fb4cd").unwrap());
    }

    #[test]
    fn test_decode_invalid() {
        // Invalid characters (0, O, I, l are not in Base58 alphabet)
        assert!(decode("0").is_err());
        assert!(decode("O").is_err());
        assert!(decode("I").is_err());
        assert!(decode("l").is_err());
        assert!(decode("").is_err());
    }

    #[test]
    fn test_roundtrip() {
        let original = from_hex(
            "02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2",
        )
        .unwrap();
        let encoded = encode(&original);
        assert_eq!(
            encoded,
            "6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
