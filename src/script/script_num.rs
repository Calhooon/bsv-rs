//! Bitcoin Script number encoding.
//!
//! Bitcoin Script uses a special little-endian sign-magnitude encoding for numbers
//! on the stack. This module provides conversion between this format and BigNumber.
//!
//! # Format
//!
//! - Little-endian byte order
//! - Sign bit in the MSB of the last byte (0x80)
//! - Zero is represented as an empty array
//! - Negative zero `[0x80]` is treated as false
//! - Numbers must be minimally encoded (no unnecessary padding)

use crate::primitives::BigNumber;
use crate::Result;
use num_bigint::{BigInt, BigUint, Sign};
use std::collections::TryReserveError;

/// Bitcoin Script number utilities.
///
/// Provides conversion between stack byte arrays and BigNumber values,
/// following Bitcoin's sign-magnitude little-endian encoding.
pub struct ScriptNum;

impl ScriptNum {
    /// Converts stack bytes to a BigNumber.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The stack element bytes
    /// * `require_minimal` - If true, rejects non-minimally encoded numbers
    ///
    /// # Returns
    ///
    /// The decoded BigNumber value, or an error if encoding is invalid
    pub fn from_bytes(bytes: &[u8], require_minimal: bool) -> Result<BigNumber> {
        // Empty array is zero
        if bytes.is_empty() {
            return Ok(BigNumber::zero());
        }

        // Check minimal encoding if required
        if require_minimal && !Self::is_minimally_encoded(bytes) {
            return Err(crate::error::Error::ScriptExecutionError(
                "Non-minimally encoded script number".to_string(),
            ));
        }

        // The magnitude is read from the element itself, the sign bit cleared
        // in place: no copy of the operand (bsv-rs#374)
        let negative = bytes[bytes.len() - 1] & 0x80 != 0;
        let mut magnitude = BigUint::from_bytes_le(bytes);
        if negative {
            magnitude.set_bit(bytes.len() as u64 * 8 - 1, false);
        }
        let sign = if negative { Sign::Minus } else { Sign::Plus };
        Ok(BigNumber::from_bigint(BigInt::from_biguint(
            sign, magnitude,
        )))
    }

    /// Converts a BigNumber to stack bytes (minimal encoding).
    ///
    /// # Arguments
    ///
    /// * `value` - The BigNumber to encode
    ///
    /// # Returns
    ///
    /// The minimally-encoded byte array
    pub fn to_bytes(value: &BigNumber) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::encoded_len(value));
        Self::write(value, &mut bytes);
        bytes
    }

    /// [`to_bytes`](Self::to_bytes) with its one allocation asked of the
    /// allocator first: a refusal is an `Err`, never an abort (bsv-rs#374).
    pub(crate) fn try_to_bytes(value: &BigNumber) -> std::result::Result<Vec<u8>, TryReserveError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(Self::encoded_len(value))?;
        Self::write(value, &mut bytes);
        Ok(bytes)
    }

    /// The minimal encoding's length: one byte for each 8 bits of the
    /// magnitude and the sign's room (0 for zero).
    fn encoded_len(value: &BigNumber) -> usize {
        match value.as_bigint().bits() {
            0 => 0,
            bits => usize::try_from(bits / 8 + 1).unwrap_or(usize::MAX),
        }
    }

    /// Writes the minimal encoding into `bytes`, whose capacity is already
    /// [`encoded_len`](Self::encoded_len): the sign byte's room is reserved
    /// before the magnitude is written, so nothing grows.
    fn write(value: &BigNumber, bytes: &mut Vec<u8>) {
        let len = Self::encoded_len(value);
        bytes.resize(len, 0);
        for (chunk, digit) in bytes.chunks_mut(8).zip(value.as_bigint().iter_u64_digits()) {
            chunk.copy_from_slice(&digit.to_le_bytes()[..chunk.len()]);
        }
        if value.is_negative() {
            if let Some(last) = bytes.last_mut() {
                *last |= 0x80;
            }
        }
    }

    /// Checks if bytes are minimally encoded as a script number.
    ///
    /// A number is minimally encoded if:
    /// - It's empty (zero), or
    /// - The last byte is non-zero after removing the sign bit, or
    /// - The second-to-last byte has its high bit set (justifying the extra byte)
    pub fn is_minimally_encoded(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }

        // If the last byte is non-zero when we mask out the sign bit,
        // the encoding is minimal
        let last_byte = bytes[bytes.len() - 1];
        if (last_byte & 0x7f) != 0 {
            return true;
        }

        // The last byte is either 0x00 or 0x80 (just a sign byte)
        // This is only valid if we have more than one byte and the
        // second-to-last byte has its high bit set
        if bytes.len() > 1 && (bytes[bytes.len() - 2] & 0x80) != 0 {
            return true;
        }

        false
    }

    /// Casts a byte array to a boolean value.
    ///
    /// Returns false for:
    /// - Empty array
    /// - Array of all zeros
    /// - Negative zero `[0x80]` or `[0x00, ..., 0x80]`
    ///
    /// Returns true otherwise.
    pub fn cast_to_bool(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }

        for (i, &byte) in bytes.iter().enumerate() {
            if byte != 0 {
                // Check for negative zero: all zeros except 0x80 in the last byte
                if i == bytes.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }

        false
    }

    /// Minimally encodes bytes in-place.
    ///
    /// Removes unnecessary trailing zeros while preserving the sign.
    pub fn minimally_encode(bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            return Vec::new();
        }

        // Decode and re-encode to get minimal form
        match Self::from_bytes(bytes, false) {
            Ok(bn) => Self::to_bytes(&bn),
            Err(_) => bytes.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        // Zero should encode to empty array
        assert_eq!(ScriptNum::to_bytes(&BigNumber::zero()), Vec::<u8>::new());

        // Empty array should decode to zero
        let bn = ScriptNum::from_bytes(&[], true).unwrap();
        assert!(bn.is_zero());
    }

    #[test]
    fn test_positive_numbers() {
        // 1 -> [0x01]
        let bn = BigNumber::from_i64(1);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0x01]);

        // 127 -> [0x7f]
        let bn = BigNumber::from_i64(127);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0x7f]);

        // 128 -> [0x80, 0x00] (needs extra byte for sign)
        let bn = BigNumber::from_i64(128);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0x80, 0x00]);

        // 255 -> [0xff, 0x00]
        let bn = BigNumber::from_i64(255);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0xff, 0x00]);

        // 256 -> [0x00, 0x01]
        let bn = BigNumber::from_i64(256);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0x00, 0x01]);
    }

    #[test]
    fn test_negative_numbers() {
        // -1 -> [0x81]
        let bn = BigNumber::from_i64(-1);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0x81]);

        // -127 -> [0xff]
        let bn = BigNumber::from_i64(-127);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0xff]);

        // -128 -> [0x80, 0x80]
        let bn = BigNumber::from_i64(-128);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0x80, 0x80]);

        // -255 -> [0xff, 0x80]
        let bn = BigNumber::from_i64(-255);
        assert_eq!(ScriptNum::to_bytes(&bn), vec![0xff, 0x80]);
    }

    #[test]
    fn test_roundtrip() {
        let test_values = [
            0i64, 1, -1, 127, -127, 128, -128, 255, -255, 256, -256, 1000, -1000,
        ];

        for val in test_values {
            let bn = BigNumber::from_i64(val);
            let bytes = ScriptNum::to_bytes(&bn);
            let decoded = ScriptNum::from_bytes(&bytes, true).unwrap();
            assert_eq!(bn, decoded, "Roundtrip failed for {}", val);
        }
    }

    #[test]
    fn encoding_across_limb_boundaries_keeps_the_sign_and_exact_bytes() {
        for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 65] {
            for high in [0x01, 0x7f, 0x80, 0xff] {
                let mut magnitude = vec![0x5a; len];
                magnitude[len - 1] = high;
                let positive = BigNumber::from_bytes_le(&magnitude);
                if high & 0x80 != 0 {
                    magnitude.push(0);
                }
                assert_eq!(ScriptNum::to_bytes(&positive), magnitude);
                assert_eq!(ScriptNum::try_to_bytes(&positive).unwrap(), magnitude);
                *magnitude.last_mut().unwrap() |= 0x80;
                assert_eq!(ScriptNum::to_bytes(&positive.neg()), magnitude);
                assert_eq!(ScriptNum::try_to_bytes(&positive.neg()).unwrap(), magnitude);
            }
        }
    }

    #[test]
    fn test_minimal_encoding() {
        // Minimally encoded
        assert!(ScriptNum::is_minimally_encoded(&[]));
        assert!(ScriptNum::is_minimally_encoded(&[0x01]));
        assert!(ScriptNum::is_minimally_encoded(&[0x7f]));
        assert!(ScriptNum::is_minimally_encoded(&[0x80, 0x00]));
        assert!(ScriptNum::is_minimally_encoded(&[0x81]));

        // Not minimally encoded
        assert!(!ScriptNum::is_minimally_encoded(&[0x00])); // Should be empty
        assert!(!ScriptNum::is_minimally_encoded(&[0x80])); // Negative zero should be empty
        assert!(!ScriptNum::is_minimally_encoded(&[0x01, 0x00])); // 1 with extra byte
    }

    #[test]
    fn test_cast_to_bool() {
        // False cases
        assert!(!ScriptNum::cast_to_bool(&[]));
        assert!(!ScriptNum::cast_to_bool(&[0x00]));
        assert!(!ScriptNum::cast_to_bool(&[0x00, 0x00]));
        assert!(!ScriptNum::cast_to_bool(&[0x80])); // Negative zero
        assert!(!ScriptNum::cast_to_bool(&[0x00, 0x80])); // Negative zero

        // True cases
        assert!(ScriptNum::cast_to_bool(&[0x01]));
        assert!(ScriptNum::cast_to_bool(&[0x81])); // -1
        assert!(ScriptNum::cast_to_bool(&[0x00, 0x01]));
        assert!(ScriptNum::cast_to_bool(&[0x7f]));
    }

    #[test]
    fn test_non_minimal_decoding() {
        // Non-minimal encoding should fail with require_minimal=true
        let result = ScriptNum::from_bytes(&[0x00], true);
        assert!(result.is_err());

        // But should succeed with require_minimal=false
        let bn = ScriptNum::from_bytes(&[0x00], false).unwrap();
        assert!(bn.is_zero());
    }
}
