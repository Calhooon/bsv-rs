//! # BigNumber
//!
//! A minimal BigNumber compatibility layer for BSV SDK operations.
//!
//! This module provides arbitrary-precision integer arithmetic compatible with
//! the TypeScript BSV SDK's BigNumber class. Instead of reimplementing the full
//! bn.js API, this follows the Go SDK approach of using standard big integer
//! operations with BSV-specific serialization methods.
//!
//! ## Key Features
//!
//! - Construction from hex, decimal strings, and byte arrays
//! - Big-endian and little-endian serialization
//! - Modular arithmetic (for EC operations)
//! - Support for 256-bit numbers (EC scalars)
//! - Compatible with BRC-42 key derivation
//!
//! ## Example
//!
//! ```rust
//! use bsv_rs::primitives::BigNumber;
//!
//! // Create from hex
//! let n = BigNumber::from_hex("deadbeef").unwrap();
//! assert_eq!(n.to_hex(), "deadbeef");
//!
//! // Key derivation math
//! let priv_key = BigNumber::from_hex("0123456789abcdef").unwrap();
//! let hmac_val = BigNumber::from_hex("fedcba9876543210").unwrap();
//! let order = BigNumber::secp256k1_order();
//! let new_key = priv_key.add(&hmac_val).modulo(&order);
//! ```

use crate::error::Error;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};
use std::cmp::Ordering;
use std::fmt;

/// BigNumber wrapper for BSV SDK compatibility.
///
/// Internally uses `num_bigint::BigInt` but provides BSV-specific serialization
/// and operations needed for cryptographic key operations.
#[derive(Clone, PartialEq, Eq)]
pub struct BigNumber {
    inner: BigInt,
}

impl BigNumber {
    // ========================================================================
    // Construction
    // ========================================================================

    /// Creates a BigNumber with value zero.
    pub fn zero() -> Self {
        Self {
            inner: BigInt::zero(),
        }
    }

    /// Creates a BigNumber with value one.
    pub fn one() -> Self {
        Self {
            inner: BigInt::one(),
        }
    }

    /// Creates a BigNumber from an i64 value.
    pub fn from_i64(val: i64) -> Self {
        Self {
            inner: BigInt::from(val),
        }
    }

    /// Creates a BigNumber from a u64 value.
    pub fn from_u64(val: u64) -> Self {
        Self {
            inner: BigInt::from(val),
        }
    }

    /// Parses a BigNumber from a hexadecimal string.
    ///
    /// Accepts optional "0x" prefix. Case-insensitive.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n1 = BigNumber::from_hex("deadbeef").unwrap();
    /// let n2 = BigNumber::from_hex("0xDEADBEEF").unwrap();
    /// assert_eq!(n1, n2);
    /// ```
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let s = s.trim();

        // Handle empty string
        if s.is_empty() {
            return Ok(Self::zero());
        }

        // Handle negative sign
        let (is_negative, s) = if let Some(stripped) = s.strip_prefix('-') {
            (true, stripped)
        } else {
            (false, s)
        };

        // Strip 0x prefix if present
        let s = s.strip_prefix("0x").unwrap_or(s);
        let s = s.strip_prefix("0X").unwrap_or(s);

        // Handle empty after stripping
        if s.is_empty() {
            return Ok(Self::zero());
        }

        // Parse as unsigned hex
        let uint = BigUint::parse_bytes(s.as_bytes(), 16)
            .ok_or_else(|| Error::InvalidHex(format!("Invalid hex string: {}", s)))?;

        let mut bigint = BigInt::from(uint);
        if is_negative {
            bigint = -bigint;
        }

        Ok(Self { inner: bigint })
    }

    /// Parses a BigNumber from a decimal string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n = BigNumber::from_dec_str("12345").unwrap();
    /// assert_eq!(n.to_dec_string(), "12345");
    /// ```
    pub fn from_dec_str(s: &str) -> Result<Self, Error> {
        let s = s.trim();

        if s.is_empty() {
            return Ok(Self::zero());
        }

        let bigint = s
            .parse::<BigInt>()
            .map_err(|e| Error::InvalidHex(format!("Invalid decimal string: {}", e)))?;

        Ok(Self { inner: bigint })
    }

    /// Creates a BigNumber from big-endian bytes (unsigned).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n = BigNumber::from_bytes_be(&[0x12, 0x34]);
    /// assert_eq!(n.to_hex(), "1234");
    /// ```
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        Self {
            inner: BigInt::from_bytes_be(Sign::Plus, bytes),
        }
    }

    /// Creates a BigNumber from little-endian bytes (unsigned).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n = BigNumber::from_bytes_le(&[0x34, 0x12]);
    /// assert_eq!(n.to_hex(), "1234");
    /// ```
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        Self {
            inner: BigInt::from_bytes_le(Sign::Plus, bytes),
        }
    }

    /// Creates a BigNumber from big-endian bytes (signed, two's complement).
    ///
    /// The most significant bit indicates the sign.
    pub fn from_signed_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        Self {
            inner: BigInt::from_signed_bytes_be(bytes),
        }
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Converts to a lowercase hex string without "0x" prefix.
    ///
    /// No leading zeros except for zero itself which returns "0".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// assert_eq!(BigNumber::zero().to_hex(), "0");
    /// assert_eq!(BigNumber::from_hex("ff").unwrap().to_hex(), "ff");
    /// ```
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }

        let prefix = if self.is_negative() { "-" } else { "" };
        let abs = self.inner.magnitude();
        let hex = format!("{:x}", abs);

        format!("{}{}", prefix, hex)
    }

    /// Converts to big-endian bytes, padded to the specified length.
    ///
    /// # Panics
    ///
    /// Panics if the number requires more bytes than `len`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n = BigNumber::from_hex("1234").unwrap();
    /// assert_eq!(n.to_bytes_be(4), vec![0x00, 0x00, 0x12, 0x34]);
    /// ```
    pub fn to_bytes_be(&self, len: usize) -> Vec<u8> {
        let bytes = self.inner.magnitude().to_bytes_be();
        let byte_len = bytes.len();

        // Handle zero case (returns [0] but we might want empty or padding)
        if self.is_zero() {
            return vec![0u8; len];
        }

        if byte_len > len {
            panic!(
                "BigNumber requires {} bytes, but only {} requested",
                byte_len, len
            );
        }

        let mut result = vec![0u8; len];
        let start = len - byte_len;
        result[start..].copy_from_slice(&bytes);
        result
    }

    /// Converts to little-endian bytes, padded to the specified length.
    ///
    /// # Panics
    ///
    /// Panics if the number requires more bytes than `len`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n = BigNumber::from_hex("1234").unwrap();
    /// assert_eq!(n.to_bytes_le(4), vec![0x34, 0x12, 0x00, 0x00]);
    /// ```
    pub fn to_bytes_le(&self, len: usize) -> Vec<u8> {
        let bytes = self.inner.magnitude().to_bytes_le();
        let byte_len = bytes.len();

        // Handle zero case
        if self.is_zero() {
            return vec![0u8; len];
        }

        if byte_len > len {
            panic!(
                "BigNumber requires {} bytes, but only {} requested",
                byte_len, len
            );
        }

        let mut result = vec![0u8; len];
        result[..byte_len].copy_from_slice(&bytes);
        result
    }

    /// Converts to big-endian bytes with minimum length (no padding).
    ///
    /// Returns an empty vec for zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n = BigNumber::from_hex("1234").unwrap();
    /// assert_eq!(n.to_bytes_be_min(), vec![0x12, 0x34]);
    ///
    /// let z = BigNumber::zero();
    /// let empty: Vec<u8> = vec![];
    /// assert_eq!(z.to_bytes_be_min(), empty);
    /// ```
    pub fn to_bytes_be_min(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }
        self.inner.magnitude().to_bytes_be()
    }

    /// Converts to little-endian bytes with minimum length (no padding).
    ///
    /// Returns an empty vec for zero.
    pub fn to_bytes_le_min(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }
        self.inner.magnitude().to_bytes_le()
    }

    /// Converts to a decimal string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let n = BigNumber::from_i64(12345);
    /// assert_eq!(n.to_dec_string(), "12345");
    /// ```
    pub fn to_dec_string(&self) -> String {
        self.inner.to_string()
    }

    // ========================================================================
    // Arithmetic Operations
    // ========================================================================

    /// Adds two BigNumbers and returns a new BigNumber.
    pub fn add(&self, other: &BigNumber) -> BigNumber {
        Self {
            inner: &self.inner + &other.inner,
        }
    }

    /// Subtracts other from self and returns a new BigNumber.
    pub fn sub(&self, other: &BigNumber) -> BigNumber {
        Self {
            inner: &self.inner - &other.inner,
        }
    }

    /// Multiplies two BigNumbers and returns a new BigNumber.
    pub fn mul(&self, other: &BigNumber) -> BigNumber {
        Self {
            inner: &self.inner * &other.inner,
        }
    }

    /// Divides self by other and returns the quotient (truncated toward zero).
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    pub fn div(&self, other: &BigNumber) -> BigNumber {
        assert!(!other.is_zero(), "Division by zero");
        Self {
            inner: &self.inner / &other.inner,
        }
    }

    /// Returns self modulo other.
    ///
    /// This always returns a non-negative result, suitable for cryptographic operations.
    /// For negative numbers, the result is adjusted to be in the range [0, |other|).
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let a = BigNumber::from_i64(-10);
    /// let b = BigNumber::from_i64(3);
    /// assert_eq!(a.modulo(&b), BigNumber::from_i64(2));
    /// ```
    pub fn modulo(&self, other: &BigNumber) -> BigNumber {
        assert!(!other.is_zero(), "Division by zero");

        let result = &self.inner % &other.inner;

        // Ensure positive result for negative dividends
        if result.is_negative() {
            Self {
                inner: result + BigInt::from(other.inner.magnitude().clone()),
            }
        } else {
            Self { inner: result }
        }
    }

    /// Returns self modulo other (can be negative).
    ///
    /// This preserves the sign of the dividend, matching JavaScript's % operator.
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    pub fn mod_floor(&self, other: &BigNumber) -> BigNumber {
        assert!(!other.is_zero(), "Division by zero");
        Self {
            inner: &self.inner % &other.inner,
        }
    }

    /// Returns the negation of this BigNumber.
    pub fn neg(&self) -> BigNumber {
        Self {
            inner: -&self.inner,
        }
    }

    /// Returns the absolute value of this BigNumber.
    pub fn abs(&self) -> BigNumber {
        Self {
            inner: self.inner.abs(),
        }
    }

    /// Raises self to the power of exp.
    ///
    /// # Panics
    ///
    /// Panics if exp is negative.
    pub fn pow(&self, exp: u32) -> BigNumber {
        Self {
            inner: self.inner.pow(exp),
        }
    }

    // ========================================================================
    // Comparisons
    // ========================================================================

    /// Compares self with other.
    ///
    /// Returns `Ordering::Less`, `Ordering::Equal`, or `Ordering::Greater`.
    ///
    /// Note: This type also implements `Ord`, so you can use standard comparison
    /// operators (`<`, `>`, `<=`, `>=`, `==`).
    pub fn compare(&self, other: &BigNumber) -> Ordering {
        self.inner.cmp(&other.inner)
    }

    /// Returns true if this BigNumber is zero.
    pub fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }

    /// Returns true if this BigNumber is negative.
    pub fn is_negative(&self) -> bool {
        self.inner.is_negative()
    }

    /// Returns true if this BigNumber is positive (greater than zero).
    pub fn is_positive(&self) -> bool {
        self.inner.is_positive()
    }

    /// Returns true if this BigNumber is odd.
    pub fn is_odd(&self) -> bool {
        !self.inner.is_even()
    }

    /// Returns true if this BigNumber is even.
    pub fn is_even(&self) -> bool {
        self.inner.is_even()
    }

    // ========================================================================
    // Bit Operations
    // ========================================================================

    /// Returns the number of bits required to represent this number.
    ///
    /// Returns 0 for zero.
    pub fn bit_length(&self) -> usize {
        self.inner.bits() as usize
    }

    /// Returns the number of bytes required to represent this number.
    ///
    /// Returns 0 for zero.
    pub fn byte_length(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        self.bit_length().div_ceil(8)
    }

    // ========================================================================
    // Modular Arithmetic
    // ========================================================================

    /// Computes the modular inverse: self^(-1) mod modulus.
    ///
    /// Returns None if the inverse does not exist (i.e., gcd(self, modulus) != 1).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bsv_rs::primitives::BigNumber;
    ///
    /// let a = BigNumber::from_i64(3);
    /// let m = BigNumber::from_i64(7);
    /// let inv = a.mod_inverse(&m).unwrap();
    /// // 3 * 5 = 15 = 1 (mod 7)
    /// assert_eq!(inv, BigNumber::from_i64(5));
    /// ```
    pub fn mod_inverse(&self, modulus: &BigNumber) -> Option<BigNumber> {
        if modulus.is_zero() {
            return None;
        }

        // Extended Euclidean algorithm
        let mut old_r = self.inner.clone();
        let mut r = modulus.inner.clone();
        let mut old_s = BigInt::one();
        let mut s = BigInt::zero();

        while !r.is_zero() {
            let quotient = &old_r / &r;
            let temp_r = r.clone();
            r = &old_r - &quotient * &r;
            old_r = temp_r;

            let temp_s = s.clone();
            s = &old_s - &quotient * &s;
            old_s = temp_s;
        }

        // gcd must be 1 for inverse to exist
        if old_r != BigInt::one() && old_r != -BigInt::one() {
            return None;
        }

        // Ensure positive result
        let result = if old_s.is_negative() {
            old_s + &modulus.inner
        } else {
            old_s
        };

        Some(Self { inner: result })
    }

    /// Computes modular exponentiation: self^exp mod modulus.
    ///
    /// Uses the square-and-multiply algorithm.
    ///
    /// # Panics
    ///
    /// Panics if modulus is zero or exp is negative.
    pub fn mod_pow(&self, exp: &BigNumber, modulus: &BigNumber) -> BigNumber {
        assert!(!modulus.is_zero(), "Modulus cannot be zero");
        assert!(!exp.is_negative(), "Exponent cannot be negative");

        if exp.is_zero() {
            return BigNumber::one();
        }

        let result = self.inner.modpow(&exp.inner, &modulus.inner);

        // Ensure non-negative result
        if result.is_negative() {
            Self {
                inner: result + &modulus.inner,
            }
        } else {
            Self { inner: result }
        }
    }

    /// Computes the GCD of self and other.
    pub fn gcd(&self, other: &BigNumber) -> BigNumber {
        use num_integer::Integer;
        Self {
            inner: self.inner.gcd(&other.inner),
        }
    }

    // ========================================================================
    // Curve Constants
    // ========================================================================

    /// Returns the secp256k1 curve order (n).
    ///
    /// This is the order of the generator point G on the secp256k1 curve.
    /// All private keys must be in the range [1, n-1].
    pub fn secp256k1_order() -> BigNumber {
        BigNumber::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .expect("valid constant")
    }

    /// Returns the secp256k1 field prime (p).
    ///
    /// This is the prime that defines the finite field for secp256k1.
    pub fn secp256k1_prime() -> BigNumber {
        BigNumber::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
            .expect("valid constant")
    }

    // ========================================================================
    // Conversion to primitive types
    // ========================================================================

    /// Converts to i64 if the value fits.
    ///
    /// Returns None if the value is too large or too small.
    pub fn to_i64(&self) -> Option<i64> {
        self.inner.to_i64()
    }

    /// Converts to u64 if the value fits and is non-negative.
    ///
    /// Returns None if the value is negative or too large.
    pub fn to_u64(&self) -> Option<u64> {
        self.inner.to_u64()
    }

    // ========================================================================
    // Internal access (for EC operations)
    // ========================================================================

    /// Returns a reference to the internal BigInt.
    pub fn as_bigint(&self) -> &BigInt {
        &self.inner
    }

    /// Creates a BigNumber from a BigInt.
    pub fn from_bigint(inner: BigInt) -> Self {
        Self { inner }
    }
}

// ============================================================================
// Trait Implementations
// ============================================================================

impl From<i64> for BigNumber {
    fn from(val: i64) -> Self {
        Self::from_i64(val)
    }
}

impl From<u64> for BigNumber {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl From<i32> for BigNumber {
    fn from(val: i32) -> Self {
        Self::from_i64(val as i64)
    }
}

impl From<u32> for BigNumber {
    fn from(val: u32) -> Self {
        Self::from_u64(val as u64)
    }
}

impl From<BigInt> for BigNumber {
    fn from(inner: BigInt) -> Self {
        Self { inner }
    }
}

impl From<BigNumber> for BigInt {
    fn from(bn: BigNumber) -> Self {
        bn.inner
    }
}

impl Default for BigNumber {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for BigNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigNumber({})", self.to_hex())
    }
}

impl fmt::Display for BigNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_dec_string())
    }
}

impl PartialOrd for BigNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for BigNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl std::hash::Hash for BigNumber {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Construction Tests
    // ========================================================================

    #[test]
    fn test_zero_and_one() {
        assert_eq!(BigNumber::zero().to_hex(), "0");
        assert_eq!(BigNumber::one().to_hex(), "1");
        assert!(BigNumber::zero().is_zero());
        assert!(!BigNumber::one().is_zero());
    }

    #[test]
    fn test_from_i64() {
        assert_eq!(BigNumber::from_i64(0).to_hex(), "0");
        assert_eq!(BigNumber::from_i64(255).to_hex(), "ff");
        assert!(BigNumber::from_i64(-1).is_negative());
        assert!(!BigNumber::from_i64(1).is_negative());
    }

    #[test]
    fn test_from_u64() {
        assert_eq!(BigNumber::from_u64(0).to_hex(), "0");
        assert_eq!(BigNumber::from_u64(0xdeadbeef).to_hex(), "deadbeef");
    }

    // ========================================================================
    // Hex Parsing Tests
    // ========================================================================

    #[test]
    fn test_from_hex_basic() {
        let n = BigNumber::from_hex("deadbeef").unwrap();
        assert_eq!(n.to_hex(), "deadbeef");

        let n = BigNumber::from_hex("0xDEADBEEF").unwrap();
        assert_eq!(n.to_hex(), "deadbeef");

        let n = BigNumber::from_hex("0").unwrap();
        assert!(n.is_zero());
    }

    #[test]
    fn test_from_hex_with_prefix() {
        let n1 = BigNumber::from_hex("0xff").unwrap();
        let n2 = BigNumber::from_hex("0XFF").unwrap();
        let n3 = BigNumber::from_hex("ff").unwrap();
        assert_eq!(n1, n2);
        assert_eq!(n2, n3);
    }

    #[test]
    fn test_from_hex_negative() {
        let n = BigNumber::from_hex("-ff").unwrap();
        assert!(n.is_negative());
        assert_eq!(n.abs().to_hex(), "ff");
    }

    #[test]
    fn test_from_hex_empty() {
        let n = BigNumber::from_hex("").unwrap();
        assert!(n.is_zero());
    }

    #[test]
    fn test_from_hex_invalid() {
        assert!(BigNumber::from_hex("gg").is_err());
        assert!(BigNumber::from_hex("xyz").is_err());
    }

    // ========================================================================
    // Decimal String Tests
    // ========================================================================

    #[test]
    fn test_from_dec_str() {
        let n = BigNumber::from_dec_str("12345").unwrap();
        assert_eq!(n.to_dec_string(), "12345");

        let n = BigNumber::from_dec_str("-12345").unwrap();
        assert_eq!(n.to_dec_string(), "-12345");
    }

    // ========================================================================
    // Byte Serialization Tests
    // ========================================================================

    #[test]
    fn test_from_bytes_be() {
        let n = BigNumber::from_bytes_be(&[0x12, 0x34]);
        assert_eq!(n.to_hex(), "1234");

        let n = BigNumber::from_bytes_be(&[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(n, BigNumber::one());

        let z = BigNumber::from_bytes_be(&[]);
        assert!(z.is_zero());
    }

    #[test]
    fn test_from_bytes_le() {
        let n = BigNumber::from_bytes_le(&[0x34, 0x12]);
        assert_eq!(n.to_hex(), "1234");
    }

    #[test]
    fn test_to_bytes_be() {
        let n = BigNumber::from_hex("1234").unwrap();
        assert_eq!(n.to_bytes_be(4), vec![0x00, 0x00, 0x12, 0x34]);

        let n = BigNumber::from_hex("0").unwrap();
        assert_eq!(n.to_bytes_be(4), vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_to_bytes_le() {
        let n = BigNumber::from_hex("1234").unwrap();
        assert_eq!(n.to_bytes_le(4), vec![0x34, 0x12, 0x00, 0x00]);
    }

    #[test]
    fn test_to_bytes_be_min() {
        let n = BigNumber::from_hex("1234").unwrap();
        assert_eq!(n.to_bytes_be_min(), vec![0x12, 0x34]);

        let z = BigNumber::zero();
        assert_eq!(z.to_bytes_be_min(), Vec::<u8>::new());
    }

    #[test]
    #[should_panic(expected = "BigNumber requires")]
    fn test_to_bytes_be_overflow() {
        let n = BigNumber::from_hex("123456").unwrap();
        n.to_bytes_be(2); // Should panic
    }

    // ========================================================================
    // Arithmetic Tests
    // ========================================================================

    #[test]
    fn test_add() {
        let a = BigNumber::from_i64(10);
        let b = BigNumber::from_i64(20);
        assert_eq!(a.add(&b), BigNumber::from_i64(30));

        let a = BigNumber::from_i64(-10);
        let b = BigNumber::from_i64(20);
        assert_eq!(a.add(&b), BigNumber::from_i64(10));
    }

    #[test]
    fn test_sub() {
        let a = BigNumber::from_i64(30);
        let b = BigNumber::from_i64(10);
        assert_eq!(a.sub(&b), BigNumber::from_i64(20));

        let a = BigNumber::from_i64(10);
        let b = BigNumber::from_i64(30);
        assert_eq!(a.sub(&b), BigNumber::from_i64(-20));
    }

    #[test]
    fn test_mul() {
        let a = BigNumber::from_i64(6);
        let b = BigNumber::from_i64(7);
        assert_eq!(a.mul(&b), BigNumber::from_i64(42));

        let a = BigNumber::from_i64(-6);
        let b = BigNumber::from_i64(7);
        assert_eq!(a.mul(&b), BigNumber::from_i64(-42));
    }

    #[test]
    fn test_div() {
        let a = BigNumber::from_i64(42);
        let b = BigNumber::from_i64(7);
        assert_eq!(a.div(&b), BigNumber::from_i64(6));

        let a = BigNumber::from_i64(43);
        let b = BigNumber::from_i64(7);
        assert_eq!(a.div(&b), BigNumber::from_i64(6)); // Truncated
    }

    #[test]
    fn test_modulo_positive() {
        let a = BigNumber::from_i64(10);
        let b = BigNumber::from_i64(3);
        assert_eq!(a.modulo(&b), BigNumber::from_i64(1));
    }

    #[test]
    fn test_modulo_negative() {
        // Negative number modulo should give positive result
        let neg = BigNumber::from_i64(-10);
        let b = BigNumber::from_i64(3);
        // -10 mod 3 = 2 (not -1!)
        assert_eq!(neg.modulo(&b), BigNumber::from_i64(2));
    }

    #[test]
    fn test_mod_floor() {
        // mod_floor preserves sign like JavaScript %
        let neg = BigNumber::from_i64(-10);
        let b = BigNumber::from_i64(3);
        assert_eq!(neg.mod_floor(&b), BigNumber::from_i64(-1));
    }

    // ========================================================================
    // Comparison Tests
    // ========================================================================

    #[test]
    fn test_cmp() {
        let a = BigNumber::from_i64(10);
        let b = BigNumber::from_i64(20);
        let c = BigNumber::from_i64(10);

        assert_eq!(a.compare(&b), Ordering::Less);
        assert_eq!(b.compare(&a), Ordering::Greater);
        assert_eq!(a.compare(&c), Ordering::Equal);
    }

    #[test]
    fn test_is_zero() {
        assert!(BigNumber::zero().is_zero());
        assert!(BigNumber::from_hex("0").unwrap().is_zero());
        assert!(!BigNumber::one().is_zero());
    }

    #[test]
    fn test_is_negative_positive() {
        assert!(BigNumber::from_i64(-1).is_negative());
        assert!(!BigNumber::from_i64(0).is_negative());
        assert!(!BigNumber::from_i64(1).is_negative());

        assert!(!BigNumber::from_i64(-1).is_positive());
        assert!(!BigNumber::from_i64(0).is_positive());
        assert!(BigNumber::from_i64(1).is_positive());
    }

    #[test]
    fn test_is_odd_even() {
        assert!(BigNumber::from_i64(0).is_even());
        assert!(!BigNumber::from_i64(0).is_odd());
        assert!(BigNumber::from_i64(1).is_odd());
        assert!(!BigNumber::from_i64(1).is_even());
        assert!(BigNumber::from_i64(2).is_even());
        assert!(BigNumber::from_i64(-1).is_odd());
        assert!(BigNumber::from_i64(-2).is_even());
    }

    // ========================================================================
    // Bit Operations Tests
    // ========================================================================

    #[test]
    fn test_bit_length() {
        assert_eq!(BigNumber::from_i64(0).bit_length(), 0);
        assert_eq!(BigNumber::from_i64(1).bit_length(), 1);
        assert_eq!(BigNumber::from_i64(2).bit_length(), 2);
        assert_eq!(BigNumber::from_i64(3).bit_length(), 2);
        assert_eq!(BigNumber::from_i64(4).bit_length(), 3);
        assert_eq!(BigNumber::from_i64(255).bit_length(), 8);
        assert_eq!(BigNumber::from_i64(256).bit_length(), 9);
    }

    #[test]
    fn test_byte_length() {
        assert_eq!(BigNumber::from_i64(0).byte_length(), 0);
        assert_eq!(BigNumber::from_i64(1).byte_length(), 1);
        assert_eq!(BigNumber::from_i64(255).byte_length(), 1);
        assert_eq!(BigNumber::from_i64(256).byte_length(), 2);
        assert_eq!(BigNumber::from_i64(0x123456).byte_length(), 3);
    }

    // ========================================================================
    // Modular Arithmetic Tests
    // ========================================================================

    #[test]
    fn test_mod_inverse() {
        let a = BigNumber::from_i64(3);
        let m = BigNumber::from_i64(7);
        let inv = a.mod_inverse(&m).unwrap();
        // 3 * 5 = 15 = 1 (mod 7)
        assert_eq!(inv, BigNumber::from_i64(5));

        // Verify: a * inv mod m = 1
        let product = a.mul(&inv).modulo(&m);
        assert_eq!(product, BigNumber::one());
    }

    #[test]
    fn test_mod_inverse_none() {
        let a = BigNumber::from_i64(4);
        let m = BigNumber::from_i64(8);
        // gcd(4, 8) = 4 != 1, so no inverse exists
        assert!(a.mod_inverse(&m).is_none());
    }

    #[test]
    fn test_mod_pow() {
        let base = BigNumber::from_i64(2);
        let exp = BigNumber::from_i64(10);
        let modulus = BigNumber::from_i64(1000);
        let result = base.mod_pow(&exp, &modulus);
        // 2^10 = 1024 mod 1000 = 24
        assert_eq!(result, BigNumber::from_i64(24));
    }

    #[test]
    fn test_gcd() {
        assert_eq!(
            BigNumber::from_i64(18).gcd(&BigNumber::from_i64(12)),
            BigNumber::from_i64(6)
        );
        assert_eq!(
            BigNumber::from_i64(17).gcd(&BigNumber::from_i64(13)),
            BigNumber::from_i64(1)
        );
    }

    // ========================================================================
    // Key Derivation Simulation Tests
    // ========================================================================

    #[test]
    fn test_key_derivation_pattern() {
        // Simulate the key derivation math
        let priv_key =
            BigNumber::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let hmac_value =
            BigNumber::from_hex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
                .unwrap();
        let order = BigNumber::secp256k1_order();

        let new_key = priv_key.add(&hmac_value).modulo(&order);

        // Result should be 32 bytes when serialized
        let bytes = new_key.to_bytes_be(32);
        assert_eq!(bytes.len(), 32);

        // The result should be less than the order
        assert!(new_key.compare(&order) == Ordering::Less);
    }

    #[test]
    fn test_256_bit_numbers() {
        // Large number (256-bit)
        let large =
            BigNumber::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert_eq!(large.byte_length(), 32);
        assert_eq!(large.bit_length(), 256);
    }

    // ========================================================================
    // Curve Constants Tests
    // ========================================================================

    #[test]
    fn test_secp256k1_order() {
        let n = BigNumber::secp256k1_order();
        assert_eq!(n.byte_length(), 32);
        assert_eq!(
            n.to_hex(),
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        );
    }

    #[test]
    fn test_secp256k1_prime() {
        let p = BigNumber::secp256k1_prime();
        assert_eq!(p.byte_length(), 32);
        assert_eq!(
            p.to_hex(),
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        );
    }

    // ========================================================================
    // Edge Cases Tests
    // ========================================================================

    #[test]
    fn test_leading_zeros_in_input() {
        let n = BigNumber::from_bytes_be(&[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(n, BigNumber::one());
    }

    #[test]
    fn test_zero_from_empty_bytes() {
        let z = BigNumber::from_bytes_be(&[]);
        assert!(z.is_zero());
    }

    #[test]
    fn test_conversion_to_i64() {
        let n = BigNumber::from_i64(12345);
        assert_eq!(n.to_i64(), Some(12345));

        let large = BigNumber::from_hex("ffffffffffffffffffffffffffffffff").unwrap();
        assert_eq!(large.to_i64(), None);
    }

    #[test]
    fn test_display_debug() {
        let n = BigNumber::from_hex("deadbeef").unwrap();
        assert_eq!(format!("{}", n), "3735928559");
        assert_eq!(format!("{:?}", n), "BigNumber(deadbeef)");
    }

    #[test]
    fn test_from_traits() {
        let a: BigNumber = 42i64.into();
        let b: BigNumber = 42u64.into();
        let c: BigNumber = 42i32.into();
        let d: BigNumber = 42u32.into();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(c, d);
    }

    #[test]
    fn test_ord_trait() {
        let a = BigNumber::from_i64(10);
        let b = BigNumber::from_i64(20);
        assert!(a < b);
        assert!(b > a);
        assert!(a <= a);
        assert!(a >= a);
    }

    // ========================================================================
    // Extended Constructor Tests
    // ========================================================================

    #[test]
    fn test_from_zero() {
        assert!(BigNumber::zero().is_zero());
        assert!(!BigNumber::zero().is_positive());
        assert!(!BigNumber::zero().is_negative());
    }

    #[test]
    fn test_from_one() {
        assert!(!BigNumber::one().is_zero());
        assert!(BigNumber::one().is_positive());
        assert_eq!(BigNumber::one().to_i64(), Some(1));
    }

    #[test]
    fn test_from_u64_max() {
        let max = BigNumber::from_u64(u64::MAX);
        assert_eq!(max.to_u64(), Some(u64::MAX));
    }

    #[test]
    fn test_from_i64_min_max() {
        let max = BigNumber::from_i64(i64::MAX);
        assert_eq!(max.to_i64(), Some(i64::MAX));

        let min = BigNumber::from_i64(i64::MIN);
        assert_eq!(min.to_i64(), Some(i64::MIN));
    }

    // ========================================================================
    // Extended Arithmetic Tests
    // ========================================================================

    #[test]
    fn test_add_with_overflow() {
        let max_u64 = BigNumber::from_u64(u64::MAX);
        let one = BigNumber::one();
        let result = max_u64.add(&one);
        // Result should be 2^64
        assert_eq!(result.to_hex(), "10000000000000000");
    }

    #[test]
    fn test_sub_to_negative() {
        let a = BigNumber::from_i64(5);
        let b = BigNumber::from_i64(10);
        let result = a.sub(&b);
        assert!(result.is_negative());
        assert_eq!(result.to_i64(), Some(-5));
    }

    #[test]
    fn test_mul_large_numbers() {
        let a = BigNumber::from_hex("ffffffff").unwrap();
        let b = BigNumber::from_hex("ffffffff").unwrap();
        let result = a.mul(&b);
        assert_eq!(result.to_hex(), "fffffffe00000001");
    }

    #[test]
    fn test_div_with_remainder() {
        let a = BigNumber::from_i64(17);
        let b = BigNumber::from_i64(5);
        assert_eq!(a.div(&b), BigNumber::from_i64(3));
    }

    #[test]
    fn test_pow_edge_cases() {
        let base = BigNumber::from_i64(2);
        assert_eq!(base.pow(0), BigNumber::one());
        assert_eq!(base.pow(1), BigNumber::from_i64(2));
        assert_eq!(base.pow(10), BigNumber::from_i64(1024));
    }

    #[test]
    fn test_neg_double() {
        let n = BigNumber::from_i64(42);
        assert_eq!(n.neg().neg(), n);
    }

    #[test]
    fn test_abs_negative() {
        let neg = BigNumber::from_i64(-42);
        let pos = BigNumber::from_i64(42);
        assert_eq!(neg.abs(), pos);
    }

    // ========================================================================
    // Extended Modular Arithmetic Tests
    // ========================================================================

    #[test]
    fn test_mod_add_overflow() {
        let a = BigNumber::from_hex("ffffffff").unwrap();
        let b = BigNumber::from_hex("00000001").unwrap();
        let m = BigNumber::from_hex("100000000").unwrap();

        let result = a.add(&b).modulo(&m);
        assert_eq!(result, BigNumber::zero());
    }

    #[test]
    fn test_mod_sub_underflow() {
        let a = BigNumber::from_i64(1);
        let b = BigNumber::from_i64(2);
        let m = BigNumber::from_hex("100000000").unwrap();

        // (1 - 2) mod 2^32 = 2^32 - 1
        let result = a.sub(&b).modulo(&m);
        assert_eq!(result, BigNumber::from_hex("ffffffff").unwrap());
    }

    #[test]
    fn test_mod_mul_large() {
        let a = BigNumber::from_hex("ffffffffffffffff").unwrap();
        let b = BigNumber::from_hex("ffffffffffffffff").unwrap();
        let m = BigNumber::from_hex("10000000000000000").unwrap();

        let result = a.mul(&b).modulo(&m);
        // (2^64-1)^2 mod 2^64 = 1
        assert_eq!(result, BigNumber::one());
    }

    #[test]
    fn test_mod_inverse_prime() {
        // Test modular inverse in prime field
        let a = BigNumber::from_u64(3);
        let p = BigNumber::from_u64(11);

        let inv = a.mod_inverse(&p).unwrap();
        let check = a.mul(&inv).modulo(&p);
        assert_eq!(check, BigNumber::one());
    }

    #[test]
    fn test_mod_inverse_secp256k1() {
        // Test with secp256k1 prime
        let p =
            BigNumber::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
                .unwrap();
        let a = BigNumber::from_hex("deadbeef").unwrap();

        let inv = a.mod_inverse(&p).unwrap();
        let check = a.mul(&inv).modulo(&p);
        assert_eq!(check, BigNumber::one());
    }

    #[test]
    fn test_mod_pow_fermat() {
        // Fermat's little theorem: a^(p-1) = 1 mod p
        let a = BigNumber::from_u64(2);
        let p = BigNumber::from_u64(17);
        let exp = BigNumber::from_u64(16); // p - 1

        let result = a.mod_pow(&exp, &p);
        assert_eq!(result, BigNumber::one());
    }

    #[test]
    fn test_mod_pow_large() {
        let base = BigNumber::from_i64(2);
        let exp = BigNumber::from_i64(100);
        let modulus = BigNumber::from_i64(1000000007);
        let result = base.mod_pow(&exp, &modulus);
        // 2^100 mod 1000000007 should be a specific value
        assert!(result.compare(&modulus) == Ordering::Less);
    }

    #[test]
    fn test_gcd_coprime() {
        let a = BigNumber::from_i64(17);
        let b = BigNumber::from_i64(13);
        assert_eq!(a.gcd(&b), BigNumber::one());
    }

    #[test]
    fn test_gcd_common_factor() {
        let a = BigNumber::from_i64(18);
        let b = BigNumber::from_i64(24);
        assert_eq!(a.gcd(&b), BigNumber::from_i64(6));
    }

    // ========================================================================
    // Extended Bit Operations Tests
    // ========================================================================

    #[test]
    fn test_bit_length_powers_of_two() {
        assert_eq!(BigNumber::from_i64(1).bit_length(), 1); // 2^0
        assert_eq!(BigNumber::from_i64(2).bit_length(), 2); // 2^1
        assert_eq!(BigNumber::from_i64(4).bit_length(), 3); // 2^2
        assert_eq!(BigNumber::from_i64(8).bit_length(), 4); // 2^3
        assert_eq!(BigNumber::from_i64(128).bit_length(), 8); // 2^7
        assert_eq!(BigNumber::from_i64(256).bit_length(), 9); // 2^8
    }

    #[test]
    fn test_byte_length_edge_cases() {
        assert_eq!(BigNumber::from_i64(0).byte_length(), 0);
        assert_eq!(BigNumber::from_i64(1).byte_length(), 1);
        assert_eq!(BigNumber::from_i64(127).byte_length(), 1);
        assert_eq!(BigNumber::from_i64(128).byte_length(), 1);
        assert_eq!(BigNumber::from_i64(255).byte_length(), 1);
        assert_eq!(BigNumber::from_i64(256).byte_length(), 2);
        assert_eq!(BigNumber::from_i64(65535).byte_length(), 2);
        assert_eq!(BigNumber::from_i64(65536).byte_length(), 3);
    }

    // ========================================================================
    // Extended Comparison Tests
    // ========================================================================

    #[test]
    fn test_is_one() {
        assert!(!BigNumber::zero().is_positive() && !BigNumber::zero().is_negative());
        assert!(BigNumber::one().is_positive());
        assert_eq!(BigNumber::one().to_i64(), Some(1));
    }

    #[test]
    fn test_sign() {
        let pos = BigNumber::from_i64(5);
        let neg = BigNumber::from_i64(-5);
        let zero = BigNumber::zero();

        assert!(pos.is_positive());
        assert!(!pos.is_negative());
        assert!(neg.is_negative());
        assert!(!neg.is_positive());
        assert!(!zero.is_positive());
        assert!(!zero.is_negative());
    }

    #[test]
    fn test_compare_across_signs() {
        let neg = BigNumber::from_i64(-100);
        let zero = BigNumber::zero();
        let pos = BigNumber::from_i64(100);

        assert_eq!(neg.compare(&zero), Ordering::Less);
        assert_eq!(zero.compare(&pos), Ordering::Less);
        assert_eq!(neg.compare(&pos), Ordering::Less);
        assert_eq!(pos.compare(&neg), Ordering::Greater);
    }

    // ========================================================================
    // Extended Serialization Tests
    // ========================================================================

    #[test]
    fn test_to_bytes_be_min_variations() {
        // Zero returns empty
        assert!(BigNumber::zero().to_bytes_be_min().is_empty());

        // One returns [1]
        assert_eq!(BigNumber::one().to_bytes_be_min(), vec![1]);

        // 256 returns [1, 0]
        assert_eq!(BigNumber::from_u64(256).to_bytes_be_min(), vec![1, 0]);

        // 255 returns [255]
        assert_eq!(BigNumber::from_u64(255).to_bytes_be_min(), vec![255]);

        // 65535 returns [255, 255]
        assert_eq!(BigNumber::from_u64(65535).to_bytes_be_min(), vec![255, 255]);
    }

    #[test]
    fn test_to_bytes_le_min() {
        assert!(BigNumber::zero().to_bytes_le_min().is_empty());
        assert_eq!(BigNumber::from_u64(256).to_bytes_le_min(), vec![0, 1]);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let values = [0u64, 1, 255, 256, 65535, 65536, u64::MAX];
        for val in values {
            let n = BigNumber::from_u64(val);
            let bytes_be = n.to_bytes_be_min();
            let bytes_le = n.to_bytes_le_min();

            let from_be = BigNumber::from_bytes_be(&bytes_be);
            let from_le = BigNumber::from_bytes_le(&bytes_le);

            assert_eq!(n, from_be, "BE roundtrip failed for {}", val);
            assert_eq!(n, from_le, "LE roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_hex_roundtrip_edge_cases() {
        let cases = [
            "0",
            "1",
            "ff",
            "100",
            "ffff",
            "10000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ];

        for hex in cases {
            let n = BigNumber::from_hex(hex).unwrap();
            let back = n.to_hex();
            let n2 = BigNumber::from_hex(&back).unwrap();
            assert_eq!(n, n2, "Roundtrip failed for {}", hex);
        }
    }

    #[test]
    fn test_from_signed_bytes_be() {
        // Positive number
        let pos = BigNumber::from_signed_bytes_be(&[0x7f, 0xff]);
        assert!(pos.is_positive());

        // Negative number (high bit set)
        let neg = BigNumber::from_signed_bytes_be(&[0xff, 0xff]);
        assert!(neg.is_negative());
    }

    #[test]
    fn test_dec_string_roundtrip() {
        let values = [
            "0",
            "1",
            "-1",
            "123456789",
            "-987654321",
            "99999999999999999999999999999999999999999999",
        ];

        for dec in values {
            let n = BigNumber::from_dec_str(dec).unwrap();
            let back = n.to_dec_string();
            assert_eq!(back, dec, "Dec roundtrip failed for {}", dec);
        }
    }

    #[test]
    fn test_to_u64_overflow() {
        let too_big = BigNumber::from_hex("10000000000000000").unwrap(); // 2^64
        assert!(too_big.to_u64().is_none());
    }

    #[test]
    fn test_to_i64_negative() {
        let neg = BigNumber::from_i64(-42);
        assert_eq!(neg.to_i64(), Some(-42));
    }

    #[test]
    fn test_hash_trait() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(BigNumber::from_i64(42));
        set.insert(BigNumber::from_i64(42));
        assert_eq!(set.len(), 1);

        set.insert(BigNumber::from_i64(43));
        assert_eq!(set.len(), 2);
    }
}
