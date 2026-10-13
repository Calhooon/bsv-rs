//! Fixed-width arithmetic for targets and chain work.
//!
//! Node semantics: bitcoin-sv@6504a3af `src/arith_uint256.h:22-280` and
//! `src/arith_uint256.cpp:20-110`, through bsv-script-lean@50d437b
//! `lean/BsvChain/Header.lean:71-108` (#63, #64).

use std::cmp::Ordering;
use std::ops::{Not, Shl, Shr};

use crate::{Error, Result};

/// Unsigned 256-bit integer, stored as four little-endian limbs.
/// Arithmetic wraps modulo 2^256. This type is not constant-time.
///
/// ```
/// use bsv_rs::primitives::U256;
/// assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256(pub(crate) [u64; 4]);

impl U256 {
    /// Zero.
    /// ```
    /// assert!(bsv_rs::primitives::U256::ZERO.is_zero());
    /// ```
    pub const ZERO: Self = Self([0; 4]);
    /// One.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::ONE.low_u64(), 1);
    /// ```
    pub const ONE: Self = Self([1, 0, 0, 0]);
    /// The largest representable value, 2^256 - 1.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::MAX.bits(), 256);
    /// ```
    pub const MAX: Self = Self([u64::MAX; 4]);

    /// Zero-extend a 64-bit integer.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_u64(1), U256::ONE);
    /// ```
    pub const fn from_u64(value: u64) -> Self {
        Self([value, 0, 0, 0])
    }

    /// Read 32 little-endian bytes.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_le_bytes([255; 32]), U256::MAX);
    /// ```
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0; 4];
        let (chunks, _) = bytes.as_slice().as_chunks::<8>();
        for (limb, chunk) in limbs.iter_mut().zip(chunks) {
            *limb = u64::from_le_bytes(*chunk);
        }
        Self(limbs)
    }

    /// Write 32 little-endian bytes.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::ONE.to_le_bytes()[0], 1);
    /// ```
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        let (chunks, _) = bytes.as_mut_slice().as_chunks_mut::<8>();
        for (chunk, limb) in chunks.iter_mut().zip(self.0) {
            *chunk = limb.to_le_bytes();
        }
        bytes
    }

    /// Read 32 big-endian bytes.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_be_bytes([255; 32]), U256::MAX);
    /// ```
    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self::from_le_bytes(bytes)
    }

    /// Write 32 big-endian bytes.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::ONE.to_be_bytes()[31], 1);
    /// ```
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }

    /// Read 1 to 64 ASCII hex digits. Signs, prefixes and whitespace are refused.
    /// Odd lengths and either letter case are accepted.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_hex("fF")?.low_u64(), 255);
    /// assert!(U256::from_hex("0x01").is_err());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_hex(s: &str) -> Result<Self> {
        if s.is_empty() || s.len() > 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidHex("expected 1 to 64 hex digits".into()));
        }
        let mut bytes = [0; 32];
        for (i, digit) in s.bytes().rev().enumerate() {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                _ => digit - b'A' + 10,
            };
            bytes[i / 2] |= nibble << ((i % 2) * 4);
        }
        Ok(Self::from_le_bytes(bytes))
    }

    /// Write exactly 64 lowercase hex digits in numeric (big-endian) order.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::ZERO.to_hex(), "0".repeat(64));
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_be_bytes())
    }

    /// Whether every bit is zero.
    /// ```
    /// assert!(!bsv_rs::primitives::U256::ONE.is_zero());
    /// ```
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    /// Number of significant bits, or zero for zero.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::from_u64(128).bits(), 8);
    /// ```
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return i as u32 * 64 + 64 - self.0[i].leading_zeros();
            }
        }
        0
    }

    /// The low 64 bits.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::MAX.low_u64(), u64::MAX);
    /// ```
    pub const fn low_u64(&self) -> u64 {
        self.0[0]
    }

    /// Complement all 256 bits.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::ZERO.not(), U256::MAX);
    /// ```
    #[allow(
        clippy::should_implement_trait,
        reason = "The specified inherent API also implements the matching operator trait."
    )]
    pub fn not(self) -> Self {
        Self(self.0.map(|limb| !limb))
    }

    /// Add modulo 2^256.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
    /// ```
    pub fn wrapping_add(self, other: Self) -> Self {
        let mut limbs = [0; 4];
        let mut carry = 0u128;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let sum = self.0[i] as u128 + other.0[i] as u128 + carry;
            *limb = sum as u64;
            carry = sum >> 64;
        }
        Self(limbs)
    }

    /// Subtract modulo 2^256.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::ZERO.wrapping_sub(U256::ONE), U256::MAX);
    /// ```
    pub fn wrapping_sub(self, other: Self) -> Self {
        self.wrapping_add(other.wrapping_neg())
    }

    /// Negate modulo 2^256.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::ONE.wrapping_neg(), U256::MAX);
    /// ```
    pub fn wrapping_neg(self) -> Self {
        self.not().wrapping_add(Self::ONE)
    }

    /// Multiply by a 64-bit integer modulo 2^256.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_u64(7).wrapping_mul_u64(6), U256::from_u64(42));
    /// ```
    pub fn wrapping_mul_u64(self, other: u64) -> Self {
        let mut limbs = [0; 4];
        let mut carry = 0u128;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let product = self.0[i] as u128 * other as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        Self(limbs)
    }

    /// Integer division, returning `None` for a zero divisor.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_u64(7).checked_div(U256::from_u64(2)), Some(U256::from_u64(3)));
    /// assert_eq!(U256::ONE.checked_div(U256::ZERO), None);
    /// ```
    pub fn checked_div(self, divisor: Self) -> Option<Self> {
        if divisor.is_zero() {
            return None;
        }
        if self < divisor {
            return Some(Self::ZERO);
        }
        let shift = self.bits() - divisor.bits();
        let mut aligned = divisor.shl(shift);
        let mut remainder = self;
        let mut quotient = Self::ZERO;
        for bit in (0..=shift).rev() {
            if remainder >= aligned {
                remainder = remainder.wrapping_sub(aligned);
                quotient.0[bit as usize / 64] |= 1u64 << (bit % 64);
            }
            aligned = aligned.shr(1);
        }
        Some(quotient)
    }

    /// Shift left, discarding high bits. A shift of 256 or more gives zero.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::ONE.shl(8), U256::from_u64(256));
    /// assert_eq!(U256::ONE.shl(256), U256::ZERO);
    /// ```
    #[allow(
        clippy::should_implement_trait,
        reason = "The specified inherent API also implements the matching operator trait."
    )]
    pub fn shl(self, shift: u32) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let (words, bits) = ((shift / 64) as usize, shift % 64);
        let mut out = [0; 4];
        for (i, limb) in out.iter_mut().enumerate().skip(words) {
            *limb = self.0[i - words] << bits;
            if bits != 0 && i > words {
                *limb |= self.0[i - words - 1] >> (64 - bits);
            }
        }
        Self(out)
    }

    /// Shift right with zero fill. A shift of 256 or more gives zero.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_u64(256).shr(8), U256::ONE);
    /// ```
    #[allow(
        clippy::should_implement_trait,
        reason = "The specified inherent API also implements the matching operator trait."
    )]
    pub fn shr(self, shift: u32) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let (words, bits) = ((shift / 64) as usize, shift % 64);
        let mut out = [0; 4];
        for (i, limb) in out.iter_mut().enumerate().take(4 - words) {
            *limb = self.0[i + words] >> bits;
            if bits != 0 && i + words + 1 < 4 {
                *limb |= self.0[i + words + 1] << (64 - bits);
            }
        }
        Self(out)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}
impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Not for U256 {
    type Output = Self;
    fn not(self) -> Self {
        U256::not(self)
    }
}
impl Shl<u32> for U256 {
    type Output = Self;
    fn shl(self, shift: u32) -> Self {
        U256::shl(self, shift)
    }
}
impl Shr<u32> for U256 {
    type Output = Self;
    fn shr(self, shift: u32) -> Self {
        U256::shr(self, shift)
    }
}
