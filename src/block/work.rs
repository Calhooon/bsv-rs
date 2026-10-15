//! Work: bitcoin-sv@6504a3af `src/block_index.cpp:114-127` and
//! `src/block_index.h:349,663-664`, through bsv-script-lean@50d437b
//! `lean/BsvChain/Header.lean:100-108` (#64).

use super::CompactTarget;
use crate::primitives::U256;
use crate::Result;

/// Numerically ordered accumulated work, wrapping at 256 bits.
/// ```
/// use bsv_rs::block::ChainWork;
/// assert!(ChainWork::from_bits(0x1d00ffff) > ChainWork::ZERO);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ChainWork(U256);

impl ChainWork {
    /// No accumulated work.
    /// ```
    /// assert_eq!(bsv_rs::block::ChainWork::ZERO.to_be_bytes(), [0; 32]);
    /// ```
    pub const ZERO: Self = Self(U256::ZERO);

    /// `GetBlockProof`: `~target / (target + 1) + 1`, or zero for invalid bits.
    /// No network limit is applied here.
    /// ```
    /// use bsv_rs::block::ChainWork;
    /// assert_eq!(ChainWork::from_bits(0x1d00ffff), ChainWork::from_hex("100010001")?);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_bits(bits: u32) -> Self {
        let compact = CompactTarget::from_bits(bits);
        if !compact.is_valid() {
            return Self::ZERO;
        }
        let target = compact.target;
        // No compact representation can decode to U256::MAX: its mantissa
        // carries at most 23 bits, so adding one cannot overflow here.
        // so the division cannot miss; were it to, zero is this function's answer
        // for a target with no work, as above.
        let Some(proof) = target.not().checked_div(target.wrapping_add(U256::ONE)) else {
            return Self::ZERO;
        };
        Self(proof.wrapping_add(U256::ONE))
    }

    /// Accumulate modulo 2^256.
    /// ```
    /// use bsv_rs::block::ChainWork;
    /// let work = ChainWork::from_bits(0x1d00ffff);
    /// assert_eq!(work.wrapping_add(ChainWork::ZERO), work);
    /// ```
    pub fn wrapping_add(self, other: Self) -> Self {
        Self(self.0.wrapping_add(other.0))
    }

    /// Work difference, returning `None` for underflow.
    /// ```
    /// use bsv_rs::block::ChainWork;
    /// assert_eq!(ChainWork::ZERO.checked_sub(ChainWork::from_bits(0x1d00ffff)), None);
    /// ```
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        (self >= other).then(|| Self(self.0.wrapping_sub(other.0)))
    }

    /// Exactly 64 lowercase hex digits in numeric order.
    /// ```
    /// assert_eq!(bsv_rs::block::ChainWork::ZERO.to_hex(), "0".repeat(64));
    /// ```
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Read 1 to 64 hex digits, refusing malformed input without a zero fallback.
    /// ```
    /// use bsv_rs::block::ChainWork;
    /// assert_eq!(ChainWork::from_hex("0")?, ChainWork::ZERO);
    /// assert!(ChainWork::from_hex("oops").is_err());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_hex(s: &str) -> Result<Self> {
        U256::from_hex(s).map(Self)
    }

    /// Write 32 big-endian bytes.
    /// ```
    /// assert_eq!(bsv_rs::block::ChainWork::ZERO.to_be_bytes(), [0; 32]);
    /// ```
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Read 32 big-endian bytes.
    /// ```
    /// use bsv_rs::block::ChainWork;
    /// assert_eq!(ChainWork::from_be_bytes([0; 32]), ChainWork::ZERO);
    /// ```
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(U256::from_be_bytes(bytes))
    }

    /// Borrow the underlying fixed-width number.
    /// ```
    /// assert!(bsv_rs::block::ChainWork::ZERO.as_u256().is_zero());
    /// ```
    pub fn as_u256(&self) -> &U256 {
        &self.0
    }
}
