//! Compact targets: bitcoin-sv@6504a3af `src/arith_uint256.cpp:182-224`,
//! through bsv-script-lean@50d437b `lean/BsvChain/Header.lean:71-96` (#63).

use crate::primitives::{Hash32, U256};

/// A decoded compact target, retaining the node's independent flags.
/// ```
/// use bsv_rs::block::CompactTarget;
/// assert!(CompactTarget::from_bits(0x1d00ffff).is_valid());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactTarget {
    /// Magnitude truncated to 256 bits.
    pub target: U256,
    /// Nonzero mantissa with the sign bit set.
    pub negative: bool,
    /// Significant bits were lost above bit 255.
    pub overflow: bool,
}

impl CompactTarget {
    /// Decode `SetCompact`, including truncation before the small-exponent flags.
    /// ```
    /// use bsv_rs::block::CompactTarget;
    /// assert!(CompactTarget::from_bits(0x21123456).overflow);
    /// assert!(!CompactTarget::from_bits(0x01803456).negative);
    /// ```
    pub fn from_bits(bits: u32) -> Self {
        let size = bits >> 24;
        let mut word = bits & 0x007f_ffff;
        let target = if size <= 3 {
            word >>= 8 * (3 - size);
            U256::from_u64(word as u64)
        } else {
            U256::from_u64(word as u64).shl(8 * (size - 3))
        };
        Self {
            target,
            negative: word != 0 && bits & 0x0080_0000 != 0,
            overflow: word != 0
                && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32)),
        }
    }

    /// Whether the target is positive, nonzero and non-overflowing.
    /// This does not apply a network limit.
    /// ```
    /// assert!(!bsv_rs::block::CompactTarget::from_bits(0).is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        !self.negative && !self.overflow && !self.target.is_zero()
    }
}

impl U256 {
    /// Encode `GetCompact(false)`, losing low bits beyond the compact mantissa.
    /// ```
    /// assert_eq!(bsv_rs::primitives::U256::from_u64(128).to_compact(), 0x02008000);
    /// ```
    pub fn to_compact(&self) -> u32 {
        self.to_compact_signed(false)
    }

    /// Encode `GetCompact(fNegative)`; zero never carries a sign.
    /// Source: bitcoin-sv@6504a3af `src/arith_uint256.cpp:203-224`.
    /// ```
    /// use bsv_rs::primitives::U256;
    /// assert_eq!(U256::from_u64(128).to_compact_signed(true), 0x02808000);
    /// assert_eq!(U256::ZERO.to_compact_signed(true), 0);
    /// ```
    pub fn to_compact_signed(&self, negative: bool) -> u32 {
        let mut size = self.bits().div_ceil(8);
        let mut compact = if size <= 3 {
            (self.low_u64() << (8 * (3 - size))) as u32
        } else {
            self.shr(8 * (size - 3)).low_u64() as u32
        };
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        compact |= size << 24;
        if negative && compact & 0x007f_ffff != 0 {
            compact |= 0x0080_0000;
        }
        compact
    }
}

/// Mainnet limit: bitcoin-sv@6504a3af `src/chainparams.cpp:1047-1048`.
/// ```
/// assert_eq!(bsv_rs::block::POW_LIMIT_MAIN.to_compact(), 0x1d00ffff);
/// ```
pub const POW_LIMIT_MAIN: U256 = U256([u64::MAX, u64::MAX, u64::MAX, 0xffff_ffff]);
/// Testnet limit: bitcoin-sv@6504a3af `src/chainparams.cpp:1343-1344`.
/// ```
/// assert_eq!(bsv_rs::block::POW_LIMIT_TEST, bsv_rs::block::POW_LIMIT_MAIN);
/// ```
pub const POW_LIMIT_TEST: U256 = POW_LIMIT_MAIN;
/// STN limit: bitcoin-sv@6504a3af `src/chainparams.cpp:1214`.
/// ```
/// assert_eq!(bsv_rs::block::POW_LIMIT_STN, bsv_rs::block::POW_LIMIT_MAIN);
/// ```
pub const POW_LIMIT_STN: U256 = POW_LIMIT_MAIN;
/// Regtest limit: bitcoin-sv@6504a3af `src/chainparams.cpp:1471-1472`.
/// ```
/// assert_eq!(bsv_rs::block::POW_LIMIT_REGTEST.to_compact(), 0x207fffff);
/// ```
pub const POW_LIMIT_REGTEST: U256 = U256([u64::MAX, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff]);

/// Why `CheckProofOfWork` refused a header. All map to the node's `high-hash`.
/// Source: bitcoin-sv@6504a3af `src/pow.cpp:150-171`, sibling #63.
/// ```
/// use bsv_rs::block::PowError;
/// assert_eq!(PowError::BitsZero { bits: 0 }.reject_reason(), "high-hash");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PowError {
    /// Negative target.
    #[error("negative compact target: {bits:#010x}")]
    BitsNegative {
        /// The header's compact target.
        bits: u32,
    },
    /// Zero target, including a value truncated to zero.
    #[error("zero compact target: {bits:#010x}")]
    BitsZero {
        /// The header's compact target.
        bits: u32,
    },
    /// Target overflow.
    #[error("overflowing compact target: {bits:#010x}")]
    BitsOverflow {
        /// The header's compact target.
        bits: u32,
    },
    /// Target exceeds the supplied network limit.
    #[error("compact target above proof-of-work limit: {bits:#010x}")]
    BitsAboveLimit {
        /// The header's compact target.
        bits: u32,
    },
    /// Hash exceeds the decoded target.
    #[error("hash above compact target: {bits:#010x}")]
    HighHash {
        /// The header's compact target.
        bits: u32,
    },
}

impl PowError {
    /// The node's block rejection word for every proof-of-work refusal.
    /// ```
    /// assert_eq!(bsv_rs::block::PowError::HighHash { bits: 1 }.reject_reason(), "high-hash");
    /// ```
    pub fn reject_reason(&self) -> &'static str {
        "high-hash"
    }
}

/// Check an internal-order hash against `bits` and the supplied network limit.
/// Does not check whether `bits` is the chain's required difficulty.
/// Refusal order follows bitcoin-sv@6504a3af `src/pow.cpp:159-167`.
/// ```
/// use bsv_rs::block::{check_proof_of_work, POW_LIMIT_MAIN};
/// assert!(check_proof_of_work(&[0; 32], 0x1d00ffff, &POW_LIMIT_MAIN).is_ok());
/// ```
pub fn check_proof_of_work(hash: &Hash32, bits: u32, pow_limit: &U256) -> Result<(), PowError> {
    let compact = CompactTarget::from_bits(bits);
    if compact.negative {
        return Err(PowError::BitsNegative { bits });
    }
    if compact.target.is_zero() {
        return Err(PowError::BitsZero { bits });
    }
    if compact.overflow {
        return Err(PowError::BitsOverflow { bits });
    }
    if compact.target > *pow_limit {
        return Err(PowError::BitsAboveLimit { bits });
    }
    if U256::from_le_bytes(*hash) > compact.target {
        return Err(PowError::HighHash { bits });
    }
    Ok(())
}
