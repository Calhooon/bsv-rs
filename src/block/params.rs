//! Chain parameters: bitcoin-sv@6504a3af `src/chainparams.cpp`
//! (`CMainParams` 1033-1160, `CTestNetParams` 1329-1428, `CRegTestParams`
//! 1456-1533) and `src/consensus/params.h:41-49`. Checkpoints, the genesis
//! hash and other unused chain parameters belong to the host. Script activation
//! heights are the defaults at bitcoin-sv@879fc8b `src/chainparams.cpp:18-26`.

use super::{POW_LIMIT_MAIN, POW_LIMIT_REGTEST, POW_LIMIT_TEST};
use crate::primitives::U256;

/// Two weeks: `consensus.nPowTargetTimespan` on every chain
/// (src/chainparams.cpp:1050, 1346, 1474).
const TWO_WEEKS: i64 = 14 * 24 * 60 * 60;
/// Ten minutes: `consensus.nPowTargetSpacing` on every chain
/// (src/chainparams.cpp:1051, 1347, 1475).
const TEN_MINUTES: i64 = 10 * 60;

/// Consensus parameters for difficulty and script activation, per chain.
///
/// The fields are public so a host can describe another chain starting from
/// one of the constructors; new fields may be added in a minor release.
/// ```
/// use bsv_rs::block::ChainParams;
/// let main = ChainParams::main();
/// assert_eq!(main.difficulty_adjustment_interval(), 2016);
/// assert_eq!(main.pow_limit_bits(), 0x1d00ffff);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainParams {
    /// `consensus.powLimit`: the easiest target a header may carry.
    pub pow_limit: U256,
    /// `consensus.nPowTargetSpacing`, seconds.
    pub pow_target_spacing: i64,
    /// `consensus.nPowTargetTimespan`, seconds.
    pub pow_target_timespan: i64,
    /// `consensus.fPowAllowMinDifficultyBlocks`: testnet's 20-minute rule.
    pub allow_min_difficulty_blocks: bool,
    /// `consensus.fPowNoRetargeting`: regtest's constant difficulty.
    pub no_retargeting: bool,
    /// `consensus.daaHeight`: the DAA governs a header whose parent is at or
    /// above this height (src/pow.cpp:111).
    pub daa_height: u32,
    /// Genesis activation, inclusive (`chainparams.cpp:18-21` at `879fc8b`).
    /// Match `-genesisactivationheight` (`init.cpp:2473-2477` at that pin)
    /// with [`Self::with_activation_heights`]. The node refuses zero or
    /// negative values (`configscriptpolicy.cpp:310-321`) and, reading the
    /// option as a signed 32-bit integer (`init.cpp:2474`), a height of 2^31
    /// or more, which this `u32` accepts.
    pub genesis_height: u32,
    /// Chronicle activation, inclusive (`chainparams.cpp:23-26` at `879fc8b`).
    /// Match `-chronicleactivationheight` (`init.cpp:2478-2481` at that pin)
    /// with [`Self::with_activation_heights`]. The node refuses zero or
    /// negative values (`configscriptpolicy.cpp:353-364`) and, reading the
    /// option as a signed 32-bit integer (`init.cpp:2478`), a height of 2^31
    /// or more, which this `u32` accepts.
    pub chronicle_height: u32,
}

impl ChainParams {
    /// `CMainParams` (src/chainparams.cpp:1047-1053, `daaHeight` 504031 at 1068).
    /// ```
    /// assert_eq!(bsv_rs::block::ChainParams::main().daa_height, 504_031);
    /// ```
    pub fn main() -> Self {
        Self {
            pow_limit: POW_LIMIT_MAIN,
            pow_target_spacing: TEN_MINUTES,
            pow_target_timespan: TWO_WEEKS,
            allow_min_difficulty_blocks: false,
            no_retargeting: false,
            daa_height: 504_031,
            genesis_height: 620_538,
            chronicle_height: 943_816,
        }
    }

    /// `CTestNetParams` (src/chainparams.cpp:1343-1349, the minimum-difficulty
    /// rule on; `daaHeight` 1188697 at 1364).
    /// ```
    /// assert!(bsv_rs::block::ChainParams::test().allow_min_difficulty_blocks);
    /// ```
    pub fn test() -> Self {
        Self {
            pow_limit: POW_LIMIT_TEST,
            pow_target_spacing: TEN_MINUTES,
            pow_target_timespan: TWO_WEEKS,
            allow_min_difficulty_blocks: true,
            no_retargeting: false,
            daa_height: 1_188_697,
            genesis_height: 1_344_302,
            chronicle_height: 1_713_168,
        }
    }

    /// `CRegTestParams` (src/chainparams.cpp:1471-1477, no retargeting;
    /// `daaHeight` 0 at 1490).
    /// The SV node uses Genesis 10,000 and Chronicle 15,000
    /// (`bitcoin-sv@879fc8b src/chainparams.cpp:21,26`). Teranode's regtest uses
    /// 100 and 200 (`go-chaincfg` v1.6.2 `params.go:475-476`); fixtures against
    /// it use `Self::regtest().with_activation_heights(100, 200)?`.
    /// ```
    /// let regtest = bsv_rs::block::ChainParams::regtest();
    /// assert!(regtest.no_retargeting);
    /// assert_eq!(regtest.pow_limit_bits(), 0x207fffff);
    /// ```
    pub fn regtest() -> Self {
        Self {
            pow_limit: POW_LIMIT_REGTEST,
            pow_target_spacing: TEN_MINUTES,
            pow_target_timespan: TWO_WEEKS,
            allow_min_difficulty_blocks: true,
            no_retargeting: true,
            daa_height: 0,
            genesis_height: 10_000,
            chronicle_height: 15_000,
        }
    }

    /// `DifficultyAdjustmentInterval()` (src/consensus/params.h:47-49); zero
    /// for a spacing of zero, where the node divides by zero.
    /// ```
    /// assert_eq!(bsv_rs::block::ChainParams::test().difficulty_adjustment_interval(), 2016);
    /// ```
    pub fn difficulty_adjustment_interval(&self) -> i64 {
        self.pow_target_timespan
            .checked_div(self.pow_target_spacing)
            .unwrap_or(0)
    }

    /// `GetCompact(powLimit)`: the bits of a minimum-difficulty header, and
    /// `GetNextWorkRequired`'s answer for the genesis (src/pow.cpp:101-104).
    /// ```
    /// assert_eq!(bsv_rs::block::ChainParams::main().pow_limit_bits(), 0x1d00ffff);
    /// ```
    pub fn pow_limit_bits(&self) -> u32 {
        self.pow_limit.to_compact()
    }

    /// How many headers, ending at the parent, `next_work_required` may read
    /// for a header whose parent is at `prev_height`: the parent alone under
    /// regtest's rule; 147 under the DAA (the parent back to the median of
    /// three around `prev - 144`); a full interval for the legacy retarget at
    /// a boundary and for testnet's walk back; 17 for the emergency
    /// adjustment (the median time past at `prev - 6`). Never more than the
    /// chain holds.
    /// ```
    /// use bsv_rs::block::ChainParams;
    /// assert_eq!(ChainParams::main().window_depth(886_000), 147);
    /// assert_eq!(ChainParams::regtest().window_depth(886_000), 1);
    /// ```
    pub fn window_depth(&self, prev_height: u32) -> u32 {
        let depth = if self.no_retargeting {
            1
        } else if prev_height >= self.daa_height {
            147
        } else {
            let interval = self.difficulty_adjustment_interval();
            if self.allow_min_difficulty_blocks
                || (i64::from(prev_height) + 1).checked_rem(interval) == Some(0)
            {
                u32::try_from(interval).unwrap_or(u32::MAX)
            } else {
                17
            }
        };
        depth.min(prev_height.saturating_add(1))
    }
}
