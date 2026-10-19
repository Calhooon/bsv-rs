//! Difficulty: `GetNextWorkRequired` and its three regimes, bitcoin-sv@6504a3af
//! `src/pow.cpp:22-148,177-297`, with `GetMedianTimePast`
//! (`src/block_index.h:720-737`) and the chain work `SetChainWork` sums
//! (`src/block_index.h:661-666`). Moved from chaintracks-cloudflare@74cc110
//! `src/consensus.rs`; header validity and proof of work are sibling #63's
//! (`check_proof_of_work`), checkpoints the host's.

use super::{ChainParams, ChainWork, CompactTarget};
use crate::primitives::U256;

/// What the rule reads of a header: its height, time and bits.
/// ```
/// let link = bsv_rs::block::HeaderLink { height: 0, time: 1231006505, bits: 0x1d00ffff };
/// assert_eq!(link.height, 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeaderLink {
    /// Height on the chain.
    pub height: u32,
    /// `nTime`, seconds since the Unix epoch.
    pub time: u32,
    /// `nBits`, the compact target.
    pub bits: u32,
}

/// The ancestors of the parent being extended, by height: the node's
/// `CBlockIndex::GetAncestor` and `GetPrev`. The host has checked the hash
/// links; the rule reads only heights, times and bits.
///
/// A slice of [`HeaderLink`]s ascending by consecutive height implements it.
/// ```
/// use bsv_rs::block::{HeaderAncestry, HeaderLink};
/// let chain = [HeaderLink { height: 5, time: 1, bits: 0x207fffff }];
/// assert_eq!(chain[..].link_at(5), Some(chain[0]));
/// assert_eq!(chain[..].link_at(4), None);
/// ```
pub trait HeaderAncestry {
    /// The header at `height` on this chain, or `None` if the host does not
    /// hold it.
    fn link_at(&self, height: u32) -> Option<HeaderLink>;

    /// `pindexLast->GetChainWork() - pindexFirst->GetChainWork()`. The default
    /// sums `GetBlockProof` over `first + 1..=last` ([`chain_work_between`]);
    /// a host that stores chain work may answer the difference directly.
    fn work_between(&self, first: u32, last: u32) -> Result<ChainWork, DifficultyError> {
        chain_work_between(self, first, last)
    }
}

impl HeaderAncestry for [HeaderLink] {
    fn link_at(&self, height: u32) -> Option<HeaderLink> {
        let first = self.first()?.height;
        let link = *self.get(height.checked_sub(first)? as usize)?;
        (link.height == height).then_some(link)
    }
}

/// Why the rule has no answer for a header.
/// ```
/// use bsv_rs::block::DifficultyError;
/// assert_eq!(
///     DifficultyError::MissingAncestor { height: 7 }.to_string(),
///     "the difficulty rule needs the header at height 7"
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DifficultyError {
    /// The rule reads a header the host does not hold.
    #[error("the difficulty rule needs the header at height {height}")]
    MissingAncestor {
        /// Height of the header the rule reads.
        height: u32,
    },
    /// The parent is too low for the regime, where the node asserts
    /// (src/pow.cpp:73, 275): the emergency adjustment below height 7, the DAA
    /// below one adjustment interval.
    #[error("no difficulty answer after a parent at height {prev_height}")]
    ChainTooShort {
        /// The parent's height.
        prev_height: u32,
    },
    /// The parameters have no adjustment interval (a spacing or timespan
    /// that is not positive), where the node divides by zero.
    #[error("the chain parameters have no difficulty adjustment interval")]
    InvalidParams,
    /// `ComputeTarget` divides by zero work, where the node throws
    /// (src/pow.cpp:207, `base_uint::operator/=`): every header between the
    /// two carries bits with no work.
    #[error("no work between heights {first} and {last}")]
    ZeroWork {
        /// Height of the first suitable block.
        first: u32,
        /// Height of the last suitable block.
        last: u32,
    },
}

/// testnet's rule: a header more than twice the spacing after its parent
/// may carry the minimum difficulty (src/pow.cpp:44-51, 264-271).
fn min_difficulty_after(params: &ChainParams, prev: HeaderLink) -> i64 {
    i64::from(prev.time).saturating_add(params.pow_target_spacing.saturating_mul(2))
}

fn get<C: HeaderAncestry + ?Sized>(chain: &C, height: u32) -> Result<HeaderLink, DifficultyError> {
    chain
        .link_at(height)
        .ok_or(DifficultyError::MissingAncestor { height })
}

/// The `GetBlockProof` sum over heights `first + 1..=last`, modulo 2^256:
/// the node's `nChainWork` difference (`SetChainWork`, src/block_index.h:661-666).
/// Zero when `last <= first`.
/// ```
/// use bsv_rs::block::{chain_work_between, ChainWork, HeaderLink};
/// let chain: Vec<_> = (0..3).map(|height| HeaderLink { height, time: 0, bits: 0x1d00ffff }).collect();
/// let one = ChainWork::from_bits(0x1d00ffff);
/// assert_eq!(chain_work_between(&chain[..], 0, 2)?, one.wrapping_add(one));
/// # Ok::<(), bsv_rs::block::DifficultyError>(())
/// ```
pub fn chain_work_between<C: HeaderAncestry + ?Sized>(
    chain: &C,
    first: u32,
    last: u32,
) -> Result<ChainWork, DifficultyError> {
    let mut sum = ChainWork::ZERO;
    for height in first.saturating_add(1)..=last {
        sum = sum.wrapping_add(ChainWork::from_bits(get(chain, height)?.bits));
    }
    Ok(sum)
}

/// `GetMedianTimePast` (src/block_index.h:720-737): the median of the times
/// of the header at `height` and up to ten before it (fewer only near the
/// genesis).
/// ```
/// use bsv_rs::block::{median_time_past, HeaderLink};
/// let chain: Vec<_> = (0..11).map(|height| HeaderLink { height, time: 100 * height, bits: 0 }).collect();
/// assert_eq!(median_time_past(&chain[..], 10)?, 500);
/// assert_eq!(median_time_past(&chain[..], 1)?, 100);
/// # Ok::<(), bsv_rs::block::DifficultyError>(())
/// ```
pub fn median_time_past<C: HeaderAncestry + ?Sized>(
    chain: &C,
    height: u32,
) -> Result<i64, DifficultyError> {
    let mut times = Vec::with_capacity(11);
    for h in height.saturating_sub(10)..=height {
        times.push(i64::from(get(chain, h)?.time));
    }
    times.sort_unstable();
    Ok(times[times.len() / 2])
}

/// `GetNextWorkRequired(pindexPrev, pblock)` (src/pow.cpp:95-117): the bits a
/// header with time `new_time` must carry on top of the parent at
/// `prev_height`. Regtest keeps the parent's bits (:106-109), a parent at or
/// above `daa_height` takes the DAA ([`next_cash_work_required`]), and
/// below it the legacy retarget with the emergency adjustment and testnet's
/// minimum-difficulty rule (`GetNextEDAWorkRequired`, :22-93). The genesis
/// has no parent; its answer is [`ChainParams::pow_limit_bits`] (:101-104).
///
/// A host enforces it as `ContextualCheckBlockHeader` does: bits that differ
/// are `bad-diffbits` (src/validation.cpp:5943-5948).
/// ```
/// use bsv_rs::block::{next_work_required, ChainParams, HeaderLink};
/// let chain = [HeaderLink { height: 7, time: 1000, bits: 0x2000ffff }];
/// assert_eq!(next_work_required(&ChainParams::regtest(), &chain[..], 7, 0)?, 0x2000ffff);
/// # Ok::<(), bsv_rs::block::DifficultyError>(())
/// ```
pub fn next_work_required<C: HeaderAncestry + ?Sized>(
    params: &ChainParams,
    chain: &C,
    prev_height: u32,
    new_time: u32,
) -> Result<u32, DifficultyError> {
    let prev = get(chain, prev_height)?;
    if params.no_retargeting {
        return Ok(prev.bits);
    }
    if prev.height >= params.daa_height {
        return next_cash_work_required(params, chain, prev_height, new_time);
    }
    next_eda_work_required(params, chain, prev, new_time)
}

/// `GetNextEDAWorkRequired` (src/pow.cpp:22-93): the legacy retarget every
/// interval, testnet's minimum-difficulty rule, and the emergency adjustment.
fn next_eda_work_required<C: HeaderAncestry + ?Sized>(
    params: &ChainParams,
    chain: &C,
    prev: HeaderLink,
    new_time: u32,
) -> Result<u32, DifficultyError> {
    let interval = params.difficulty_adjustment_interval();
    if interval <= 0 {
        return Err(DifficultyError::InvalidParams);
    }
    let height = i64::from(prev.height) + 1;
    if height % interval == 0 {
        // height is a positive multiple of the interval, so the first block
        // of the interval is a height on the chain (the node's assert, :31)
        let first = get(chain, (height - interval) as u32)?;
        return Ok(calculate_next_work_required(
            params,
            prev,
            i64::from(first.time),
        ));
    }
    let pow_limit_bits = params.pow_limit_bits();
    if params.allow_min_difficulty_blocks {
        if i64::from(new_time) > min_difficulty_after(params, prev) {
            return Ok(pow_limit_bits);
        }
        let mut index = prev;
        while index.height != 0
            && i64::from(index.height) % interval != 0
            && index.bits == pow_limit_bits
        {
            index = get(chain, index.height - 1)?;
        }
        return Ok(index.bits);
    }
    if prev.bits == pow_limit_bits {
        return Ok(pow_limit_bits);
    }
    let six = prev
        .height
        .checked_sub(6)
        .ok_or(DifficultyError::ChainTooShort {
            prev_height: prev.height,
        })?;
    let mtp6 = median_time_past(chain, prev.height)? - median_time_past(chain, six)?;
    if mtp6 < 12 * 3600 {
        return Ok(prev.bits);
    }
    let mut pow = CompactTarget::from_bits(prev.bits).target;
    pow = pow.wrapping_add(pow.shr(2));
    if pow > params.pow_limit {
        pow = params.pow_limit;
    }
    Ok(pow.to_compact())
}

/// `CalculateNextWorkRequired` (src/pow.cpp:119-148): the two-week retarget,
/// the timespan clamped to a quarter and four times the target. The node's
/// `bnNew *= nActualTimespan` takes the `uint32_t` overload
/// (src/arith_uint256.cpp:52-60); the clamped timespan is far below 2^32.
/// ```
/// use bsv_rs::block::{calculate_next_work_required, ChainParams, HeaderLink};
/// // pow_tests.cpp `get_next_work`: block 32255 against the time of block 30240
/// let prev = HeaderLink { height: 32255, time: 1262152739, bits: 0x1d00ffff };
/// assert_eq!(calculate_next_work_required(&ChainParams::main(), prev, 1261130161), 0x1d00d86a);
/// ```
pub fn calculate_next_work_required(
    params: &ChainParams,
    prev: HeaderLink,
    first_block_time: i64,
) -> u32 {
    if params.no_retargeting {
        return prev.bits;
    }
    let timespan = params.pow_target_timespan;
    // max then min, as the node's two ifs: no panic on parameters a host set
    let actual = (i64::from(prev.time) - first_block_time)
        .max(timespan / 4)
        .min(timespan.saturating_mul(4));
    let mut target = CompactTarget::from_bits(prev.bits).target;
    target = target.wrapping_mul_u64(u64::from(actual as u32));
    target = target
        .checked_div(U256::from_u64(timespan as u64))
        .unwrap_or(U256::ZERO);
    if target > params.pow_limit {
        target = params.pow_limit;
    }
    target.to_compact()
}

/// `GetSuitableBlock` (src/pow.cpp:214-245): the median by time of the header
/// at `height` and its two parents, by the node's own sorting network (its
/// choice among equal times decides whose chain work is read).
fn suitable_block<C: HeaderAncestry + ?Sized>(
    chain: &C,
    height: u32,
) -> Result<HeaderLink, DifficultyError> {
    let mut blocks = [
        get(chain, height - 2)?,
        get(chain, height - 1)?,
        get(chain, height)?,
    ];
    if blocks[0].time > blocks[2].time {
        blocks.swap(0, 2);
    }
    if blocks[0].time > blocks[1].time {
        blocks.swap(0, 1);
    }
    if blocks[1].time > blocks[2].time {
        blocks.swap(1, 2);
    }
    Ok(blocks[1])
}

/// `ComputeTarget` (src/pow.cpp:177-208).
fn compute_target<C: HeaderAncestry + ?Sized>(
    params: &ChainParams,
    chain: &C,
    first: HeaderLink,
    last: HeaderLink,
) -> Result<U256, DifficultyError> {
    let spacing = params.pow_target_spacing;
    let mut work = *chain.work_between(first.height, last.height)?.as_u256();
    work = work.wrapping_mul_u64(spacing as u64);
    let actual = (i64::from(last.time) - i64::from(first.time))
        .min(spacing.saturating_mul(288))
        .max(spacing.saturating_mul(72));
    work = work
        .checked_div(U256::from_u64(actual as u64))
        .unwrap_or(U256::ZERO);
    work.wrapping_neg()
        .checked_div(work)
        .ok_or(DifficultyError::ZeroWork {
            first: first.height,
            last: last.height,
        })
}

/// `GetNextCashWorkRequired` (src/pow.cpp:256-297): the DAA over the last 144
/// blocks, with testnet's minimum-difficulty rule first.
/// ```
/// use bsv_rs::block::{next_cash_work_required, ChainParams, DifficultyError, HeaderLink};
/// let chain = [HeaderLink { height: 9, time: 1000, bits: 0x1d00ffff }];
/// assert_eq!(
///     next_cash_work_required(&ChainParams::main(), &chain[..], 9, 0),
///     Err(DifficultyError::ChainTooShort { prev_height: 9 })
/// );
/// ```
pub fn next_cash_work_required<C: HeaderAncestry + ?Sized>(
    params: &ChainParams,
    chain: &C,
    prev_height: u32,
    new_time: u32,
) -> Result<u32, DifficultyError> {
    let prev = get(chain, prev_height)?;
    if params.allow_min_difficulty_blocks
        && i64::from(new_time) > min_difficulty_after(params, prev)
    {
        return Ok(params.pow_limit_bits());
    }
    if i64::from(prev_height) < params.difficulty_adjustment_interval().max(147) {
        // the node asserts here (:275), and in `GetSuitableBlock` (:215) on
        // `prev - 144` for an interval shorter than 147
        return Err(DifficultyError::ChainTooShort { prev_height });
    }
    let last = suitable_block(chain, prev_height)?;
    let first = suitable_block(chain, prev_height - 144)?;
    let target = compute_target(params, chain, first, last)?;
    if target > params.pow_limit {
        return Ok(params.pow_limit_bits());
    }
    Ok(target.to_compact())
}
