//! The headers a reader checks proofs against, and the caller's tip.

use std::collections::HashMap;

use super::{display_hex, Hash32};
use crate::transaction::MockChainTracker;

/// Header context for checking mining in the next block (since 0.5.0).
/// The activation heights belong to the caller's network. After CSV activation,
/// finality uses median time past; before it the candidate block's time is needed.
/// \[SRC\] bsv-script-lean@87f0461 docs/BLOCK-CONSENSUS.md:83-88.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// Active chain tip's height.
    pub height: u32,
    /// Tip's median time past, in seconds.
    pub median_time_past: u32,
    /// This network's Genesis activation height. It also decides a coin's
    /// era: the streaming reader and [`Transaction::verify`] judge a coin
    /// whose parent is proven below it by the rules of a coin created before
    /// Genesis as well (GHSA-h4m7-c6p8-725m); without a tip they take
    /// mainnet's, 620,538. A caller on a test chain names its chain here.
    ///
    /// [`Transaction::verify`]: crate::transaction::Transaction::verify
    pub genesis_height: u32,
    /// This network's CSV activation height.
    pub csv_height: u32,
    /// Candidate block time, required only for time locks before CSV.
    pub next_block_time: Option<u32>,
}

/// Active-chain roots and optional mining context. Missing roots fail closed;
/// missing tip context declines checks that need it.
pub trait Headers {
    /// The header at `height` carries `root` (wire order).
    fn carries(&self, height: u64, root: &Hash32) -> bool;
    /// The caller's active tip and network; none means no contextual evidence.
    fn mining_tip(&self) -> Option<ChainTip> {
        None
    }
}

impl<H: Headers + ?Sized> Headers for &H {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        (**self).carries(height, root)
    }
    fn mining_tip(&self) -> Option<ChainTip> {
        (**self).mining_tip()
    }
}

/// Roots by height, in wire order.
impl Headers for HashMap<u64, Hash32> {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        self.get(&height) == Some(root)
    }
}

/// The mock tracker's roots (display hex by height).
impl Headers for MockChainTracker {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        u32::try_from(height)
            .ok()
            .and_then(|h| self.roots.get(&h))
            .is_some_and(|carried| carried.eq_ignore_ascii_case(&display_hex(root)))
    }
}

/// A function as the headers.
pub struct HeadersFn<F>(pub F);

impl<F: Fn(u64, &Hash32) -> bool> Headers for HeadersFn<F> {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        (self.0)(height, root)
    }
}
