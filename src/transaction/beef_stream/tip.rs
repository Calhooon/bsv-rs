//! The mining tip a header source answers (`Headers::mining_tip`,
//! `ChainTracker::mining_tip`).

/// Mainnet's CSV activation height (bitcoin-sv@879fc8b `src/chainparams.cpp:1046`).
pub(crate) const MAINNET_CSV_HEIGHT: u32 = 419_328;

/// Header context for checking mining in the next block (since 0.5.0).
/// After CSV activation, finality uses median time past; before it the
/// candidate block's time is needed.
/// \[SRC\] bsv-script-lean@87f0461 docs/BLOCK-CONSENSUS.md:83-88.
///
/// A context block that grows, so it is `#[non_exhaustive]` (#843): build it
/// with [`ChainTip::new`] and the `with_` setters; the fields stay readable,
/// and a pattern over it ends in `..`. `new` takes the tip's height and its
/// median time past and sets mainnet's CSV activation height (419,328) and no
/// candidate block time; a caller on another chain names its own with
/// [`ChainTip::with_csv_height`].
///
/// The tip names no Genesis height (its `genesis_height`, deprecated since
/// `0.9.0-beta.4`, is removed, #451): without chain parameters the doors judge
/// by mainnet's heights, as the reference does, and a caller on another chain
/// supplies its [`ChainParams`](crate::block::ChainParams) at a door that
/// takes them.
///
/// ```
/// use bsv_rs::transaction::beef_stream::ChainTip;
/// let tip = ChainTip::new(900_000, 1_700_000_000);
/// assert_eq!((tip.csv_height, tip.next_block_time), (419_328, None));
/// let regtest = ChainTip::new(120, 1_700_000_000).with_csv_height(0).with_next_block_time(1_700_000_600);
/// assert_eq!((regtest.csv_height, regtest.next_block_time), (0, Some(1_700_000_600)));
/// ```
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::transaction::beef_stream::ChainTip) -> bsv_rs::transaction::beef_stream::ChainTip {
///     bsv_rs::transaction::beef_stream::ChainTip { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::transaction::beef_stream::ChainTip) -> bsv_rs::transaction::beef_stream::ChainTip {
///     value
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainTip {
    /// Active chain tip's height.
    pub height: u32,
    /// Tip's median time past, in seconds.
    pub median_time_past: u32,
    /// This network's CSV activation height.
    pub csv_height: u32,
    /// Candidate block time, required only for time locks before CSV.
    pub next_block_time: Option<u32>,
}

crate::util::non_exhaustive::assert_no_drop!(ChainTip, bsv_rs::transaction::beef_stream::ChainTip);

impl ChainTip {
    /// The tip at `height` with `median_time_past` (seconds), mainnet's CSV
    /// activation height and no candidate block time.
    #[must_use]
    pub const fn new(height: u32, median_time_past: u32) -> Self {
        Self {
            height,
            median_time_past,
            csv_height: MAINNET_CSV_HEIGHT,
            next_block_time: None,
        }
    }

    /// Sets the network's CSV activation height.
    #[must_use]
    pub const fn with_csv_height(mut self, csv_height: u32) -> Self {
        self.csv_height = csv_height;
        self
    }

    /// Sets the candidate block's time, read only for a time lock judged
    /// before CSV activation.
    #[must_use]
    pub const fn with_next_block_time(mut self, next_block_time: u32) -> Self {
        self.next_block_time = Some(next_block_time);
        self
    }
}
