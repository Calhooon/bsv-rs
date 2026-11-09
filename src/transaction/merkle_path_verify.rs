//! `MerklePath::verify`, the reference's (`ts-stack@edf6e03`
//! `MerklePath.ts:476-500`): an offset-0 proof under 100 blocks deep is not
//! proven (#734).

use super::merkle_path::MerklePath;
use super::ChainTracker;
use crate::Result;

impl MerklePath {
    /// Verifies `txid` against a chain tracker, as the reference's
    /// `MerklePath.verify` does: the root is computed, and when the txid sits
    /// at level-0 offset 0 (a coinbase's place, the lone leaf one case) the
    /// tracker's current height is asked and a proof with
    /// `block_height + 100 > current_height` answers `Ok(false)` before the
    /// root is asked; otherwise the answer is the tracker's
    /// `is_valid_root_for_height` (#734).
    ///
    /// A txid the path does not hold, or a path that does not compute, is the
    /// `Err` of [`compute_root`](Self::compute_root); a tracker's `Err` is
    /// carried as `From<ChainTrackerError>` carries it.
    pub async fn verify(&self, txid: &str, tracker: &dyn ChainTracker) -> Result<bool> {
        let root = self.compute_root(Some(txid))?;
        if self.index_of(txid)? == 0 {
            let height = tracker.current_height().await?;
            if u64::from(self.block_height) + 100 > u64::from(height) {
                return Ok(false);
            }
        }
        Ok(tracker
            .is_valid_root_for_height(&root, self.block_height)
            .await?)
    }
}
