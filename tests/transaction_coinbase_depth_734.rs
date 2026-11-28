//! An offset-0 proof under 100 blocks deep is not proven (#734).
//!
//! The reference's `MerklePath.verify` (`ts-stack@edf6e03`
//! `MerklePath.ts:476-500`) computes the root, reads the txid's level-0 offset
//! and, at offset 0 alone (a coinbase's place, the lone leaf one case), asks
//! the tracker's current height and answers `false` when
//! `block_height + 100 > height`, before the root is asked; `Transaction.verify`
//! throws `Invalid merkle path for transaction <txid>` on that `false`
//! (`Transaction.ts:1298-1316`) for every proven transaction it reaches, the
//! subject included.
//!
//! Each input here is built by this crate's own writer (a transaction, then a
//! merkle path at a chosen block height) and judged against
//! `AlwaysValidChainTracker`, whose reported current height is the tip knob.
//! Before the fix `Transaction::verify` asked the root alone, so the lone
//! offset-0 leaf verified at any depth.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    AlwaysValidChainTracker, ChainTracker, ChainTrackerError, MerklePath, MerklePathLeaf,
    Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

/// A coinbase-shaped input (a null previous outpoint) so the proven subject
/// passes the `NoInputs`/`NoOutputs` structural check before its proof is read.
fn coinbase_input() -> TransactionInput {
    let mut input = TransactionInput::new("00".repeat(32), 0xffff_ffff);
    input.set_unlocking_script(UnlockingScript::from_hex("00").unwrap());
    input
}

/// A proven transaction whose lone level-0 leaf sits at offset 0 (a coinbase's
/// place), built by this crate's writer and given a merkle path at `height`.
fn proven_at_offset0(height: u32) -> (Transaction, String) {
    let mut tx = Transaction::new();
    tx.add_input(coinbase_input()).unwrap();
    tx.add_output(TransactionOutput::new(
        1000,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let txid = tx.id();
    tx.merkle_path = Some(MerklePath::from_coinbase_txid(&txid, height));
    (tx, txid)
}

/// A proven transaction whose txid sits at level-0 offset 1, beside a sibling
/// at offset 0 (so it is not a coinbase).
fn proven_at_offset1(height: u32) -> (Transaction, String) {
    let mut tx = Transaction::new();
    tx.add_input(coinbase_input()).unwrap();
    tx.add_output(TransactionOutput::new(
        1000,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let txid = tx.id();
    let sibling = "11".repeat(32); // a 64-hex sibling at offset 0
    let path = MerklePath::new(
        height,
        vec![vec![
            MerklePathLeaf::new(0, sibling),
            MerklePathLeaf::new_txid(1, txid.clone()),
        ]],
    )
    .unwrap();
    tx.merkle_path = Some(path);
    (tx, txid)
}

/// A proven transaction whose txid sits at level-0 offset 0 beside a sibling at
/// offset 1 (a two-leaf block, the common multi-leaf coinbase case). The offset,
/// not the lone leaf, decides the maturity gate, so this is refused under 100
/// blocks deep exactly as the lone leaf is (the beta `#734` witness's two-leaf
/// offset-0 cell, `an_offset_0_proof_beside_a_sibling`).
fn proven_at_offset0_beside_sibling(height: u32) -> (Transaction, String) {
    let mut tx = Transaction::new();
    tx.add_input(coinbase_input()).unwrap();
    tx.add_output(TransactionOutput::new(
        1000,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let txid = tx.id();
    let sibling = "11".repeat(32); // a 64-hex sibling at offset 1
    let path = MerklePath::new(
        height,
        vec![vec![
            MerklePathLeaf::new_txid(0, txid.clone()),
            MerklePathLeaf::new(1, sibling),
        ]],
    )
    .unwrap();
    tx.merkle_path = Some(path);
    (tx, txid)
}

fn invalid_path(txid: &str) -> Error {
    Error::TransactionError(format!("Invalid merkle path for transaction {}", txid))
}

#[tokio::test]
async fn a_lone_leaf_under_100_blocks_deep_is_refused_by_transaction_verify_734() {
    let (tx, txid) = proven_at_offset0(50);
    // 0 deep: tip == block height.
    let r = tx.verify(&AlwaysValidChainTracker::new(50), None).await;
    assert_eq!(r.unwrap_err(), invalid_path(&txid), "0 blocks deep");
    // 99 deep: still immature (50 + 100 > 149).
    let r = tx.verify(&AlwaysValidChainTracker::new(149), None).await;
    assert_eq!(r.unwrap_err(), invalid_path(&txid), "99 blocks deep");
}

#[tokio::test]
async fn an_offset_0_proof_beside_a_sibling_is_refused_under_100_blocks_deep_734() {
    // The offset decides, not the lone leaf: a txid at offset 0 of a two-leaf
    // path (a multi-leaf coinbase) is refused under 100 blocks deep, as the
    // reference refuses it, and proven at 100 deep.
    let (tx, txid) = proven_at_offset0_beside_sibling(50);
    // 0 deep: tip == block height.
    let r = tx.verify(&AlwaysValidChainTracker::new(50), None).await;
    assert_eq!(r.unwrap_err(), invalid_path(&txid), "0 blocks deep");
    // 99 deep: still immature (50 + 100 > 149).
    let r = tx.verify(&AlwaysValidChainTracker::new(149), None).await;
    assert_eq!(r.unwrap_err(), invalid_path(&txid), "99 blocks deep");
    // 100 deep: mature -> proven, the honest deep coinbase proof.
    let (tx, _txid) = proven_at_offset0_beside_sibling(50);
    let r = tx.verify(&AlwaysValidChainTracker::new(150), None).await;
    assert!(r.unwrap(), "100 blocks deep is proven");
}

#[tokio::test]
async fn a_mature_offset_0_proof_100_blocks_deep_is_proven_734() {
    let (tx, _txid) = proven_at_offset0(50);
    // 100 deep: 50 + 100 > 150 is false -> mature, the honest deep coinbase proof.
    let r = tx.verify(&AlwaysValidChainTracker::new(150), None).await;
    assert!(r.unwrap(), "100 blocks deep is proven");
}

#[tokio::test]
async fn an_offset_0_proof_at_the_maximum_block_height_is_refused_without_overflow_734() {
    // The maturity gate widens `block_height` and the tracker height to u64
    // before adding 100 (`u64::from(self.block_height) + 100 > u64::from(height)`),
    // so an offset-0 proof at the largest representable block height is judged
    // without a u32 `block_height + 100` overflow. Such a coinbase can never sit
    // 100 blocks below a u32 tip, so it is always immature and refused. A u32
    // addition here would overflow: it panics in an overflow-checked (debug)
    // build and wraps to 99 in a release build, where 99 is not greater than the
    // tip and the gate wrongly admits the immature proof. The widening is the
    // only reason the correct verdict holds at this boundary.
    let (tx, txid) = proven_at_offset0(u32::MAX);
    // tip == block height (0 deep); u32::MAX + 100 > u32::MAX holds only in u64.
    let r = tx
        .verify(&AlwaysValidChainTracker::new(u32::MAX), None)
        .await;
    assert_eq!(
        r.unwrap_err(),
        invalid_path(&txid),
        "a u32::MAX-height coinbase at the u32::MAX tip is immature and refused"
    );
    // One below the tip, still immature, still no overflow (u32::MAX - 1 + 100).
    let (tx, txid) = proven_at_offset0(u32::MAX - 1);
    let r = tx
        .verify(&AlwaysValidChainTracker::new(u32::MAX), None)
        .await;
    assert_eq!(
        r.unwrap_err(),
        invalid_path(&txid),
        "a near-maximum-height coinbase one below the tip is immature and refused"
    );
}

#[tokio::test]
async fn an_offset_1_proof_asks_no_height_and_is_proven_at_every_tip_734() {
    // Offset != 0, so the depth gate never fires: proven even 0 deep.
    let (tx, _txid) = proven_at_offset1(50);
    let r = tx.verify(&AlwaysValidChainTracker::new(50), None).await;
    assert!(r.unwrap(), "a non-coinbase proof is proven at any tip");
}

/// A tracker whose current height query fails, to show the stable line's
/// `Transaction::verify` keeps wrapping a tracker error as
/// `Chain tracker error: {e}` (0.9's raw `From<ChainTrackerError>` wrapper did
/// not travel with the depth gate).
struct ErringHeight;

#[async_trait::async_trait]
impl ChainTracker for ErringHeight {
    async fn is_valid_root_for_height(
        &self,
        _root: &str,
        _height: u32,
    ) -> Result<bool, ChainTrackerError> {
        Ok(true)
    }
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        Err(ChainTrackerError::NetworkError("boom".to_string()))
    }
}

#[tokio::test]
async fn a_tracker_height_error_keeps_the_stable_chain_tracker_error_text_734() {
    let (tx, _txid) = proven_at_offset0(50);
    let r = tx.verify(&ErringHeight, None).await;
    match r {
        Err(Error::TransactionError(m)) => {
            assert!(
                m.starts_with("Chain tracker error:"),
                "unexpected message: {m}"
            );
        }
        other => panic!("expected a wrapped chain tracker error, got {other:?}"),
    }
}
