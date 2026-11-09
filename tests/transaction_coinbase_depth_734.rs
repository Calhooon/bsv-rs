//! An offset-0 proof under 100 blocks deep is not proven (#734).
//!
//! The reference's `MerklePath.verify` (`ts-stack@edf6e03`
//! `packages/sdk/src/transaction/MerklePath.ts:476-500`) computes the root,
//! reads the txid's level-0 offset (`indexOf`, `:327-333`) and, at offset 0
//! alone, asks the tracker's current height and answers `false` when
//! `blockHeight + 100 > height`, before the root is asked: a coinbase's
//! maturity, read from the offset, so the lone leaf (a transaction alone in
//! its block) is one case of it. `Transaction.verify` throws `Invalid merkle
//! path for transaction <txid>` on that `false` (`Transaction.ts:1298-1316`)
//! for every proven transaction it reaches, the subject included;
//! `Beef.verify` (`Beef.ts:1020-1035`) has no depth rule.
//!
//! Every cell of `vectors/coinbase_depth_734.json`
//! (`support/coinbase_depth_734.mjs`, Node v22.18.0) is rebuilt here by this
//! crate's writer (the parent, its BUMP, the child, the BEEF), the bytes
//! compared, then each door's verdict or words and the tracker's calls in
//! order: `MerklePath::verify`, `Transaction::verify` on the child (the parent
//! proven) and on the parent (the subject proven), and the BEEF's
//! `verify_valid` roots asked of the tracker (the reference's `Beef.verify`).
//! The streaming reader keeps its verdict at the four tips: it reads a
//! coinbase by its null input (`beef_stream/spends.rs`), not by its offset,
//! so at a tip of `h + 99` the doors part (a stated difference, the root
//! `CLAUDE.md`'s row).
//!
//! The fold of the strength read adds 24 cells (80 in all): the lone leaf and
//! the two-leaf offset 0 against a tip of 0, of 1 and of `h - 1`, a tracker
//! whose current height is a placeholder or under the proof, refused as at
//! `h` (`a_tip_below_the_proof_refuses_an_offset_0_proof_734`).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::beef_stream::{verify_stream, Verdict};
use bsv_rs::transaction::{
    Beef, ChainTracker, ChainTrackerError, MerklePath, MockChainTracker, Transaction,
    TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

const VECTOR: &str = include_str!("vectors/coinbase_depth_734.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

/// A tracker that answers the cell's height and roots and records each call.
struct Recording {
    height: u32,
    roots: HashMap<u32, String>,
    calls: Mutex<Vec<Value>>,
}

impl Recording {
    fn new(height: u32, roots: HashMap<u32, String>) -> Self {
        Self {
            height,
            roots,
            calls: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Value {
        Value::Array(self.calls.lock().unwrap().clone())
    }
}

#[async_trait::async_trait]
impl ChainTracker for Recording {
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError> {
        self.calls
            .lock()
            .unwrap()
            .push(json!(["isValidRootForHeight", root, height]));
        Ok(self.roots.get(&height).is_some_and(|r| r == root))
    }
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        self.calls.lock().unwrap().push(json!(["currentHeight"]));
        Ok(self.height)
    }
}

/// The cell's parent (its path the cell's BUMP, rebuilt and compared) and
/// child, the child's bytes compared with the recording's.
fn build(v: &Value, cell: &Value) -> (Transaction, Transaction) {
    let mut parent = Transaction::from_hex(v["parent"]["raw"].as_str().unwrap()).unwrap();
    assert_eq!(parent.id(), v["parent"]["txid"].as_str().unwrap());
    let name = format!(
        "{}_{}",
        cell["path"].as_str().unwrap(),
        cell["block_height"]
    );
    let hex = v["bumps"][&name].as_str().unwrap();
    let path = MerklePath::from_hex(hex).unwrap();
    assert_eq!(path.to_hex(), hex, "{name}");
    parent.merkle_path = Some(path);
    let mut child = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(parent.clone(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("5151").unwrap());
    child.add_input(input).unwrap();
    child
        .add_output(TransactionOutput::new(
            900,
            LockingScript::from_hex("51").unwrap(),
        ))
        .unwrap();
    assert_eq!(child.to_hex(), cell["child_hex"].as_str().unwrap());
    (parent, child)
}

/// The tracker of a cell: its tip, and the BUMP's root at its height when
/// the cell says the root is known.
fn tracker_of(cell: &Value, root: &str) -> Recording {
    let h = cell["block_height"].as_u64().unwrap() as u32;
    let mut roots = HashMap::new();
    if cell["root_known"].as_bool().unwrap() {
        roots.insert(h, root.to_string());
    }
    Recording::new(cell["tip"].as_u64().unwrap() as u32, roots)
}

/// A door's answer as the recording writes it: `{ok}` or `{err}` (the words
/// inside the error class, the reference's `Error.message`).
fn answer(r: Result<bool, Error>) -> Value {
    match r {
        Ok(b) => json!({ "ok": b }),
        Err(Error::TransactionError(words)) => json!({ "err": words }),
        Err(e) => panic!("an error of another class: {e:?}"),
    }
}

async fn run_cell(v: &Value, cell: &Value) -> (Value, Value) {
    let (parent, child) = build(v, cell);
    let path = parent.merkle_path.clone().unwrap();
    let txid = parent.id();
    let root = path.compute_root(Some(&txid)).unwrap();
    let t = tracker_of(cell, &root);
    let got = match cell["door"].as_str().unwrap() {
        "merklePath" => answer(path.verify(&txid, &t).await),
        "child" => answer(child.verify(&t, None, None).await),
        "parent" => answer(parent.verify(&t, None, None).await),
        "beef" => {
            // The reference's `Beef.verify`: `verifyValid`, then each root
            // asked of the tracker; no depth rule.
            let bytes = child.to_beef_v1(false).unwrap();
            assert_eq!(
                bsv_rs::primitives::to_hex(&bytes),
                cell["beef_hex"].as_str().unwrap()
            );
            let mut beef = Beef::from_binary(&bytes).unwrap();
            let r = beef.verify_valid(false);
            assert!(r.valid);
            let mut ok = true;
            for (h, root) in r.roots {
                if !t.is_valid_root_for_height(&root, h).await.unwrap() {
                    ok = false;
                    break;
                }
            }
            json!({ "ok": ok })
        }
        door => panic!("door {door}"),
    };
    (got, t.calls())
}

fn expected(cell: &Value) -> Value {
    match (cell.get("ok"), cell.get("err")) {
        (Some(ok), _) => json!({ "ok": ok }),
        (None, Some(err)) => json!({ "err": err }),
        _ => panic!("a cell with no answer"),
    }
}

fn cells<'a>(v: &'a Value, f: impl Fn(&Value) -> bool + 'a) -> Vec<&'a Value> {
    v["cells"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| f(c))
        .collect()
}

/// A cell whose tip is at or above the proof's height: the 56 cells of the
/// lane, apart from the fold's tips below the proof.
fn at_or_above(c: &Value) -> bool {
    c["tip"].as_u64().unwrap() >= c["block_height"].as_u64().unwrap()
}

async fn check(v: &Value, selected: Vec<&Value>) {
    assert!(!selected.is_empty());
    for cell in selected {
        let label = format!(
            "{} at {} tip {:+} root_known {} door {}",
            cell["path"],
            cell["block_height"],
            cell["tip"].as_i64().unwrap() - cell["block_height"].as_i64().unwrap(),
            cell["root_known"],
            cell["door"]
        );
        let (got, calls) = run_cell(v, cell).await;
        assert_eq!(got, expected(cell), "{label}");
        assert_eq!(calls, cell["calls"], "{label}: the tracker's calls");
    }
}

/// The lone leaf under 100 blocks deep: `MerklePath::verify` false and
/// `Transaction::verify` refused in the reference's words, the child's and
/// the subject's alike, the root never asked; at 100 and 101 deep proven.
#[tokio::test]
async fn a_lone_leaf_under_100_blocks_deep_is_refused_by_transaction_verify_734() {
    let v = vector();
    check(
        &v,
        cells(&v, |c| {
            c["path"] == "lone"
                && c["block_height"] == 800_000
                && c["root_known"] == true
                && at_or_above(c)
        }),
    )
    .await;
}

/// The txid at offset 0 of a two-leaf path: the same rule (the offset, not
/// the lone leaf, decides).
#[tokio::test]
async fn an_offset_0_proof_beside_a_sibling_is_refused_under_100_blocks_deep_734() {
    let v = vector();
    check(&v, cells(&v, |c| c["path"] == "left" && at_or_above(c))).await;
}

/// The control: the txid at offset 1, no height asked at any tip.
#[tokio::test]
async fn an_offset_1_proof_asks_no_height_and_is_proven_at_every_tip_734() {
    let v = vector();
    check(&v, cells(&v, |c| c["path"] == "right")).await;
}

/// At depth, a root the tracker refuses: the height asked, then the root,
/// refused in the same words.
#[tokio::test]
async fn a_root_refused_at_depth_is_asked_after_the_height_734() {
    let v = vector();
    check(&v, cells(&v, |c| c["root_known"] == false)).await;
}

/// The top of the `u32` range: `block_height + 100` computed without
/// overflow, the proof not deep enough.
#[tokio::test]
async fn an_offset_0_proof_at_u32_max_is_not_deep_without_overflow_734() {
    let v = vector();
    check(&v, cells(&v, |c| c["block_height"] == u64::from(u32::MAX))).await;
}

/// The tip below the proof (the fold of the strength read): a tracker whose
/// current height is a placeholder (0, 1) or one block short of the proof,
/// and the tip at the proof's own height, for the lone leaf and the two-leaf
/// offset 0. `block_height + 100 > height` answers false at each, before the
/// root is asked: `MerklePath::verify` false, `Transaction::verify` refused
/// in the reference's words, the BEEF's roots still proven. A subtraction
/// (`height.wrapping_sub(block_height) < 100`) passes the cells above and
/// fails these.
#[tokio::test]
async fn a_tip_below_the_proof_refuses_an_offset_0_proof_734() {
    let v = vector();
    let selected = cells(&v, |c| {
        (c["path"] == "lone" || c["path"] == "left")
            && c["block_height"] == 800_000
            && c["root_known"] == true
            && [0, 1, 799_999, 800_000].contains(&c["tip"].as_u64().unwrap())
    });
    assert_eq!(
        selected.len(),
        2 * 4 * 4,
        "two paths, four tips, four doors"
    );
    assert_eq!(
        selected.iter().filter(|c| !at_or_above(c)).count(),
        24,
        "the fold's cells"
    );
    check(&v, selected).await;
}

/// A tracker's error at the height is carried as the root's always was
/// (`From<ChainTrackerError>`: `Chain tracker error: ...`), never the merkle
/// path's words.
#[tokio::test]
async fn a_trackers_height_error_keeps_its_class_734() {
    struct NoHeight;
    #[async_trait::async_trait]
    impl ChainTracker for NoHeight {
        async fn is_valid_root_for_height(
            &self,
            _: &str,
            _: u32,
        ) -> Result<bool, ChainTrackerError> {
            Ok(true)
        }
        async fn current_height(&self) -> Result<u32, ChainTrackerError> {
            Err(ChainTrackerError::NetworkError("no height".into()))
        }
    }
    let v = vector();
    let cell = cells(&v, |c| c["path"] == "lone" && c["door"] == "parent")[0];
    let (parent, _) = build(&v, cell);
    let err = parent.verify(&NoHeight, None, None).await.unwrap_err();
    assert_eq!(
        err,
        Error::from(ChainTrackerError::NetworkError("no height".into()))
    );
    assert_eq!(
        err,
        Error::TransactionError("Chain tracker error: network error: no height".into())
    );
}

/// The streaming reader on the same BEEF at the four tips: valid at each
/// (no null input, so no coinbase by its rule), where `Transaction::verify`
/// refuses at `h` and `h + 99` (the stated difference).
#[test]
fn the_stream_keeps_its_verdict_on_the_same_beef_at_the_four_tips_734() {
    let v = vector();
    for cell in cells(&v, |c| {
        c["path"] == "lone"
            && c["door"] == "beef"
            && c["block_height"] == 800_000
            && c["root_known"] == true
            && at_or_above(c)
    }) {
        let (parent, child) = build(&v, cell);
        let path = parent.merkle_path.clone().unwrap();
        let root = path.compute_root(Some(&parent.id())).unwrap();
        let mut tracker = MockChainTracker::new(cell["tip"].as_u64().unwrap() as u32);
        tracker.add_root(path.block_height, root);
        let bytes = child.to_beef_v1(false).unwrap();
        let verdict = verify_stream(bytes.as_slice(), &tracker, None).unwrap();
        assert!(
            matches!(verdict, Verdict::Valid { .. }),
            "tip {}: {verdict:?}",
            cell["tip"]
        );
    }
}
