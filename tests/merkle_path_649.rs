//! A path with no levels at all (`path` empty) is refused at every door and
//! answered without a panic by every walk (bsv-rs#649, `CLAUDE.md` rule 5).
//! The reference's constructor refuses it, `Merkle Path must contain between
//! 1 and 54 levels` (`ts-stack@edf6e03` `MerklePath.ts:198-200`), and so does
//! `fromHex` of its bytes (`:104-168`, a tree height of 0 read into the same
//! constructor); its walks on one held through the public field
//! (`computeRoot` `:375-382`, `indexOf` `:327-333`, `trim` `:544-600`,
//! `combine` `:508-537`) read `path[0]` unasked and throw the runtime's
//! `TypeError`, words of no rule. This crate's constructors refuse it in the
//! reference's sentence with this crate's bound (BRC-74's 64, the stated
//! divergence of #603); its readers in the stream's words; `compute_root`
//! (and `combine` through it) in the words `computeRoot` gives a level 0 with
//! no leaf to climb from (`:378-379`) or `indexOf` a txid it does not carry
//! (`:330`); `trim`, `contains`, `contains_and_mark` and `txids` find no
//! leaf. Until #649 every walk indexed `path[0]` and panicked.
//!
//! The shapes and the reference's verdicts are
//! `tests/vectors/merkle_path_649.json`, written by
//! `tests/support/merkle_path_649.mjs` against `@bsv/sdk` at
//! `ts-stack@edf6e03` under Node v22.18.0. Each shape's bytes are this
//! crate's writer's (`MerklePath::to_hex`), equal to the reference's.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::from_hex;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    verify_stream_structure, Beef, Headers, Kind, MerklePath, MockChainTracker, Transaction,
    TransactionInput, TransactionOutput, Verdict,
};
use bsv_rs::Error;
use serde::Deserialize;

const VECTORS: &str = "tests/vectors/merkle_path_649.json";

#[derive(Deserialize)]
struct Vectors {
    reference: String,
    node: String,
    shapes: Vec<Shape>,
}

#[derive(Deserialize)]
struct Shape {
    name: String,
    block_height: u32,
    path: Vec<Vec<serde_json::Value>>,
    txid: String,
    hex: String,
    checked: Answer,
    unchecked: Answer,
    from_hex: Answer,
    compute_root: Answer,
    compute_root_txid: Answer,
    trim: Answer,
    combine_into_empty: Answer,
    combine_empty_into: Answer,
}

#[derive(Deserialize)]
struct Answer {
    accepted: bool,
    refusal: Option<String>,
    class: Option<String>,
}

fn vectors() -> Vectors {
    let data = std::fs::read_to_string(VECTORS).expect("read the #649 vectors");
    let v: Vectors = serde_json::from_str(&data).expect("parse the #649 vectors");
    assert_eq!(
        v.reference,
        "ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts"
    );
    assert_eq!(v.node, "v22.18.0");
    assert_eq!(v.shapes.len(), 2);
    for shape in &v.shapes {
        assert!(shape.path.is_empty(), "{}", shape.name);
    }
    v
}

/// The shape held in memory with no check (the fields are public).
fn held(shape: &Shape) -> MerklePath {
    MerklePath {
        block_height: shape.block_height,
        path: Vec::new(),
    }
}

/// The reference's constructor's words with this crate's bound: BRC-74's 64
/// levels where the reference holds 54 (#603's stated divergence).
fn constructor_words(shape: &Shape, answer: &Answer) -> Error {
    assert!(!answer.accepted, "{}: the reference refuses", shape.name);
    let theirs = answer.refusal.clone().unwrap();
    assert_eq!(theirs, "Merkle Path must contain between 1 and 54 levels");
    Error::MerklePathError(theirs.replace("54", "64"))
}

/// A walk the reference has no words for: it reads `path[0]` unasked and
/// throws the runtime's `TypeError`.
fn crashes_there(shape: &Shape, answer: &Answer) {
    assert!(!answer.accepted, "{}", shape.name);
    assert_eq!(answer.class.as_deref(), Some("TypeError"), "{}", shape.name);
    assert!(
        answer
            .refusal
            .as_deref()
            .unwrap()
            .starts_with("Cannot read properties of undefined"),
        "{}",
        shape.name
    );
}

fn no_leaf() -> Error {
    Error::MerklePathError("No valid leaf found in the Merkle Path".to_string())
}

fn not_found(txid: &str) -> Error {
    Error::MerklePathError(format!(
        "Transaction ID {txid} not found in the Merkle Path"
    ))
}

/// A one-leaf path at the shape's height (`fromCoinbaseTxidAndHeight`).
fn one_leaf(shape: &Shape) -> MerklePath {
    MerklePath::from_coinbase_txid(&shape.txid, shape.block_height)
}

/// A transaction of one input and one output, no proof attached.
fn unproven() -> Transaction {
    let mut tx = Transaction::new();
    tx.inputs_mut()
        .push(TransactionInput::new("11".repeat(32).parse().unwrap(), 0));
    let lock = LockingScript::from_binary(&[0x51]).unwrap();
    tx.outputs_mut().push(TransactionOutput::new(1, lock));
    tx
}

struct NoRoot;

impl Headers for NoRoot {
    fn carries(&self, _height: u64, _root: &[u8; 32]) -> bool {
        false
    }
}

#[test]
fn the_shapes_bytes_are_this_crates_writers() {
    for shape in vectors().shapes {
        assert_eq!(
            held(&shape)
                .to_hex()
                .expect("the path holds only states a BUMP writes (#817)"),
            shape.hex,
            "{}",
            shape.name
        );
    }
}

#[test]
fn an_empty_path_is_refused_at_new() {
    for shape in vectors().shapes {
        let built = MerklePath::new(shape.block_height, Vec::new());
        assert_eq!(
            built.err(),
            Some(constructor_words(&shape, &shape.checked)),
            "{}",
            shape.name
        );
    }
}

#[test]
fn an_empty_path_is_refused_at_new_unchecked() {
    for shape in vectors().shapes {
        let built = MerklePath::new_unchecked(shape.block_height, Vec::new());
        assert_eq!(
            built.err(),
            Some(constructor_words(&shape, &shape.unchecked)),
            "{}",
            shape.name
        );
    }
}

/// `from_binary` and `from_hex` are the BEEF reader's BUMP decoder (#167): a
/// tree height of 0 refused in the stream's words at the height byte, where
/// the reference throws from its constructor.
#[test]
fn an_empty_path_is_refused_at_from_binary() {
    for shape in vectors().shapes {
        assert!(!shape.from_hex.accepted, "{}", shape.name);
        let bytes = from_hex(&shape.hex).unwrap();
        let at = bytes.len() - 1;
        for read in [
            MerklePath::from_binary(&bytes),
            MerklePath::from_hex(&shape.hex),
        ] {
            let text = read.unwrap_err().to_string();
            assert!(
                text.ends_with(&format!("invalid BUMP at byte {at}: TreeHeightZero")),
                "{}: {text}",
                shape.name
            );
        }
    }
}

#[test]
fn an_empty_path_is_refused_at_the_stream() {
    for shape in vectors().shapes {
        let mut beef = vec![0x02, 0x00, 0xbe, 0xef, 0x01];
        beef.extend_from_slice(&from_hex(&shape.hex).unwrap());
        beef.push(0);
        let verdict = verify_stream_structure(beef.as_slice(), NoRoot, None).unwrap();
        assert!(
            matches!(
                verdict,
                Verdict::Invalid {
                    kind: Kind::TreeHeightZero,
                    ..
                }
            ),
            "{}: {verdict:?}",
            shape.name
        );
        let whole = Beef::from_binary(&beef).err().map(|e| e.to_string());
        assert!(
            whole
                .as_deref()
                .is_some_and(|t| t.contains("TreeHeightZero")),
            "{}: {whole:?}",
            shape.name
        );
    }
}

/// A path no door builds, held by its public fields: `compute_root` refuses
/// it in the words of `computeRoot` and `indexOf`, no panic.
#[test]
fn an_empty_path_is_refused_at_compute_root() {
    for shape in vectors().shapes {
        crashes_there(&shape, &shape.compute_root);
        crashes_there(&shape, &shape.compute_root_txid);
        let path = held(&shape);
        assert_eq!(
            path.compute_root(None).err(),
            Some(no_leaf()),
            "{}",
            shape.name
        );
        assert_eq!(
            path.compute_root(Some(&shape.txid)).err(),
            Some(not_found(&shape.txid)),
            "{}",
            shape.name
        );
    }
}

/// `combine` either way refuses through `compute_root`, both paths unchanged.
#[test]
fn an_empty_path_is_refused_at_combine() {
    for shape in vectors().shapes {
        crashes_there(&shape, &shape.combine_into_empty);
        crashes_there(&shape, &shape.combine_empty_into);
        let mut empty = held(&shape);
        assert_eq!(empty.combine(&one_leaf(&shape)).err(), Some(no_leaf()));
        assert!(empty.path.is_empty(), "{}", shape.name);
        let mut one = one_leaf(&shape);
        assert_eq!(one.combine(&held(&shape)).err(), Some(no_leaf()));
        assert_eq!(
            one.to_hex()
                .expect("the path holds only states a BUMP writes (#817)"),
            one_leaf(&shape)
                .to_hex()
                .expect("the path holds only states a BUMP writes (#817)"),
            "{}",
            shape.name
        );
    }
}

/// `trim` has nothing to trim; `contains`, `contains_and_mark` and `txids`
/// find no leaf. None panics.
#[test]
fn an_empty_path_does_not_panic_at_trim_or_the_leaf_queries() {
    for shape in vectors().shapes {
        crashes_there(&shape, &shape.trim);
        let mut path = held(&shape);
        path.trim();
        assert!(path.path.is_empty(), "{}", shape.name);
        assert!(!path.contains(&shape.txid), "{}", shape.name);
        assert!(!path.contains_and_mark(&shape.txid), "{}", shape.name);
        assert!(path.txids().is_empty(), "{}", shape.name);
        assert_eq!(
            path.to_hex()
                .expect("the path holds only states a BUMP writes (#817)"),
            shape.hex,
            "{}",
            shape.name
        );
    }
}

/// The BEEF's walks over a bump held with no levels, beside a transaction no
/// bump proves: `merge_bump` (which asks each bump for its txid leaves),
/// `find_bump`, `verify_structure` and `verify_valid` answer, no panic.
#[test]
fn an_empty_path_does_not_panic_in_a_beef() {
    for shape in vectors().shapes {
        let mut beef = Beef::new();
        let tx = unproven();
        let txid = tx.id();
        beef.merge_transaction(tx);
        let index = beef.merge_bump(one_leaf(&shape));
        assert_eq!(beef.merge_bump(held(&shape)), index + 1, "{}", shape.name);
        assert!(beef.find_bump(&txid).is_none(), "{}", shape.name);
        assert!(beef.find_txid(&txid).unwrap().bump_index().is_none());
        assert!(beef.verify_structure().is_err(), "{}", shape.name);
        assert!(!beef.verify_valid(false).valid, "{}", shape.name);
    }
}

/// A transaction whose proof is held with no levels: `Transaction::verify`
/// refuses it in `compute_root`'s words.
#[tokio::test]
async fn an_empty_path_is_refused_at_transaction_verify() {
    for shape in vectors().shapes {
        let mut tx = unproven();
        tx.merkle_path = Some(held(&shape));
        let txid = tx.id();
        let tracker = MockChainTracker::always_valid(shape.block_height);
        let verdict = tx.verify(&tracker, None, None).await;
        assert_eq!(verdict.err(), Some(not_found(&txid)), "{}", shape.name);
    }
}
