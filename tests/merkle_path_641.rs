//! A level 0 made only of duplicate-flagged leaves (no txid leaf, no hash
//! leaf) is refused at every door, as the reference's constructor refuses it
//! (bsv-rs#641): its root check asks `computeRootCached` for a root from a
//! level-0 leaf, finds no leaf with a hash and throws `Transaction ID is
//! undefined` (`ts-stack@edf6e03` `MerklePath.ts:241-263`, `:342-343`), with
//! `legalOffsetsOnly` true or false, after the offset checks (`:213-236`);
//! `fromHex` reads through the same constructor (`:104-168`), and
//! `computeRoot()` on a path built with no check throws `No valid leaf found
//! in the Merkle Path` (`:375-381`).
//!
//! The shapes and the reference's verdicts are
//! `tests/vectors/merkle_path_641.json`, written by
//! `tests/support/merkle_path_641.mjs` against `@bsv/sdk` at
//! `ts-stack@edf6e03` under Node v22.18.0. Each shape's bytes are this
//! crate's writer's (`MerklePath::to_hex`), equal to the reference's.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::from_hex;
use bsv_rs::transaction::{
    verify_stream_structure, Beef, Headers, Kind, MerklePath, MerklePathLeaf, Verdict,
};
use bsv_rs::Error;
use serde::Deserialize;

const VECTORS: &str = "tests/vectors/merkle_path_641.json";

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
    path: Vec<Vec<JsonLeaf>>,
    hex: String,
    checked: Answer,
    unchecked: Answer,
    from_hex: Answer,
    compute_root: Answer,
}

#[derive(Deserialize)]
struct JsonLeaf {
    offset: u64,
    hash: Option<String>,
    #[serde(default)]
    txid: bool,
    #[serde(default)]
    duplicate: bool,
}

#[derive(Deserialize)]
struct Answer {
    accepted: bool,
    refusal: Option<String>,
}

fn vectors() -> Vectors {
    let data = std::fs::read_to_string(VECTORS).expect("read the #641 vectors");
    let v: Vectors = serde_json::from_str(&data).expect("parse the #641 vectors");
    assert_eq!(
        v.reference,
        "ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts"
    );
    assert_eq!(v.node, "v22.18.0");
    assert_eq!(v.shapes.len(), 5);
    v
}

fn path_of(shape: &Shape) -> Vec<Vec<MerklePathLeaf>> {
    shape
        .path
        .iter()
        .map(|level| {
            level
                .iter()
                .map(|l| MerklePathLeaf {
                    offset: l.offset,
                    hash: l.hash.clone(),
                    txid: l.txid,
                    duplicate: l.duplicate,
                })
                .collect()
        })
        .collect()
}

/// The shape held in memory with no check (the fields are public).
fn held(shape: &Shape) -> MerklePath {
    MerklePath {
        block_height: shape.block_height,
        path: path_of(shape),
    }
}

/// The reference's words, as this crate's `MerklePathError` carries them.
fn refused_as(shape: &Shape, answer: &Answer) -> Error {
    assert!(!answer.accepted, "{}: the reference refuses", shape.name);
    Error::MerklePathError(answer.refusal.clone().unwrap())
}

/// The shape as a V2 BEEF of one BUMP and no transaction.
fn beef_of(bump: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x02, 0x00, 0xbe, 0xef, 0x01];
    bytes.extend_from_slice(bump);
    bytes.push(0);
    bytes
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
        assert_eq!(held(&shape).to_hex(), shape.hex, "{}", shape.name);
    }
}

#[test]
fn a_level_zero_of_duplicates_alone_is_refused_at_new() {
    for shape in vectors().shapes {
        let built = MerklePath::new(shape.block_height, path_of(&shape));
        assert_eq!(
            built.err(),
            Some(refused_as(&shape, &shape.checked)),
            "{}",
            shape.name
        );
    }
}

#[test]
fn a_level_zero_of_duplicates_alone_is_refused_at_new_unchecked() {
    for shape in vectors().shapes {
        let built = MerklePath::new_unchecked(shape.block_height, path_of(&shape));
        assert_eq!(
            built.err(),
            Some(refused_as(&shape, &shape.unchecked)),
            "{}",
            shape.name
        );
    }
}

/// `from_binary` and `from_hex` are the BEEF reader's BUMP decoder (#167):
/// a refusal in the stream's words, `NoTxidAtLevelZero` at the BUMP, where
/// the reference throws from its constructor.
#[test]
fn a_level_zero_of_duplicates_alone_is_refused_at_from_binary() {
    for shape in vectors().shapes {
        assert!(!shape.from_hex.accepted, "{}", shape.name);
        let bytes = from_hex(&shape.hex).unwrap();
        for read in [
            MerklePath::from_binary(&bytes),
            MerklePath::from_hex(&shape.hex),
        ] {
            let text = read.unwrap_err().to_string();
            assert!(
                text.ends_with("invalid BUMP at byte 0: NoTxidAtLevelZero"),
                "{}: {text}",
                shape.name
            );
        }
    }
}

#[test]
fn a_level_zero_of_duplicates_alone_is_refused_at_the_stream() {
    for shape in vectors().shapes {
        let beef = beef_of(&from_hex(&shape.hex).unwrap());
        let verdict = verify_stream_structure(beef.as_slice(), NoRoot, None).unwrap();
        assert!(
            matches!(
                verdict,
                Verdict::Invalid {
                    offset: 5,
                    kind: Kind::NoTxidAtLevelZero,
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
                .is_some_and(|t| t.ends_with("invalid BEEF at byte 5: NoTxidAtLevelZero")),
            "{}: {whole:?}",
            shape.name
        );
        let mut in_memory = Beef::new();
        in_memory.bumps.push(held(&shape));
        assert_eq!(
            in_memory.verify_structure().err(),
            Some(Kind::NoTxidAtLevelZero),
            "{}",
            shape.name
        );
    }
}

/// A path no door builds, held by its public fields: `compute_root` refuses
/// it in the reference's words and neither panics nor walks.
#[test]
fn a_level_zero_of_duplicates_alone_held_unchecked_is_refused_by_compute_root() {
    for shape in vectors().shapes {
        let path = held(&shape);
        assert_eq!(
            path.compute_root(None).err(),
            Some(refused_as(&shape, &shape.compute_root)),
            "{}",
            shape.name
        );
        let txid = "00".repeat(32);
        assert_eq!(
            path.compute_root(Some(&txid)).err(),
            Some(Error::MerklePathError(format!(
                "Transaction ID {txid} not found in the Merkle Path"
            ))),
            "{}",
            shape.name
        );
        assert!(path.txids().is_empty(), "{}", shape.name);
    }
}
