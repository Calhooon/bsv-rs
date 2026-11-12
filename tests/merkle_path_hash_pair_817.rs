//! #817, line 11 of the bucket: a merkle walk pairs two hash texts as the
//! reference's `hashPair` does (`ts-stack@edf6e03` `MerklePath.ts:30-32`):
//! the two texts concatenated as text, one leading `0` when the total length
//! is odd (`utils.ts:125-128`), the bytes decoded once, reversed whole and
//! hashed. Until #817 this crate decoded each side alone and dropped a side of
//! odd length, so a path holding such a hash (through `MerklePath::new`,
//! `new_unchecked`, `from_coinbase_txid` or the public fields; no reader
//! builds one, they read 32 bytes) computed another root than the reference's.
//! No wire byte moves.
//!
//! The reference's side is recorded in `tests/vectors/transaction_fold_817.json`
//! (group `hash_pair`) by `tests/support/transaction_fold_817.mjs` (Node 22,
//! the bundle at the pin), each cell a path held through the public fields:
//! `computeRoot()` and both constructors.

#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::transaction::{MerklePath, MerklePathLeaf};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/transaction_fold_817.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("the vector is JSON")
}

fn cell(name: &str) -> Value {
    vector()["hash_pair"]
        .as_array()
        .expect("hash_pair")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no cell {name}"))
        .clone()
}

fn levels(cell: &Value) -> Vec<Vec<MerklePathLeaf>> {
    cell["path"]
        .as_array()
        .expect("path")
        .iter()
        .map(|level| {
            level
                .as_array()
                .expect("level")
                .iter()
                .map(|leaf| MerklePathLeaf {
                    offset: leaf["offset"].as_u64().expect("offset"),
                    hash: leaf["hash"].as_str().map(str::to_string),
                    txid: leaf["txid"].as_bool().unwrap_or(false),
                    duplicate: leaf["duplicate"].as_bool().unwrap_or(false),
                })
                .collect()
        })
        .collect()
}

fn block_height() -> u32 {
    vector()["block_height"].as_u64().expect("height") as u32
}

/// The cell's root on every door, against the reference's: the held path's
/// `compute_root`, and both constructors accepting as the reference's do.
fn agrees(name: &str) {
    let c = cell(name);
    for door in ["compute_root", "checked", "unchecked"] {
        assert_eq!(
            c[door]["accepted"], true,
            "{name}: the reference's {door} accepts (a refusal is a cell to state)"
        );
    }
    let root = c["compute_root"]["result"].as_str().expect("root");
    let held = MerklePath {
        block_height: block_height(),
        path: levels(&c),
    };
    assert_eq!(
        held.compute_root(None).unwrap(),
        root,
        "{name}: compute_root"
    );
    let checked = MerklePath::new(block_height(), levels(&c))
        .unwrap_or_else(|e| panic!("{name}: new refused: {e:?}"));
    assert_eq!(checked.compute_root(None).unwrap(), root, "{name}: new");
    let unchecked = MerklePath::new_unchecked(block_height(), levels(&c))
        .unwrap_or_else(|e| panic!("{name}: new_unchecked refused: {e:?}"));
    assert_eq!(
        unchecked.compute_root(None).unwrap(),
        root,
        "{name}: new_unchecked"
    );
}

const ODD_SIBLING: [&str; 4] = [
    "sibling_of_63_digits",
    "txid_of_63_digits",
    "sibling_of_1_digit",
    "sibling_of_65_digits",
];
const TWO_ODD: [&str; 2] = ["both_of_63_digits", "txid_of_63_digits_beside_a_duplicate"];
const COMPUTED: [&str; 2] = [
    "computed_node_leaf0_of_63_digits",
    "computed_node_leaf1_of_63_digits",
];
const EVEN: [&str; 5] = [
    "sibling_of_62_digits",
    "sibling_of_64_digits",
    "sibling_of_66_digits",
    "empty_sibling",
    "computed_node_of_64_digits",
];

/// One odd-length side: dropped until #817, padded with the other side's
/// text by the reference.
#[test]
fn an_odd_length_sibling_is_paired_as_the_reference_concatenates_it_817() {
    for name in ODD_SIBLING {
        agrees(name);
    }
}

/// Two odd-length sides (two texts of 63 digits, and a 63-digit txid paired
/// with itself beside a duplicate): both dropped until #817, decoded across
/// their boundary by the reference.
#[test]
fn two_odd_length_hashes_are_read_across_their_boundary_817() {
    for name in TWO_ODD {
        agrees(name);
    }
}

/// A node computed from level 0 (`findOrComputeLeaf`, `MerklePath.ts:455-459`,
/// `hashPair(leaf1.hash, leaf0.hash)`) whose `leaf0` or `leaf1` has 63 digits.
#[test]
fn an_odd_length_child_of_a_computed_node_is_paired_as_the_reference_817() {
    for name in COMPUTED {
        agrees(name);
    }
}

/// Even lengths (62, 64, 66 digits, the empty text, a computed node of
/// 64-digit children) pair as before: green before and after #817.
#[test]
fn an_even_length_hash_pairs_as_before_817() {
    for name in EVEN {
        agrees(name);
    }
}

/// Every recorded cell is judged by exactly one test above.
#[test]
fn every_recorded_hash_pair_cell_is_judged_817() {
    let mut named: Vec<&str> = ODD_SIBLING
        .iter()
        .chain(&TWO_ODD)
        .chain(&COMPUTED)
        .chain(&EVEN)
        .copied()
        .collect();
    named.sort_unstable();
    let mut recorded: Vec<String> = vector()["hash_pair"]
        .as_array()
        .expect("hash_pair")
        .iter()
        .map(|c| c["name"].as_str().expect("name").to_string())
        .collect();
    recorded.sort_unstable();
    assert_eq!(recorded.len(), 13);
    assert_eq!(recorded, named);
}
