//! The states #817's recording builds (`vectors/beef_v1_txid_only_writer_817.json`,
//! `support/beef_v1_txid_only_writer_817.mjs`): its fixture (a proven parent and
//! its child, the child's V1 BEEF) and each `writers` and `merge_door` state,
//! built by this crate's writer as the recorder built it. Shared by
//! `beef_writer_refusals_817.rs` and the lib's `merge_beef` pre-pass
//! differential (`src/transaction/beef/prepass_621_tests.rs`, #621), which
//! reaches the crate as `bsv_rs` through the lib's `extern crate self`.
#![allow(dead_code)] // each includer reads its own part

use bsv_rs::primitives::to_hex;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput, BEEF_V2,
};
use serde_json::Value;

pub const VECTOR: &str = include_str!("../vectors/beef_v1_txid_only_writer_817.json");
pub const FRESH: &str = "8170000000000000000000000000000000000000000000000000000000000817";
pub const BAD_WORD: u32 = 0xEFBE_0003;

pub fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

pub fn spend(source: &str, vout: u32, sats: u64) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new(source.to_string(), vout);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    tx.inputs.push(input);
    tx.outputs.push(TransactionOutput::new(
        sats,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    tx
}

/// The recording's fixture: a proven parent and its child, the child's V1
/// BEEF, and both raw transactions, each checked against the recording.
pub struct Fixture {
    pub v1: Vec<u8>,
    pub parent_raw: Vec<u8>,
    pub child_raw: Vec<u8>,
}

pub fn fixture(v: &Value) -> Fixture {
    let mut parent = spend(&"81".repeat(32), 0, 2_000);
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 817_000));
    let mut child = spend(&parent.id(), 0, 1_000);
    child.inputs[0].source_transaction = Some(Box::new(parent.clone()));
    let v1 = child.to_beef_v1(false).unwrap();
    assert_eq!(
        to_hex(&v1),
        v["v1_hex"].as_str().unwrap(),
        "the recording's V1 BEEF"
    );
    let parent_raw = parent.to_binary();
    let child_raw = child.to_binary();
    assert_eq!(to_hex(&parent_raw), v["parent_raw"].as_str().unwrap());
    assert_eq!(to_hex(&child_raw), v["child_raw"].as_str().unwrap());
    Fixture {
        v1,
        parent_raw,
        child_raw,
    }
}

/// The states of the `writers` group, each built here as the recorder built
/// it. A state this crate's doors refuse (a raw entry that is not one
/// transaction) has no builder: its cell is pinned at the door.
pub fn writer_state(name: &str, f: &Fixture) -> Option<Beef> {
    let v1 = || Beef::from_binary(&f.v1).unwrap();
    let txid_only = |txid: &str| {
        let mut b = Beef::new();
        b.merge_txid_only(txid.to_string());
        b
    };
    Some(match name {
        "version_word_efbe0003" | "version_word_atomic" | "version_word_zero" => {
            let mut b = v1();
            b.version = match name {
                "version_word_efbe0003" => BAD_WORD,
                "version_word_atomic" => 0x0101_0101,
                _ => 0,
            };
            b
        }
        "version_word_with_txid_only" => {
            let mut b = v1();
            b.version = BAD_WORD;
            b.merge_txid_only(FRESH.to_string());
            b
        }
        "version_word_with_non_hex_bump_hash" => {
            let mut b = v1();
            b.version = BAD_WORD;
            b.bumps[0].path[0][0].hash = Some("zz".repeat(32));
            b
        }
        "v1_txid_only_with_non_hex_bump_hash" => {
            let mut b = v1();
            b.merge_txid_only(FRESH.to_string());
            b.bumps[0].path[0][0].hash = Some("zz".repeat(32));
            b
        }
        "txid_only_non_hex" => txid_only(&"zz".repeat(32)),
        "txid_only_62_digits" => txid_only(&"ab".repeat(31)),
        "txid_only_66_digits" => txid_only(&"ab".repeat(33)),
        "txid_only_63_digits" => txid_only(&format!("a{}", "bc".repeat(31))),
        "txid_only_upper_case" => txid_only(&"AB".repeat(32)),
        "txid_only_non_hex_short" => txid_only("zz"),
        "txid_only_empty_after_merge_threw" => txid_only(""),
        "txid_only_empty_with_non_hex_bump_hash" => {
            let mut b = v1();
            b.version = BEEF_V2;
            b.bumps[0].path[0][0].hash = Some("zz".repeat(32));
            b.merge_txid_only(String::new());
            b
        }
        "raw_index_out_of_range" => {
            let mut b = Beef::new();
            b.merge_raw_tx(f.child_raw.clone(), Some(5))
                .expect("the bytes are one transaction");
            b
        }
        "raw_both_versions_v1" => v1(),
        _ => return None,
    })
}

pub fn merge_source(name: &str, f: &Fixture) -> Option<Beef> {
    let v1 = || Beef::from_binary(&f.v1).unwrap();
    Some(match name {
        "v1_source_with_txid_only" => {
            let mut b = v1();
            b.merge_txid_only(FRESH.to_string());
            b
        }
        "source_version_word" => {
            let mut b = v1();
            b.version = BAD_WORD;
            b
        }
        "source_txid_only_non_hex" | "source_txid_only_62_digits" => {
            let mut b = Beef::new();
            let digits = if name.ends_with("non_hex") {
                "zz".repeat(32)
            } else {
                "ab".repeat(31)
            };
            b.merge_txid_only(digits);
            b
        }
        "source_bump_non_hex_hash" => {
            let mut b = v1();
            b.bumps[0].path[0][0].hash = Some("zz".repeat(32));
            b
        }
        "source_bump_two_leaves_at_one_offset" => {
            let mut b = v1();
            b.bumps[0].path[0].push(MerklePathLeaf::new(0, "11".repeat(32)));
            b
        }
        "source_bump_no_levels" => {
            let mut b = v1();
            b.bumps[0].path.clear();
            b
        }
        "source_bump_duplicate_with_hash" => {
            let mut b = v1();
            let mut dup = MerklePathLeaf::new_duplicate(1);
            dup.hash = Some("11".repeat(32));
            b.bumps[0].path[0].push(dup);
            b
        }
        "source_version_word_and_txid_only_62_digits" => {
            let mut b = Beef::new();
            b.merge_txid_only("ab".repeat(31));
            b.version = BAD_WORD;
            b
        }
        "source_version_word_and_bump_no_levels" => {
            let mut b = v1();
            b.bumps[0].path.clear();
            b.version = BAD_WORD;
            b
        }
        "source_valid" => v1(),
        _ => return None,
    })
}
