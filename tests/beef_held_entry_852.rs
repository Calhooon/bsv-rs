//! #852 (the stable line of #840): a BEEF entry built from raw bytes is a
//! transaction only if its bytes are exactly one transaction. On this line
//! `BeefTx::from_raw_tx` and `Beef::merge_raw_tx` return no `Result`, so such
//! bytes are held unparsed; they are refused at every verdict door instead
//! (`sort_txs`, `verify_structure`, `verify_valid`, `is_valid`), with or
//! without a BUMP index, in the streaming reader's kind for them
//! (`TrailingBytes`, `Truncated`, `BadVarint`), and so is every child that
//! names one. 0.9.0 refuses the same bytes at construction (#817).
//!
//! The table: twelve shapes (one transaction, the control; a transaction
//! followed by one byte, four bytes and itself; four cuts of it; bytes that
//! are no transaction, 3 and 40 of them; no bytes; a transaction of no input
//! followed by a byte) by six states (unproven with its parent absent;
//! unproven with its parent present and proven; carrying its own BUMP
//! index; the atomic subject; the parent of a child; carried into another
//! BEEF by `merge_beef`) by the doors. Against
//! `vectors/beef_held_entry_852.json` (`support/beef_held_entry_852.mjs`,
//! the reference at `ts-stack@edf6e03` under Node 22, two runs
//! byte-identical): for every cell that is not one transaction, the
//! reference's END-TO-END answer is a refusal too (`mergeRawTx` or
//! `mergeBeef` throws, or the BEEF it writes is refused by
//! `fromBinaryStrict`); the cells its `verifyValid` alone answers valid are
//! the stated divergence, counted.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use bsv_rs::primitives::{from_hex, sha256d, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    verify_stream, verify_stream_structure, Beef, Kind, MerklePath, MerklePathLeaf,
    MockChainTracker, Transaction, TransactionInput, TransactionOutput, Verdict,
};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/beef_held_entry_852.json");

/// Block 170's transaction (f4184fc5..., 275 bytes).
const TX_HEX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
/// The coinbase of block 9 (0437cd7f..., its block's one transaction), the
/// coin block 170's transaction spends.
const PARENT_HEX: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0134ffffffff0100f2052a0100000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
const PARENT_HEIGHT: u32 = 9;
const ENTRY_HEIGHT: u32 = 1000;

/// The cells the reference's `verifyValid` alone answers valid for bytes that
/// are not one transaction: the stated divergence.
const STATED_DIVERGENCES: usize = 23;

const STATES: [&str; 6] = [
    "parent_absent",
    "parent_present_proven",
    "entry_proven",
    "atomic_subject",
    "parent_of_child",
    "merged",
];

/// The writer's bytes of a transaction read from hex.
fn written(hex: &str) -> Vec<u8> {
    Transaction::from_hex(hex).unwrap().to_binary()
}

/// The shapes, by the recorder's names, and the kind `verify_structure`
/// answers for each that is not one transaction (`None` for the control).
fn shapes() -> Vec<(&'static str, Vec<u8>, Option<Kind>)> {
    let tx = written(TX_HEX);
    let cut = |n: usize| tx[..n].to_vec();
    let mut zero_inputs = Transaction::with_params(
        1,
        Vec::new(),
        vec![TransactionOutput::new(
            0,
            LockingScript::from_binary(&[]).unwrap(),
        )],
        0,
    )
    .to_binary();
    zero_inputs.push(0);
    let mut forty = from_hex("01000000fd0100").unwrap();
    forty.resize(40, 0);
    vec![
        ("exact", tx.clone(), None),
        (
            "plus_one_byte",
            [&tx[..], &[0]].concat(),
            Some(Kind::TrailingBytes),
        ),
        (
            "plus_four_bytes",
            [&tx[..], &[1, 2, 3, 4]].concat(),
            Some(Kind::TrailingBytes),
        ),
        (
            "plus_itself",
            [&tx[..], &tx[..]].concat(),
            Some(Kind::TrailingBytes),
        ),
        ("cut_in_inputs", cut(20), Some(Kind::Truncated)),
        ("cut_at_output_count", cut(118), Some(Kind::BadVarint)),
        ("cut_in_output", cut(150), Some(Kind::Truncated)),
        ("cut_in_lock_time", cut(273), Some(Kind::Truncated)),
        (
            "no_transaction_3_bytes",
            vec![1, 0, 0],
            Some(Kind::Truncated),
        ),
        ("no_transaction_40_bytes", forty, Some(Kind::BadVarint)),
        ("no_bytes", Vec::new(), Some(Kind::Truncated)),
        // A held entry whose version is followed by an input count of 0 is
        // `NoInputs`, ahead of its held kind, as 0.8.3 named it.
        ("zero_inputs_plus_byte", zero_inputs, Some(Kind::NoInputs)),
    ]
}

fn txid(raw: &[u8]) -> String {
    let mut h = sha256d(raw);
    h.reverse();
    to_hex(&h)
}

/// A child that spends output 0 of `parent`: one input with an empty
/// unlocking script, one output of 1,000 satoshis to OP_TRUE.
fn child_of(parent: &str) -> Vec<u8> {
    let mut input = TransactionInput::new(parent.to_string(), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
    let output = TransactionOutput::new(1000, LockingScript::from_binary(&[0x51]).unwrap());
    Transaction::with_params(1, vec![input], vec![output], 0).to_binary()
}

/// The BEEF of `raw` in `state`, and the child's txid when there is one.
fn build(raw: &[u8], state: &str) -> (Beef, Option<String>) {
    let entry = txid(raw);
    let mut beef = Beef::new();
    if state == "entry_proven" {
        beef.merge_bump(MerklePath::from_coinbase_txid(&entry, ENTRY_HEIGHT));
    } else if state != "parent_absent" {
        let parent = written(PARENT_HEX);
        beef.merge_bump(MerklePath::from_coinbase_txid(
            &txid(&parent),
            PARENT_HEIGHT,
        ));
        beef.merge_raw_tx(parent, Some(0));
    }
    let bump_index = (state == "entry_proven").then_some(0);
    beef.merge_raw_tx(raw.to_vec(), bump_index);
    let mut child = None;
    if state == "parent_of_child" {
        let bytes = child_of(&entry);
        child = Some(txid(&bytes));
        beef.merge_raw_tx(bytes, None);
    }
    if state == "atomic_subject" {
        beef.atomic_txid = Some(entry);
    }
    if state == "merged" {
        let mut merged = Beef::new();
        merged.merge_beef(&beef);
        return (merged, None);
    }
    (beef, child)
}

/// The `sort_txs` partition `txid` lands in.
fn partition(beef: &Beef, txid: &str) -> &'static str {
    let sr = beef.clone().sort_txs();
    let has = |v: &[String]| v.iter().any(|t| t == txid);
    match () {
        _ if has(&sr.not_valid) => "not_valid",
        _ if has(&sr.with_missing_inputs) => "with_missing_inputs",
        _ if has(&sr.valid) => "valid",
        _ => "none",
    }
}

/// What this crate answers at each door for one cell.
#[derive(Debug, PartialEq)]
struct Doors {
    entry: &'static str,
    child: Option<&'static str>,
    kind: Result<(), Kind>,
    verify_valid: bool,
    is_valid_false: bool,
    is_valid_true: bool,
    /// The BEEF written then read by `Beef::from_binary`, and that BEEF's
    /// `verify_valid`: `Some(valid)`, or `None` for a refusal.
    reread: Option<bool>,
    /// The BEEF written then read by `Transaction::from_beef`
    /// (`from_atomic_beef` for the atomic subject): the id, or `None`.
    from_beef: Option<String>,
    /// The BEEF written then judged by `verify_stream_structure` (no script
    /// run: block 170 spends a coinbase, whose maturity asks for a mining
    /// tip) with headers that carry every root its BUMPs claim.
    stream_valid: bool,
    /// The same bytes judged by `verify_stream`, scripts run: `Valid` for the
    /// control only when it is proven (its spend of a coinbase is otherwise
    /// `Unverifiable` without a mining tip), kept so that a held entry stays
    /// refused there too.
    stream_full_valid: bool,
    /// `find_atomic_transaction` of the entry.
    atomic_found: bool,
}

fn doors(raw: &[u8], state: &str) -> Doors {
    let entry = txid(raw);
    let (beef, child) = build(raw, state);
    let atomic = state == "atomic_subject";
    let bytes = if atomic {
        beef.clone().to_binary_atomic(&entry).unwrap()
    } else {
        beef.clone().to_binary()
    };
    let mut tracker = MockChainTracker::new(ENTRY_HEIGHT);
    for bump in &beef.bumps {
        tracker.add_root(bump.block_height, bump.compute_root(None).unwrap());
    }
    let stream = verify_stream_structure(&bytes[..], &tracker, None).unwrap();
    Doors {
        entry: partition(&beef, &entry),
        child: child.as_deref().map(|c| partition(&beef, c)),
        kind: beef.clone().verify_structure().map(|_| ()),
        verify_valid: beef.clone().verify_valid(false).valid,
        is_valid_false: beef.clone().is_valid(false),
        is_valid_true: beef.clone().is_valid(true),
        reread: Beef::from_binary(&bytes)
            .ok()
            .map(|mut b| b.verify_valid(false).valid),
        from_beef: if atomic {
            Transaction::from_atomic_beef(&bytes).ok()
        } else {
            Transaction::from_beef(&bytes, Some(&entry)).ok()
        }
        .map(|t| t.id()),
        stream_valid: matches!(stream, Verdict::Valid { .. }),
        stream_full_valid: matches!(
            verify_stream(&bytes[..], &tracker, None).unwrap(),
            Verdict::Valid { .. }
        ),
        atomic_found: beef.find_atomic_transaction(&entry).is_some(),
    }
}

fn vector_cell<'a>(v: &'a Value, shape: &str, state: &str) -> &'a Value {
    v["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["shape"] == shape && c["state"] == state)
        .unwrap_or_else(|| panic!("{shape} {state}: no recorded cell"))
}

/// The reference's end-to-end answer: false when `mergeRawTx` or `mergeBeef`
/// throws, the BEEF it writes is refused by `fromBinaryStrict`, or the BEEF
/// read back is not valid.
fn reference_end_to_end(cell: &Value) -> bool {
    let ok = |k: &str| cell[k].is_null() || cell[k]["ok"] == true;
    ok("merge_raw_tx")
        && ok("merge_beef")
        && cell["from_binary_strict"]["ok"] == true
        && cell["from_binary_strict"]["value"]["verify_valid"] == true
}

#[test]
fn bytes_that_are_not_one_transaction_are_refused_at_every_verdict_door_852() {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(v["reference"], "ts-stack@edf6e03 packages/sdk");
    let mut cells = 0;
    let mut mismatches = Vec::new();
    for (shape, raw, kind) in shapes() {
        for state in STATES {
            let cell = vector_cell(&v, shape, state);
            assert_eq!(
                cell["raw"],
                to_hex(&raw),
                "{shape} {state}: the shape's bytes"
            );
            assert_eq!(cell["entry_txid"], txid(&raw), "{shape} {state}");
            let got = doors(&raw, state);
            let id = txid(&raw);
            let want = match kind {
                // The control: what 0.8.3 answers.
                None if state == "parent_absent" => Doors {
                    entry: "with_missing_inputs",
                    child: None,
                    kind: Err(Kind::InputNamesNoElement),
                    verify_valid: false,
                    is_valid_false: false,
                    is_valid_true: false,
                    reread: Some(false),
                    from_beef: Some(id.clone()),
                    stream_valid: false,
                    stream_full_valid: false,
                    atomic_found: true,
                },
                None => Doors {
                    entry: "valid",
                    child: (state == "parent_of_child").then_some("valid"),
                    kind: Ok(()),
                    verify_valid: true,
                    is_valid_false: true,
                    is_valid_true: true,
                    reread: Some(true),
                    from_beef: Some(id.clone()),
                    stream_valid: true,
                    // Proven itself, nothing to run.
                    stream_full_valid: state == "entry_proven",
                    // A raw entry merged with its BUMP index is not parsed.
                    atomic_found: state != "entry_proven",
                },
                Some(kind) => Doors {
                    entry: "not_valid",
                    child: (state == "parent_of_child").then_some("not_valid"),
                    kind: Err(kind),
                    verify_valid: false,
                    is_valid_false: false,
                    is_valid_true: false,
                    reread: got.reread.filter(|valid| !valid),
                    from_beef: None,
                    stream_valid: false,
                    stream_full_valid: false,
                    atomic_found: false,
                },
            };
            if got != want {
                mismatches.push(format!("{shape} {state}: got {got:?}"));
            }
            if let Some(child) = cell["child_txid"].as_str() {
                assert_eq!(Some(child), got_child(&raw).as_deref(), "{shape} {state}");
            }
            let reference = reference_end_to_end(cell);
            if kind.is_some() {
                assert!(
                    !reference,
                    "{shape} {state}: the reference reads it back valid"
                );
            } else {
                assert_eq!(reference, want.verify_valid, "{shape} {state}: the control");
            }
            cells += 1;
        }
    }
    assert_eq!(cells, 72);
    assert!(
        mismatches.is_empty(),
        "{} cells:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

fn got_child(raw: &[u8]) -> Option<String> {
    Some(txid(&child_of(&txid(raw))))
}

#[test]
fn the_reference_verify_valid_alone_answers_valid_in_the_stated_cells_852() {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    let cells = v["cells"].as_array().unwrap();
    let stated: Vec<&Value> = cells
        .iter()
        .filter(|c| c["stated_divergence"] == true)
        .collect();
    assert_eq!(stated.len(), STATED_DIVERGENCES);
    for c in cells {
        let alone = c["shape"] != "exact" && c["verify_valid"]["value"] == true;
        assert_eq!(c["stated_divergence"] == true, alone, "{c}");
    }
    // Each of them is refused here, and by the reference's own end-to-end read.
    let shapes: HashMap<&str, Vec<u8>> = shapes().into_iter().map(|(n, r, _)| (n, r)).collect();
    let mut valid_here = Vec::new();
    for c in stated {
        let raw = &shapes[c["shape"].as_str().unwrap()];
        let state = c["state"].as_str().unwrap();
        assert!(!reference_end_to_end(c), "{c}");
        if doors(raw, state).verify_valid {
            valid_here.push(format!("{} {state}", c["shape"]));
        }
    }
    assert!(
        valid_here.is_empty(),
        "{} valid here: {valid_here:?}",
        valid_here.len()
    );
}

#[test]
fn a_held_entry_lists_no_input_where_the_reference_scans_the_prefix_852() {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    let raw = [written(TX_HEX), vec![0]].concat();
    let mut beef = Beef::new();
    let held = beef.merge_raw_tx(raw, None);
    assert!(held.tx().is_none());
    assert!(held.input_txids.is_empty());
    let cell = vector_cell(&v, "plus_one_byte", "parent_absent");
    assert_eq!(
        cell["merge_raw_tx"]["value"]["input_txids"][0],
        "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"
    );
}

/// A held entry's public `is_valid` field is `Some(false)` after `sort_txs`,
/// with a BUMP index or without (#852).
#[test]
fn a_held_entry_is_valid_field_is_false_after_the_sort_852() {
    let raw = [written(TX_HEX), vec![0]].concat();
    for state in ["parent_absent", "entry_proven"] {
        let (mut beef, _) = build(&raw, state);
        beef.sort_txs();
        let entry = beef.find_txid(&txid(&raw)).unwrap();
        assert_eq!(entry.is_valid, Some(false), "{state}");
    }
}

/// `verify_structure` leaves the order and the `is_valid` fields `sort_txs`
/// leaves (#852): a held entry under a BUMP index sorts with the entries
/// that are not valid, ahead of a proven one.
#[test]
fn verify_structure_leaves_the_order_sort_txs_leaves_852() {
    let parent = written(PARENT_HEX);
    let raw = [written(TX_HEX), vec![0]].concat();
    let mut beef = Beef::new();
    beef.merge_bump(MerklePath::from_coinbase_txid(
        &txid(&parent),
        PARENT_HEIGHT,
    ));
    beef.merge_raw_tx(parent.clone(), Some(0));
    beef.merge_bump(MerklePath::from_coinbase_txid(&txid(&raw), ENTRY_HEIGHT));
    beef.merge_raw_tx(raw.clone(), Some(1));
    let read = |b: &Beef| -> Vec<(String, Option<bool>)> {
        b.txs.iter().map(|t| (t.txid(), t.is_valid)).collect()
    };
    let mut sorted = beef.clone();
    sorted.sort_txs();
    assert_eq!(beef.verify_structure(), Err(Kind::TrailingBytes));
    assert_eq!(read(&beef), read(&sorted));
    assert_eq!(
        read(&beef),
        [(txid(&raw), Some(false)), (txid(&parent), Some(true))]
    );
}

/// A BEEF holding a held entry and a BUMP whose root does not compute is
/// refused for the BUMP, as the streaming reader meets it (BUMPs precede
/// the transactions) (#852).
#[test]
fn a_bump_that_does_not_compute_is_refused_ahead_of_a_held_entry_852() {
    let raw = [written(TX_HEX), vec![0]].concat();
    let mut beef = Beef::new();
    beef.merge_bump(MerklePath {
        block_height: PARENT_HEIGHT,
        path: vec![vec![MerklePathLeaf::new_txid(
            1,
            txid(&written(PARENT_HEX)),
        )]],
    });
    beef.merge_raw_tx(raw, None);
    assert_eq!(beef.clone().verify_structure(), Err(Kind::MissingSibling));
    assert!(!beef.clone().verify_valid(false).valid);
    let bytes = beef.to_binary();
    let stream = verify_stream_structure(&bytes[..], MockChainTracker::new(ENTRY_HEIGHT), None);
    assert!(
        matches!(
            stream,
            Ok(Verdict::Invalid {
                kind: Kind::MissingSibling,
                ..
            })
        ),
        "{stream:?}"
    );
}
