//! #603 shard S2: `src/transaction/beef_stream.rs`'s index folds
//! (`BeefIndex::fold_bump`, `fold_tx`, `fold_txid_only`), their 35 survivors
//! of the widened oracle (run 41327640129, `docs/census/mutants-2026-11-01.md`)
//! each killed by a BEEF of the sibling's rows read through the stream.
//!
//! The BEEFs are `tests/vectors/beef_reference_603.json`'s `stream_s2_*`
//! cases, written by `tests/support/beef_reference_603.mjs` from the rows of
//! bsv-script-lean `corpus/wire/beef.jsonl` (beef-001, -003, -004, -014, -015,
//! -023, -026, by id; the rows are byte-identical at 5dc337e1 and 387dab35)
//! with the reference's verdict (`Beef.verifyValid(true)` at `ts-stack@edf6e03`
//! under Node v22.18.0). The Lean's reading of the same bytes is
//! `tests/vectors/beef_stream_603_s2_lean.json`, written by
//! `tests/support/beef_stream_603_s2.lean`: bsv-stack-lean@88c37ac8's
//! `readBytes` (`lean/BeefOfAnySize.lean:1151-1155`, the definition this reader
//! states) under SHA-256 with headers carrying the reference's roots, and
//! bsv-script-lean's `isFinalTx` (`lean/BsvChain/Finality.lean:116-120`).
//!
//! The counts the folds keep (`steps`, the cost model's `work`, the index's
//! size) reach no verdict: they are compared with the Lean's `summary` of the
//! same reading (`BeefOfAnySize/Scenarios.lean:91-95`; `Parsed.cost`,
//! `BeefOfAnySize.lean:913-926`; `Index.size`, :860-861), the only place they
//! are stated. Every other fold mutant moves a verdict.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use bsv_rs::primitives::from_hex;
use bsv_rs::transaction::beef_stream::{
    ChainTip, Hash32, Headers, Progress, SpendRefusal, StreamVerifier, Verdict,
};
use serde_json::Value;

const REFERENCE: &str = include_str!("vectors/beef_reference_603.json");
const LEAN: &str = include_str!("vectors/beef_stream_603_s2_lean.json");

/// The reference's case and the Lean's reading of it.
fn case(name: &str) -> (Value, Value) {
    let reference: Value = serde_json::from_str(REFERENCE).unwrap();
    let lean: Value = serde_json::from_str(LEAN).unwrap();
    (
        reference["cases"][name].clone(),
        lean["cases"][name].clone(),
    )
}

fn bytes(case: &Value) -> Vec<u8> {
    from_hex(case["hex"].as_str().unwrap()).unwrap()
}

fn wire(display: &str) -> Hash32 {
    let mut h: Hash32 = from_hex(display).unwrap().try_into().unwrap();
    h.reverse();
    h
}

/// Headers carrying the roots the reference checked (display hex, by height).
fn roots(case: &Value) -> HashMap<u64, Hash32> {
    case["roots"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(h, r)| (h.parse().unwrap(), wire(r.as_str().unwrap())))
        .collect()
}

/// The roots of a `Valid` verdict, as the reference names them.
fn checked(verdict: &Verdict) -> HashMap<u64, Hash32> {
    match verdict {
        Verdict::Valid { roots, .. } => roots.iter().copied().collect(),
        other => panic!("not valid: {other:?}"),
    }
}

/// A reading to its verdict, with the Lean's `summary` counts of the state:
/// steps, work, index size.
fn read<H: Headers>(mut reader: StreamVerifier<&[u8], H>) -> (Verdict, (u64, u64, u64)) {
    let verdict = loop {
        if let Progress::Verdict(v) = reader.step().unwrap() {
            break v;
        }
    };
    let index = reader.index();
    (
        verdict,
        (index.steps(), index.model_work(), index.spec_size()),
    )
}

/// The Lean's acceptance and its `summary` counts.
fn lean_summary(lean: &Value) -> (u64, u64, u64) {
    let r = &lean["reading"];
    assert!(r["refusal"].is_null(), "the Lean refuses: {r}");
    (
        r["steps"].as_u64().unwrap(),
        r["work"].as_u64().unwrap(),
        r["size"].as_u64().unwrap(),
    )
}

/// The headers, and a chain tip for the finality rule.
struct Tipped(HashMap<u64, Hash32>, ChainTip);

impl Headers for Tipped {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        self.0.carries(height, root)
    }
    fn mining_tip(&self) -> Option<ChainTip> {
        Some(self.1)
    }
}

/// `finality/threshold-500000000`'s network (genesis at 10, CSV at 5: the
/// candidate's cutoff is the tip's median time past) at a tip.
#[allow(deprecated)] // The default path still reads ChainTip's Genesis height (#451).
fn tip(height: u32, median_time_past: u32) -> ChainTip {
    ChainTip {
        height,
        median_time_past,
        genesis_height: 10,
        csv_height: 5,
        next_block_time: None,
    }
}

// ---------------------------------------------------------------------------
// fold_bump and fold_txid_only and fold_tx: the cost model's counts
// ---------------------------------------------------------------------------

/// mergeBump (`Beef.ts:687-811`): beef-014's and beef-015's BUMPs, one height
/// and one root (block 500000), combined into one proving two txids (8 levels,
/// 10 leaves); beef-023's BUMP of block 9 proves one; beef-014's transaction a
/// txid-only entry the combined BUMP proves (`makeTxidOnly`, :552-563);
/// beef-015's transaction of three inputs. The Lean accepts with steps 6, work
/// 1611 (`Parsed.cost`: a BUMP's bytes + `2 * leaves + 6 * treeHeight *
/// proven` + 1 + `2 * proven`, a transaction's bytes + 5 + `2 * inputs`, a
/// txid-only entry 32 + 3; `BeefOfAnySize.lean:920-926`) and index size 21.
///
/// Kills: fold_bump 1942:20 (`hashed` not counted), 1954:22, 1954:31,
/// 1954:35, 1954:62, 1956:19, 1956:36, 1956:43, 1956:47, 1956:51 (the walk
/// and the work: the combined BUMP's two txids and the lone BUMP's one tell
/// `2 * hashed` from `2 + hashed`); fold_txid_only 2062:20, 2063:19, 2063:25
/// (its step and its 35 units); fold_tx 2228:38, 2228:42, 2228:46 (three
/// inputs tell `2 * n` from `2 + n` and `2 / n`).
#[test]
fn the_folds_count_the_leans_cost_two_bumps_combined_and_a_txid_only_entry_beef_014_015_023() {
    let (reference, lean) = case("stream_s2_two_bumps_combined_and_a_txid_only_entry");
    assert_eq!(reference["valid"], true, "the reference's verdict");
    assert_eq!(
        reference["bumps"],
        serde_json::json!([
            {"height": 500000, "levels": 8, "leaves": 10, "txids": 2},
            {"height": 9, "levels": 1, "leaves": 1, "txids": 1}
        ])
    );
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let (verdict, counts) = read(StreamVerifier::structure_only(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
    assert_eq!(counts, lean_summary(&lean));
    assert_eq!(counts, (6, 1611, 21));
}

/// One BUMP whose level 0 carries beef-003's txid at offsets 0 and 1. The
/// Lean's index keeps a BUMP's txids as a set (`setOf`, `Index.size`:
/// `BeefOfAnySize.lean:475,860-861`): size 5, the txid once for the BUMP.
///
/// Kills: fold_bump 1947:35 guard `true` (the BUMP's second carrying of its
/// own txid recorded as a carrying by another BUMP).
#[test]
fn a_bump_carrying_one_txid_twice_holds_it_once_beef_003() {
    let (reference, lean) = case("stream_s2_one_bump_carries_one_txid_twice");
    assert_eq!(reference["valid"], true, "the reference's verdict");
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let (verdict, counts) = read(StreamVerifier::structure_only(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
    assert_eq!(counts, lean_summary(&lean));
    assert_eq!(counts.2, 5);
}

// ---------------------------------------------------------------------------
// fold_bump: the BUMP index rule
// ---------------------------------------------------------------------------

/// BRC-62's BUMP index rule (the Lean's `checkBump`, `BeefOfAnySize.lean:888-892`:
/// the BUMP the index names carries the txid at level 0; the reference's
/// `#verifyBumpIndexLeaves`, `Beef.ts:1129-1139`): beef-003's transaction is
/// carried by its own BUMP (block 100000) and by a later one (block 800000,
/// beef-004's txid its sibling), and names the later. Valid for both.
///
/// Kills: fold_bump 1947:35 guard `false`, 1947:45 `==` (the later BUMP's
/// carrying not recorded: `TxidNotInBump { index: 1 }`).
#[test]
fn a_txid_two_bumps_carry_is_proven_by_the_later_it_names_beef_003_004() {
    let (reference, lean) = case("stream_s2_one_txid_in_two_bumps_named_by_the_later");
    assert_eq!(reference["valid"], true, "the reference's verdict");
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let (verdict, counts) = read(StreamVerifier::structure_only(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
    assert_eq!(counts, lean_summary(&lean));
    let (verdict, _) = read(StreamVerifier::new(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
}

// ---------------------------------------------------------------------------
// fold_txid_only and fold_tx: an entry new to the index releases its children
// ---------------------------------------------------------------------------

/// beef-026 with its parent a txid-only entry: the child ahead of the parent
/// its BUMP proves. The reference sorts before it checks (`sortTxs`,
/// `Beef.ts:1065`) and answers valid; this reader holds the child until the
/// parent is in (bsv-rs#240). The Lean is order-bound and refuses at the
/// child's input (`inputNamesNoElement`; its row (b),
/// `BeefOfAnySize.lean:3381-3392`, "a divergence row, no filing").
///
/// Kills: fold_txid_only 2052:19 (the new entry read as a repeat: the held
/// child never released, `InputNamesNoElement`).
#[test]
fn a_child_ahead_of_its_txid_only_parent_is_released_by_it_beef_026() {
    let (reference, lean) = case("stream_s2_child_before_its_txid_only_parent");
    assert_eq!(reference["valid"], true, "the reference's verdict");
    assert!(lean["reading"]["refusal"]
        .as_str()
        .unwrap()
        .contains("inputNamesNoElement"));
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let (verdict, _) = read(StreamVerifier::structure_only(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
}

/// beef-026 as the sibling wrote it (`shape: child-before-parent`): the child
/// ahead of its parent, the parent under its BUMP. Valid for the reference
/// (the sort, `Beef.ts:1065`) and for this reader (bsv-rs#240), on the
/// structure and with the scripts; the Lean's row (b) again.
///
/// Kills: fold_tx 2200:19 (the parent read as a repeat: the held child never
/// released).
#[test]
fn a_child_ahead_of_its_parent_is_released_by_it_beef_026() {
    let (reference, lean) = case("stream_s2_child_before_its_parent");
    assert_eq!(reference["row"], "beef-026");
    assert_eq!(reference["valid"], true, "the reference's verdict");
    assert!(lean["reading"]["refusal"]
        .as_str()
        .unwrap()
        .contains("inputNamesNoElement"));
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let (verdict, _) = read(StreamVerifier::structure_only(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
    // The child, mined at 170, spends block 9's coinbase: a tip at 169
    // (mainnet's activation heights) for its maturity.
    #[allow(deprecated)] // The default path still reads ChainTip's Genesis height (#451).
    let at_170 = ChainTip {
        height: 169,
        median_time_past: 1_231_731_025,
        genesis_height: 620_538,
        csv_height: 419_328,
        next_block_time: None,
    };
    let (verdict, _) = read(StreamVerifier::new(
        &bytes[..],
        Tipped(headers.clone(), at_170),
        None,
    ));
    assert_eq!(checked(&verdict), headers);
}

// ---------------------------------------------------------------------------
// fold_tx: a repeat keeps the transaction's outputs
// ---------------------------------------------------------------------------

/// P (block 800000, under its BUMP) read first as a txid-only entry, then as
/// its raw transaction, then C0 spending P:0 (P2PKH; the reference's scripts
/// verdict true). The Lean's index takes the repeat (`enter`, `enterRaw`:
/// the earliest entry's offset kept, the raw entry's edges added;
/// `BeefOfAnySize.lean:900-910`) and accepts. The reference reads the frame as
/// two entries of one txid and refuses it (`#hasDuplicateTxids`,
/// `Beef.ts:1066,1092-1099`); merged into a BEEF (`mergeBeef`, :971) it is one
/// entry, raw, and valid: the stated parity note of this shard.
///
/// Kills: fold_tx 2203:20 (the txid-only entry not upgraded to its raw
/// transaction: P's outputs never kept, C0's spend refused).
#[test]
fn a_txid_only_entry_then_its_transaction_keeps_its_outputs_for_the_child() {
    let (reference, lean) = case("stream_s2_txid_only_entry_then_its_transaction");
    assert_eq!(
        reference["scripts"], true,
        "the reference's scripts verdict"
    );
    assert_eq!(reference["valid"], false, "the reference: a repeated txid");
    assert_eq!(reference["merged_valid"], true, "the reference, merged");
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let (verdict, counts) = read(StreamVerifier::structure_only(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
    assert_eq!(counts, lean_summary(&lean));
    let (verdict, _) = read(StreamVerifier::new(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
}

/// P read twice as its raw transaction, then C0 spending P:0. The Lean takes
/// the repeat and accepts; the reference refuses the repeated txid and accepts
/// the merge, as above.
///
/// Kills: fold_tx 2203:20 (the repeat re-entered: P's outputs replaced by
/// none, C0's spend refused).
#[test]
fn a_transaction_read_twice_keeps_its_outputs_for_the_child() {
    let (reference, lean) = case("stream_s2_transaction_twice");
    assert_eq!(
        reference["scripts"], true,
        "the reference's scripts verdict"
    );
    assert_eq!(reference["valid"], false, "the reference: a repeated txid");
    assert_eq!(reference["merged_valid"], true, "the reference, merged");
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let (verdict, counts) = read(StreamVerifier::structure_only(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
    assert_eq!(counts, lean_summary(&lean));
    let (verdict, _) = read(StreamVerifier::new(&bytes[..], &headers, None));
    assert_eq!(checked(&verdict), headers);
}

// ---------------------------------------------------------------------------
// fold_tx: the finality rule's threshold
// ---------------------------------------------------------------------------

/// `finality/threshold-500000000` (bsv-script-lean `corpus/chain/finality/
/// finality.jsonl`, expected false: "Below 500000000 the selected limit is
/// height; from that value it is time"; node validation.cpp:227-247 at
/// 6504a3af; `isFinalTx`, `lean/BsvChain/Finality.lean:116-120`): C1 (version
/// 2, lock time 500000000, sequence 0) spending P:0, its scripts valid for the
/// reference. At the row's own candidate (height 500000000, cutoff 500000000)
/// the Lean answers not final; at candidate 800001 with the tip's median time
/// past 500000001 it answers final, the lock read as a time.
///
/// Kills: fold_tx 2143:46 (`<=`: the lock at the threshold read as a height,
/// not final at 800001).
#[test]
fn a_lock_time_at_the_threshold_is_a_time_finality_threshold_500000000() {
    let (reference, lean) = case("stream_s2_lock_time_at_the_threshold");
    assert_eq!(reference["finality_row"], "finality/threshold-500000000");
    assert_eq!(reference["lock_time"], 500_000_000);
    assert_eq!(reference["sequences"], serde_json::json!([0]));
    assert_eq!(
        reference["scripts"], true,
        "the reference's scripts verdict"
    );
    let row = lean["is_final_tx"]["row_height_500000000_time_500000000"]
        .as_bool()
        .unwrap();
    let later = lean["is_final_tx"]["height_800001_time_500000001"]
        .as_bool()
        .unwrap();
    assert!(!row && later, "the Lean's isFinalTx");
    let bytes = bytes(&reference);
    let headers = roots(&reference);
    let txid = wire(reference["child"].as_str().unwrap());

    let (verdict, _) = read(StreamVerifier::new(
        &bytes[..],
        Tipped(headers.clone(), tip(800_000, 500_000_001)),
        None,
    ));
    assert_eq!(checked(&verdict), headers);

    let (verdict, _) = read(StreamVerifier::new(
        &bytes[..],
        Tipped(headers.clone(), tip(499_999_999, 500_000_000)),
        None,
    ));
    match verdict {
        Verdict::SpendRefused {
            txid: refused,
            input: None,
            why: SpendRefusal::NonFinal { lock_time },
            ..
        } => {
            assert_eq!(refused, txid);
            assert_eq!(lock_time, 500_000_000);
        }
        other => panic!("not refused as non-final: {other:?}"),
    }
}
