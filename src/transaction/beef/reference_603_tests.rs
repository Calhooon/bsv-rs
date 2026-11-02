#![cfg(test)]
//! #603: `src/transaction/beef.rs`'s surviving mutants of the widened oracle
//! (run 41327640129), each killed by a row of the sibling's wire corpus
//! (`bsv-script-lean@387dab35` `corpus/wire/beef.jsonl`, `atomic-beef.jsonl`,
//! the BEEF view `lean/BsvChain/Views/Wire/BEEF.lean`) and the reference's
//! answer on it: `tests/vectors/beef_reference_603.json`, recorded from
//! `Beef.ts` at `ts-stack@edf6e03` under Node v22.18.0 by
//! `tests/support/beef_reference_603.mjs`. The module sits inside the BEEF
//! surface's mutation selection (`--lib`, the `transaction::` tree), outside
//! the `src/transaction/beef*.rs` glob it mutates.
#![allow(clippy::unwrap_used, clippy::expect_used)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use serde_json::Value;

use crate::primitives::{from_hex, Reader};
use crate::transaction::beef_stream::{verify_stream_structure, Kind, Verdict};
use crate::transaction::{Beef, MerklePath, BEEF_V1};

const VECTOR: &str = include_str!("../../../tests/vectors/beef_reference_603.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

/// A recorded case by its name.
fn case(name: &str) -> Value {
    vector()["cases"][name].clone()
}

/// The bytes of a row of the sibling's wire corpus, copied by id.
fn row(id: &str) -> Vec<u8> {
    from_hex(vector()["rows"][id]["hex"].as_str().unwrap()).unwrap()
}

fn read(id: &str) -> Beef {
    Beef::from_binary(&row(id)).unwrap()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| text(s).to_string())
        .collect()
}

/// beef-023's parts: the parent (block 9's coinbase, `0437cd7f…`), its BUMP and
/// the child (`f4184fc5…`, block 170's second transaction) that spends it.
struct Family {
    parent: Vec<u8>,
    bump: MerklePath,
    child: Vec<u8>,
}

const PARENT: &str = "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9";
const CHILD: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

fn family() -> Family {
    let beef = read("beef-023");
    let parent = beef.find_txid(PARENT).unwrap();
    Family {
        parent: parent.raw_tx().unwrap().to_vec(),
        bump: beef.bumps[parent.bump_index().unwrap()].clone(),
        child: beef.find_txid(CHILD).unwrap().raw_tx().unwrap().to_vec(),
    }
}

/// A row's one raw transaction and its BUMP (beef-002, beef-004: one each).
fn proven(id: &str) -> (Vec<u8>, MerklePath) {
    let beef = read(id);
    (
        beef.txs[0].raw_tx().unwrap().to_vec(),
        beef.bumps[0].clone(),
    )
}

/// Kills `merge_bump`'s `==` to `!=` at 332:38 and 336:30: a BUMP of the
/// height and root one held is combined with it, not added (`#findOrInsertBump`,
/// `Beef.ts:791-811`); the BEEF merged into itself keeps one BUMP and its bytes.
#[test]
fn a_bump_of_a_held_height_and_root_is_combined_wire_beef_001() {
    let expected = case("merge_beef_into_itself");
    let mut beef = read("beef-001");
    beef.merge_beef(&read("beef-001"));
    assert_eq!(beef.bumps.len() as u64, expected["bumps"].as_u64().unwrap());
    assert_eq!(beef.to_hex(), text(&expected["hex"]));
}

/// Kills `update_bump_indices` replaced with `()` at 359:9: a BUMP merged after
/// the raw transaction it proves marks it proven (`#mergeBumpEntry`,
/// `Beef.ts:774-789`; the mined object, `BEEF.lean:344-364`).
#[test]
fn a_bump_merged_after_its_transaction_proves_it_wire_beef_023() {
    let f = family();
    let mut beef = Beef::with_version(BEEF_V1);
    beef.merge_raw_tx(f.parent, None);
    beef.merge_raw_tx(f.child, None);
    beef.merge_bump(f.bump);
    assert_eq!(
        beef.to_hex(),
        text(&case("bump_merged_after_its_transaction")["hex"])
    );
}

/// Kills `mark_mutated` replaced with `()` at 132:9: a merge after a
/// serialization sorts again before the next (`#markMutated`,
/// `#ensureSortedForSerialization`, `Beef.ts:325-358`), the parent before its
/// child (BRC-62's order, `BEEF.lean:409-416`).
#[test]
fn a_merge_after_a_serialization_sorts_again_wire_beef_023() {
    let expected = case("parent_merged_after_a_serialization");
    let f = family();
    let mut beef = Beef::with_version(BEEF_V1);
    beef.merge_bump(f.bump);
    beef.merge_raw_tx(f.child, None);
    assert_eq!(beef.to_hex(), text(&expected["first"]));
    beef.merge_raw_tx(f.parent, None);
    assert_eq!(beef.to_hex(), text(&expected["second"]));
}

/// Kills `find_bump` replaced with `None` at 145:9 (`Beef.ts:570-574`).
#[test]
fn find_bump_answers_the_bump_carrying_the_txid_wire_beef_001() {
    let expected = case("find_bump");
    let beef = read("beef-001");
    let bump = beef.find_bump(text(&expected["txid"])).unwrap();
    assert_eq!(
        u64::from(bump.block_height),
        expected["block_height"].as_u64().unwrap()
    );
    assert_eq!(bump.compute_root(None).unwrap(), text(&expected["root"]));
    assert!(expected["absent"].as_bool().unwrap());
    assert!(read("beef-023").find_bump(CHILD).is_none());
}

/// Kills `find_transaction_for_signing` replaced with `None` and with
/// `Some(Default::default())` at 150:9: the transaction, each input's source
/// linked from the BEEF (`Beef.ts:615-631`).
#[test]
fn find_transaction_for_signing_links_each_source_wire_beef_023() {
    let expected = case("find_transaction_for_signing");
    let beef = read("beef-023");
    let tx = beef
        .find_transaction_for_signing(text(&expected["txid"]))
        .unwrap();
    assert_eq!(tx.id(), text(&expected["found"]));
    let sources: Vec<Option<String>> = tx
        .inputs
        .iter()
        .map(|i| i.source_transaction.as_ref().map(|s| s.id()))
        .collect();
    let recorded: Vec<Option<String>> = expected["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().map(str::to_string))
        .collect();
    assert_eq!(sources, recorded);
    assert!(expected["absent"].as_bool().unwrap());
    assert!(beef
        .find_transaction_for_signing(&"00".repeat(32))
        .is_none());
}

/// Kills `add_input_proof`'s `+=` to `*=` at 271:28 (a timeout in the census:
/// here the walk's index never moves and the frame's parent index underflows):
/// the source linked with its BUMP attached (`Beef.ts:639-668`; the ancestry,
/// `BEEF.lean:398-407`).
#[test]
fn find_atomic_transaction_links_the_proven_source_wire_beef_023() {
    let expected = case("find_atomic_transaction");
    let beef = read("beef-023");
    let tx = beef
        .find_atomic_transaction(text(&expected["txid"]))
        .unwrap();
    let source = tx.inputs[0].source_transaction.as_ref().unwrap();
    assert_eq!(source.id(), text(&expected["source"]));
    let height = source.merkle_path.as_ref().unwrap().block_height;
    assert_eq!(
        u64::from(height),
        expected["source_block_height"].as_u64().unwrap()
    );
}

/// Kills `from_reader` replaced with `Ok(Default::default())` at 997:9: one
/// BEEF read from the front, the byte after it left (`Beef.fromReader`,
/// `Beef.ts:1240-1284`; `Beef.decodePrefix`, `BEEF.lean:121-128`).
#[test]
fn from_reader_reads_the_frame_and_leaves_the_byte_after_it_wire_beef_030() {
    let expected = case("from_reader");
    let bytes = row("beef-030");
    let mut reader = Reader::new(&bytes);
    let mut beef = Beef::from_reader(&mut reader).unwrap();
    assert_eq!(beef.to_hex(), text(&expected["hex"]));
    assert_eq!(
        reader.remaining() as u64,
        expected["left"].as_u64().unwrap()
    );
}

/// Kills `is_atomic` replaced with `true` at 1146:9: a plain BEEF is not
/// atomic (`Beef.ts:482-495`; an Atomic BEEF is never read as a plain one and
/// the converse, `AtomicBEEF.lean:102-112`).
#[test]
fn a_plain_beef_is_not_atomic_wire_beef_001_atomic_beef_001() {
    let expected = case("is_atomic");
    for id in ["beef-001", "atomic-beef-001"] {
        assert_eq!(
            read(id).is_atomic(),
            expected["rows"][id].as_bool().unwrap(),
            "{id}"
        );
    }
}

/// Kills `clone_shallow` replaced with `Default::default()` at 1151:9
/// (`Beef.clone`, `Beef.ts:1605-1622`).
#[test]
fn a_shallow_clone_writes_the_bytes_of_the_original_wire_beef_023() {
    let mut clone = read("beef-023").clone_shallow();
    assert_eq!(clone.to_hex(), text(&case("clone")["hex"]));
}

/// Kills `to_log_string` replaced with `String::new()` and `"xyzzy".into()` at
/// 1163:9 and the inputs list's `delete !`: the reference's text
/// (`Beef.toLogString`, `Beef.ts:1698-1733`), conformed by #603.
#[test]
fn the_log_string_is_the_reference_text_wire_beef_023() {
    assert_eq!(
        read("beef-023").to_log_string(),
        text(&case("to_log_string")["log"])
    );
}

/// Kills `bump_roots`' guard to `true` at 740:35 and `!=` to `==` at 740:45:
/// two BUMPs at one height that agree on its root are valid
/// (`#collectBumpTxids`, `#confirmComputedRoot`, `Beef.ts:1112-1127,1153-1167`).
#[test]
fn two_bumps_at_one_height_with_one_root_are_valid_wire_beef_001() {
    let expected = case("two_bumps_one_root");
    let mut beef = read("beef-001");
    let bump = beef.bumps[0].clone();
    beef.bumps.push(bump);
    assert_eq!(beef.to_hex(), text(&expected["hex"]));
    assert_eq!(
        beef.verify_valid(false).valid,
        expected["valid"].as_bool().unwrap()
    );
    assert!(beef.verify_structure().is_ok());
}

/// Kills `bump_roots`' guard to `false` at 740:35: two BUMPs at one height with
/// two roots are refused, the headers carrying one root per height (the same
/// sites); beef-002's BUMP set at beef-001's height.
#[test]
fn two_bumps_at_one_height_with_two_roots_are_refused_wire_beef_001_beef_002() {
    let expected = case("two_bumps_two_roots");
    let mut beef = read("beef-001");
    let (_, mut other) = proven("beef-002");
    other.block_height = beef.bumps[0].block_height;
    beef.bumps.push(other);
    assert_eq!(beef.to_hex(), text(&expected["hex"]));
    assert_eq!(
        beef.verify_valid(false).valid,
        expected["valid"].as_bool().unwrap()
    );
    assert_eq!(beef.verify_structure(), Err(Kind::RootNotCarried));
}

/// Kills `entries_as_folded`'s guard to `false` at 786:41: a BUMP index naming
/// a BUMP that does not carry the txid is refused (`#verifyBumpIndexLeaves`,
/// `Beef.ts:1129-1139`; no object, `BEEF.lean:354-364`).
#[test]
fn a_bump_index_naming_a_bump_without_the_txid_is_refused_wire_beef_023() {
    let expected = case("bump_index_names_a_bump_without_the_txid");
    let mut beef = read("beef-023");
    let at = beef.txs.iter().position(|t| t.txid() == CHILD).unwrap();
    beef.txs[at].set_bump_index(Some(0));
    assert_eq!(
        beef.verify_valid(false).valid,
        expected["valid"].as_bool().unwrap()
    );
    assert_eq!(beef.verify_structure(), Err(Kind::TxidNotInBump));
}

/// Kills `entries_as_folded`'s guard to `false` at 783:41: a BUMP index naming
/// no BUMP is refused (the reference's `false`, `Beef.ts:1132-1133`; the
/// sibling's `accept: false` on beef-029), and in the kind the streaming
/// reader names on the same bytes (one reader for both paths, bsv-rs#86).
#[test]
fn a_bump_index_naming_no_bump_is_refused_in_the_stream_kind_wire_beef_029() {
    let expected = case("bump_index_names_no_bump");
    let bytes = row("beef-029");
    let mut beef = Beef::from_binary(&bytes).unwrap();
    let mut root = from_hex(&beef.bumps[0].compute_root(None).unwrap()).unwrap();
    root.reverse();
    let headers: HashMap<u64, [u8; 32]> = HashMap::from([(
        u64::from(beef.bumps[0].block_height),
        root.try_into().unwrap(),
    )]);
    let stream = verify_stream_structure(bytes.as_slice(), &headers, None).unwrap();
    assert!(
        matches!(
            stream,
            Verdict::Invalid {
                kind: Kind::BumpIndexNamesNoBump,
                ..
            }
        ),
        "{stream:?}"
    );
    assert_eq!(
        beef.verify_valid(false).valid,
        expected["valid"].as_bool().unwrap()
    );
    assert_eq!(beef.verify_structure(), Err(Kind::BumpIndexNamesNoBump));
}

/// Kills `sort_txs`' `&&` to `||` at 842:41: a raw transaction with no input
/// is not a txid-only entry and sorts after the proven ones (`partitionTxs`,
/// `Beef.ts:1450-1472`).
#[test]
fn a_raw_transaction_without_inputs_sorts_after_the_proven_wire_beef_023() {
    let expected = case("raw_transaction_without_inputs");
    let f = family();
    let mut beef = Beef::with_version(BEEF_V1);
    beef.merge_bump(f.bump);
    beef.merge_raw_tx(f.parent, None);
    beef.merge_raw_tx(from_hex(text(&expected["raw"])).unwrap(), None);
    let sorted = beef.sort_txs();
    assert_eq!(sorted.txid_only, strings(&expected["txid_only"]));
    let order: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
    assert_eq!(order, strings(&expected["order"]));
}

/// Kills `verify_structure`'s `||` to `&&` at 719:13 and 720:13: a ring held
/// in the input cache is not valid with no input missing, and refused
/// (`verifyValid`, `Beef.ts:1065-1073`).
#[test]
fn a_ring_in_the_input_cache_is_refused_wire_beef_002_beef_004() {
    let expected = case("ring_in_the_input_cache");
    let (one, _) = proven("beef-002");
    let (two, _) = proven("beef-004");
    let mut beef = Beef::with_version(BEEF_V1);
    let a = beef.merge_raw_tx(one, None).txid();
    let c = beef.merge_raw_tx(two, None).txid();
    beef.find_txid_mut(&a).unwrap().input_txids = vec![c.clone()];
    beef.find_txid_mut(&c).unwrap().input_txids = vec![a];
    let sorted = beef.sort_txs();
    assert_eq!(sorted.missing_inputs, strings(&expected["missing_inputs"]));
    let mut not_valid = sorted.not_valid;
    not_valid.sort();
    assert_eq!(not_valid, strings(&expected["not_valid"]));
    assert_eq!(
        beef.verify_valid(false).valid,
        expected["valid"].as_bool().unwrap()
    );
    assert_eq!(beef.verify_structure(), Err(Kind::InputNamesNoElement));
}

/// beef-023's parent unproven, beef-002's transaction proven by its BUMP
/// (spending that parent), beef-004's transaction unproven (spending outside).
fn behind_a_proof() -> Beef {
    let f = family();
    let (spend, bump) = proven("beef-002");
    let (outside, _) = proven("beef-004");
    let mut beef = Beef::with_version(BEEF_V1);
    beef.merge_raw_tx(f.parent, None);
    beef.merge_bump(bump);
    beef.merge_raw_tx(spend, None);
    beef.merge_raw_tx(outside, None);
    beef
}

/// Kills `trim_known_proven`'s `&&` to `||` at 585:56: an ancestor reached only
/// through a proven transaction is dropped, an input outside the BEEF counting
/// for nothing (the mined object needs no parent, `BEEF.lean:344-352`, BRC-62
/// `0062.md:183-187`; the reference's atomic cut at a proof, `Beef.ts:420-434`).
#[test]
fn an_ancestor_behind_a_proof_is_trimmed_wire_beef_002_beef_004_beef_023() {
    let mut beef = behind_a_proof();
    beef.trim_known_proven();
    let mut held: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
    held.sort();
    let (spend, _) = proven("beef-002");
    let (outside, _) = proven("beef-004");
    let mut kept = vec![
        crate::transaction::Transaction::from_binary(&spend)
            .unwrap()
            .id(),
        crate::transaction::Transaction::from_binary(&outside)
            .unwrap()
            .id(),
    ];
    kept.sort();
    assert_eq!(held, kept);
    assert_eq!(beef.bumps.len(), 1);
}

/// Kills `trim_known_proven`'s `<` to `<=` at 605:36: no BUMP is removed while
/// the BUMP indices named are as many as the BUMPs, one of them past the BUMPs
/// (`#reindexBumps`' guard, `Beef.ts:1649-1660`, recorded on the same two
/// BUMPs and indices; here after the trim drops the ancestor).
#[test]
fn the_bump_clean_up_keeps_every_bump_while_as_many_are_named_wire_beef_002_beef_004() {
    let expected = case("reindex_guard_with_an_index_past_the_bumps");
    let mut beef = behind_a_proof();
    let (outside, outside_bump) = proven("beef-004");
    beef.bumps.push(outside_bump);
    let txid = crate::transaction::Transaction::from_binary(&outside)
        .unwrap()
        .id();
    beef.find_txid_mut(&txid).unwrap().set_bump_index(Some(5));
    beef.trim_known_proven();
    assert_eq!(beef.txs.len(), 2);
    assert_eq!(beef.bumps.len() as u64, expected["bumps"].as_u64().unwrap());
}
