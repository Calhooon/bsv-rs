//! #817: an entry edited in place, then each door, and the BUMP an entry
//! names, against the reference's recordings (`ts-stack@edf6e03`
//! `packages/sdk/src/transaction/Beef.ts`: `synchronizeNestedTransactionMutations`,
//! `:342-352`, at `mergeBump` `:688`, `mergeRawTx` `:836`, `mergeTransaction`
//! `:876`, `findTxid` `:498` and `mergeBeef` `:976`; the BUMP txid map,
//! `#ensureBumpTxidIndex` `:576-586`, set again by `#findOrInsertBump`
//! `:791-811` and dropped by `#synchronizeNestedBumpMutations` `:296-309`).
//!
//! Each case rebuilds a BEEF from the steps the vector names with this
//! crate's writer and compares `to_hex`, the BUMP count, each entry's name,
//! index and form and each lookup's answer with what the reference recorded
//! (`vectors/beef_door_sync_817.json`, `support/beef_door_sync_817.mjs`,
//! Node v22.23.3). The edit is `Beef::edit_tx` (eager: the entry re-keyed at
//! once), where the reference re-keys at its next door that synchronizes.
//! An entry names the LAST BUMP holding its txid at level 0, read live from
//! `bumps` (#732, #757, #765), where the reference's txid map answers by
//! which doors ran (a combine into an earlier BUMP sets its txids to it
//! until a BUMP synchronization finds the BUMPs moved).
//!
//! Fourteen of the 43 cells are stated, each test named `_stated_817` or
//! `_stated_843b` with the reference's recorded answer asserted beside this
//! crate's: the seven BUMP cells where the reference's map still holds a
//! combine's index, the two `makeTxidOnly` cells (the reference's stale
//! index), the edit onto a txid another entry holds (refused here), and the
//! four cells the recorder made by a hand edit of its `txs` (a drop, a
//! push, a swap, a replacement keeping the count), where the reference's
//! index is never rebuilt. The 33 cells recorded for PR #832 came earliest,
//! then seven by the edit door's lane, two by its fold of the rebuild (the
//! sort marks after an edit) and the last by its second fold (a twin read
//! from bytes, one edited), additions only; 29 recorded and 14 stated.
//!
//! Since #843b a `Beef` owns its rows: no hand edit of `txs`, no
//! `find_txid_mut`, no `tx_mut`, no `reindex` (each a compile error,
//! `src/transaction/beef/rows.rs`' `compile_fail` doc tests). The recorder's
//! hand steps are replayed through the door that makes the same rows
//! (`drop:` by `retain_txs`, `push:` by `merge_raw_tx`, `swap:` by a frame
//! read in the swapped order, `replace:` and `editpub:` by `edit_tx`), and
//! `mut:` by the one lookup left, `find_txid`. The vector is unchanged. Two
//! cells moved: the edit the recorder made through the public `txs` (stated
//! until then as the #171 window of `tx_mut`) is the reference's recording
//! now, and the replacement keeping the count (stated until then as a
//! window on both sides: the new txid missed, stored twice) is found at
//! once and held once here.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::transaction::{Beef, MerklePath, Transaction};
use serde_json::{json, Value};

const VECTOR: &str = include_str!("vectors/beef_door_sync_817.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn tx(v: &Value, name: &str) -> Transaction {
    let t = Transaction::from_hex(v["txs"][name]["raw"].as_str().unwrap()).unwrap();
    assert_eq!(t.id(), v["txs"][name]["txid"].as_str().unwrap());
    t
}

fn txid(v: &Value, name: &str) -> String {
    v["txs"][name]["txid"].as_str().unwrap().to_string()
}

fn bump(v: &Value, name: &str) -> MerklePath {
    MerklePath::from_hex(v["bumps"][name].as_str().unwrap()).unwrap()
}

fn name_of(v: &Value, id: &str) -> Value {
    let txs = v["txs"].as_object().unwrap();
    let found = txs.iter().find(|(_, t)| t["txid"] == id);
    json!(found.map_or(id, |(n, _)| n.as_str()))
}

/// The vector's steps applied to `beef`, each lookup's answer pushed: the
/// recorder's grammar (`bump:`, `raw:`, `txid:`, `tx:`, `graph:<t>@<b>`,
/// `edit:u_to_v`, `sort:`, `reread:`, `find:`, `make:`, `findbump:`,
/// `sign:`, `atomic:`; #817's fold: `editpub:u_to_v`, `edit:u_input_to_y`,
/// `mut:`, `inputs:`, `atomicpath:`, `clone:`, `hex:`, `valid:`,
/// `atomicbin:`; the edit door's lane: `drop:`, `push:`, `swap:`,
/// `replace:<a>_<b>`, the hand edits of the public `txs`; the fold of the
/// rebuild: `wire:`, `noop:`, `order:`; its second fold: `twin:`).
fn apply(v: &Value, beef: &mut Beef, steps: &Value, answers: &mut Vec<Value>) {
    for step in steps.as_array().unwrap() {
        let step = step.as_str().unwrap();
        let (kind, arg) = step.split_once(':').unwrap();
        let answer = match kind {
            "reread" => {
                *beef = Beef::from_hex(&beef.to_hex().expect("the BEEF writes")).unwrap();
                None
            }
            "twin" => {
                // A BEEF read holding the transaction as a txid alone and
                // then raw (the strength read's F1 of the second fold).
                let t = tx(v, arg);
                let mut w = bsv_rs::primitives::Writer::new();
                w.write_u32_le(0xefbe_0002);
                w.write_var_int(0);
                w.write_var_int(2);
                w.write_u8(2);
                // The txid in its internal byte order, as `writeReverse`.
                w.write_bytes(&t.hash());
                w.write_u8(0);
                w.write_bytes(&t.to_binary());
                *beef = Beef::from_binary(w.as_bytes()).unwrap();
                None
            }
            "sort" => {
                beef.sort_txs();
                None
            }
            "clone" => {
                *beef = beef.clone_shallow();
                None
            }
            "hex" => {
                beef.to_hex().expect("the BEEF writes");
                None
            }
            "valid" => {
                beef.verify_valid(false);
                None
            }
            "atomicbin" => {
                beef.to_binary_atomic(txid(v, arg).parse().unwrap())
                    .unwrap();
                None
            }
            "wire" => {
                // The bytes `to_writer` writes, unsorted, read back.
                let mut writer = bsv_rs::primitives::Writer::new();
                beef.to_writer(&mut writer).expect("the BEEF writes");
                *beef = Beef::from_binary(writer.as_bytes()).unwrap();
                None
            }
            "noop" => {
                // The lock time set to its own value, as the recorder's
                // `e.tx.lockTime = e.tx.lockTime`.
                beef.edit_tx(txid(v, arg).parse().unwrap(), |t| {
                    t.set_lock_time(std::hint::black_box(t.lock_time()))
                })
                .unwrap();
                None
            }
            "order" => Some(Some(json!(beef
                .txs()
                .iter()
                .map(|t| name_of(v, &t.id()))
                .collect::<Vec<_>>()))),
            "editpub" => {
                // The recorder's edit of the object reached through its
                // public `txs`, no door before it. `edit_tx` is the one edit
                // of a held transaction since #843b (until then this step
                // was the deprecated `tx_mut`, its #171 window).
                beef.edit_tx(txid(v, "u").parse().unwrap(), |t| t.set_lock_time(1))
                    .unwrap();
                None
            }
            "bump" => {
                beef.merge_bump(bump(v, arg));
                None
            }
            "raw" => {
                beef.merge_raw_tx(tx(v, arg).to_binary(), None)
                    .expect("the bytes are one transaction");
                None
            }
            "txid" => {
                beef.merge_txid_only(txid(v, arg).parse().unwrap());
                None
            }
            "tx" => {
                beef.merge_transaction(tx(v, arg));
                None
            }
            "graph" => {
                let (t, b) = arg.split_once('@').unwrap();
                let mut t = tx(v, t);
                t.merkle_path = Some(bump(v, b));
                beef.merge_transaction(t);
                None
            }
            "edit" if arg == "u_input_to_y" => {
                let cc = "cc".repeat(32);
                beef.edit_tx(txid(v, "u").parse().unwrap(), |t| {
                    t.inputs_mut()[0].source_txid = Some(cc.parse().unwrap())
                })
                .unwrap();
                None
            }
            "edit" if arg == "y_input_to_u" => {
                let u = txid(v, "u");
                beef.edit_tx(txid(v, "y").parse().unwrap(), |t| {
                    t.inputs_mut()[0].source_txid = Some(u.parse().unwrap())
                })
                .unwrap();
                None
            }
            "edit" => match beef.edit_tx(txid(v, "u").parse().unwrap(), |t| t.set_lock_time(1)) {
                Ok(()) => None,
                // Refused (another entry holds V): this crate's answer.
                Err(_) => Some(Some(json!("refused"))),
            },
            // The recorder's four hand edits of its public `txs`, each made
            // here through the door that leaves the same rows (#843b: the
            // hand edit does not compile).
            "drop" => {
                let id = txid(v, arg);
                beef.retain_txs(|t| t.txid() != id);
                None
            }
            "push" => {
                // An entry no entry's txid: the merge appends it, as the
                // push did, and keys it.
                let raw = tx(v, arg);
                assert!(beef.find_txid(raw.txid()).is_none(), "{step}: not held");
                beef.merge_raw_tx(raw.to_binary(), None)
                    .expect("one transaction");
                None
            }
            "swap" => {
                // No door reorders the entries: the BEEF is read again from
                // a frame of its rows with the entries at 0 and 1 swapped
                // (as read, each entry holding its bytes and its parse).
                let mut order: Vec<usize> = (0..beef.txs().len()).collect();
                order.swap(0, 1);
                let mut frame = bsv_rs::primitives::Writer::new();
                frame.write_u32_le(beef.version);
                frame.write_var_int(beef.bumps().len() as u64);
                for bump in beef.bumps() {
                    bump.to_writer(&mut frame).expect("the BUMP writes");
                }
                frame.write_var_int(order.len() as u64);
                for at in order {
                    beef.txs()[at]
                        .to_writer(&mut frame, beef.version)
                        .expect("the entry writes");
                }
                *beef = Beef::from_binary(frame.as_bytes()).unwrap();
                None
            }
            "replace" => {
                // The entry holding `a` made to hold `b`, its place kept:
                // `edit_tx` with the transaction assigned whole.
                let (a, b) = arg.split_once('_').unwrap();
                let replacement = tx(v, b);
                beef.edit_tx(txid(v, a).parse().unwrap(), |t| *t = replacement)
                    .unwrap();
                None
            }
            // The recorder's `findTxid` before an in-place write; no door
            // lends an entry mutably since #843b, so the lookup is the
            // shared one.
            "mut" => Some(
                beef.find_txid(txid(v, arg).parse().unwrap())
                    .map(|e| name_of(v, &e.id())),
            ),
            "inputs" => Some(beef.find_txid(txid(v, arg).parse().unwrap()).map(|e| {
                let names: Vec<Value> = e
                    .input_txids()
                    .iter()
                    .map(|t| name_of(v, &t.to_string()))
                    .collect();
                json!(names)
            })),
            "atomicpath" => Some(
                beef.find_atomic_transaction(txid(v, arg).parse().unwrap())
                    .and_then(|t| t.merkle_path.as_ref().map(|mp| json!(mp.block_height))),
            ),
            "find" => Some(
                beef.find_txid(txid(v, arg).parse().unwrap())
                    .map(|e| name_of(v, &e.id())),
            ),
            "make" => Some(
                beef.make_txid_only(txid(v, arg).parse().unwrap())
                    .map(|e| name_of(v, &e.id())),
            ),
            "findbump" => Some(beef.find_bump(txid(v, arg).parse().unwrap()).map(|mp| {
                let at = beef
                    .bumps()
                    .iter()
                    .position(|b| std::ptr::eq(b, mp))
                    .unwrap();
                json!(at)
            })),
            "sign" => Some(
                beef.find_transaction_for_signing(txid(v, arg).parse().unwrap())
                    .map(|t| name_of(v, &t.id())),
            ),
            "atomic" => Some(
                beef.find_atomic_transaction(txid(v, arg).parse().unwrap())
                    .map(|t| name_of(v, &t.id())),
            ),
            other => panic!("no step {other}"),
        };
        if let Some(answer) = answer {
            answers.push(json!({ "step": step, "answer": answer.unwrap_or(Value::Null) }));
        }
    }
}

/// What this crate writes and answers for the case named `name`.
fn run(name: &str) -> (Value, Value) {
    let v = vector();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
        .clone();
    let mut answers = Vec::new();
    let mut beef = Beef::new();
    apply(&v, &mut beef, &case["target"], &mut answers);
    if let Some(source) = case.get("source") {
        let mut other = Beef::new();
        apply(&v, &mut other, source, &mut Vec::new());
        beef.merge_beef(&other)
            .expect("the source writes and reads back");
    }
    if let Some(after) = case.get("after") {
        apply(&v, &mut beef, after, &mut answers);
    }
    // Written first, as the recorder reads the entries after its `toHex`.
    let hex = beef.to_hex().expect("the BEEF writes");
    let entries: Vec<Value> = beef
        .txs()
        .iter()
        .map(|t| {
            let form = if t.is_txid_only() { "txid" } else { "raw" };
            json!({ "name": name_of(&v, &t.id()), "bump_index": t.bump_index(), "form": form })
        })
        .collect();
    let ours = json!({
        "answers": answers,
        "beef": hex,
        "bumps": beef.bumps().len(),
        "entries": entries,
    });
    (ours, case)
}

/// The case is the reference's, byte for byte and answer for answer.
fn assert_recorded(name: &str) {
    let (ours, case) = run(name);
    for key in ["answers", "beef", "bumps", "entries"] {
        assert_eq!(ours[key], case[key], "{name}: {key}");
    }
}

/// A stated cell: the reference's recording is `reference` on the keys it
/// names (the vector unchanged, asserted here so the statement cannot
/// drift), this crate's answer is `here` on the same keys, every other key
/// the recording's, and this crate's bytes read back to its own entries.
fn assert_stated(name: &str, reference: Value, here: Value) {
    let (ours, case) = run(name);
    let (reference, here) = (reference.as_object().unwrap(), here.as_object().unwrap());
    for key in ["answers", "beef", "bumps", "entries"] {
        match (reference.get(key), here.get(key)) {
            (Some(theirs), Some(mine)) => {
                assert_eq!(&case[key], theirs, "{name}: the reference's {key}");
                assert_eq!(&ours[key], mine, "{name}: this crate's {key}");
                assert_ne!(theirs, mine, "{name}: a stated {key} differs");
            }
            _ if key == "beef" => {}
            _ => assert_eq!(ours[key], case[key], "{name}: {key}"),
        }
    }
    // The bytes written carry this crate's entries, index for index.
    let v = vector();
    let back = Beef::from_hex(ours["beef"].as_str().unwrap()).unwrap();
    let read: Vec<Value> = back
        .txs()
        .iter()
        .map(|t| {
            let form = if t.is_txid_only() { "txid" } else { "raw" };
            json!({ "name": name_of(&v, &t.id()), "bump_index": t.bump_index(), "form": form })
        })
        .collect();
    // A txid-only entry's index is not written (BRC-96's format 2 carries
    // the txid alone), so it reads back with none.
    let mut held: Vec<Value> = ours["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let mut e = e.clone();
            if e["form"] == "txid" {
                e["bump_index"] = Value::Null;
            }
            e
        })
        .collect();
    let mut read = read;
    let key = |e: &Value| e["name"].to_string();
    held.sort_by_key(key);
    read.sort_by_key(key);
    assert_eq!(read, held, "{name}: the bytes are this crate's entries");
}

/// The bytes this crate writes for the raw entries `names`, merged in order.
fn written(names: &[&str]) -> String {
    let v = vector();
    let mut b = Beef::new();
    for name in names {
        b.merge_raw_tx(tx(&v, name).to_binary(), None)
            .expect("the bytes are one transaction");
    }
    b.to_hex().expect("the BEEF writes")
}

fn entry(name: &str, bump_index: Option<usize>, form: &str) -> Value {
    json!({ "name": name, "bump_index": bump_index, "form": form })
}

// U held raw, edited to V through `edit_tx`, then each door: one entry held,
// V found, written once, as the reference after its synchronization.

#[test]
fn an_edit_then_merge_raw_tx_finds_the_edited_entry_held_817() {
    assert_recorded("an_edit_then_merge_raw_tx_finds_the_edited_entry_held");
}

#[test]
fn an_edit_then_merge_transaction_finds_the_edited_entry_held_817() {
    assert_recorded("an_edit_then_merge_transaction_finds_the_edited_entry_held");
}

#[test]
fn an_edit_then_merge_txid_only_finds_the_edited_entry_held_817() {
    assert_recorded("an_edit_then_merge_txid_only_finds_the_edited_entry_held");
}

#[test]
fn an_edit_then_find_txid_answers_the_edited_txid_817() {
    assert_recorded("an_edit_then_find_txid_answers_the_edited_txid");
}

#[test]
fn an_edit_then_merge_bump_proves_the_edited_entry_817() {
    assert_recorded("an_edit_then_merge_bump_proves_the_edited_entry");
}

#[test]
fn an_edit_then_the_signing_lookups_answer_the_edited_txid_817() {
    assert_recorded("an_edit_then_the_signing_lookups_answer_the_edited_txid");
}

#[test]
fn an_edit_then_merge_bump_then_make_txid_only_of_the_new_txid_817() {
    assert_recorded("an_edit_then_merge_bump_then_make_txid_only_of_the_new_txid");
}

/// The recorded answers of the reference's lookup ahead of an in-place
/// write, replayed through `find_txid`.
///
/// Replaces `an_edit_then_find_txid_mut_answers_the_edited_txid_817`:
/// `find_txid_mut` does not compile since #843b
/// (`src/transaction/beef/rows.rs`' `compile_fail` doc tests), and the
/// entry it lent is reached through `edit_tx` and `set_bump_index`.
#[test]
fn an_edit_then_the_lookup_answers_the_edited_txid_as_find_txid_mut_did_843b() {
    assert_recorded("an_edit_then_find_txid_mut_answers_the_edited_txid");
}

/// The edit's input list is read at once, so `find_txid` (`&self`) hands
/// back the reference's list (`BeefTx.ts:160-166`); stated until the eager
/// door, where the `&self` lookups kept the list from before the edit.
#[test]
fn an_edit_of_an_input_then_find_txid_reads_the_new_input_list_817() {
    assert_recorded("an_edit_of_an_input_then_find_txid_reads_the_new_input_list");
}

/// The reference's `makeTxidOnly(U)` after the edit reads its stale
/// position index (`Beef.ts:552-565`, no synchronization) and replaces the
/// edited V with U alone, V's transaction lost and a txid the BEEF no
/// longer holds written in its place; this crate answers `None` and keeps
/// V, as it answers for a txid it does not hold.
#[test]
fn an_edit_then_make_txid_only_of_the_old_txid_is_stated_817() {
    assert_stated(
        "an_edit_then_make_txid_only_of_the_old_txid",
        json!({
            "answers": [{ "step": "make:u", "answer": "u" }],
            "entries": [entry("u", None, "txid")],
            "beef": "0200beef000102f0a7e65a7a9de349d6ba4377de2076e0e1f729bd682c93ecd5992136661c05ba",
        }),
        json!({
            "answers": [{ "step": "make:u", "answer": null }],
            "entries": [entry("v", None, "raw")],
            "beef": run("an_edit_then_merge_raw_tx_finds_the_edited_entry_held").1["beef"],
        }),
    );
}

/// The reference's `makeTxidOnly(V)` after the edit misses on the same
/// stale index (nothing synchronized V's position), so V stays whole; this
/// crate's `edit_tx` re-keyed V at once and `make_txid_only(V)` makes it a
/// txid alone, as the reference does once a door has synchronized (the
/// recorded `an_edit_then_merge_bump_then_make_txid_only_of_the_new_txid`).
#[test]
fn an_edit_then_make_txid_only_of_the_new_txid_is_stated_817() {
    let after_sync = run("an_edit_then_merge_bump_then_make_txid_only_of_the_new_txid").1;
    assert_eq!(
        after_sync["answers"][0]["answer"], "v",
        "the reference after a sync"
    );
    assert_stated(
        "an_edit_then_make_txid_only_of_the_new_txid",
        json!({
            "answers": [{ "step": "make:v", "answer": null }],
            "entries": [entry("v", None, "raw")],
            "beef": run("an_edit_then_merge_raw_tx_finds_the_edited_entry_held").1["beef"],
        }),
        json!({
            "answers": [{ "step": "make:v", "answer": "v" }],
            "entries": [entry("v", None, "txid")],
            "beef": "0200beef00010280b28256fbf81e8daf80d3f1a6eb9d9b4ca5001db528a0746ff39d55e810e6b4",
        }),
    );
}

/// The recorder's edit of the object reached through its public `txs`, no
/// door between: the reference's `findTxid(V)` synchronizes and finds V,
/// and its `mergeRawTx(V)` replaces it; this crate's `edit_tx` re-keyed V
/// at once, so V is found and held once, the reference's recording byte for
/// byte and answer for answer.
///
/// Replaces `an_edit_through_txs_by_tx_mut_is_the_171_window_stated_817`,
/// which stated the cell: the deprecated `tx_mut` kept the #171 window (the
/// per-entry doors did not re-key), so V was not found and was stored a
/// second time. `tx_mut` does not compile since #843b and the window is
/// closed; the cell is no longer stated.
#[test]
fn an_edit_of_a_held_transaction_is_found_by_its_new_txid_and_held_once_843b() {
    assert_recorded("an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid");
}

// X held by b0 (900000) and b1 (900001). This crate's rule: an entry names
// the last BUMP holding its txid (b1, index 1), read live; the reference's
// map names b0 (index 0) after a combine into b0 until a BUMP
// synchronization finds the BUMPs moved. Where its map was dropped, or the
// combine went into the later BUMP, the two agree.

#[test]
fn a_combine_into_the_later_bump_gives_its_txids_that_index_817() {
    assert_recorded("a_combine_into_the_later_bump_gives_its_txids_that_index");
}

#[test]
fn a_combine_is_forgotten_at_the_next_bump_sync_817() {
    assert_recorded("a_combine_is_forgotten_at_the_next_bump_sync");
}

#[test]
fn a_combine_is_forgotten_at_find_bump_817() {
    assert_recorded("a_combine_is_forgotten_at_find_bump");
}

#[test]
fn a_combine_after_a_read_is_forgotten_at_find_bump_817() {
    assert_recorded("a_combine_after_a_read_is_forgotten_at_find_bump");
}

#[test]
fn a_push_after_an_unsynced_combine_takes_the_pushed_index_817() {
    assert_recorded("a_push_after_an_unsynced_combine_takes_the_pushed_index");
}

#[test]
fn a_combine_is_forgotten_at_find_atomic_transaction_817() {
    assert_recorded("a_combine_is_forgotten_at_find_atomic_transaction");
}

#[test]
fn a_combine_is_forgotten_at_merge_beef_817() {
    assert_recorded("a_combine_is_forgotten_at_merge_beef");
}

#[test]
fn a_combine_is_forgotten_at_verify_valid_817() {
    assert_recorded("a_combine_is_forgotten_at_verify_valid");
}

#[test]
fn a_combine_is_forgotten_at_verify_valid_refusing_before_its_sort_817() {
    assert_recorded("a_combine_is_forgotten_at_verify_valid_refusing_before_its_sort");
}

#[test]
fn a_combine_after_a_sort_is_forgotten_at_to_hex_817() {
    assert_recorded("a_combine_after_a_sort_is_forgotten_at_to_hex");
}

#[test]
fn a_combine_is_forgotten_at_to_binary_atomic_817() {
    assert_recorded("a_combine_is_forgotten_at_to_binary_atomic");
}

#[test]
fn a_combine_changing_no_leaf_is_forgotten_at_the_next_sync_817() {
    assert_recorded("a_combine_changing_no_leaf_is_forgotten_at_the_next_sync");
}

#[test]
fn a_combine_on_a_clone_of_a_read_beef_is_forgotten_at_find_bump_817() {
    assert_recorded("a_combine_on_a_clone_of_a_read_beef_is_forgotten_at_find_bump");
}

/// Stated until the live rule: the reference's clone takes the snapshot,
/// its combine forgotten; this crate never kept the combine's index.
#[test]
fn a_combine_on_a_clone_of_a_serialized_beef_817() {
    assert_recorded("a_combine_on_a_clone_of_a_serialized_beef");
}

// The edit door's lane: the edit then the writer and `merge_beef`.

/// #817's fold of the rebuild (the strength read's S3): an edit keeping the
/// txid of a BEEF read children first leaves its read order, so
/// `merge_beef` into an empty BEEF walks it as read (C, then P), as the
/// reference's `mergeBeef` takes the bytes read (`Beef.ts:360-364`). RED
/// with the no-change early return removed (the read order dropped, the
/// source sorted: P, C).
#[test]
fn a_children_first_read_then_an_edit_keeping_the_txid_merges_in_its_read_order_817() {
    assert_recorded(
        "a_children_first_beef_read_then_an_edit_keeping_the_txid_merged_into_an_empty_beef",
    );
}

/// #817's fold of the rebuild (S3): after a write (no sort pending), an
/// input moved to a later entry marks the BEEF for a sort, so the next
/// write puts the parent first, as the reference's writer does. RED with
/// `edit_tx`'s `mark_mutated` removed (Y' written before U).
#[test]
fn a_write_then_an_input_moved_to_a_later_entry_writes_the_parent_first_817() {
    assert_recorded("a_write_then_an_input_moved_to_a_later_entry_writes_the_parent_first");
}

/// The second fold of the rebuild (the strength read's F1): a BEEF read
/// from bytes holding U as a txid alone and then raw, the index naming the
/// raw entry; `edit_tx(U)` edits that entry to V, and U, still held by the
/// txid-only entry, is found there and not stored a third time by
/// `merge_txid_only`, as the reference's index rebuilt after the edit finds
/// it (`Beef.ts:342-352,516-524`). RED on `ba0dc50e` (`edit_tx` removed U's
/// key: `find:u` answered `null`, a third entry stored).
#[test]
fn a_twin_read_from_bytes_then_an_edit_keeps_the_other_entry_found_817() {
    assert_recorded("a_twin_read_from_bytes_then_an_edit_keeps_the_other_entry_found");
}

#[test]
fn an_edit_then_to_hex_writes_the_edited_entry_once_817() {
    assert_recorded("an_edit_then_to_hex_writes_the_edited_entry_once");
}

#[test]
fn an_edit_then_merge_beef_finds_the_edited_entry_held_817() {
    assert_recorded("an_edit_then_merge_beef_finds_the_edited_entry_held");
}

/// An edit onto a txid another entry holds: the reference keeps both
/// entries (V twice, its index the last position); `edit_tx` refuses, the
/// BEEF unchanged (U and V).
#[test]
fn an_edit_onto_a_txid_another_entry_holds_is_refused_stated_817() {
    assert_stated(
        "an_edit_onto_a_txid_another_entry_holds",
        json!({
            "answers": [{ "step": "find:v", "answer": "v" }],
            "entries": [entry("v", None, "raw"), entry("v", None, "raw")],
            "beef": run("an_edit_onto_a_txid_another_entry_holds").1["beef"],
        }),
        json!({
            "answers": [
                { "step": "edit:u_to_v", "answer": "refused" },
                { "step": "find:v", "answer": "v" },
            ],
            "entries": [entry("u", None, "raw"), entry("v", None, "raw")],
            "beef": written(&["u", "v"]),
        }),
    );
}

// The recorder's hand edits of its public `txs`, no door between. The
// reference's index maps a txid to its object and its position
// (`Beef.ts:507-529`), never rebuilt by a hand edit, so a dropped entry is
// still found, a pushed one is not, and `mergeRawTx` replaces at a stale
// position (a swap loses U) or appends a second copy. Here each step goes
// through a door (`apply`), after which a lookup answers the last entry
// holding the txid and `None` for a txid no entry holds (#843b).

/// The toolbox's `retain`, through `retain_txs`: W and U found, the dropped
/// X not, and W merged into its place (the reference: X found, W stored
/// twice).
///
/// Replaces `a_hand_drop_then_the_lookups_and_merge_raw_tx_stated_817`,
/// whose drop was a hand `retain` of the public `txs`; the answers here are
/// the ones it stated.
#[test]
fn a_retain_then_the_lookups_and_merge_raw_tx_stated_843b() {
    let name = "a_hand_drop_then_the_lookups_and_merge_raw_tx";
    assert_stated(
        name,
        json!({
            "answers": [
                { "step": "find:w", "answer": "w" },
                { "step": "find:u", "answer": "u" },
                { "step": "find:x", "answer": "x" },
            ],
            "entries": [entry("u", None, "raw"), entry("w", None, "raw"), entry("w", None, "raw")],
            "beef": run(name).1["beef"],
        }),
        // Stated: the dropped X names nothing and W is held once (#843b).
        json!({
            "answers": [
                { "step": "find:w", "answer": "w" },
                { "step": "find:u", "answer": "u" },
                { "step": "find:x", "answer": null },
            ],
            "entries": [entry("u", None, "raw"), entry("w", None, "raw")],
            "beef": written(&["u", "w"]),
        }),
    );
}

/// An entry appended by a merge, where the recorder pushed it by hand: W
/// found and merged into its place (the reference: not found, stored
/// twice).
///
/// Replaces `a_hand_push_then_find_txid_and_merge_raw_tx_stated_817`; the
/// answers here are the ones it stated.
#[test]
fn an_append_then_find_txid_and_merge_raw_tx_stated_843b() {
    let name = "a_hand_push_then_find_txid_and_merge_raw_tx";
    assert_stated(
        name,
        json!({
            "answers": [{ "step": "find:w", "answer": null }],
            "entries": [entry("x", None, "raw"), entry("w", None, "raw"), entry("w", None, "raw")],
            "beef": run(name).1["beef"],
        }),
        // Stated: an entry is keyed as it is appended, so W is found and
        // held once (#843b).
        json!({
            "answers": [{ "step": "find:w", "answer": "w" }],
            "entries": [entry("x", None, "raw"), entry("w", None, "raw")],
            "beef": written(&["x", "w"]),
        }),
    );
}

/// The entries in the swapped order (read from a frame, where the recorder
/// swapped them by hand): both found on both sides (the answers the
/// recording's), X merged into its own new place (the reference's
/// `mergeRawTx(X)` writes X over U at X's old position, U lost).
///
/// Replaces `a_hand_swap_then_find_each_and_merge_raw_tx_stated_817`; the
/// answers here are the ones it stated.
#[test]
fn a_swapped_order_then_find_each_and_merge_raw_tx_stated_843b() {
    let name = "a_hand_swap_then_find_each_and_merge_raw_tx";
    assert_stated(
        name,
        json!({
            "entries": [entry("x", None, "raw"), entry("x", None, "raw")],
            "beef": run(name).1["beef"],
        }),
        // Stated: X is merged where it is held, U kept (#843b).
        json!({
            "entries": [entry("u", None, "raw"), entry("x", None, "raw")],
            "beef": written(&["u", "x"]),
        }),
    );
}

/// A replacement keeping the count, through `edit_tx`: W is found at once,
/// the replaced X names nothing, and `merge_raw_tx(W)` stores W in its
/// place, held once. The reference misses W (its index was never given it),
/// still finds X's object and stores W twice.
///
/// Replaces `a_hand_replace_keeping_the_count_is_the_window_stated_817`,
/// which stated the window on both sides: after the hand replacement this
/// crate's lookup of W missed too and W was stored twice, the bytes the
/// reference's, with `reindex` its door. The window is closed (#843b), so
/// the answers, the entries and the bytes all part from the recording.
#[test]
fn a_replacement_keeping_the_count_is_found_at_once_stated_843b() {
    let name = "a_hand_replace_keeping_the_count_then_find_and_merge_raw_tx";
    assert_stated(
        name,
        json!({
            "answers": [{ "step": "find:w", "answer": null }, { "step": "find:x", "answer": "x" }],
            "entries": [entry("w", None, "raw"), entry("u", None, "raw"), entry("w", None, "raw")],
            "beef": run(name).1["beef"],
        }),
        // Stated: W is found where it is held and held once; X, which no
        // entry holds, names nothing (#843b).
        json!({
            "answers": [{ "step": "find:w", "answer": "w" }, { "step": "find:x", "answer": null }],
            "entries": [entry("w", None, "raw"), entry("u", None, "raw")],
            "beef": written(&["w", "u"]),
        }),
    );
}

/// The bytes a stated BUMP cell writes: the recording's with X's index byte
/// (`0x00` there) written `0x01`, the last BUMP holding X.
fn with_index_one(name: &str, recorded_x: &str) -> String {
    let (_, case) = run(name);
    let bytes = case["beef"].as_str().unwrap();
    let at = bytes.rfind(recorded_x).unwrap();
    let (front, back) = bytes.split_at(at);
    let mut front = front.to_string();
    front.replace_range(front.len() - 2.., "01");
    front + back
}

/// The written index of a raw X: `01` (raw with an index), the index, X.
fn raw_x(v: &Value) -> String {
    tx(v, "x").to_hex()
}

#[test]
fn a_combine_into_the_earlier_bump_names_the_last_bump_stated_817() {
    let v = vector();
    let name = "a_combine_into_the_earlier_bump_gives_its_txids_that_index";
    assert_stated(
        name,
        json!({ "entries": [entry("x", Some(0), "raw")], "beef": run(name).1["beef"] }),
        json!({ "entries": [entry("x", Some(1), "raw")], "beef": with_index_one(name, &raw_x(&v)) }),
    );
}

#[test]
fn a_combine_gives_a_txid_only_entry_the_last_bump_stated_817() {
    assert_stated(
        "a_combine_gives_a_txid_only_entry_that_index",
        json!({ "entries": [entry("x", Some(0), "txid")] }),
        json!({ "entries": [entry("x", Some(1), "txid")] }),
    );
}

#[test]
fn a_combine_through_merge_bump_then_merge_raw_tx_names_the_last_bump_stated_817() {
    let v = vector();
    let name = "a_combine_through_merge_bump_survives_merge_raw_tx";
    assert_stated(
        name,
        json!({ "entries": [entry("x", Some(0), "raw")], "beef": run(name).1["beef"] }),
        json!({ "entries": [entry("x", Some(1), "raw")], "beef": with_index_one(name, &raw_x(&v)) }),
    );
}

#[test]
fn a_combine_before_any_bump_sync_names_the_last_bump_stated_817() {
    assert_stated(
        "a_combine_before_any_bump_sync_survives_the_first",
        json!({
            "answers": [{ "step": "findbump:x", "answer": 0 }, { "step": "make:x", "answer": "x" }],
            "entries": [entry("x", Some(0), "txid"), entry("w", Some(0), "raw")],
        }),
        json!({
            "answers": [{ "step": "findbump:x", "answer": 1 }, { "step": "make:x", "answer": "x" }],
            "entries": [entry("x", Some(1), "txid"), entry("w", Some(0), "raw")],
        }),
    );
}

#[test]
fn a_combine_before_any_bump_sync_then_a_sort_names_the_last_bump_stated_817() {
    let v = vector();
    let name = "a_combine_before_any_bump_sync_survives_a_sort";
    assert_stated(
        name,
        json!({
            "answers": [{ "step": "findbump:x", "answer": 0 }],
            "entries": [entry("x", Some(0), "raw"), entry("w", Some(0), "raw")],
            "beef": run(name).1["beef"],
        }),
        json!({
            "answers": [{ "step": "findbump:x", "answer": 1 }],
            "entries": [entry("x", Some(1), "raw"), entry("w", Some(0), "raw")],
            "beef": with_index_one(name, &raw_x(&v)),
        }),
    );
}

#[test]
fn an_unsynced_combine_and_the_atomic_path_name_the_last_bump_stated_817() {
    assert_stated(
        "an_unsynced_combine_is_the_atomic_paths_index",
        json!({ "answers": [{ "step": "atomicpath:x", "answer": 900000 }] }),
        json!({ "answers": [{ "step": "atomicpath:x", "answer": 900001 }] }),
    );
}

#[test]
fn a_combine_on_a_clone_of_an_unread_beef_names_the_last_bump_stated_817() {
    let v = vector();
    let name = "a_combine_on_a_clone_of_an_unread_beef_survives_find_bump";
    assert_stated(
        name,
        json!({
            "answers": [{ "step": "findbump:x", "answer": 0 }],
            "entries": [entry("w", Some(0), "raw"), entry("x", Some(0), "raw")],
            "beef": run(name).1["beef"],
        }),
        json!({
            "answers": [{ "step": "findbump:x", "answer": 1 }],
            "entries": [entry("w", Some(0), "raw"), entry("x", Some(1), "raw")],
            "beef": with_index_one(name, &raw_x(&v)),
        }),
    );
}

/// The fourteen stated cells of the forty-three, counted: a cell that moves
/// is a finding. (Named so that its own name does not end in the stated
/// cells' suffix, which a count of the suffix would take for one more.)
///
/// Replaces `the_stated_cells_counted_are_fifteen_of_forty_three_817`: the
/// fifteenth was `an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid`,
/// the #171 window of `tx_mut`, which is the reference's recording since
/// #843b.
#[test]
fn the_stated_cells_counted_are_fourteen_of_forty_three_843b() {
    let v = vector();
    let differing: Vec<String> = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .filter(|name| {
            let (ours, case) = run(name);
            ["answers", "beef", "bumps", "entries"]
                .iter()
                .any(|k| ours[*k] != case[*k])
        })
        .collect();
    assert_eq!(
        differing,
        [
            "an_edit_then_make_txid_only_of_the_old_txid",
            "an_edit_then_make_txid_only_of_the_new_txid",
            "a_combine_into_the_earlier_bump_gives_its_txids_that_index",
            "a_combine_gives_a_txid_only_entry_that_index",
            "a_combine_through_merge_bump_survives_merge_raw_tx",
            "a_combine_before_any_bump_sync_survives_the_first",
            "a_combine_before_any_bump_sync_survives_a_sort",
            "an_unsynced_combine_is_the_atomic_paths_index",
            "a_combine_on_a_clone_of_an_unread_beef_survives_find_bump",
            "an_edit_onto_a_txid_another_entry_holds",
            "a_hand_drop_then_the_lookups_and_merge_raw_tx",
            "a_hand_push_then_find_txid_and_merge_raw_tx",
            "a_hand_swap_then_find_each_and_merge_raw_tx",
            "a_hand_replace_keeping_the_count_then_find_and_merge_raw_tx",
        ]
    );
}

/// Every recorded case has its test above (the vector's count pinned).
#[test]
fn every_recorded_case_is_tested_817() {
    let v = vector();
    assert_eq!(v["cases"].as_array().unwrap().len(), 43);
    let src = include_str!("beef_door_sync_817.rs");
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert!(src.contains(&format!("\"{name}\"")), "{name} untested");
    }
}
