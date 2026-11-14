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
//! Fifteen of the 43 cells are stated, each test named `_stated_817` with
//! the reference's recorded answer asserted beside this crate's: the seven
//! BUMP cells where the reference's map still holds a combine's index, the
//! two `makeTxidOnly` cells (the reference's stale index), the edit through
//! the public `txs` by the deprecated `tx_mut` (the #171 window), the edit
//! onto a txid another entry holds (refused here), and the four hand edits
//! of `txs` (a drop, a push, a swap, a replacement keeping the count), where
//! the reference's index is never rebuilt and this crate's notices the
//! count or a mismatched hit. The first 33 cells were recorded for PR #832,
//! seven by the edit door's lane, two by its fold of the rebuild (the sort
//! marks after an edit) and the last by its second fold (a twin read from
//! bytes, one edited), additions only; 28 recorded and 15 stated.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::transaction::{Beef, BeefTx, MerklePath, Transaction};
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
                beef.to_binary_atomic(&txid(v, arg)).unwrap();
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
                beef.edit_tx(&txid(v, arg), |t| {
                    t.set_lock_time(std::hint::black_box(t.lock_time()))
                })
                .unwrap();
                None
            }
            "order" => Some(Some(json!(beef
                .txs
                .iter()
                .map(|t| name_of(v, &t.txid()))
                .collect::<Vec<_>>()))),
            "editpub" => {
                // The edit through the public `txs`, no door before it: the
                // deprecated `tx_mut`, its #171 window (the stated cell).
                let u = txid(v, "u");
                let at = beef.txs.iter().position(|t| t.txid() == u).unwrap();
                #[allow(deprecated)] // the hand edit the cell states
                let edited = beef.txs[at].tx_mut().unwrap();
                edited.set_lock_time(1);
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
                beef.merge_txid_only(txid(v, arg));
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
                beef.edit_tx(&txid(v, "u"), |t| {
                    t.inputs_mut()[0].source_txid = Some(cc.parse().unwrap())
                })
                .unwrap();
                None
            }
            "edit" if arg == "y_input_to_u" => {
                let u = txid(v, "u");
                beef.edit_tx(&txid(v, "y"), |t| {
                    t.inputs_mut()[0].source_txid = Some(u.parse().unwrap())
                })
                .unwrap();
                None
            }
            "edit" => match beef.edit_tx(&txid(v, "u"), |t| t.set_lock_time(1)) {
                Ok(()) => None,
                // Refused (another entry holds V): this crate's answer.
                Err(_) => Some(Some(json!("refused"))),
            },
            "drop" => {
                let id = txid(v, arg);
                beef.txs.retain(|t| t.txid() != id);
                None
            }
            "push" => {
                beef.txs.push(
                    BeefTx::from_raw_tx(tx(v, arg).to_binary(), None).expect("one transaction"),
                );
                None
            }
            "swap" => {
                beef.txs.swap(0, 1);
                None
            }
            "replace" => {
                let (a, b) = arg.split_once('_').unwrap();
                let a = txid(v, a);
                let at = beef.txs.iter().position(|t| t.txid() == a).unwrap();
                beef.txs[at] =
                    BeefTx::from_raw_tx(tx(v, b).to_binary(), None).expect("one transaction");
                None
            }
            "mut" => Some(
                beef.find_txid_mut(&txid(v, arg))
                    .map(|e| name_of(v, &e.txid())),
            ),
            "inputs" => Some(beef.find_txid(&txid(v, arg)).map(|e| {
                let names: Vec<Value> = e.input_txids.iter().map(|t| name_of(v, t)).collect();
                json!(names)
            })),
            "atomicpath" => Some(
                beef.find_atomic_transaction(&txid(v, arg))
                    .and_then(|t| t.merkle_path.as_ref().map(|mp| json!(mp.block_height))),
            ),
            "find" => Some(beef.find_txid(&txid(v, arg)).map(|e| name_of(v, &e.txid()))),
            "make" => Some(
                beef.make_txid_only(&txid(v, arg))
                    .map(|e| name_of(v, &e.txid())),
            ),
            "findbump" => Some(beef.find_bump(&txid(v, arg)).map(|mp| {
                let at = beef.bumps.iter().position(|b| std::ptr::eq(b, mp)).unwrap();
                json!(at)
            })),
            "sign" => Some(
                beef.find_transaction_for_signing(&txid(v, arg))
                    .map(|t| name_of(v, &t.id())),
            ),
            "atomic" => Some(
                beef.find_atomic_transaction(&txid(v, arg))
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
        .txs
        .iter()
        .map(|t| {
            let form = if t.is_txid_only() { "txid" } else { "raw" };
            json!({ "name": name_of(&v, &t.txid()), "bump_index": t.bump_index(), "form": form })
        })
        .collect();
    let ours = json!({
        "answers": answers,
        "beef": hex,
        "bumps": beef.bumps.len(),
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
        .txs
        .iter()
        .map(|t| {
            let form = if t.is_txid_only() { "txid" } else { "raw" };
            json!({ "name": name_of(&v, &t.txid()), "bump_index": t.bump_index(), "form": form })
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

#[test]
fn an_edit_then_find_txid_mut_answers_the_edited_txid_817() {
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

/// The edit through the public `txs` by the deprecated `tx_mut`, no door
/// between: the reference's `findTxid(V)` synchronizes and finds V, and its
/// `mergeRawTx(V)` replaces it; here the deprecated path keeps the #171
/// window (the per-entry doors do not re-key), so V is not found and is
/// stored a second time. `edit_tx` is the door that closes it
/// (`tests/beef_edit_door_817.rs`), and `reindex` re-keys a hand edit.
#[test]
fn an_edit_through_txs_by_tx_mut_is_the_171_window_stated_817() {
    let v = vector();
    let (_, case) = run("an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid");
    let mut doubled = case["entries"].as_array().unwrap().clone();
    doubled.push(entry("v", None, "raw"));
    let (ours, _) = run("an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid");
    let mut written = case["beef"].as_str().unwrap().to_string();
    // The recorded bytes with a second V appended: the count, then V again.
    let v_raw = tx(&v, "v").to_hex();
    written = written.replacen("0200beef0002", "0200beef0003", 1) + "00" + &v_raw;
    assert_eq!(ours["beef"].as_str().unwrap(), written);
    assert_stated(
        "an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid",
        json!({
            "answers": [
                { "step": "find:u", "answer": "u" },
                { "step": "find:v", "answer": "v" },
                { "step": "find:u", "answer": null },
            ],
            "entries": case["entries"],
            "beef": case["beef"],
        }),
        json!({
            "answers": [
                { "step": "find:u", "answer": "u" },
                { "step": "find:v", "answer": null },
                { "step": "find:u", "answer": null },
            ],
            "entries": doubled,
            "beef": written,
        }),
    );
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

// The hand edits of the public `txs`, no door between. The reference's
// index maps a txid to its object and its position (`Beef.ts:507-529`), never
// rebuilt by a hand edit, so a dropped entry is still found, a pushed one is
// not, and `mergeRawTx` replaces at a stale position (a swap loses U) or
// appends a second copy. This crate's index notices a moved count or a hit
// naming another entry (a scan answers, the next `&mut` door rebuilds).

/// The toolbox's `retain`: W and U found, the dropped X not, and W merged
/// into its place (the reference: X found, W stored twice).
#[test]
fn a_hand_drop_then_the_lookups_and_merge_raw_tx_stated_817() {
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

/// A hand push: W found and merged into its place (the reference: not
/// found, stored twice).
#[test]
fn a_hand_push_then_find_txid_and_merge_raw_tx_stated_817() {
    let name = "a_hand_push_then_find_txid_and_merge_raw_tx";
    assert_stated(
        name,
        json!({
            "answers": [{ "step": "find:w", "answer": null }],
            "entries": [entry("x", None, "raw"), entry("w", None, "raw"), entry("w", None, "raw")],
            "beef": run(name).1["beef"],
        }),
        json!({
            "answers": [{ "step": "find:w", "answer": "w" }],
            "entries": [entry("x", None, "raw"), entry("w", None, "raw")],
            "beef": written(&["x", "w"]),
        }),
    );
}

/// A hand swap: both found on both sides (the answers the recording's), X merged into its own new place (the
/// reference's `mergeRawTx(X)` writes X over U at X's old position, U lost).
#[test]
fn a_hand_swap_then_find_each_and_merge_raw_tx_stated_817() {
    let name = "a_hand_swap_then_find_each_and_merge_raw_tx";
    assert_stated(
        name,
        json!({
            "entries": [entry("x", None, "raw"), entry("x", None, "raw")],
            "beef": run(name).1["beef"],
        }),
        json!({
            "entries": [entry("u", None, "raw"), entry("x", None, "raw")],
            "beef": written(&["u", "x"]),
        }),
    );
}

/// The stated window, on both sides: a hand replacement that keeps the
/// count makes a lookup of the new entry miss, so `merge_raw_tx(W)` stores
/// W twice there and here (the bytes agree); the replaced X is not found
/// here (its hit names W) where the reference still finds its object.
/// `reindex` is this crate's door for it (`tests/beef_edit_door_817.rs`).
#[test]
fn a_hand_replace_keeping_the_count_is_the_window_stated_817() {
    let name = "a_hand_replace_keeping_the_count_then_find_and_merge_raw_tx";
    assert_stated(
        name,
        json!({ "answers": [{ "step": "find:w", "answer": null }, { "step": "find:x", "answer": "x" }] }),
        json!({ "answers": [{ "step": "find:w", "answer": null }, { "step": "find:x", "answer": null }] }),
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

/// The fifteen stated cells of the forty-three, counted: a cell that moves
/// is a finding. (Named so that its own name does not end in the stated
/// cells' suffix, which a count of the suffix would take for a sixteenth.)
#[test]
fn the_stated_cells_counted_are_fifteen_of_forty_three_817() {
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
            "an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid",
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
