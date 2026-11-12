//! #869's fold: the strength read's attempts to break #843's IDENTITY law in
//! safe code, each as a compiled cell asserting the law holds (the attempts
//! that must not compile are `compile_fail` doc tests on the doors,
//! `src/transaction/transaction/fields.rs`). The law: `id()` is the display
//! hex of `sha256d` of the fields' serialization, written here from the four
//! accessors alone, and a fresh parse of `to_binary()` has the same id.
//!
//! Which cells are whose: every cell here is the `Transaction`'s own law. A
//! BEEF's derived values (an entry's txid, `input_txids`, the index) are
//! #843's next PR; the two BEEF cells below judge only the transaction a BEEF
//! door hands out. An input whose `source_txid` differs from its linked
//! source's id keeps the law (the serializer reads the text); whether the
//! two agree is #848's coherence, not judged here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use bsv_rs::primitives::{from_hex, sha256d, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, MerklePath, Transaction, TransactionInput, TransactionOutput};

fn var_int(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

/// The fields' bytes, from the accessors alone.
fn fields_bytes(tx: &Transaction) -> Vec<u8> {
    let mut out = tx.version().to_le_bytes().to_vec();
    var_int(&mut out, tx.inputs().len() as u64);
    for input in tx.inputs() {
        let wire = match (&input.source_txid, &input.source_transaction) {
            (Some(txid), _) => {
                let mut b = from_hex(txid).unwrap();
                b.reverse();
                b
            }
            (None, Some(source)) => sha256d(&fields_bytes(source)).to_vec(),
            (None, None) => vec![0; 32],
        };
        out.extend_from_slice(&wire);
        out.extend_from_slice(&input.source_output_index.to_le_bytes());
        let script = input
            .unlocking_script
            .as_ref()
            .map(|s| s.to_binary())
            .unwrap_or_default();
        var_int(&mut out, script.len() as u64);
        out.extend_from_slice(&script);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    var_int(&mut out, tx.outputs().len() as u64);
    for output in tx.outputs() {
        out.extend_from_slice(&output.satoshis.unwrap_or(0).to_le_bytes());
        let script = output.locking_script.to_binary();
        var_int(&mut out, script.len() as u64);
        out.extend_from_slice(&script);
    }
    out.extend_from_slice(&tx.lock_time().to_le_bytes());
    out
}

fn law(tx: &Transaction, at: &str) {
    let mut h = sha256d(&fields_bytes(tx));
    h.reverse();
    assert_eq!(tx.id(), to_hex(&h), "{at}: id() is the hash of the fields");
    assert_eq!(tx.to_binary(), fields_bytes(tx), "{at}: to_binary()");
    assert_eq!(tx.to_hex(), to_hex(&fields_bytes(tx)), "{at}: to_hex()");
    let fresh = Transaction::from_binary(&tx.to_binary()).unwrap();
    assert_eq!(fresh.id(), tx.id(), "{at}: a fresh parse has the same id");
}

fn script(bytes: &[u8]) -> LockingScript {
    LockingScript::from_binary(bytes).unwrap()
}

/// A transaction of two inputs and two outputs, its caches full.
fn sample() -> Transaction {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    let mut second = TransactionInput::new("22".repeat(32), 1);
    second.unlocking_script = Some(UnlockingScript::from_binary(&[0x51, 0x52]).unwrap());
    tx.add_input(second).unwrap();
    tx.add_output(TransactionOutput::new(1_000, script(&[0x76, 0xa9])))
        .unwrap();
    tx.add_output(TransactionOutput::new(2_000, script(&[0x51])))
        .unwrap();
    let _ = (tx.id(), tx.to_hex());
    tx
}

/// `Script`'s `&self` methods (`to_binary`, `to_hex`, `chunks`) reached
/// through `inputs()` and `outputs()` fill the script's own caches from state
/// that cannot change; the transaction's bytes do not move.
#[test]
fn a_scripts_self_methods_through_the_reads_move_no_byte_869() {
    let tx = sample();
    let (id, bytes) = (tx.id(), tx.to_binary());
    for input in tx.inputs() {
        if let Some(s) = &input.unlocking_script {
            let _ = (s.to_binary(), s.to_hex(), s.chunks());
        }
    }
    for output in tx.outputs() {
        let s = &output.locking_script;
        let _ = (s.to_binary(), s.to_hex(), s.chunks(), s.to_asm());
    }
    assert_eq!(tx.id(), id);
    assert_eq!(tx.to_binary(), bytes);
    law(&tx, "after the scripts' &self methods");
}

/// `mem::swap`, `mem::take` and `mem::replace` on what each door lends: each
/// lend clears first, so whatever the swap leaves is what the id hashes.
#[test]
fn swap_take_and_replace_on_what_each_door_lends_keep_the_law_869() {
    let mut tx = sample();
    let mut other = vec![TransactionInput::new("33".repeat(32), 7)];
    std::mem::swap(tx.inputs_mut(), &mut other);
    law(&tx, "mem::swap on inputs_mut()");
    let taken = std::mem::take(tx.outputs_mut());
    assert_eq!(taken.len(), 2);
    law(&tx, "mem::take on outputs_mut()");
    let _ = std::mem::replace(tx.outputs_mut(), taken);
    law(&tx, "mem::replace on outputs_mut()");
    {
        let parts = tx.parts_mut();
        let _ = std::mem::replace(parts.version, 2);
        let _ = std::mem::replace(parts.lock_time, 9);
        std::mem::swap(parts.inputs, &mut other);
        let _ = std::mem::take(parts.metadata);
        *parts.merkle_path = Some(MerklePath::from_coinbase_txid(&"44".repeat(32), 1));
    }
    assert_eq!((tx.version(), tx.lock_time(), tx.inputs().len()), (2, 9, 2));
    law(&tx, "mem::swap, take and replace through parts_mut()");
    let mut lone = sample();
    std::mem::swap(&mut tx, &mut lone);
    law(&tx, "mem::swap of two transactions");
    law(&lone, "the other side of the swap");
}

/// `from_json` with members that contradict `hex`: `hex` decides, and the
/// fields are read from it.
#[test]
fn from_json_with_members_contradicting_hex_keeps_the_law_869() {
    let tx = sample();
    let mut json: serde_json::Value = serde_json::from_str(&tx.to_json().unwrap()).unwrap();
    json["lockTime"] = serde_json::json!(99);
    json["version"] = serde_json::json!(7);
    json["txid"] = serde_json::json!("00".repeat(32));
    json["outputs"] = serde_json::json!([]);
    json["inputs"][0]["vout"] = serde_json::json!(5);
    let back = Transaction::from_json(&json.to_string()).unwrap();
    assert_eq!(back.id(), tx.id(), "hex decides");
    assert_eq!(
        (back.version(), back.lock_time(), back.outputs().len()),
        (1, 0, 2)
    );
    law(&back, "from_json with contradicting members");
}

/// `Default` is `new()`: version 1, no field, the law.
#[test]
fn default_keeps_the_law_869() {
    let tx = Transaction::default();
    assert!(tx == Transaction::new());
    assert_eq!((tx.version(), tx.lock_time()), (1, 0));
    let bytes = tx.to_binary();
    assert_eq!(bytes, fields_bytes(&tx));
    let mut h = sha256d(&bytes);
    h.reverse();
    assert_eq!(tx.id(), to_hex(&h));
}

/// A BEEF door handing out a `&mut Transaction` (`edit_tx`) and one handing
/// out an owned copy (`find_transaction_for_signing`): the transaction's own
/// law holds through both. The entry's derived values are #843's next PR.
#[test]
fn a_beef_door_lending_a_transaction_keeps_its_law_869() {
    let parent = sample();
    let mut child = Transaction::new();
    child
        .add_input(TransactionInput::new(parent.id(), 0))
        .unwrap();
    child
        .add_output(TransactionOutput::new(500, script(&[0x51])))
        .unwrap();
    let mut beef = Beef::new();
    beef.merge_raw_tx(parent.to_binary(), None).unwrap();
    beef.merge_raw_tx(child.to_binary(), None).unwrap();
    let id = child.id();
    let seen = beef
        .edit_tx(&id, |tx| {
            let _ = tx.id();
            tx.set_lock_time(31);
            law(tx, "inside edit_tx");
            tx.outputs_mut()[0].satoshis = Some(400);
            law(tx, "inside edit_tx, a second edit");
            tx.id()
        })
        .unwrap();
    assert_ne!(seen, id);
    let held = beef.find_txid(&seen).unwrap().tx().unwrap().clone();
    assert_eq!(held.id(), seen, "the entry holds the edited transaction");
    law(&held, "the edited entry's transaction");
    let mut signing = beef.find_transaction_for_signing(&seen).unwrap();
    law(&signing, "find_transaction_for_signing's copy");
    signing.inputs_mut()[0]
        .source_transaction
        .as_mut()
        .unwrap()
        .set_lock_time(77);
    law(&signing, "after an edit of its linked source");
}

/// An input whose `source_txid` names another transaction than its linked
/// source: the serializer reads the text, so the id is the hash of those
/// fields, and an edit of the source (through the child's door) leaves the
/// child's id where the text puts it. The law holds; whether the text and
/// the link agree is #848's coherence.
#[test]
fn a_source_txid_other_than_the_linked_sources_id_keeps_the_law_869() {
    let parent = sample();
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.source_txid = Some("55".repeat(32));
    let mut child = Transaction::new();
    child.add_input(input).unwrap();
    child
        .add_output(TransactionOutput::new(500, script(&[0x51])))
        .unwrap();
    law(&child, "a source_txid other than the source's id");
    let before = child.id();
    child.inputs_mut()[0]
        .source_transaction
        .as_mut()
        .unwrap()
        .set_lock_time(3);
    assert_eq!(
        child.id(),
        before,
        "the text decides the wire, not the link"
    );
    law(&child, "after the source's edit");
}
