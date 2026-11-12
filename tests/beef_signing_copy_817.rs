//! #817, line 13 of the bucket, stated: `Beef::find_transaction_for_signing`
//! answers a copy. The reference's `findTransactionForSigning`
//! (`ts-stack@edf6e03` `Beef.ts:615-631`) links the inputs of the object the
//! BEEF holds and returns that object, so a signature put on it is the
//! entry's; go-sdk@2ca481c returns the held pointer too
//! (`transaction/beef.go:655-671`). Here `&self` cannot lend the entry: the
//! copy is linked, the entry is left as held, and a signature put on the copy
//! reaches the BEEF through `Beef::edit_tx` (or a merge of the signed
//! transaction). No code changes; both tests are statements, green before and
//! after #817's fold.
//!
//! The reference's side is recorded in `tests/vectors/transaction_fold_817.json`
//! (group `signing`) by `tests/support/transaction_fold_817.mjs` (Node 22, the
//! bundle at the pin): a parent and a child spending it, written to a BEEF and
//! read back; the identity of the object returned, the entry's input link,
//! the BEEF's hex before and after the returned object is signed (P2PKH,
//! SIGHASH_ALL | FORKID, the scalar 7).

#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::SignOutputs;
use bsv_rs::transaction::{Beef, Transaction};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/transaction_fold_817.json");

fn signing() -> Value {
    let v: Value = serde_json::from_str(VECTOR).expect("the vector is JSON");
    v["signing"].clone()
}

fn text(s: &Value, key: &str) -> String {
    s[key]
        .as_str()
        .unwrap_or_else(|| panic!("no {key}"))
        .to_string()
}

fn key() -> PrivateKey {
    let scalar = signing()["key_scalar"].as_u64().expect("scalar") as u8;
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
}

/// The copy signed here with the reference's key and template.
fn sign(mut copy: Transaction) -> Transaction {
    copy.inputs_mut()[0].set_unlocking_script_template(P2PKH::unlock(
        &key(),
        SignOutputs::All,
        false,
    ));
    futures::executor::block_on(copy.sign()).unwrap();
    copy
}

fn entry_input_linked(beef: &Beef, txid: &str) -> bool {
    beef.find_txid(txid)
        .expect("the child is held")
        .tx()
        .is_some_and(|tx| tx.inputs()[0].source_transaction.is_some())
}

#[test]
fn find_transaction_for_signing_answers_a_copy_and_leaves_the_entry_as_held_stated_817() {
    let s = signing();
    let before = text(&s, "before");
    let child = text(&s, "child_txid");
    let mut beef = Beef::from_hex(&before).unwrap();
    assert_eq!(
        beef.to_hex().unwrap(),
        before,
        "this crate's writer's bytes"
    );
    assert!(!entry_input_linked(&beef, &child));
    assert_eq!(s["entry_input_linked_before"], false);

    let copy = beef.find_transaction_for_signing(&child).unwrap();
    assert_eq!(copy.id(), child);
    let source = copy.inputs()[0]
        .source_transaction
        .as_deref()
        .expect("the copy's input is linked");
    assert_eq!(source.id(), text(&s, "parent_txid"));

    // Ours: the entry left as held, its bytes unchanged by finding or by
    // signing the copy.
    assert!(!entry_input_linked(&beef, &child));
    assert_eq!(beef.to_hex().unwrap(), before);
    let signed = sign(copy);
    assert_eq!(signed.id(), text(&s, "signed_child_txid"));
    assert_eq!(beef.to_hex().unwrap(), before);
    assert!(beef.find_txid(&child).is_some());

    // Theirs, the other column: the entry itself returned, its input linked,
    // the BEEF's bytes moved by the signature.
    assert_eq!(s["returned_is_the_entry"], true);
    assert_eq!(s["entry_input_linked_after"], true);
    assert_eq!(text(&s, "hex_after_find"), before);
    assert_ne!(text(&s, "hex_after_signing_the_returned"), before);
}

#[test]
fn a_signed_copy_returns_through_edit_tx_stated_817() {
    let s = signing();
    let child = text(&s, "child_txid");
    let mut beef = Beef::from_hex(&text(&s, "before")).unwrap();
    let signed = sign(beef.find_transaction_for_signing(&child).unwrap());
    assert_eq!(signed.to_hex(), text(&s, "signed_child"));

    let script = signed.inputs()[0].unlocking_script.clone();
    beef.edit_tx(&child, |tx| tx.inputs_mut()[0].unlocking_script = script)
        .unwrap();
    assert_eq!(
        beef.to_hex().unwrap(),
        text(&s, "hex_after_signing_the_returned"),
        "the BEEF after edit_tx is the reference's after its in-place signing"
    );
    assert!(beef.find_txid(&child).is_none());
    assert!(beef.find_txid(&text(&s, "signed_child_txid")).is_some());
}
