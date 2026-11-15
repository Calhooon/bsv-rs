//! #845: an input's `source_txid` is a `Txid`, so a text that is not 64 hex
//! digits is refused where it enters and is never written as 32 zero bytes.
//!
//! Until #845 the field was a `String` nothing checked: `TransactionInput::new`,
//! a struct literal and `add_input` held `"zz"`, `"abcd"`, `""` or 66 digits,
//! and the serializer wrote each as the linked source's hash or as 32 zero
//! bytes (the null outpoint's txid; `is_coinbase` answered true for `""`),
//! so different inputs were one transaction; an upper-case text wrote the
//! same bytes as its lower-case twin and missed its held parent in a BEEF.
//! The reference never writes such a text: `addInput` refuses it and
//! lower-cases the rest, and its writer refuses a hand-built one
//! (`requireTXID`, `ts-stack@edf6e03` `Transaction.ts:95-100`, `:708-709`,
//! `:1070`). This crate's `to_binary` cannot refuse, so the check is the
//! type's: `Txid::from_hex` is the one door from text.
//!
//! The reference's answers are `vectors/source_txid_doors_845.json`
//! (`support/source_txid_doors_845.mjs`, Node v22.18.0, two runs
//! byte-identical). This file cannot compile on the base (it names `Txid`):
//! its RED there is the base probe's run, `docs/lanes/fix-845.md`; the doors
//! both trees share are `transaction_source_txid_text_doors_845.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput, Txid};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/source_txid_doors_845.json");
const REFUSAL: &str = "sourceTXID must be a 32-byte hexadecimal transaction ID.";

fn cases() -> Vec<Value> {
    let doc: Value = serde_json::from_str(VECTOR).unwrap();
    doc["cases"].as_array().unwrap().clone()
}

fn one_sat() -> TransactionOutput {
    TransactionOutput::new(1, LockingScript::from_hex("51").unwrap())
}

/// The recorder's source: no input, one output of 1000 satoshis locked `51`.
fn source() -> Transaction {
    let lock = LockingScript::from_hex("51").unwrap();
    Transaction::with_params(1, vec![], vec![TransactionOutput::new(1000, lock)], 0)
}

/// The recorder's transaction around `input`.
fn around(mut input: TransactionInput) -> Transaction {
    input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
    Transaction::with_params(1, vec![input], vec![one_sat()], 0)
}

/// The 32 outpoint txid bytes as written, in hex.
fn outpoint(tx: &Transaction) -> String {
    hex::encode(&tx.to_binary()[5..37])
}

/// Every text of the recording is a `Txid` exactly when the reference's
/// `addInput` takes it, held in the lower case the reference holds, and
/// refused in the reference's words under its label otherwise.
#[test]
fn a_text_is_a_txid_exactly_when_the_reference_takes_it_845() {
    let mut refused = 0;
    let mut differing = Vec::new();
    for case in cases() {
        let Some(text) = case["text"].as_str() else {
            continue; // absent: no text to read
        };
        let name = case["name"].as_str().unwrap();
        let there = &case["add_input"];
        let here = Txid::from_hex(text);
        match (there["ok"]["held"].as_str(), &here) {
            (Some(held), Ok(txid)) => {
                // The text shown, digit for digit (`==` on a `Txid` and a
                // text reads either case).
                let shown = txid.to_string();
                if shown != held || text.parse::<Txid>().ok() != Some(*txid) {
                    differing.push(format!("{name}: held {txid}, the reference {held}"));
                }
            }
            (None, Err(e)) => {
                refused += 1;
                assert_eq!(there["error"], REFUSAL, "{name}");
                assert_eq!(
                    e.to_string(),
                    "transaction error: txid must be a 32-byte hexadecimal transaction ID.",
                    "{name}"
                );
                assert!(
                    !e.to_string().contains("zz"),
                    "{name}: the text is not echoed"
                );
            }
            (there, here) => differing.push(format!("{name}: {here:?}, the reference {there:?}")),
        }
    }
    assert!(differing.is_empty(), "{differing:#?}");
    assert_eq!(refused, 26, "13 refused texts, each linked and not");
}

/// Every input the type can hold is written as the reference writes it: the
/// outpoint's bytes and the id, cell for cell; a text the reference's writer
/// refuses cannot be held, so no cell of the recording is 32 zero bytes but
/// the one whose text is 64 zeros.
#[test]
fn every_input_that_can_be_held_is_written_as_the_reference_writes_it_845() {
    let (mut written, mut unbuildable) = (0, 0);
    for case in cases() {
        let name = case["name"].as_str().unwrap();
        let linked = case["linked"].as_bool().unwrap();
        let there = &case["hand_built"];
        let txid = match case["text"].as_str() {
            Some(text) => match Txid::from_hex(text) {
                Ok(txid) => Some(txid),
                Err(_) => {
                    // No input holds it: the reference's writer refuses it.
                    assert_eq!(there["error"], REFUSAL, "{name}");
                    unbuildable += 1;
                    continue;
                }
            },
            None => None,
        };
        let input = TransactionInput {
            source_txid: txid,
            source_transaction: linked.then(|| Box::new(source())),
            ..TransactionInput::default()
        };
        let tx = around(input);
        if txid.is_none() && !linked {
            // Names nothing and links nothing: the reference's writer throws
            // and `add_input` refuses; a struct literal writes 32 zero bytes
            // (stated, the one state left under any txid type).
            assert_eq!(there["error"], "sourceTransaction is undefined", "{name}");
            assert_eq!(outpoint(&tx), "00".repeat(32), "{name}");
            assert!(Transaction::new()
                .add_input(TransactionInput::default())
                .is_err());
            continue;
        }
        assert_eq!(
            outpoint(&tx),
            there["ok"]["outpoint"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(tx.id(), there["ok"]["id"].as_str().unwrap(), "{name}");
        assert_eq!(tx.txid().to_string(), tx.id(), "{name}");
        // `add_input` takes it too, and holds what the reference holds.
        let add = &case["add_input"]["ok"];
        let mut built = Transaction::new();
        let mut input = tx.inputs()[0].clone();
        input.source_transaction = linked.then(|| Box::new(source()));
        built.add_input(input).unwrap();
        assert_eq!(
            built.inputs()[0].source_txid.map(|t| t.to_string()),
            add["held"].as_str().map(str::to_string),
            "{name}"
        );
        if outpoint(&tx) == "00".repeat(32) {
            assert_eq!(
                case["text"],
                "00".repeat(32),
                "{name}: zeros only for the null txid"
            );
        }
        written += 1;
    }
    assert_eq!((written, unbuildable), (9, 26));
}

/// The issue's table: three documents were one transaction. Each is refused,
/// and so is a hand-built input of the same text, at the type's door.
#[test]
fn the_issues_three_documents_are_refused_and_no_input_holds_their_text_845() {
    for text in ["zz", "abcd", ""] {
        let json = format!(
            r#"{{"inputs":[{{"unlockingScript":"51","txid":"{text}","vout":0,"sequence":4294967295}}],"outputs":[{{"satoshis":1,"lockingScript":"51"}}],"version":1,"lockTime":0}}"#
        );
        assert_eq!(
            Transaction::from_json(&json).map(|t| t.id()),
            Err(bsv_rs::Error::TransactionError(
                "Invalid txid of input 0: expected 64 hex digits".to_string()
            )),
            "{text:?}"
        );
        assert!(Txid::from_hex(text).is_err(), "{text:?}");
    }
}

/// `is_coinbase` reads the null txid alone: true for 64 zeros at index
/// 0xffffffff, false for an input naming no txid (until #845 an empty text
/// read as "all zeros" and answered true).
#[test]
fn is_coinbase_is_the_null_txid_alone_845() {
    let null = Txid::from_hex(&"00".repeat(32)).unwrap();
    assert!(null.is_null());
    assert!(around(TransactionInput::new(null, 0xffff_ffff)).is_coinbase());
    assert!(!around(TransactionInput::new(null, 0)).is_coinbase());
    let one = Txid::from_hex(&format!("{}01", "00".repeat(31))).unwrap();
    assert!(!around(TransactionInput::new(one, 0xffff_ffff)).is_coinbase());
    let unnamed = TransactionInput {
        source_output_index: 0xffff_ffff,
        ..TransactionInput::default()
    };
    assert!(!around(unnamed).is_coinbase());
}

/// One txid, one value: an input named in upper case is the input named in
/// lower case (the same bytes, the same id, equal), and it finds its held
/// parent in a BEEF, which keys on the lower-case text (missed until #845).
#[test]
fn an_upper_case_text_names_the_same_input_and_finds_its_held_parent_845() {
    let mut parent = Transaction::new();
    parent.add_output(one_sat()).unwrap();
    let pid = parent.id();
    let child = |text: &str| {
        let mut c = Transaction::new();
        c.add_input(TransactionInput::new(text.parse().unwrap(), 0))
            .unwrap();
        c.add_output(one_sat()).unwrap();
        c
    };
    let (lower, upper) = (child(&pid), child(&pid.to_uppercase()));
    assert_eq!(lower.inputs()[0].source_txid, upper.inputs()[0].source_txid);
    assert_eq!(upper.inputs()[0].source_txid, Some(parent.txid()));
    assert_eq!(upper.inputs()[0].get_source_txid().unwrap(), pid);
    assert_eq!(lower.to_binary(), upper.to_binary());
    let mut beef = Beef::new();
    beef.merge_transaction(parent.clone());
    beef.merge_transaction(upper.clone());
    let signing = beef.find_transaction_for_signing(&upper.id()).unwrap();
    assert_eq!(
        signing.inputs()[0]
            .source_transaction
            .as_deref()
            .map(Transaction::id),
        Some(pid.clone()),
        "the held parent linked"
    );
    assert_eq!(beef.find_txid(&upper.id()).unwrap().input_txids, vec![pid]);
}

/// The JSON a transaction writes carries each input's txid as the 64
/// lower-case digits `from_json` reads back to the same transaction; an
/// input naming no txid over a linked source is written by its source's id.
#[test]
fn the_json_written_reads_back_to_the_same_transaction_845() {
    let named = around(TransactionInput::new("AB".repeat(32).parse().unwrap(), 3));
    let mut unnamed = TransactionInput::with_source_transaction(source(), 0);
    unnamed.sequence = 7;
    let unnamed = around(unnamed);
    for (tx, txid) in [(named, "ab".repeat(32)), (unnamed, source().id())] {
        let json: Value = serde_json::from_str(&tx.to_json().unwrap()).unwrap();
        assert_eq!(json["inputs"][0]["txid"], txid);
        let mut fields = json.clone();
        fields.as_object_mut().unwrap().remove("hex");
        let back = Transaction::from_json(&fields.to_string()).unwrap();
        assert_eq!(back.to_binary(), tx.to_binary());
        assert_eq!(back.inputs()[0].source_txid.unwrap(), txid);
    }
}

/// A `Txid` prints as its text, in `Display` and inside an input's `Debug`,
/// and `Transaction::txid` is `hash()` in wire order, `id()` as text.
#[test]
fn a_txid_prints_its_text_and_a_transaction_answers_its_own_845() {
    let text = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
    let input = TransactionInput::new(Txid::from_hex(text).unwrap(), 1);
    assert!(format!("{input:?}").contains(&format!("source_txid: Some(Txid({text}))")));
    let tx = around(input);
    assert_eq!(tx.txid().as_wire_bytes(), &tx.hash());
    assert_eq!(tx.txid().to_string(), tx.id());
    assert_eq!(tx.txid(), tx.id().as_str());
    assert_eq!(Txid::from_wire_bytes(tx.hash()), tx.txid());
}
