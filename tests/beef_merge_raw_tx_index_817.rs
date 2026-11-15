//! #817, a parity pin: `Beef::merge_raw_tx(raw, Some(n))` takes the index as
//! given, as the reference's `mergeRawTx(rawTx, bumpIndex)` does
//! (`ts-stack@edf6e03` `Beef.ts:835-847`: the entry built with the index,
//! `#tryToValidateBumpIndex` returning at an index already set,
//! `:1329-1332`). Neither side checks it against the BUMPs held: an index
//! past the list, one given with no BUMP held and one naming a BUMP that
//! does not hold the txid are each stored, written and read back as given,
//! and the BEEF is then not valid.
//!
//! The file pins today's answers on both sides and adds no check: whether the
//! door should refuse such an index is a decision not taken. A refusal here
//! would be a stated divergence, and these cells would then be its record.
//!
//! The reference's side is `tests/vectors/beef_pins_817.json`'s `raw_index`
//! (`tests/support/beef_pins_817.mjs`, Node v22.18.0, the bundle at the pin):
//! the entry returned, the entries held, the SHA-256 and length of
//! `toBinary`, what `Beef.fromString` and `Beef.fromBinaryStrict` read back
//! from those bytes, `verifyValid(true).valid` and `isValid(true)`. The
//! vector carries the steps and no BEEF: each is rebuilt by this crate's
//! writer and compared by the SHA-256 of its bytes.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::transaction::{Beef, MerklePath, Transaction};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/beef_pins_817.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn raw(v: &Value, name: &str) -> Vec<u8> {
    let t = Transaction::from_hex(v["txs"][name]["raw"].as_str().unwrap()).unwrap();
    assert_eq!(t.id(), v["txs"][name]["txid"].as_str().unwrap());
    t.to_binary()
}

/// An entry as the vector names one: the txid, the index, the form.
type Entry = (String, Option<u64>, bool);

fn recorded(v: &Value, list: &Value) -> Vec<Entry> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let n = e["tx"].as_str().unwrap();
            (
                v["txs"][n]["txid"].as_str().unwrap().to_string(),
                e["bump_index"].as_u64(),
                e["txid_only"].as_bool().unwrap(),
            )
        })
        .collect()
}

fn entries(beef: &Beef) -> Vec<Entry> {
    beef.txs()
        .iter()
        .map(|t| (t.id(), t.bump_index().map(|i| i as u64), t.is_txid_only()))
        .collect()
}

/// The case's BEEF built by its steps (`bump:<name>`, `raw:<name>:<n>`), and
/// the entry its `merge_raw_tx` returned as (txid, index).
fn built(v: &Value, steps: &Value) -> (Beef, (String, Option<u64>)) {
    let mut beef = Beef::new();
    let mut returned = None;
    for step in steps.as_array().unwrap() {
        let mut parts = step.as_str().unwrap().split(':');
        match (parts.next().unwrap(), parts.next().unwrap(), parts.next()) {
            ("bump", name, None) => {
                let bump = MerklePath::from_hex(v["bumps"][name].as_str().unwrap()).unwrap();
                beef.merge_bump(bump);
            }
            ("raw", name, Some(index)) => {
                let entry = beef
                    .merge_raw_tx(raw(v, name), Some(index.parse().unwrap()))
                    .expect("the bytes are one transaction: the index is not judged");
                returned = Some((entry.id(), entry.bump_index().map(|i| i as u64)));
            }
            other => panic!("no step {other:?}"),
        }
    }
    (beef, returned.expect("a raw step"))
}

fn case(v: &Value, name: &str) -> Value {
    v["raw_index"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone()
}

/// The case on this crate against the recording: the entry returned and the
/// entries held carry the index given, the bytes written are the
/// reference's, both of its readers and `Beef::from_binary` read them back
/// with the index as written, and the BEEF's validity is the recorded one.
fn assert_as_recorded(name: &str) {
    let v = vector();
    let c = case(&v, name);
    let (mut beef, returned) = built(&v, &c["steps"]);
    let named = c["returned"]["tx"].as_str().unwrap();
    assert_eq!(
        returned,
        (
            v["txs"][named]["txid"].as_str().unwrap().to_string(),
            c["returned"]["bump_index"].as_u64()
        ),
        "{name}: the entry returned"
    );
    assert_eq!(
        entries(&beef),
        recorded(&v, &c["entries"]),
        "{name}: the entries held"
    );
    assert_eq!(beef.bumps().len() as u64, c["bumps"].as_u64().unwrap());

    let bytes = beef
        .to_binary()
        .unwrap_or_else(|e| panic!("{name}: the reference writes this BEEF, refused here: {e:?}"));
    assert_eq!(bytes.len() as u64, c["beef_length"].as_u64().unwrap());
    assert_eq!(
        to_hex(&sha256(&bytes)),
        c["beef_sha256"].as_str().unwrap(),
        "{name}: the bytes the reference's toBinary writes"
    );

    for reader in ["read_back", "read_back_strict"] {
        assert_eq!(
            c[reader]["accepted"], true,
            "{name}: the reference's {reader} reads its bytes (a refusal is a cell to state)"
        );
        let read = Beef::from_binary(&bytes)
            .unwrap_or_else(|e| panic!("{name}: read there by {reader}, refused here: {e:?}"));
        assert_eq!(
            entries(&read),
            recorded(&v, &c[reader]["entries"]),
            "{name}: the entries {reader} reads"
        );
    }

    let valid = c["verify_valid"].as_bool().unwrap();
    assert_eq!(c["is_valid"].as_bool().unwrap(), valid);
    assert_eq!(beef.verify_valid(true).valid, valid, "{name}: verify_valid");
    assert_eq!(beef.is_valid(true), valid, "{name}: is_valid");
    let mut read = Beef::from_binary(&bytes).unwrap();
    assert_eq!(
        read.verify_valid(true).valid,
        valid,
        "{name}: verify_valid of the BEEF read back"
    );
}

/// One BUMP held, the index given 5 and then 1 (the count): stored as given.
#[test]
fn an_index_past_the_bumps_held_is_taken_as_given_as_the_reference_takes_it_817() {
    for name in ["index_past_the_list", "index_at_the_count"] {
        assert_as_recorded(name);
        assert!(!case(&vector(), name)["verify_valid"].as_bool().unwrap());
    }
}

/// No BUMP held, the index given 0: stored as given.
#[test]
fn an_index_given_with_no_bump_held_is_taken_as_given_as_the_reference_takes_it_817() {
    assert_as_recorded("index_with_no_bump_held");
    assert!(!case(&vector(), "index_with_no_bump_held")["verify_valid"]
        .as_bool()
        .unwrap());
}

/// The BUMP at the index given holds another txid, with no BUMP holding the
/// transaction's and with a later BUMP holding it: the index is stored as
/// given and the BUMPs are not scanned for the txid.
#[test]
fn an_index_naming_a_bump_without_the_txid_is_taken_as_given_as_the_reference_takes_it_817() {
    for name in [
        "index_naming_a_bump_without_the_txid",
        "index_naming_the_other_of_two_bumps",
    ] {
        assert_as_recorded(name);
        assert!(!case(&vector(), name)["verify_valid"].as_bool().unwrap());
    }
}

/// The control: the index given names the BUMP holding the txid, and the
/// BEEF is valid on both sides.
#[test]
fn an_index_naming_the_bump_holding_the_txid_is_valid_817() {
    assert_as_recorded("index_naming_the_bump_holding_the_txid");
    assert!(
        case(&vector(), "index_naming_the_bump_holding_the_txid")["verify_valid"]
            .as_bool()
            .unwrap()
    );
}

/// Every recorded cell is judged by a test above.
#[test]
fn every_recorded_raw_index_cell_is_judged_817() {
    let mut names: Vec<String> = vector()["raw_index"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "index_at_the_count",
            "index_naming_a_bump_without_the_txid",
            "index_naming_the_bump_holding_the_txid",
            "index_naming_the_other_of_two_bumps",
            "index_past_the_list",
            "index_with_no_bump_held",
        ]
    );
}
