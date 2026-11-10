//! #840: `Transaction::from_binary` and `from_hex` refuse bytes after the
//! transaction, as the reference's readers do (`ts-stack@edf6e03`
//! `Transaction.ts:532-535`, `Serialized transaction contains trailing
//! data`); until #840 they read the transaction from the front, kept the
//! whole input as its cached serialization and hashed it into the txid.
//! `from_ef` and `from_hex_ef` refuse in the EF reader's words (`:419`),
//! `parse_script_offsets` in `:462`'s, and `from_reader` reads one
//! transaction from the front and leaves the rest, as `fromReader` does.
//!
//! Against `vectors/transaction_trailing_data_840.json`
//! (`support/transaction_trailing_data_840.mjs`, the reference under
//! Node v22.18.0, two runs byte-identical): block 170's transaction, its EF
//! form and a BEEF of it, clean and followed by one byte, four bytes and
//! itself, and the hex followed by two and by one hex digit.
//!
//! Three cells refuse on both sides in other words, stated (`STATED`): a hex
//! text of odd length is `InvalidHex` here, where the reference pads it with
//! a leading zero and fails reading the shifted bytes (`utils.ts`'s
//! `hexToUint8Array`); a BEEF followed by bytes is refused in the stream's
//! words (`TrailingBytes`, #86), where the reference says `Serialized BEEF
//! contains trailing data`; a transaction without its lock time is this
//! crate's reader underflow, where the reference's reader says `Reader read
//! exceeds available data`.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_hex, Reader};
use bsv_rs::transaction::Transaction;
use bsv_rs::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/transaction_trailing_data_840.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("the vector parses")
}

/// The recorded cell of `reader` named `name`: its input text and answer.
fn cell(reader: &str, name: &str) -> (String, Value) {
    let v = vector();
    let c = v["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["reader"] == reader && c["name"] == name)
        .unwrap_or_else(|| panic!("no recorded cell {reader} {name}"))
        .clone();
    (
        c["input"].as_str().unwrap().to_string(),
        c["answer"].clone(),
    )
}

/// The cells refusing on both sides in other words (the module's doc).
const STATED: [(&str, &str); 5] = [
    ("fromHex", "hex_plus_one_digit"),
    ("fromHexEF", "hex_plus_one_digit"),
    ("fromBEEF", "plus_one_byte"),
    ("fromBEEF", "plus_four_bytes"),
    ("parseScriptOffsets", "no_lock_time"),
];

/// A transaction answer as the recording writes it.
fn assert_tx(reader: &str, name: &str, got: bsv_rs::Result<Transaction>, answer: &Value) {
    let tx = got.unwrap_or_else(|e| panic!("{reader} {name}: {e}"));
    assert_eq!(answer["ok"], true, "{reader} {name}");
    assert_eq!(tx.id(), answer["id"].as_str().unwrap(), "{reader} {name}");
    assert_eq!(
        tx.to_binary().len() as u64,
        answer["to_binary_len"].as_u64().unwrap(),
        "{reader} {name}"
    );
    assert_eq!(
        tx.to_hex(),
        answer["to_hex"].as_str().unwrap(),
        "{reader} {name}"
    );
}

/// A refusal in the recorded words, as `TransactionError`.
fn assert_refused(reader: &str, name: &str, got: bsv_rs::Result<Transaction>, answer: &Value) {
    assert_eq!(answer["ok"], false, "{reader} {name}");
    let words = answer["error"].as_str().unwrap().to_string();
    match got {
        Err(e) => assert_eq!(e, Error::TransactionError(words), "{reader} {name}"),
        Ok(tx) => panic!(
            "{reader} {name}: Ok with id {} where the reference refuses",
            tx.id()
        ),
    }
}

const SUFFIXED: [&str; 3] = ["plus_one_byte", "plus_four_bytes", "plus_itself"];

#[test]
fn a_clean_transaction_reads_to_the_same_id_bytes_and_hex_840() {
    for reader in ["fromBinary", "fromHex", "fromEF", "fromHexEF", "fromBEEF"] {
        let (input, answer) = cell(reader, "clean");
        let bytes = from_hex(&input).unwrap();
        let got = match reader {
            "fromBinary" => Transaction::from_binary(&bytes),
            "fromHex" => Transaction::from_hex(&input),
            "fromEF" => Transaction::from_ef(&bytes),
            "fromHexEF" => Transaction::from_hex_ef(&input),
            _ => Transaction::from_beef(&bytes, None),
        };
        assert_tx(reader, "clean", got, &answer);
    }
    // The clean transaction's own bytes and hex, unchanged by the fix.
    let v = vector();
    let tx_hex = v["tx_hex"].as_str().unwrap();
    let tx = Transaction::from_hex(tx_hex).unwrap();
    assert_eq!(tx.to_hex(), tx_hex);
    assert_eq!(tx.to_binary(), from_hex(tx_hex).unwrap());
    assert_eq!(
        tx.id(),
        "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    );
    // Upper-case hex reads to the lower-case cache, as before.
    let upper = Transaction::from_hex(&tx_hex.to_uppercase()).unwrap();
    assert_eq!(upper.to_hex(), tx_hex);
    assert_eq!(upper.id(), tx.id());
}

#[test]
fn a_transaction_followed_by_bytes_is_refused_840() {
    for name in SUFFIXED {
        let (input, answer) = cell("fromBinary", name);
        let got = Transaction::from_binary(&from_hex(&input).unwrap());
        assert_refused("fromBinary", name, got, &answer);
    }
}

#[test]
fn a_transaction_hex_followed_by_bytes_is_refused_840() {
    for name in SUFFIXED.iter().copied().chain(["hex_plus_two_digits"]) {
        let (input, answer) = cell("fromHex", name);
        assert_refused("fromHex", name, Transaction::from_hex(&input), &answer);
    }
}

#[test]
fn a_transaction_hex_with_one_digit_more_is_refused_in_other_words_stated_840() {
    let (input, answer) = cell("fromHex", "hex_plus_one_digit");
    assert_eq!(answer["ok"], false);
    assert_eq!(
        answer["error"],
        "Number can only safely store up to 53 bits"
    );
    assert!(matches!(
        Transaction::from_hex(&input),
        Err(Error::InvalidHex(_))
    ));
}

#[test]
fn an_ef_transaction_followed_by_bytes_is_refused_840() {
    for name in SUFFIXED {
        let (input, answer) = cell("fromEF", name);
        assert_refused(
            "fromEF",
            name,
            Transaction::from_ef(&from_hex(&input).unwrap()),
            &answer,
        );
        let (input, answer) = cell("fromHexEF", name);
        assert_refused("fromHexEF", name, Transaction::from_hex_ef(&input), &answer);
    }
    let (input, answer) = cell("fromHexEF", "hex_plus_one_digit");
    assert_eq!(answer["error"], "Invalid EF marker");
    assert!(matches!(
        Transaction::from_hex_ef(&input),
        Err(Error::InvalidHex(_))
    ));
}

#[test]
fn a_beef_followed_by_bytes_is_refused_in_the_streams_words_stated_840() {
    for name in ["plus_one_byte", "plus_four_bytes"] {
        let (input, answer) = cell("fromBEEF", name);
        assert_eq!(answer["error"], "Serialized BEEF contains trailing data");
        match Transaction::from_beef(&from_hex(&input).unwrap(), None) {
            Err(Error::BeefError(words)) => assert!(words.contains("TrailingBytes"), "{words}"),
            other => panic!("fromBEEF {name}: {other:?}"),
        }
    }
}

#[test]
fn script_offsets_refuse_bytes_after_the_lock_time_and_a_missing_lock_time_840() {
    let (input, answer) = cell("parseScriptOffsets", "clean");
    let offsets = Transaction::parse_script_offsets(&from_hex(&input).unwrap()).unwrap();
    let pairs = |list: Vec<(usize, usize)>| -> Value {
        Value::Array(
            list.into_iter()
                .map(|(o, l)| Value::Array(vec![o.into(), l.into()]))
                .collect(),
        )
    };
    let ins: Vec<_> = offsets
        .inputs
        .iter()
        .map(|o| (o.offset, o.length))
        .collect();
    let outs: Vec<_> = offsets
        .outputs
        .iter()
        .map(|o| (o.offset, o.length))
        .collect();
    assert_eq!(pairs(ins), answer["inputs"]);
    assert_eq!(pairs(outs), answer["outputs"]);
    for name in ["plus_one_byte", "plus_four_bytes"] {
        let (input, answer) = cell("parseScriptOffsets", name);
        assert_eq!(
            Transaction::parse_script_offsets(&from_hex(&input).unwrap()).unwrap_err(),
            Error::TransactionError(answer["error"].as_str().unwrap().to_string()),
            "{name}"
        );
    }
    // Refused on both sides, the reader's own words each (stated).
    let (input, answer) = cell("parseScriptOffsets", "no_lock_time");
    assert_eq!(answer["error"], "Reader read exceeds available data");
    assert!(matches!(
        Transaction::parse_script_offsets(&from_hex(&input).unwrap()),
        Err(Error::ReaderUnderflow { .. })
    ));
}

#[test]
fn the_reader_form_reads_one_transaction_and_leaves_the_rest_840() {
    for name in ["clean", "plus_one_byte", "plus_four_bytes", "plus_itself"] {
        let (input, answer) = cell("fromReader", name);
        let bytes = from_hex(&input).unwrap();
        let mut reader = Reader::new(&bytes);
        let got = Transaction::from_reader(&mut reader);
        assert_tx("fromReader", name, got, &answer);
        assert_eq!(
            reader.remaining() as u64,
            answer["remaining"].as_u64().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn a_json_hex_followed_by_bytes_is_refused_840() {
    let (input, answer) = cell("fromHex", "plus_four_bytes");
    let json = format!(r#"{{"hex":"{input}"}}"#);
    assert_refused(
        "fromJson",
        "plus_four_bytes",
        Transaction::from_json(&json),
        &answer,
    );
}

#[test]
fn every_recorded_cell_is_asserted_or_stated_840() {
    let v = vector();
    let cells = v["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 30);
    let refused_both = cells.iter().filter(|c| c["answer"]["ok"] == false).count();
    // Every suffixed cell of every reader but `fromReader` is a refusal
    // there and here; the stated five in other words.
    assert_eq!(refused_both, 20);
    for (reader, name) in STATED {
        assert_eq!(cell(reader, name).1["ok"], false, "{reader} {name}");
    }
}

// The 53-bit cells (the cold read's item 7, older than #840; #844 conformed
// them). The reference reads an amount through `readUInt64LEBn().toNumber()`
// (`ts-stack@edf6e03` `Transaction.ts:388,409,497`) and refuses one of 2^53 or
// more in `Number can only safely store up to 53 bits` (`BigNumber.ts:628`);
// since #844 this crate's readers refuse it in those words (until then each
// read a `u64`, as go-sdk@2ca481c does, `transaction/output.go:29,53`). No such
// output is valid at the node (`MAX_MONEY`, bitcoin-sv v1.2.2 `amount.h:130`,
// `validation.cpp:543-551`). The edges of every numeric field are
// `transaction_numbers_844.rs`'s.

/// The recorded 53-bit cell of `reader` named `name`.
fn cell_53(reader: &str, name: &str) -> (String, Value) {
    let v = vector();
    let c = v["cells_53"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["reader"] == reader && c["name"] == name)
        .unwrap_or_else(|| panic!("no recorded 53-bit cell {reader} {name}"))
        .clone();
    (
        c["input"].as_str().unwrap().to_string(),
        c["answer"].clone(),
    )
}

/// The txid of `bytes`: their double SHA-256, reversed, in hex.
fn id_of(bytes: &[u8]) -> String {
    let mut h = bsv_rs::primitives::sha256d(bytes);
    h.reverse();
    bsv_rs::primitives::to_hex(&h)
}

/// The output amount at the three readers against the recording: read on
/// both sides, the id the hash of the bytes, or refused on both in the
/// reference's words (#844).
fn assert_amount_as_recorded(name: &str, amount: u64, reference_refuses: bool) {
    for reader in ["fromBinary", "fromHex", "fromReader"] {
        let (input, answer) = cell_53(reader, name);
        let bytes = from_hex(&input).unwrap();
        let mut reader_bytes = Reader::new(&bytes);
        let got = match reader {
            "fromBinary" => Transaction::from_binary(&bytes),
            "fromHex" => Transaction::from_hex(&input),
            _ => Transaction::from_reader(&mut reader_bytes),
        };
        if reference_refuses {
            assert_refused(reader, name, got, &answer);
            assert_eq!(
                answer["error"], "Number can only safely store up to 53 bits",
                "{reader} {name}"
            );
            continue;
        }
        assert_eq!(answer["ok"], true, "{reader} {name}");
        let tx = got.unwrap_or_else(|e| panic!("{reader} {name}: {e}"));
        assert_eq!(tx.outputs[0].satoshis, Some(amount), "{reader} {name}");
        assert_eq!(tx.id(), id_of(&bytes), "{reader} {name}");
        assert_eq!(tx.id(), answer["id"].as_str().unwrap(), "{reader} {name}");
        assert_eq!(tx.to_hex(), input, "{reader} {name}");
    }
}

#[test]
fn an_output_of_two_to_the_53_minus_1_satoshis_is_read_on_both_sides_840() {
    assert_amount_as_recorded("output_two_to_the_53_minus_1", (1 << 53) - 1, false);
}

#[test]
fn an_output_of_two_to_the_53_satoshis_is_refused_as_the_reference_refuses_840() {
    assert_amount_as_recorded("output_two_to_the_53", 1 << 53, true);
}

#[test]
fn an_output_of_two_to_the_64_minus_1_satoshis_is_refused_as_the_reference_refuses_840() {
    assert_amount_as_recorded("output_two_to_the_64_minus_1", u64::MAX, true);
}

#[test]
fn an_ef_source_of_two_to_the_53_satoshis_is_refused_as_the_reference_refuses_840() {
    let (input, answer) = cell_53("fromEF", "source_two_to_the_53");
    assert_eq!(
        answer["error"],
        "Number can only safely store up to 53 bits"
    );
    assert_refused(
        "fromEF",
        "source_two_to_the_53",
        Transaction::from_ef(&from_hex(&input).unwrap()),
        &answer,
    );
}

#[test]
fn the_reference_writer_refuses_an_amount_of_two_to_the_53_for_844_840() {
    // For #844's lane: the reference's `toBinary` of a transaction built with
    // such a number throws in `BigNumber`'s constructor words
    // (`BigNumber.ts:462`, through `writeUInt64LE`, `Transaction.ts:1083`).
    let v = vector();
    for name in ["two_to_the_53", "two_to_the_64"] {
        let answer = &v["writer_53"][name];
        assert_eq!(answer["ok"], false, "{name}");
        assert_eq!(
            answer["error"], "The number is larger than 2 ^ 53 (unsafe)",
            "{name}"
        );
    }
    let v53 = v["cells_53"].as_array().unwrap();
    assert_eq!(v53.len(), 10);
    assert_eq!(v53.iter().filter(|c| c["answer"]["ok"] == false).count(), 7);
}
