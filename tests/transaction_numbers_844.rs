//! #844 and the reader half of #845: every wire number a transaction reader
//! reads, at its edge, against the reference's answer
//! (`vectors/transaction_numbers_844.json`, `support/transaction_numbers_844.mjs`,
//! `ts-stack@edf6e03` under Node v22.18.0, two runs byte-identical).
//!
//! The reference reads an amount through `readUInt64LEBn().toNumber()`
//! (`Transaction.ts:388,409,497`) and refuses one of 2^53 or more in `Number
//! can only safely store up to 53 bits` (`BigNumber.ts:628`); since #844 so do
//! `from_binary`, `from_hex`, `from_reader`, `from_ef` and `from_hex_ef`
//! (`src/transaction/amount.rs`). `parseScriptOffsets` skips the eight bytes
//! unread (`Transaction.ts:456`), and so does `parse_script_offsets`.
//!
//! The sweep (`every_recorded_transaction_cell_is_this_crates_verdict_844`) is
//! the class's machine: 156 cells, one field of block 170's transaction (or
//! its EF form) at an edge per cell, each door's verdict the reference's, the
//! words the reference's save the enumerated `STATED_WORDS` (a varint in a
//! longer form than its value needs, or at 2^53 and 2^64 - 1: refused on both
//! sides, this crate's reader in its own words, the canonical-varint row of
//! 0.6.0), each entry failing when it stops being true.
//!
//! The BEEF doors: the reference's BEEF reader scans a raw transaction
//! without its amounts (`BeefTx.ts:16-48`), so `Beef.fromBinary`,
//! `fromBinaryStrict`, `verifyValid`, `isValid`, `mergeRawTx` and `mergeBeef`
//! take a transaction with a 2^53 output that its `Transaction.fromBEEF`,
//! `fromAtomicBEEF` and the entry's `tx` getter refuse. This crate's BEEF
//! readers parse every entry in full (the 0.4.1-0.4.3 rows: the structural
//! verdict is a full parse's), so the stream and `Beef::from_binary` refuse
//! it, at the same offset and kind (`ValueOutOfRange`, the node's
//! `MoneyRange`, which 2^53 is past), and the raw-entry scan refuses it in the
//! reader's words: stated rows.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use bsv_rs::primitives::bsv::sighash::parse_transaction;
use bsv_rs::primitives::{from_hex, Reader};
use bsv_rs::script::Script;
use bsv_rs::transaction::{
    verify_stream_structure, Beef, BeefStream, BeefTx, Element, Kind, MerklePath, Transaction,
    TransactionOutput, Verdict, BEEF_V1, BEEF_V2,
};
use bsv_rs::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/transaction_numbers_844.json");
const TRAILING_840: &str = include_str!("vectors/transaction_trailing_data_840.json");
const UNSAFE: &str = "Number can only safely store up to 53 bits";

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("the vector parses")
}

/// The fields whose cells refuse on both sides in other words: a varint in a
/// longer form than its value needs (`non-canonical varInt` there,
/// `NonCanonicalVarInt` here), and a count or length of 2^53 or 2^64 - 1
/// (`number too large to retain precision - use readVarIntBn` there; here the
/// value is read and the bytes it names are not there).
const VARINT_FIELDS: [&str; 3] = ["input_count", "input_script_len", "output_count"];
const VARINT_EDGES: [&str; 5] = [
    "fd_form",
    "fe_form",
    "ff_form_below_2_32",
    "ff_form_two_to_the_53",
    "ff_form_two_to_the_64_minus_1",
];

/// Whether a cell is one of the stated word differences.
fn stated_words(field: &str, edge: &str) -> bool {
    VARINT_FIELDS.contains(&field) && VARINT_EDGES.contains(&edge)
}

/// This crate's answer at `reader` for `input`, as the recorder writes one.
fn answer_here(reader: &str, input: &str) -> Result<Value, Error> {
    let bytes = from_hex(input).unwrap();
    let tx_answer =
        |t: Transaction| serde_json::json!({ "ok": true, "id": t.id(), "to_hex": t.to_hex() });
    match reader {
        "fromBinary" => Transaction::from_binary(&bytes).map(tx_answer),
        "fromHex" => Transaction::from_hex(input).map(tx_answer),
        "fromEF" => Transaction::from_ef(&bytes).map(tx_answer),
        "fromHexEF" => Transaction::from_hex_ef(input).map(tx_answer),
        "fromReader" => {
            let mut r = Reader::new(&bytes);
            let t = Transaction::from_reader(&mut r)?;
            let mut a = tx_answer(t);
            a["remaining"] = r.remaining().into();
            Ok(a)
        }
        "parseScriptOffsets" => Transaction::parse_script_offsets(&bytes).map(|o| {
            let pairs = |list: &[bsv_rs::transaction::ScriptOffset]| -> Value {
                list.iter()
                    .map(|x| serde_json::json!([x.offset, x.length]))
                    .collect()
            };
            serde_json::json!({ "ok": true, "inputs": pairs(&o.inputs), "outputs": pairs(&o.outputs) })
        }),
        other => panic!("no reader {other}"),
    }
}

#[test]
fn every_recorded_transaction_cell_is_this_crates_verdict_844() {
    let v = vector();
    let cells = v["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 156);
    let (mut agreed, mut stated) = (0, 0);
    for c in cells {
        let (reader, field, edge) = (
            c["reader"].as_str().unwrap(),
            c["field"].as_str().unwrap(),
            c["edge"].as_str().unwrap(),
        );
        let recorded = &c["answer"];
        let here = answer_here(reader, c["input"].as_str().unwrap());
        let at = format!("{reader} {field} {edge}");
        if recorded["ok"] == true {
            assert_eq!(
                &here.unwrap_or_else(|e| panic!("{at}: {e}")),
                recorded,
                "{at}"
            );
            agreed += 1;
            continue;
        }
        let words = recorded["error"].as_str().unwrap();
        let err = here.expect_err(&at);
        if stated_words(field, edge) {
            // Stated: refused on both, in other words. Fails when the words
            // become the reference's (the entry then leaves the list).
            assert_ne!(err.to_string(), words, "{at}: no longer a stated cell");
            assert_ne!(err, Error::TransactionError(words.to_string()), "{at}");
            stated += 1;
        } else {
            assert_eq!(err, Error::TransactionError(words.to_string()), "{at}");
            agreed += 1;
        }
    }
    // 4 readers x 15 varint cells stated; every other cell agrees, words too.
    assert_eq!((agreed, stated), (96, 60));
}

#[test]
fn an_output_of_two_to_the_53_satoshis_is_refused_844() {
    let v = vector();
    let mut seen = 0;
    for c in v["cells"].as_array().unwrap() {
        if c["field"] != "output_value" || c["edge"] == "two_to_the_53_minus_1" {
            continue;
        }
        let reader = c["reader"].as_str().unwrap();
        let input = c["input"].as_str().unwrap();
        if reader == "parseScriptOffsets" {
            // The reference skips the eight bytes unread (`Transaction.ts:456`).
            assert_eq!(c["answer"]["ok"], true);
            assert!(answer_here(reader, input).is_ok());
            continue;
        }
        assert_eq!(c["answer"]["error"], UNSAFE, "{reader}");
        assert_eq!(
            answer_here(reader, input).unwrap_err(),
            Error::TransactionError(UNSAFE.into()),
            "{reader} {}",
            c["edge"]
        );
        seen += 1;
    }
    // fromBinary, fromHex, fromReader, fromEF, fromHexEF at 2^53, 2^63, 2^64 - 1.
    assert_eq!(seen, 15);
}

#[test]
fn an_ef_source_of_two_to_the_53_satoshis_is_refused_844() {
    let v = vector();
    for c in v["cells"].as_array().unwrap() {
        if c["field"] != "source_value" {
            continue;
        }
        let reader = c["reader"].as_str().unwrap();
        let here = answer_here(reader, c["input"].as_str().unwrap());
        if c["edge"] == "two_to_the_53_minus_1" {
            assert_eq!(&here.unwrap(), &c["answer"], "{reader}");
            let tx = Transaction::from_hex_ef(c["input"].as_str().unwrap()).unwrap();
            assert_eq!(tx.inputs[0].source_satoshis(), Some((1 << 53) - 1));
        } else {
            assert_eq!(here.unwrap_err(), Error::TransactionError(UNSAFE.into()));
        }
    }
}

#[test]
fn script_offsets_skip_the_amount_unread_as_the_reference_does_844() {
    let v = vector();
    let c = v["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["reader"] == "parseScriptOffsets"
                && c["field"] == "output_value"
                && c["edge"] == "two_to_the_64_minus_1"
        })
        .unwrap();
    assert_eq!(
        answer_here("parseScriptOffsets", c["input"].as_str().unwrap()).unwrap(),
        c["answer"]
    );
}

/// The root the leading BUMP at each height carries, as the stream reads them.
fn leading_roots(bytes: &[u8]) -> HashMap<u64, [u8; 32]> {
    let mut roots = HashMap::new();
    for element in BeefStream::new(bytes) {
        match element {
            Ok(Element::Bump(bump)) => {
                roots.entry(bump.block_height).or_insert(bump.root);
            }
            _ => break,
        }
    }
    roots
}

/// The stream's refusal: offset and kind.
fn stream_refusal(bytes: &[u8]) -> (u64, Kind) {
    match verify_stream_structure(bytes, leading_roots(bytes), None).unwrap() {
        Verdict::Invalid { offset, kind, .. } => (offset, kind),
        other => panic!("the stream accepted: {other:?}"),
    }
}

fn beef_cell(edge: &str) -> Value {
    vector()["beef_cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["edge"] == edge)
        .unwrap()
        .clone()
}

/// Block 170's transaction with its output 0 at 2^53, and that output's
/// offset in the bytes.
fn raw_53() -> (Vec<u8>, usize) {
    let raw = from_hex(beef_cell("two_to_the_53")["raw"].as_str().unwrap()).unwrap();
    (raw, 119)
}

#[test]
fn a_beef_whose_transaction_carries_such_an_output_is_refused_by_both_readers_844() {
    let c = beef_cell("two_to_the_53");
    let a = &c["answers"];
    // The reference's BEEF reader takes the bytes; its transaction doors refuse.
    for door in ["Beef.fromBinary", "Beef.fromBinaryStrict"] {
        assert_eq!(a[door]["ok"], true, "{door}");
    }
    assert_eq!(a["Beef.verifyValid"]["valid"], true);
    assert_eq!(a["Beef.isValid"]["valid"], true);
    for door in [
        "BeefTx.tx",
        "Transaction.fromBEEF",
        "Transaction.fromAtomicBEEF",
    ] {
        assert_eq!(a[door]["error"], UNSAFE, "{door}");
    }
    let beef = from_hex(c["beef"].as_str().unwrap()).unwrap();
    let atomic = from_hex(c["atomic"]["hex"].as_str().unwrap()).unwrap();
    for bytes in [&beef, &atomic] {
        // The stream refuses at the output's value (`ValueOutOfRange`: past
        // `MAX_MONEY`), and the whole reader at the same offset and kind.
        let (offset, kind) = stream_refusal(bytes);
        assert_eq!(kind, Kind::ValueOutOfRange);
        let whole = Beef::from_binary(bytes).unwrap_err().to_string();
        assert!(
            whole.contains(&format!("invalid BEEF at byte {offset}: ValueOutOfRange")),
            "{whole}"
        );
    }
    assert!(Transaction::from_beef(&beef, None).is_err());
    assert!(Transaction::from_atomic_beef(&atomic).is_err());
    // The 2^53 - 1 control: read by both whole readers, judged by the node's
    // rule in `verify_structure` and the stream alike (`MoneyRange`).
    let c = beef_cell("two_to_the_53_minus_1");
    assert_eq!(c["answers"]["Beef.verifyValid"]["valid"], true);
    let bytes = from_hex(c["beef"].as_str().unwrap()).unwrap();
    let mut held = Beef::from_binary(&bytes).unwrap();
    assert_eq!(held.verify_structure(), Err(Kind::ValueOutOfRange));
    assert_eq!(stream_refusal(&bytes).1, Kind::ValueOutOfRange);
    assert_eq!(
        Transaction::from_beef(&bytes, None).unwrap().id(),
        c["answers"]["Transaction.fromBEEF"]["id"].as_str().unwrap()
    );
}

#[test]
fn every_entry_shape_carrying_such_an_output_is_refused_by_both_readers_844() {
    let (raw, at) = raw_53();
    // V1 and V2 raw entries, with and without a BUMP index, and a child of
    // it: each built by this crate's writer from bytes at a safe amount,
    // then the eight bytes set to 2^53, so no door is asked to hold it.
    let mut safe = raw.clone();
    safe[at..at + 8].copy_from_slice(&1u64.to_le_bytes());
    let parent = Transaction::from_binary(&safe).unwrap();
    for version in [BEEF_V1, BEEF_V2] {
        for proven in [false, true] {
            let mut beef = Beef::with_version(version);
            let index =
                proven.then(|| beef.merge_bump(MerklePath::from_coinbase_txid(&parent.id(), 170)));
            beef.merge_raw_tx(safe.clone(), index).unwrap();
            let mut bytes = beef.to_binary().unwrap();
            let start = bytes
                .windows(safe.len())
                .position(|w| w == safe.as_slice())
                .unwrap();
            bytes[start + at..start + at + 8].copy_from_slice(&(1u64 << 53).to_le_bytes());
            let (offset, kind) = stream_refusal(&bytes);
            assert_eq!(
                (offset, kind),
                ((start + at) as u64, Kind::ValueOutOfRange),
                "v{version:x} proven {proven}"
            );
            let whole = Beef::from_binary(&bytes).unwrap_err().to_string();
            assert!(
                whole.contains(&format!("invalid BEEF at byte {offset}: ValueOutOfRange")),
                "{whole}"
            );
            let mut reader = Reader::new(&bytes);
            assert!(Beef::from_reader(&mut reader).is_err());
        }
    }
}

#[test]
fn the_raw_entry_doors_refuse_such_an_output_in_the_readers_words_stated_844() {
    let (raw, _) = raw_53();
    let c = beef_cell("two_to_the_53");
    // Stated: the reference's `mergeRawTx` and `mergeBeef` take it.
    assert_eq!(c["answers"]["Beef.mergeRawTx"]["ok"], true);
    assert_eq!(c["answers"]["Beef.mergeBeef"]["ok"], true);
    let mut beef = Beef::new();
    assert_eq!(
        beef.merge_raw_tx(raw.clone(), None).unwrap_err(),
        Error::BeefError(UNSAFE.into())
    );
    assert!(beef.txs.is_empty(), "the BEEF untouched");
    assert_eq!(
        BeefTx::from_raw_tx(raw.clone(), Some(0)).unwrap_err(),
        Error::BeefError(UNSAFE.into())
    );
    // An entry read by `BeefTx::from_reader` is a transaction reader's.
    let mut entry = vec![0u8];
    entry.extend_from_slice(&raw);
    assert_eq!(
        BeefTx::from_reader(&mut Reader::new(&entry), BEEF_V2).unwrap_err(),
        Error::TransactionError(UNSAFE.into())
    );
    // A source holding such a transaction by hand: `merge_beef` refuses it,
    // the target untouched, in the reference's writer's words since #844's
    // fold (its snapshot's `toBinary` throws them; the scan's until then).
    // The reference refuses earlier, at `mergeTransaction` itself (recorded,
    // `writer_cells`), where this crate's `merge_transaction` holds the entry
    // (its signature has no `Result`: stated, the writers refusing it).
    let tx = by_hand_53();
    let mut source = Beef::new();
    source.merge_transaction(tx);
    let mut target = Beef::new();
    assert_eq!(
        target.merge_beef(&source).unwrap_err(),
        Error::BeefError(UNSAFE_WRITE.into())
    );
    assert!(target.txs.is_empty());
    assert_eq!(
        source.to_binary().unwrap_err(),
        Error::BeefError(UNSAFE_WRITE.into()),
        "the writer's check refuses it too"
    );
}

/// The reference's writer's words (`BigNumber.ts:462`), recorded.
const UNSAFE_WRITE: &str = "The number is larger than 2 ^ 53 (unsafe)";

/// The recorder's three-output transaction: block 170's with a copy of its
/// last output appended, read here, its output `position` set to `value`
/// through the public field, as the recorder sets the reference's.
fn three_outputs(position: usize, value: u64) -> Transaction {
    let mut tx = three_outputs_unchanged();
    tx.outputs[position].satoshis = Some(value);
    // Fresh, so no cached bytes stand for the edited fields.
    Transaction::with_params(
        tx.version,
        tx.inputs.clone(),
        tx.outputs.clone(),
        tx.lock_time,
    )
}

/// Block 170's transaction with a copy of its last output appended.
fn three_outputs_unchanged() -> Transaction {
    let mut tx = Transaction::from_hex(TX_170).unwrap();
    let last = tx.outputs[1].clone();
    tx.outputs.push(last);
    Transaction::with_params(
        tx.version,
        tx.inputs.clone(),
        tx.outputs.clone(),
        tx.lock_time,
    )
}

/// The BEEF the recorder edits in place: the three-output transaction
/// proven by a one-leaf BUMP of its txid at 170, this crate's writer.
fn three_outputs_beef() -> (Beef, String) {
    let tx = three_outputs_unchanged();
    let txid = tx.id();
    let mut beef = Beef::new();
    beef.merge_bump(MerklePath::from_coinbase_txid(&txid, 170));
    beef.merge_raw_tx(tx.to_binary(), Some(0)).unwrap();
    let bytes = beef.to_binary().unwrap();
    (Beef::from_binary(&bytes).unwrap(), txid)
}

/// This crate's answer at one recorded door: `Ok` with the bytes written
/// (hex) or the entries held, else the error.
fn writer_door_here(door: &str, position: usize, value: u64, txid: &str) -> Result<Value, Error> {
    let tx = three_outputs(position, value);
    let pushed = |tx: Transaction| {
        let mut b = Beef::new();
        b.txs.push(BeefTx::from_tx(tx, None));
        b
    };
    let hex_of = |bytes: Vec<u8>| serde_json::json!({ "hex": bsv_rs::primitives::to_hex(&bytes) });
    Ok(match door {
        "Transaction.toBinary" => hex_of(tx.to_binary()),
        // The reference's `toBEEF` writes BRC-62's V1 (`Transaction.ts:1933`);
        // this crate's V1 writer is `to_beef_v1`.
        "Transaction.toBEEF" => hex_of(tx.to_beef_v1(true)?),
        // Its `toAtomicBEEF` writes a V1 body where `to_atomic_beef` writes
        // V2 through the closure (older than #844, the #798 entry's row):
        // the verdict and the words compared, not the bytes.
        "Transaction.toAtomicBEEF" => {
            tx.to_atomic_beef(true)?;
            serde_json::json!({})
        }
        "Beef.mergeTransaction" => {
            let mut b = Beef::new();
            b.merge_transaction(tx);
            serde_json::json!({ "txs": b.txs.len() })
        }
        "Beef.toBinary (pushed)" => hex_of(pushed(tx).to_binary()?),
        "Beef.toHex (pushed)" => serde_json::json!({ "hex": pushed(tx).to_hex()? }),
        "Beef.toBinaryAtomic (pushed)" => hex_of(pushed(tx).to_binary_atomic(txid)?),
        "BeefTx.toWriter (pushed)" => {
            let mut w = bsv_rs::primitives::Writer::new();
            BeefTx::from_tx(tx, None).to_writer(&mut w, BEEF_V2)?;
            hex_of(w.into_bytes())
        }
        "Beef.mergeBeef (pushed)" => {
            let source = pushed(tx);
            let mut target = Beef::new();
            let answer = target.merge_beef(&source);
            if answer.is_err() {
                assert!(target.txs.is_empty(), "the target untouched on Err");
            }
            answer?;
            serde_json::json!({ "txs": target.txs.len() })
        }
        "Beef.toBinary (edited in place)" => {
            let (mut beef, held) = three_outputs_beef();
            beef.edit_tx(&held, |t| t.outputs[position].satoshis = Some(value))?;
            hex_of(beef.to_binary()?)
        }
        other => panic!("a door this test does not know: {other}"),
    })
}

/// The cells where this crate answers otherwise than the reference, each
/// stated: the plain transaction writer writes such an amount (#843's
/// break), and `merge_transaction` holds the entry, its signature without a
/// `Result` (the writers refuse it after).
const WRITER_STATED: [&str; 2] = ["Transaction.toBinary", "Beef.mergeTransaction"];

#[test]
fn the_writers_refuse_such_an_output_in_the_reference_writers_words_in_any_output_844() {
    // Every recorded writer door, with the amount in the first, the middle
    // and the last of three outputs: the reference's verdict, its words on
    // a refusal and its bytes on a write, save the two stated cells.
    let v = vector();
    let cells = v["writer_cells"].as_array().unwrap();
    assert_eq!(cells.len(), 6, "two edges by three positions");
    let mut differing = Vec::new();
    for c in cells {
        let edge = c["edge"].as_str().unwrap();
        let position = c["position"].as_u64().unwrap() as usize;
        let value: u64 = if edge == "two_to_the_53" {
            1 << 53
        } else {
            (1 << 53) - 1
        };
        let txid = c["txid"].as_str().unwrap();
        assert_eq!(
            three_outputs(position, value).id(),
            txid,
            "the recorded txid"
        );
        for (door, there) in c["answers"].as_object().unwrap() {
            let here = writer_door_here(door, position, value, txid);
            let stated = edge == "two_to_the_53" && WRITER_STATED.contains(&door.as_str());
            let agrees = match (&here, there["ok"].as_bool().unwrap()) {
                (Ok(answer), true) => answer
                    .as_object()
                    .unwrap()
                    .iter()
                    .all(|(k, val)| &there[k] == val),
                (Err(Error::BeefError(words)), false) => there["error"] == words.as_str(),
                _ => false,
            };
            if stated {
                assert!(
                    !agrees,
                    "{edge} {position} {door}: a stated cell now agrees"
                );
                assert_eq!(there["error"], UNSAFE_WRITE, "{door}");
            } else if !agrees {
                differing.push(format!(
                    "{edge} {position} {door}: here {here:?}, there {there}"
                ));
            }
        }
    }
    assert!(differing.is_empty(), "{differing:#?}");
}

#[test]
fn a_hand_pushed_entry_with_such_an_output_is_refused_by_every_writer_and_merged_as_the_round_trip_844(
) {
    // `fuzz_beef_parser`'s state, through public calls alone: a transaction
    // built by hand with the amount in a later output, pushed into `txs`
    // without being hashed. Every writer refuses it in the reference's
    // writer's words, and `merge_beef` answers what writing the source and
    // reading it back answers (the reference's `mergeBeef`,
    // `fromBinaryStrict(beef.toBinary())`), the target untouched.
    for position in [0, 1, 2] {
        // A BEEF read from bytes (so `merge_beef` takes its entries in the
        // order read and hashes none), then the entry pushed by hand.
        let source = || {
            let (mut b, _) = three_outputs_beef();
            b.txs
                .push(BeefTx::from_tx(three_outputs(position, 1 << 53), None));
            b
        };
        let refused = Error::BeefError(UNSAFE_WRITE.into());
        let txid = three_outputs(position, 1 << 53).id();
        // First, on a source no writer has touched (no cached bytes): the
        // fuzzer's state, where the pre-pass once passed what the round trip
        // refused.
        let mut target = Beef::new();
        let merged = target.merge_beef(&source());
        let round_trip = match source().to_binary() {
            Ok(bytes) => Beef::from_binary(&bytes).map(|_| ()),
            Err(e) => Err(e),
        };
        assert_eq!(merged, round_trip, "merge_beef {position}");
        assert!(target.txs.is_empty(), "the target untouched");
        assert!(round_trip.is_err());
        assert_eq!(
            source().to_binary().unwrap_err(),
            refused,
            "to_binary {position}"
        );
        assert_eq!(source().to_hex().unwrap_err(), refused, "to_hex {position}");
        let mut w = bsv_rs::primitives::Writer::new();
        assert_eq!(
            source().to_writer(&mut w).unwrap_err(),
            refused,
            "to_writer {position}"
        );
        assert!(w.into_bytes().is_empty(), "the writer untouched");
        assert_eq!(
            source().to_binary_atomic(&txid).unwrap_err(),
            refused,
            "to_binary_atomic {position}"
        );
        // Before the subject is looked for, as the reference synchronizes
        // every entry before `#getBeefForAtomic`.
        assert_eq!(
            source().to_binary_atomic(&"00".repeat(32)).unwrap_err(),
            refused,
            "to_binary_atomic of an absent txid {position}"
        );
        let mut w = bsv_rs::primitives::Writer::new();
        assert_eq!(
            source()
                .txs
                .last()
                .unwrap()
                .to_writer(&mut w, BEEF_V1)
                .unwrap_err(),
            refused,
            "BeefTx::to_writer {position}"
        );
    }
}

const TX_170: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

/// Block 170's transaction rebuilt from its fields with its output 0 at
/// 2^53 (fresh, so no cached bytes stand for the edited fields).
fn by_hand_53() -> Transaction {
    let read = Transaction::from_hex(TX_170).unwrap();
    let mut outputs = read.outputs.clone();
    outputs[0] = TransactionOutput::new(1 << 53, outputs[0].locking_script.clone());
    Transaction::with_params(read.version, read.inputs.clone(), outputs, read.lock_time)
}

#[test]
fn this_crates_writer_writes_an_amount_its_readers_refuse_stated_844() {
    // The writer's half is #843's break: a `Transaction` built by hand holds
    // the amount and `to_binary` writes it, where the reference's writer
    // refuses it before any byte (`BigNumber.ts:462`, recorded by #840).
    let v: Value = serde_json::from_str(TRAILING_840).unwrap();
    assert_eq!(
        v["writer_53"]["two_to_the_53"]["error"],
        "The number is larger than 2 ^ 53 (unsafe)"
    );
    let tx = by_hand_53();
    let bytes = tx.to_binary();
    assert_eq!(
        Transaction::from_binary(&bytes).unwrap_err(),
        Error::TransactionError(UNSAFE.into())
    );
    assert!(Transaction::from_hex(&tx.to_hex()).is_err());
    // Its JSON carries `hex`, so `from_json` refuses its own writer's text.
    assert_eq!(
        Transaction::from_json(&tx.to_json().unwrap()).unwrap_err(),
        Error::TransactionError(UNSAFE.into())
    );
}

#[test]
fn the_sighash_parser_reads_such_an_amount_stated_844() {
    // A prefix reader of this crate's (no reference twin), handed a
    // transaction's own bytes by the signers: it reads the `u64`, so a
    // signer handed a hand-built transaction with such an output signs it.
    let (raw, _) = raw_53();
    assert_eq!(
        parse_transaction(&raw).unwrap().outputs[0].satoshis,
        1 << 53
    );
}

#[test]
fn a_json_hex_with_such_an_output_is_refused_844() {
    let (raw, _) = raw_53();
    let json = format!(r#"{{"hex":"{}"}}"#, bsv_rs::primitives::to_hex(&raw));
    assert_eq!(
        Transaction::from_json(&json).unwrap_err(),
        Error::TransactionError(UNSAFE.into())
    );
}

#[test]
fn the_json_fields_carry_an_amount_the_readers_refuse_stated_844() {
    // A document with no `hex` reads `satoshis` as a `u64` (Go's twin a
    // `uint64`, `txjson.go:28-31`): stated, a cell for the captain.
    let json = r#"{"inputs":[],"outputs":[{"satoshis":9007199254740992,"lockingScript":"51"}],"version":1,"lockTime":0}"#;
    let tx = Transaction::from_json(json).unwrap();
    assert_eq!(tx.outputs[0].satoshis, Some(1 << 53));
    assert!(Transaction::from_binary(&tx.to_binary()).is_err());
}

/// A field-built document with one input per `txids`.
fn json_with_txids(txids: &[&str]) -> String {
    let inputs: Vec<String> = txids
        .iter()
        .map(|t| format!(r#"{{"unlockingScript":"","txid":"{t}","vout":0,"sequence":4294967295}}"#))
        .collect();
    format!(
        r#"{{"inputs":[{}],"outputs":[{{"satoshis":1,"lockingScript":"51"}}],"version":1,"lockTime":0}}"#,
        inputs.join(",")
    )
}

const GOOD: &str = "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5";

#[test]
fn a_json_input_txid_that_is_not_64_hex_digits_is_refused_845() {
    let sixty_three = &GOOD[..63];
    let sixty_five = format!("{GOOD}0");
    let non_hex = format!("{}g", &GOOD[..63]);
    let spaced = format!(" {}", &GOOD[..63]);
    for bad in [
        "zz",
        "abcd",
        "",
        sixty_three,
        &sixty_five,
        &non_hex,
        &spaced,
    ] {
        let err = Transaction::from_json(&json_with_txids(&[GOOD, bad])).unwrap_err();
        assert_eq!(
            err,
            Error::TransactionError("Invalid txid of input 1: expected 64 hex digits".into()),
            "{bad:?}"
        );
        if !bad.is_empty() {
            assert!(!err.to_string().contains(bad), "the text is not echoed");
        }
    }
    // The captain's three documents were one transaction; each is refused.
    for bad in ["zz", "abcd", ""] {
        assert!(Transaction::from_json(&json_with_txids(&[bad])).is_err());
    }
}

#[test]
fn a_json_input_txid_in_upper_case_is_held_in_lower_case_845() {
    let lower = Transaction::from_json(&json_with_txids(&[GOOD])).unwrap();
    let mixed: String = GOOD
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    for text in [GOOD.to_uppercase(), mixed] {
        let tx = Transaction::from_json(&json_with_txids(&[&text])).unwrap();
        assert_eq!(tx.inputs[0].source_txid.as_deref(), Some(GOOD));
        assert_eq!(tx.id(), lower.id());
        assert_eq!(tx.to_binary(), lower.to_binary());
        let json: Value = serde_json::from_str(&tx.to_json().unwrap()).unwrap();
        assert_eq!(json["inputs"][0]["txid"], GOOD);
    }
}

#[test]
fn a_json_txid_member_beside_its_hex_is_unread_stated_845() {
    // The top-level `txid` member is not read: with `hex` the transaction is
    // the hex's whatever the member says (Go's `UnmarshalJSON` the same,
    // `txjson.go:49-66`). Reported, not changed here.
    let json = format!(r#"{{"txid":"{}","hex":"{TX_170}"}}"#, "00".repeat(32));
    let tx = Transaction::from_json(&json).unwrap();
    assert_eq!(
        tx.id(),
        "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    );
}

fn bump_cell(edge: &str) -> Value {
    vector()["bump_cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["edge"] == edge)
        .unwrap()
        .clone()
}

#[test]
fn the_bump_numbers_at_their_edges_844() {
    // A block height of 2^32 - 1 read on both sides.
    let c = bump_cell("height_two_to_the_32_minus_1");
    let path = MerklePath::from_hex(c["input"].as_str().unwrap()).unwrap();
    assert_eq!(
        u64::from(path.block_height),
        c["answer"]["height"].as_u64().unwrap()
    );
    // 2^32: read there, refused here (#167's stated row: the height is a `u32`).
    let c = bump_cell("height_two_to_the_32");
    assert_eq!(c["answer"]["ok"], true);
    let err = MerklePath::from_hex(c["input"].as_str().unwrap()).unwrap_err();
    assert!(err.to_string().contains("RootNotCarried"), "{err}");
    // 2^53: refused on both, in other words.
    let c = bump_cell("height_two_to_the_53");
    assert_eq!(
        c["answer"]["error"],
        "number too large to retain precision - use readVarIntBn"
    );
    assert!(MerklePath::from_hex(c["input"].as_str().unwrap()).is_err());
    // A 54-level path, its txid at offset 2^53 - 1: the same root on both.
    let c = bump_cell("offset_two_to_the_53_minus_1");
    let path = MerklePath::from_hex(c["input"].as_str().unwrap()).unwrap();
    let txid = "ab".repeat(32);
    assert_eq!(
        path.compute_root(Some(&txid)).unwrap(),
        c["answer"]["root"].as_str().unwrap()
    );
}

#[test]
fn a_bump_leaf_offset_of_two_to_the_53_is_read_where_the_reference_refuses_stated_844() {
    // Not conformed (two defensible answers, reported): BRC-74 carries an
    // offset as a varint to 2^64 - 1 and this crate holds BRC-74's 64 levels,
    // where the reference's `readVarIntNumStrict` refuses an offset past
    // 2^53 - 1 (`MerklePath.ts:125`).
    let c = bump_cell("offset_two_to_the_53");
    assert_eq!(
        c["answer"]["error"],
        "number too large to retain precision - use readVarIntBn"
    );
    let path = MerklePath::from_hex(c["input"].as_str().unwrap()).unwrap();
    assert_eq!(path.path.len(), 54);
    assert!(path.compute_root(Some(&"ab".repeat(32))).is_ok());
}

#[test]
fn a_script_push_length_at_its_32_bit_edge_844() {
    // A push length is a `u32` on both sides (`Script.ts:590-596`): no
    // number edge past its field; a truncated push at that edge held as one
    // chunk and written back as read on both.
    for c in vector()["script_cells"].as_array().unwrap() {
        assert_eq!(c["answer"]["ok"], true);
        let here = Script::from_hex(c["input"].as_str().unwrap()).unwrap();
        assert_eq!(here.to_hex(), c["answer"]["to_hex"], "{}", c["edge"]);
        assert_eq!(
            here.chunks().len() as u64,
            c["answer"]["chunks"].as_u64().unwrap(),
            "{}",
            c["edge"]
        );
    }
}
