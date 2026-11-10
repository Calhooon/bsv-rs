#![cfg(test)]
//! The framing scan against this crate's transaction reader and the
//! reference's recorded words (#817; `tests/vectors/beef_v1_txid_only_writer_817.json`,
//! `raw_door`).
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use super::*;
use crate::primitives::{from_hex, Reader};
use crate::transaction::Transaction;

const VECTOR: &str = include_str!("../../tests/vectors/beef_v1_txid_only_writer_817.json");

fn child_raw() -> Vec<u8> {
    let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    from_hex(v["child_raw"].as_str().unwrap()).unwrap()
}

/// This crate's reader takes `bytes` whole as one transaction.
fn parses_whole(bytes: &[u8]) -> bool {
    let mut reader = Reader::new(bytes);
    Transaction::from_reader_internal(&mut reader).is_ok() && reader.remaining() == 0
}

#[test]
fn a_frame_the_scan_accepts_is_the_one_the_parser_reads_817() {
    let raw = child_raw();
    let mut cases = vec![raw.clone(), Vec::new()];
    for cut in 0..raw.len() {
        cases.push(raw[..cut].to_vec());
    }
    for at in 0..raw.len() {
        for byte in [0x00, 0x01, 0xfc, 0xfd, 0xfe, 0xff] {
            let mut changed = raw.clone();
            changed[at] = byte;
            cases.push(changed);
        }
    }
    let mut longer = raw.clone();
    longer.push(0);
    cases.push(longer);
    let mut agreed = 0;
    for bytes in &cases {
        assert_eq!(
            one_transaction(bytes).is_ok(),
            parses_whole(bytes),
            "the scan and the parser part on {}",
            crate::primitives::to_hex(bytes)
        );
        agreed += 1;
    }
    assert_eq!(agreed, 3 + 7 * raw.len(), "every case compared");
}

#[test]
fn each_refusal_is_the_reference_scans_words_where_it_refuses_817() {
    let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    let raw = child_raw();
    let raws = [
        ("empty", Vec::new()),
        ("truncated_version", from_hex("010000").unwrap()),
        ("truncated_in_input", raw[..10].to_vec()),
        ("truncated_lock_time", raw[..raw.len() - 1].to_vec()),
        ("non_canonical_input_count", {
            let mut b = raw[..4].to_vec();
            b.extend([0xfd, 0x01, 0x00]);
            b.extend(&raw[5..]);
            b
        }),
    ];
    for (name, bytes) in raws {
        let cell = v["raw_door"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name && c["bump_index"].is_null())
            .unwrap();
        assert_eq!(
            one_transaction(&bytes).unwrap_err(),
            cell["merge"]["thrown"].as_str().unwrap(),
            "{name}"
        );
    }
    let mut longer = raw.clone();
    longer.push(0);
    assert_eq!(
        one_transaction(&longer).unwrap_err(),
        "Serialized transaction has 1 bytes after its lock time",
        "ours: the reference's door keeps it (`trailing_byte` recorded ok)"
    );
    assert!(one_transaction(&raw).is_ok());
}

#[test]
fn the_varint_rules_are_read_strict_s_817() {
    // Version, then an input count in each form.
    let with_count = |count: &[u8]| {
        let mut b = vec![1, 0, 0, 0];
        b.extend(count);
        b
    };
    assert_eq!(
        one_transaction(&with_count(&[0xfd, 0xfc, 0x00])).unwrap_err(),
        NON_CANONICAL
    );
    assert_eq!(
        one_transaction(&with_count(&[0xfe, 0xff, 0xff, 0x00, 0x00])).unwrap_err(),
        NON_CANONICAL
    );
    assert_eq!(
        one_transaction(&with_count(&[0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0])).unwrap_err(),
        NON_CANONICAL
    );
    assert_eq!(
        one_transaction(&with_count(&[0xff, 0, 0, 0, 0, 0, 0, 0x20, 0])).unwrap_err(),
        TOO_LARGE
    );
    assert_eq!(
        one_transaction(&with_count(&[0xfd, 0xfd])).unwrap_err(),
        READ_EXCEEDS
    );
    assert_eq!(one_transaction(&with_count(&[])).unwrap_err(), READ_EXCEEDS);
    // Each side of each bound (#817's fold, the strength read's survivors
    // `:67`, `<` to `<=`, and `:70`, `>` to `>=`): the minimal long forms
    // `fd fd00`, `fe 00000100` and `ff 0000000001000000` read, and so is
    // 2^53 - 1, each count then cut inside its leading input, as the
    // reference's scan answers them (`readVarIntNumStrict`, a probe of the
    // bundle at `ts-stack@edf6e03` under Node v22.18.0): `ReaderUint8Array
    // read exceeds available data` on all four, 2^53 `TOO_LARGE` above.
    for count in [
        &[0xfd, 0xfd, 0x00][..],
        &[0xfe, 0x00, 0x00, 0x01, 0x00][..],
        &[0xff, 0, 0, 0, 0, 0x01, 0, 0, 0][..],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0][..],
    ] {
        assert_eq!(
            one_transaction(&with_count(count)).unwrap_err(),
            READ_EXCEEDS,
            "{count:02x?}"
        );
    }
    // A count read, its input cut inside the txid's 32 bytes.
    assert_eq!(
        one_transaction(&with_count(&[1, 0xaa])).unwrap_err(),
        READ_EXCEEDS
    );
    // An output script length past the bytes left.
    let mut b = with_count(&[0, 1]);
    b.extend([0; 8]);
    b.extend([0xfd, 0x00, 0x01]);
    assert_eq!(one_transaction(&b).unwrap_err(), EXCEEDS);
}

/// The writers' own scan of a raw entry held without its parse: no public
/// door holds such an entry since #817 (`from_raw_tx` scans first), so the
/// state is built through the crate-private constructor, refused by
/// `BeefTx::to_writer` and the BEEF writers with nothing written, and the
/// framed entry written.
#[test]
fn the_writers_refuse_a_raw_entry_held_unframed_which_no_door_holds_817() {
    use crate::primitives::Writer;
    use crate::transaction::{Beef, BeefTx, BEEF_V1, BEEF_V2};
    let mut longer = child_raw();
    longer.push(0);
    let words = "Serialized transaction has 1 bytes after its lock time";
    for version in [BEEF_V1, BEEF_V2] {
        // A BUMP index: held unparsed, so the writer scans it.
        let entry = BeefTx::from_framed_raw_tx(longer.clone(), Some(0));
        assert!(entry.tx().is_none(), "held without its parse");
        let mut writer = Writer::new();
        assert_eq!(
            entry.to_writer(&mut writer, version),
            Err(crate::Error::BeefError(words.to_string()))
        );
        assert!(writer.into_bytes().is_empty(), "nothing written");
        let mut beef = Beef::with_version(version);
        beef.txs.push(entry);
        assert_eq!(
            beef.to_binary(),
            Err(crate::Error::BeefError(words.to_string()))
        );
    }
    let framed = BeefTx::from_framed_raw_tx(child_raw(), Some(0));
    let mut writer = Writer::new();
    framed.to_writer(&mut writer, BEEF_V2).unwrap();
    assert_eq!(writer.into_bytes().len(), 2 + child_raw().len());
}
