//! #843, W1: the wallet's id and a transaction's id are one type.
//!
//! Until W1 the wallet held `TxId = [u8; 32]` in display order beside the
//! wire-order `Txid`, and `Outpoint::new(tx.hash(), 0)` type-checked and
//! named another transaction. Now `Outpoint` and every wallet type hold the
//! crate's one `Txid`: an outpoint built from a transaction, read from its
//! text, read from JSON and read from the wallet wire are equal, as a seeded
//! property over generated transactions. The `compile_fail` twins are the
//! doc tests of `wallet::Outpoint`.

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionOutput, Txid};
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::{
    CreateActionOptions, CreateActionResult, Outpoint, SendWithResult, SendWithResultStatus,
};

/// A transaction of the seed: its output count, amounts, version and lock
/// time all move with it, so each seed has an id of its own.
fn transaction(seed: u64) -> Transaction {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut tx = Transaction::new();
    tx.set_version((next() % 3) as u32);
    tx.set_lock_time((next() % 500_000) as u32);
    for _ in 0..=(next() % 4) {
        let script = LockingScript::from_binary(&[0x51 + (next() % 16) as u8]).unwrap();
        tx.add_output(TransactionOutput::new(next() % 1_000_000, script))
            .unwrap();
    }
    tx
}

fn reversed(text: &str) -> String {
    let mut bytes = hex::decode(text).unwrap();
    bytes.reverse();
    hex::encode(bytes)
}

#[test]
fn the_wallets_txid_is_the_crates_one_type_843w1() {
    fn same<T>(_: &T, _: &T) {}
    let tx = transaction(1);
    let wallet: bsv_rs::wallet::Txid = tx.txid();
    let root: bsv_rs::Txid = tx.txid();
    same(&wallet, &root);
    same(&wallet, &Outpoint::new(tx.txid(), 0).txid);
    assert_eq!(wallet, root);
}

#[test]
fn an_outpoint_from_a_transaction_from_text_from_json_and_from_the_wire_is_one_843w1() {
    let mut ids = std::collections::HashSet::new();
    for seed in 0..500u64 {
        let tx = transaction(seed);
        let vout = (seed * 31 % 7) as u32;
        let text = format!("{}.{vout}", tx.id());
        assert_ne!(reversed(&tx.id()), tx.id(), "an id that is its own reverse");
        ids.insert(tx.id());

        let built = Outpoint::new(tx.txid(), vout);
        let from_text = Outpoint::from_string(&text).unwrap();
        assert_eq!(from_text.txid, tx.txid(), "seed {seed}");
        assert_eq!(built.to_string(), text, "seed {seed}");
        assert_eq!(built, from_text);

        let from_json: Outpoint = serde_json::from_str(&format!("\"{text}\"")).unwrap();
        let from_object: Outpoint =
            serde_json::from_value(serde_json::json!({ "txid": tx.id(), "vout": vout })).unwrap();
        assert_eq!(from_json, built);
        assert_eq!(from_object, built);
        assert_eq!(
            serde_json::to_string(&built).unwrap(),
            format!("\"{text}\"")
        );

        let mut writer = WireWriter::new();
        writer.write_outpoint(&built);
        // The wire carries the id's text, decoded: the display order.
        assert_eq!(&writer.as_bytes()[..32], &hex::decode(tx.id()).unwrap()[..]);
        assert_ne!(&writer.as_bytes()[..32], &tx.hash()[..]);
        let from_wire = WireReader::new(writer.as_bytes()).read_outpoint().unwrap();
        assert_eq!(from_wire, built, "seed {seed}");
        assert_eq!(from_wire.txid, tx.txid());

        // The wire-order bytes handed as the id name another transaction,
        // and say so by a door that names its order.
        let other = Outpoint::new(Txid::from_display_bytes(tx.hash()), vout);
        assert_ne!(other, built);
        assert_eq!(other.to_string(), format!("{}.{vout}", reversed(&tx.id())));
    }
    assert_eq!(ids.len(), 500, "each seed its own transaction");
}

#[test]
fn a_result_and_a_list_hold_the_transactions_id_843w1() {
    for seed in 500..600u64 {
        let tx = transaction(seed);
        let result = SendWithResult {
            txid: tx.txid(),
            status: SendWithResultStatus::Sending,
        };
        assert_eq!(
            serde_json::to_string(&result).unwrap(),
            format!("{{\"txid\":\"{}\",\"status\":\"sending\"}}", tx.id())
        );
        let mut writer = WireWriter::new();
        writer.write_send_with_result(&result);
        assert_eq!(&writer.as_bytes()[..32], &hex::decode(tx.id()).unwrap()[..]);
        let read = WireReader::new(writer.as_bytes())
            .read_send_with_result()
            .unwrap();
        assert_eq!(read.txid, tx.txid());

        let options = CreateActionOptions {
            known_txids: Some(vec![tx.txid()]),
            send_with: Some(vec![tx.txid()]),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&options).unwrap(),
            format!(
                "{{\"knownTxids\":[\"{0}\"],\"sendWith\":[\"{0}\"]}}",
                tx.id()
            )
        );
        let back: CreateActionOptions =
            serde_json::from_str(&serde_json::to_string(&options).unwrap()).unwrap();
        assert_eq!(back.known_txids, Some(vec![tx.txid()]));

        let result = CreateActionResult {
            txid: Some(tx.txid()),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&result).unwrap(),
            format!("{{\"txid\":\"{}\"}}", tx.id())
        );
    }
}

#[test]
fn a_holders_debug_prints_the_id_as_its_digits_843w1() {
    let tx = transaction(7);
    let outpoint = Outpoint::new(tx.txid(), 3);
    assert_eq!(
        format!("{outpoint:?}"),
        format!("Outpoint {{ txid: Txid({}), vout: 3 }}", tx.id())
    );
}
