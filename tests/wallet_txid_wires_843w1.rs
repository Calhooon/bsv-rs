//! #843, W1: no wire byte moved when the wallet's `TxId` alias went.
//!
//! Every wallet type holds the crate's one `Txid` (wire order inside) and the
//! wallet wire and the certificate binary convert at one codec pair
//! (`src/wallet/wire/txid_codec.rs`), the display order being those wires'
//! own: the reference writes the decoded hex unreversed (`ts-stack@edf6e03`
//! `WalletWireTransceiver.ts:724-726,732,1211`, `Certificate.ts:271,351-354`).
//!
//! The values are built through text doors alone
//! (`support/wallet_txid_843w1.rs`), so this source compiled on the base
//! `471bdaf6`, where the vector was recorded once
//! (`BSV_RECORD_843W1=1 cargo test --features "full" --test
//! wallet_txid_wires_843w1 record`, on a scratch copy of that commit). It is
//! never recorded again: the bytes are the base's.
//!
//! RED is three plants on a scratch copy of the tip (the lane record):
//! `write_txid` writing the wire order, `read_txid` reading it, and one site
//! bypassing the pair with `as_wire_bytes`.

#![cfg(all(feature = "wallet", feature = "auth"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/wallet_txid_843w1.rs"]
mod support;

use serde_json::Value;
use support::{compute, recorded, IDS};

fn entries(value: &Value, key: &str) -> Vec<Value> {
    value[key].as_array().expect(key).clone()
}

/// Compares one member of every entry, naming the entry and the member that
/// differs.
fn same(key: &str, name: &str, member: &str, now: &Value, base: &Value) {
    let (now, base) = (entries(now, key), entries(base, key));
    assert_eq!(now.len(), base.len(), "{key}: the count");
    for (now, base) in now.iter().zip(&base) {
        assert_eq!(now[name], base[name], "{key}: the {name}");
        let (now_members, base_members) = (
            now[member].as_object().expect(member),
            base[member].as_object().expect(member),
        );
        assert_eq!(
            now_members.keys().collect::<Vec<_>>(),
            base_members.keys().collect::<Vec<_>>(),
            "{key} {}: the members of {member}",
            now[name]
        );
        for (door, answer) in now_members {
            assert_eq!(
                answer, &base_members[door],
                "{key} {}, {member}, {door}",
                now[name]
            );
        }
    }
}

/// The recorder: writes the vector. Run once, on the base.
#[tokio::test]
async fn record() {
    if std::env::var("BSV_RECORD_843W1").is_err() {
        return;
    }
    let text = serde_json::to_string_pretty(&compute().await).unwrap();
    std::fs::write(support::VECTOR, text + "\n").unwrap();
}

#[tokio::test]
async fn every_wire_door_writes_and_reads_the_bases_bytes_843w1() {
    let (now, base) = (compute().await, recorded());
    assert_eq!(entries(&base, "ids").len(), IDS as usize);
    same("ids", "id", "wires", &now, &base);
    // The reading is not vacuous: each call answered a value.
    for entry in entries(&now, "ids") {
        for call in [
            "create_action_result",
            "sign_action_result",
            "relinquish_output_result",
            "list_actions_result",
            "list_outputs_result",
        ] {
            assert!(
                entry["wires"][call].get("ok").is_some(),
                "{call} of {}: {}",
                entry["id"],
                entry["wires"][call]
            );
        }
    }
}

#[tokio::test]
async fn every_frame_carries_the_decoded_text_of_its_id_unreversed_843w1() {
    // With no recording: `compute` asserts, door by door, that each frame's
    // 32 bytes are `hex::decode` of the id's text, and that no id is its own
    // reverse. Here the same on the plainest door, read back.
    let now = compute().await;
    for entry in entries(&now, "ids") {
        let id = entry["id"].as_str().unwrap();
        let wires = &entry["wires"];
        assert_eq!(wires["txid_hex"], id, "the wire's 32 bytes are the text's");
        assert_eq!(wires["txid_hex_read"], id);
        assert!(wires["outpoint"].as_str().unwrap().starts_with(id));
        assert!(wires["outpoint_read"].as_str().unwrap().starts_with(id));
        let reversed: String = hex::encode(
            hex::decode(id)
                .unwrap()
                .into_iter()
                .rev()
                .collect::<Vec<_>>(),
        );
        for (door, bytes) in wires.as_object().unwrap() {
            let bytes = bytes.to_string();
            assert!(
                !bytes.contains(&reversed),
                "{door} of {id} carries the id reversed"
            );
        }
    }
}

#[tokio::test]
async fn the_whole_recording_is_what_the_tree_answers_843w1() {
    let (mut now, mut base) = (compute().await, recorded());
    for value in [&mut now, &mut base] {
        value.as_object_mut().unwrap().remove("source");
    }
    assert!(now == base, "compute() is not the recorded vector");
}
