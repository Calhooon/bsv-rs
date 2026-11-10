//! #603, kill lane rv-wire: the typed byte slices' total at `wire.rs:43`, the
//! reference's strict `>` (`WalletResultValidation.ts:632-637` at
//! `ts-stack@edf6e03`: exactly `MAX_WALLET_WIRE_FRAME_BYTES` passes, one more
//! refused in `byte arrays: at most 268435456 total bytes`), against
//! `tests/vectors/rv_wire_kill_603.json` (`tests/support/rv_wire_kill_603.mjs`,
//! the reference's exported `validateWalletResult`).
//!
//! Through `WalletWireTransceiver` no answer reaches this check with a total
//! past the cap, since `transceiver.rs` refuses a response over `MAX_BYTES`
//! before decoding (`boundary.rs`, the reference's
//! `WalletWireTransceiver.ts:108-132`); `WalletWireProcessor` reaches it with
//! a wallet's linkage result before encoding (`processor.rs:447`, the
//! reference's `#invokeValidatedWallet`, `WalletWireProcessor.ts:2421-2431`).
//! `WireResult::check` is the Rust form of the reference's
//! exported `validateWalletResult` (`WalletResultValidation.ts:2179`), so the
//! check is pinned here on its own.
#![cfg(test)]

use super::{boundary::MAX_BYTES, wire::WireResult};
use crate::primitives::PublicKey;
use crate::wallet::{KeyLinkageResult, RevealCounterpartyKeyLinkageResult};
use crate::Error;
use serde_json::Value;

const RECORDING: &str = include_str!("../../../../tests/vectors/rv_wire_kill_603.json");

fn row(name: &str) -> Value {
    let recording: Value = serde_json::from_str(RECORDING).unwrap();
    assert_eq!(recording["source"], "ts-stack@edf6e03");
    recording["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("row {name} is not recorded"))
        .clone()
}

/// The recorded row's result with zeroed slices of its lengths
/// (`vec![0; n]` is a zeroed allocation; no path reads a byte).
fn result_of(row: &Value) -> RevealCounterpartyKeyLinkageResult {
    let key = |name: &str| PublicKey::from_hex(row[name].as_str().unwrap()).unwrap();
    let length = |name: &str| usize::try_from(row[name].as_u64().unwrap()).unwrap();
    RevealCounterpartyKeyLinkageResult {
        linkage: KeyLinkageResult {
            encrypted_linkage: vec![0u8; length("encrypted_linkage_length")],
            encrypted_linkage_proof: vec![0u8; length("encrypted_linkage_proof_length")],
            prover: key("prover"),
            verifier: key("verifier"),
            counterparty: key("counterparty"),
        },
        revelation_time: row["revelation_time"].as_str().unwrap().to_owned(),
    }
}

fn check(row: &Value) -> crate::Result<()> {
    let call = row["call"].as_str().unwrap();
    WireResult::check(&result_of(row), call, &Value::Null, None)
}

#[test]
fn a_linkage_whose_byte_fields_are_small_is_accepted_603() {
    let row = row("small_control");
    assert_eq!(row["reference"]["accepted"], true);
    assert!(check(&row).is_ok(), "{:?}", check(&row));
}

#[test]
fn a_linkage_whose_byte_fields_total_the_cap_is_accepted_603() {
    let row = row("total_at_cap");
    assert_eq!(row["reference"]["accepted"], true);
    assert_eq!(
        row["encrypted_linkage_length"].as_u64().unwrap()
            + row["encrypted_linkage_proof_length"].as_u64().unwrap(),
        MAX_BYTES as u64
    );
    let verdict = check(&row);
    assert!(verdict.is_ok(), "{verdict:?}");
}

#[test]
fn a_linkage_whose_byte_fields_total_past_the_cap_is_refused_603() {
    let row = row("total_past_cap");
    assert_eq!(row["reference"]["accepted"], false);
    assert_eq!(
        row["encrypted_linkage_length"].as_u64().unwrap()
            + row["encrypted_linkage_proof_length"].as_u64().unwrap(),
        MAX_BYTES as u64 + 1
    );
    match check(&row) {
        Err(Error::WalletError(words)) => {
            assert_eq!(Some(words.as_str()), row["reference"]["message"].as_str())
        }
        other => panic!("expected a WalletError refusal, got {other:?}"),
    }
}
