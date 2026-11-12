//! The door's source amount of 2^53 satoshis or more under a signature check
//! (#874, "Beside it"): the reference's default mode against this crate's,
//! recorded by running the reference (`support/door_source_amount_874.mjs`,
//! `ts-stack@edf6e03` `packages/sdk` bundled with bun, Node v22.18.0;
//! `vectors/door_source_amount_874.json`).
//!
//! Each cell is a P2PKH spend this crate's writer signs over its own BIP143
//! preimage with the source amount written as its eight bytes, as the node
//! writes an `int64` amount (bitcoin-sv v1.2.2 `SignatureHash`). The
//! reference's `Spend` writes the preimage through a `BigNumber` built from
//! the JavaScript number (`TransactionSignature.ts:399`, `utils.ts:545-551`),
//! which throws for an amount past 2^53 - 1 (`BigNumber.ts:462`); its
//! signature checks catch the throw as a failed check (`Spend.ts:1696-1705`,
//! `:1816-1825`), so the recorded default `Spend` answers `The top stack
//! element must be truthy after script evaluation.` on every cell past the
//! control. This crate's default mode judges the input over the amount's
//! bytes, valid, as every word and the node do: the stated row of #874 in the
//! root `CLAUDE.md`, by the recording beside each cell. No coin holds such an amount (`MAX_MONEY`,
//! `amount.h:130`), and this crate's readers refuse a source amount of 2^53 or
//! more read from bytes (`from_ef`, the BEEF readers, #844), so only a caller's
//! own `source_satoshis` reaches the cell.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Test code: a failed unwrap is the test failing.

use bsv_rs::primitives::{from_hex, to_hex, PrivateKey};
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{ProtocolEra, ScriptFlags, SignOutputs, UnlockingScript};
use bsv_rs::transaction::{
    verify_input, InputRules, InputVerified, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

/// The source amounts: the largest the reference holds (the control), then
/// 2^53, 2^63 and 2^64 - 1.
const AMOUNTS: [u64; 4] = [(1 << 53) - 1, 1 << 53, 1 << 63, u64::MAX];

/// A P2PKH spend of `amount` satoshis at `version`, signed by this crate's
/// writer: the spending transaction's bytes and the locking script.
fn cell(amount: u64, version: u32) -> (Vec<u8>, Vec<u8>) {
    let key = PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    let address = key.public_key().to_address();
    let lock = P2PKH::lock_from_address(&address).unwrap();
    let mut funding = Transaction::new();
    let mut mined = TransactionInput::new("11".repeat(32), 0);
    mined.set_unlocking_script(UnlockingScript::new());
    funding.add_input(mined).unwrap();
    funding
        .add_output(TransactionOutput::new(amount, lock.clone()))
        .unwrap();
    let mut spend = Transaction::new();
    spend.set_version(version);
    let mut input = TransactionInput::with_source_transaction(funding, 0);
    input.set_unlocking_script_template(P2PKH::unlock(&key, SignOutputs::All, false));
    spend.add_input(input).unwrap();
    spend.add_p2pkh_output(&address, Some(1_000)).unwrap();
    futures::executor::block_on(spend.sign()).unwrap();
    (spend.to_binary(), lock.to_binary())
}

fn rules_of(mode: &str) -> InputRules {
    match mode {
        "default" => InputRules::reference_default(),
        "block" => InputRules::under(ScriptFlags::block(ProtocolEra::PostChronicle)).unwrap(),
        "standard" => InputRules::under(ScriptFlags::standard(ProtocolEra::PostChronicle)).unwrap(),
        other => panic!("no mode {other}"),
    }
}

/// Prints the cells the reference's script reads.
#[test]
#[ignore = "a recorder: prints the cells for support/door_source_amount_874.mjs"]
fn record_the_cells_874() {
    let mut cells = Vec::new();
    for amount in AMOUNTS {
        for version in [1u32, 2] {
            let (tx, lock) = cell(amount, version);
            cells.push(serde_json::json!({
                "amount": amount.to_string(),
                "version": version,
                "tx": to_hex(&tx),
                "lock": to_hex(&lock),
            }));
        }
    }
    println!("{}", serde_json::to_string_pretty(&cells).unwrap());
}

fn vector() -> Value {
    let text = std::fs::read_to_string("tests/vectors/door_source_amount_874.json").unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn a_source_amount_of_two_to_the_53_or_more_is_judged_over_its_bytes_in_every_mode_874() {
    let vector = vector();
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), AMOUNTS.len() * 2);
    for case in cases {
        let amount: u64 = case["amount"].as_str().unwrap().parse().unwrap();
        let version = u32::try_from(case["version"].as_u64().unwrap()).unwrap();
        let (tx, lock) = cell(amount, version);
        // The recording's bytes are this crate's writer's.
        assert_eq!(
            to_hex(&tx),
            case["tx"].as_str().unwrap(),
            "{amount} v{version}"
        );
        assert_eq!(to_hex(&lock), case["lock"].as_str().unwrap());
        for mode in ["default", "block", "standard"] {
            let answer = verify_input(&lock, amount, &tx, 0, &rules_of(mode));
            assert!(
                matches!(answer, Ok(InputVerified { .. })),
                "{amount} v{version} {mode}: {answer:?}"
            );
            // One satoshi off: the signature is over the amount's bytes.
            let off = verify_input(&lock, amount ^ 1, &tx, 0, &rules_of(mode));
            assert!(off.is_err(), "{amount} v{version} {mode}: {off:?}");
        }
    }
}

#[test]
fn the_reference_fails_the_check_on_a_source_amount_past_two_to_the_53_stated_874() {
    // The recording: the reference's default `Spend` on each cell. Valid at
    // 2^53 - 1, as here; past it the preimage writer throws, the check is
    // failed and the script ends false, where this crate's default mode
    // judges the input valid (the stated row).
    let vector = vector();
    for case in vector["cases"].as_array().unwrap() {
        let amount: u64 = case["amount"].as_str().unwrap().parse().unwrap();
        let reference = &case["reference_default"];
        if amount < (1 << 53) {
            assert_eq!(reference["valid"], Value::Bool(true), "{amount}");
        } else {
            assert_eq!(
                reference["error"].as_str(),
                Some(
                    "Script evaluation error: The top stack element must be truthy after script evaluation."
                ),
                "{amount}"
            );
        }
        // This crate's answer beside it.
        let tx = from_hex(case["tx"].as_str().unwrap()).unwrap();
        let lock = from_hex(case["lock"].as_str().unwrap()).unwrap();
        assert!(verify_input(&lock, amount, &tx, 0, &InputRules::reference_default()).is_ok());
    }
}
