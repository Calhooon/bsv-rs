//! #603: `beef.rs`'s survivors of the complete run of 2026-11-04, killed from
//! the reference's recorded verdicts (`ts-stack@edf6e03`
//! `packages/sdk/src/wallet/WalletResultBEEF.ts`, Node v22.18.0;
//! `tests/vectors/wallet_result_beef_603.json`, recorded by
//! `tests/support/wallet_result_beef_603.mjs`). Every caller drops the
//! error's content, so each test asserts the verdict and the subject's txid,
//! never a message.
#![cfg(test)]

use super::beef::parse;
use serde_json::Value;

fn case(name: &str) -> (Vec<u8>, Value) {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/wallet_result_beef_603.json"
    ))
    .unwrap();
    let case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone();
    (hex::decode(case["hex"].as_str().unwrap()).unwrap(), case)
}

fn assert_reference_verdict(name: &str) {
    let (bytes, case) = case(name);
    let ok = case["parse"] == "ok";
    let parsed = parse(&bytes);
    assert_eq!(
        parsed.is_ok(),
        ok,
        "{name}: the reference says {}",
        case["parse"]
    );
    if let Ok(envelope) = parsed {
        let txids: Vec<&str> = envelope.transactions.keys().map(String::as_str).collect();
        let recorded: Vec<&str> = case["txids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        assert_eq!(txids, recorded, "{name}");
    }
}

/// K1 (`53:10`): the BUMP's block height is the one count with no later
/// bound; the reference refuses a varint above 2^53 - 1 (`:84`).
#[test]
fn a_bump_height_past_the_safe_integer_is_refused_and_at_it_read_603() {
    assert_reference_verdict("height_2_53");
    assert_reference_verdict("height_2_53_minus_1");
}

/// K2 (`88:36`): 18 bytes after the output count, a multiple of 9.
#[test]
fn a_transaction_whose_output_bytes_are_a_multiple_of_nine_is_read_603() {
    assert_reference_verdict("outputs_remaining_multiple_of_9");
}

/// K3 (`119:19`): a level of one duplicate leaf with three bytes left
/// (count equal to half the remaining bytes), self-paired as `:224-225` does.
#[test]
fn a_level_count_equal_to_half_the_bytes_left_is_read_603() {
    assert_reference_verdict("level_count_half_remaining");
}

/// K4 (`126:23`): a level-1 leaf at `floor(0xffffffff / 2)` (`:257`).
#[test]
fn a_leaf_at_its_levels_maximum_offset_is_read_603() {
    assert_reference_verdict("offset_at_level_max");
}

/// K5 (`126:46`, `126:56`): one past it refused (`:259`).
#[test]
fn a_leaf_past_its_levels_maximum_offset_is_refused_603() {
    assert_reference_verdict("offset_past_level_max");
}

/// K6 (`247:9`, `252:16`, `271:21`): a closed Atomic BEEF's subject is the
/// atomic txid, whatever txid the caller expects, as the reference's strict
/// `parseWalletResultAtomicBEEF` returns it before the expected txid is read
/// (`:401-427`; `WalletResultValidation.ts:1376-1415`).
#[test]
fn a_closed_atomic_subject_wins_over_the_expected_parent_603() {
    let (bytes, case) = case("atomic_closed_expected_parent");
    let parent = case["parent"].as_str().unwrap();
    let subject = case["subject"].as_str().unwrap();
    assert_eq!(case["atomic_strict"], subject);
    assert_eq!(case["atomic_partial"], subject);
    assert_reference_verdict("atomic_closed_expected_parent");
    let chosen = parse(&bytes).unwrap().subject(Some(parent)).unwrap();
    assert_eq!(chosen.txid, subject);
    let control = parse(&bytes).unwrap().subject(None).unwrap();
    assert_eq!(control.txid, subject);
}
