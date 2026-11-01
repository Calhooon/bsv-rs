//! #588: the processor's getPublicKey result check (`validation::public_key_result`)
//! against the recorder's `result` outcomes (`tests/vectors/public_key_validation_579.json`,
//! `validateWalletResult('getPublicKey', ..)` at `ts-stack@edf6e03`): an accepted
//! key the 33 bytes the frame carries, a refused one code 1 in the recorded words.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::validation::{public_key_result, Refusal};
use serde_json::Value;

#[test]
fn the_get_public_key_result_check_is_the_result_validators_outcome_588() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/public_key_validation_579.json"
    ))
    .unwrap();
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let text = case["text"].as_str().unwrap();
        let recorded = &case["result"];
        let outcome = public_key_result(text);
        if recorded["ok"].as_bool().unwrap() {
            assert_eq!(outcome, Ok(hex::decode(text).unwrap()), "{}", case["name"]);
        } else {
            assert_eq!(
                outcome,
                Err(Refusal::plain(recorded["message"].as_str().unwrap())),
                "{}",
                case["name"]
            );
        }
    }
}
