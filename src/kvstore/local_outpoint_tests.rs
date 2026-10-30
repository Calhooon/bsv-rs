//! The reference's search, isolated from the ordered action boundary (#478).
#![cfg(test)]
use super::*;
use crate::primitives::from_hex;

#[test]
fn local_outpoint_matches_recorded_nonzero_absent_and_duplicate_tokens_478() {
    let recorded: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/kvstore_local_454.json")).unwrap();
    for case in recorded["token_search"]["cases"].as_array().unwrap() {
        let tx = Transaction::from_atomic_beef(
            &from_hex(case["transaction"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let lock = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let expected = if let Some(outpoint) = case["outpoint"].as_str() {
            Ok(outpoint.to_owned())
        } else {
            Err("Final transaction does not contain one unique KVStore token".to_owned())
        };
        assert_eq!(
            token_outpoint(&tx, &lock, 1).map_err(|error| error.to_string()),
            expected,
            "{}",
            case["name"]
        );
    }
}
