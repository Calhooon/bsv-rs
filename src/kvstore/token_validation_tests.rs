//! The reader's verdicts and words on the kvstore cases of
//! `tests/vectors/token_envelope_544.json` (#544), each the reference's
//! `decodeAndVerifyKVStoreToken` at `ts-stack@edf6e03` under Node v22.18.0.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[test]
fn the_reader_gives_the_reference_verdict_in_its_words_544() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/token_envelope_544.json")).unwrap();
    let cases = v["kvstore"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let read = decode_and_verify(&script);
        match (case["words"].as_str(), case["name"].as_str().unwrap()) {
            (None, name) => assert_eq!(read.unwrap().value, case["value"], "{name}"),
            // V8's `JSON.parse` words for a protocol text that is no JSON;
            // serde's here, the same refusal.
            (Some(words), "raw_protocol") => {
                assert!(words.contains("is not valid JSON"));
                assert!(read.is_err());
            }
            (Some(words), name) => {
                assert_eq!(read.unwrap_err(), refused(words), "{name}");
            }
        }
    }
}

/// #550: the reference's token with its locking key's or its controller
/// field's tag set to `05` (the compact form k256 read as `02 || x`), refused
/// in `Point.fromDER`'s words, as `tests/vectors/sec1_tag_05_550.json` records
/// the reference refusing both (`kvStoreTokenValidation.ts:76-81`, `:88`).
#[test]
fn a_tag_05_key_is_refused_in_the_reference_words_550() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/sec1_tag_05_550.json")).unwrap();
    for name in ["kvstore_lock_key", "kvstore_controller"] {
        let case = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        let script = LockingScript::from_hex(case["input"].as_str().unwrap()).unwrap();
        let words = case["words"].as_str().unwrap();
        assert_eq!(words, "Unknown point format");
        assert_eq!(
            decode_and_verify(&script).unwrap_err(),
            refused(words),
            "{name}"
        );
    }
}
