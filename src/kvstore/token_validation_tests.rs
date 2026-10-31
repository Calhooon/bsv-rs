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
