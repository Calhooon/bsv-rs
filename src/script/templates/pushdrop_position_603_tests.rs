#![cfg(test)]
//! #603's witnesses for the position read and its words helpers, inside the
//! script surface's mutation selection. Every expectation is a recording of
//! the reference (`ts-stack@edf6e03`, Node v22.18.0), never written by hand:
//! `tests/vectors/public_key_forms_498.json` (`PublicKey.fromString`, by
//! `tests/support/public_key_forms_498.mjs`), `tests/vectors/sec1_tag_05_550.json`
//! (`PublicKey.fromDER`), and `tests/vectors/kvstore_local_454.json`'s
//! `parser_words_489` (`PushDrop.decode` at its default position as
//! `parser_error`; `LocalKVStore.ts:278-279`'s `decodeCanonicalPushDrop` with
//! `fieldCount: 2` after `Original error: `, by
//! `tests/support/kvstore_local_parser_words_489.mjs`). The one token no
//! recording carries, zero fields, is written by this crate's template in the
//! shape the reference's `PushDrop.lock` writes (`PushDrop.ts:164-171,185-193`).

#[cfg(any(feature = "kvstore", feature = "registry"))]
use super::key_text_refusal;
use super::{canonical_refusal, point_message};
use crate::primitives::{from_hex, PrivateKey, PublicKey};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use serde_json::Value;

fn recorded(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn key_forms_498() -> Vec<Value> {
    let v = recorded(include_str!(
        "../../../tests/vectors/public_key_forms_498.json"
    ));
    v["cases"].as_array().unwrap().clone()
}

/// `parser_words_489`'s token cases, the `get` run (`set` records the same
/// script and words).
fn token_cases_489() -> Vec<Value> {
    let v = recorded(include_str!(
        "../../../tests/vectors/kvstore_local_454.json"
    ));
    let cases: Vec<Value> = v["parser_words_489"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["operation"] == "get")
        .filter(|case| case["name"].as_str().unwrap().starts_with("token_"))
        .cloned()
        .collect();
    assert_eq!(cases.len(), 16, "the recording's token cases");
    cases
}

fn case_489(name: &str) -> Value {
    token_cases_489()
        .into_iter()
        .find(|case| case["name"] == name)
        .unwrap()
}

fn script_of(case: &Value) -> LockingScript {
    LockingScript::from_binary(&from_hex(case["locking_script"].as_str().unwrap()).unwrap())
        .unwrap()
}

/// The words `decodeCanonicalPushDrop` threw, as `LocalKVStore.ts:320` wraps them.
fn canonical_words(case: &Value) -> &str {
    let error = case["error"].as_str().unwrap();
    error.split_once("Original error: ").unwrap().1
}

/// The reference decodes a key and a CHECKSIG as a zero-field token
/// (`PushDrop.ts:73-77`, the field loop at `:97` starting past the end); the
/// two-chunk script is `PushDrop.lock` with no field and no signature
/// (`PushDrop.ts:164-171,185-193`). Kills `pushdrop_position.rs:18:25` `<=`.
#[test]
fn decode_before_reads_a_two_chunk_token_pushdrop_ts_73_97() {
    let key = PrivateKey::from_bytes(&[7; 32]).unwrap().public_key();
    let script = PushDrop::new(key.clone(), Vec::new()).lock();
    assert_eq!(script.chunks().len(), 2);
    let decoded = PushDrop::decode_before(&script).unwrap();
    assert_eq!(decoded.locking_public_key, key);
    assert!(decoded.fields.is_empty());
}

/// `parser_words_489` `token_empty`: `PushDrop.decode` of an empty script
/// throws (`PushDrop.ts:75`, `script.chunks[0]` undefined); this read refuses
/// it, never indexing a chunk that is not there. Kills
/// `pushdrop_position.rs:18:25` `==` (the empty script then reaches the
/// lock-before read's `chunks[0]`).
#[test]
fn decode_before_refuses_an_empty_script_kvstore_local_489_token_empty() {
    let case = case_489("token_empty");
    assert_eq!(
        case["parser_error"],
        "Cannot read properties of undefined (reading 'data')"
    );
    assert!(PushDrop::decode_before(&script_of(&case)).is_err());
}

/// `parser_words_489`: every token the reference's `PushDrop.decode` refuses
/// (`parser_error` recorded) this read refuses too.
#[test]
fn decode_before_refuses_what_the_reference_refuses_kvstore_local_489() {
    let mut refused = 0;
    for case in token_cases_489() {
        if case["parser_error"].is_string() {
            refused += 1;
            assert!(
                PushDrop::decode_before(&script_of(&case)).is_err(),
                "{}",
                case["name"]
            );
        }
    }
    assert_eq!(refused, 12);
}

/// `public_key_forms_498`: `PublicKey.fromString`'s verdict and words
/// (`PublicKey.ts:49-51`, `hex.ts:28-30`, `Point.ts:303-325`) on every
/// recorded key text: `None` where it accepted, its words where it refused.
/// Kills `pushdrop_position.rs:38:5` (`None`, `Some("")`, `Some("xyzzy")`),
/// `:38:8` and `:41:8` (the negations deleted).
#[cfg(any(feature = "kvstore", feature = "registry"))]
#[test]
fn key_text_refusal_is_public_key_from_string_public_key_forms_498() {
    let cases = key_forms_498();
    assert_eq!(cases.len(), 39);
    for case in cases {
        let input = case["input"].as_str().unwrap();
        let expected =
            (!case["accepted"].as_bool().unwrap()).then(|| case["error"].as_str().unwrap());
        assert_eq!(key_text_refusal(input), expected, "{}", case["name"]);
    }
}

/// `public_key_forms_498`: `Point.fromDER`'s verdict and words
/// (`Point.ts:303-325`) on every recorded key whose text is hex, read as the
/// bytes `toArray(hex)` gives (`hex.ts:28-30` pads an odd length with a
/// leading zero), and `sec1_tag_05_550`'s `PublicKey.fromDER` case. Kills
/// `pushdrop_position.rs:58:5` (`None`, `Some("")`, `Some("xyzzy")`), `:59:53`
/// (the guard `true`, `false`), `:59:61` (`^`, `|`), `:59:66` (`==`), `:59:75`
/// (`^`, `|`) and `:62:9` (the accepted forms' arm deleted).
#[test]
fn point_message_is_point_from_der_public_key_forms_498() {
    let mut read = 0;
    for case in key_forms_498() {
        let input = case["input"].as_str().unwrap();
        if !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            assert_eq!(case["error"], "Invalid hex string", "{}", case["name"]);
            continue;
        }
        let padded = if input.len() % 2 == 1 {
            format!("0{input}")
        } else {
            input.to_string()
        };
        let expected =
            (!case["accepted"].as_bool().unwrap()).then(|| case["error"].as_str().unwrap());
        assert_eq!(
            point_message(&from_hex(&padded).unwrap()),
            expected,
            "{}",
            case["name"]
        );
        read += 1;
    }
    assert_eq!(read, 34);

    let v = recorded(include_str!("../../../tests/vectors/sec1_tag_05_550.json"));
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["site"] == "PublicKey.fromDER")
        .unwrap();
    assert_eq!(case["accepted"], false);
    let bytes = from_hex(case["input"].as_str().unwrap()).unwrap();
    assert_eq!(point_message(&bytes), case["words"].as_str());
}

/// `parser_words_489`: `decodeCanonicalPushDrop`'s words with `fieldCount: 2`
/// (`PushDropValidation.ts:54-79`, `LocalKVStore.ts:278-279`) on every
/// recorded token: the first chunk's read, the key's (`PushDrop.ts:73-77`),
/// the field count read up to the chunk before a DROP (`:96-115`), the
/// envelope. `token_no_checksig` reads two fields from index 2 and meets the
/// envelope; `token_key_only` reads none. Kills `pushdrop_position.rs:77:5`
/// (`None`, `Some("")`, `Some("xyzzy")`), `:89:16` (`*=`, `-=`) and `:91:24`
/// (`*`, `-`).
#[test]
fn canonical_refusal_is_decode_canonical_pushdrop_kvstore_local_489() {
    let mut read = 0;
    for case in token_cases_489() {
        let script = script_of(&case);
        if case["parser_accepted"] == true {
            // #489's recorded divergences (`token_hybrid_valid`,
            // `token_reduced_x`): the reference read the key this crate's
            // strict parse refuses, so the words are the caller's.
            let key = script.chunks()[0].data.clone().unwrap();
            assert!(PublicKey::from_bytes(&key).is_err(), "{}", case["name"]);
            assert_eq!(point_message(&key), None, "{}", case["name"]);
            continue;
        }
        assert_eq!(
            canonical_refusal(&script, &[2]),
            Some(canonical_words(&case)),
            "{}",
            case["name"]
        );
        read += 1;
    }
    assert_eq!(read, 14);
    assert_eq!(
        canonical_words(&case_489("token_no_checksig")),
        "PushDrop token must use the canonical PushDrop envelope"
    );
}
