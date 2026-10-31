#![cfg(test)]
//! #545's template witnesses: against `tests/vectors/pushdrop_key_bytes_545.json`,
//! recorded by `tests/support/pushdrop_key_bytes_545.mjs` under Node v22.18.0,
//! the reference's `PushDrop.lock` (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:158-175`) on a compressed,
//! an uncompressed, a hybrid and an odd-length answer at both lock positions.
//! The wallet sites' witnesses are `tests/script_pushdrop_key_bytes_545.rs`.

use super::super::pushdrop::{LockPosition, PushDrop};
use crate::primitives::{from_hex, PublicKey};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/vectors/pushdrop_key_bytes_545.json"
    ))
    .unwrap()
}

fn position(case: &Value) -> LockPosition {
    match case["lock_position"].as_str().unwrap() {
        "before" => LockPosition::Before,
        _ => LockPosition::After,
    }
}

/// Each recorded case's script written by this crate's template from the
/// wallet's answer, the key pushed as the bytes the answer decodes to.
fn this_crates_script(case: &Value, fields: &[Vec<u8>]) -> Vec<u8> {
    let answer = case["wallet_answer"].as_str().unwrap();
    let key_bytes = from_hex(case["answer_bytes"].as_str().unwrap()).unwrap();
    PushDrop::new(PublicKey::from_hex(answer).unwrap(), fields.to_vec())
        .with_position(position(case))
        .lock_with_key_bytes(&key_bytes)
        .to_binary()
}

fn recorded_fields(v: &Value) -> Vec<Vec<u8>> {
    let fields = v["fields"].as_array().unwrap();
    fields
        .iter()
        .map(|field| from_hex(field.as_str().unwrap()).unwrap())
        .collect()
}

#[test]
fn the_wallet_key_is_pushed_as_returned_as_the_reference_pushes_it_545() {
    let v = vector();
    let fields = recorded_fields(&v);
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases.iter().filter(|case| case["form"] != "odd_length") {
        let name = format!("{} {}", case["form"], case["lock_position"]);
        let reference = from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        assert_eq!(this_crates_script(case, &fields), reference, "{name}");
    }
}

#[test]
fn a_compressed_key_s_token_is_unchanged_by_545() {
    let v = vector();
    let fields = recorded_fields(&v);
    for case in v["cases"].as_array().unwrap() {
        if case["form"] != "compressed" {
            continue;
        }
        let key = PublicKey::from_hex(case["wallet_answer"].as_str().unwrap()).unwrap();
        let lock = PushDrop::new(key, fields.clone())
            .with_position(position(case))
            .lock();
        let reference = from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        assert_eq!(lock.to_binary(), reference, "{}", case["lock_position"]);
    }
}

/// The stated residue: for an odd-length key text the reference writes the
/// opcode `33.5` truncated, `0x20`, before the 33 bytes `toArray` reads, a
/// script whose key push is cut; this crate writes the 33 bytes' own push,
/// `0x21`, every other byte the reference's.
#[test]
fn an_odd_length_key_text_differs_only_at_the_reference_s_truncated_opcode_545() {
    let v = vector();
    let fields = recorded_fields(&v);
    let odd: Vec<&Value> = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["form"] == "odd_length")
        .collect();
    assert_eq!(odd.len(), 2);
    for case in odd {
        let mut reference = from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let offset = case["key_push_offset"].as_u64().unwrap() as usize;
        assert_eq!(reference[offset], 0x20, "{}", case["lock_position"]);
        reference[offset] = 0x21;
        assert_eq!(this_crates_script(case, &fields), reference);
    }
}
