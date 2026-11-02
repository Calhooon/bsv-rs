//! `src/script/templates/pushdrop.rs`'s mutants the widened oracle left
//! (#603, run 41327640129), killed here by the reference's recordings: the
//! `locks_603` and `two_chunks_603` sections of
//! `tests/vectors/pushdrop_decode_618.json`, written by
//! `tests/support/pushdrop_decode_618.mjs` under Node 22 against
//! `ts-stack@edf6e03` (`packages/sdk/src/script/templates/PushDrop.ts`).
//!
//! The rules:
//!
//! * the writer is the reference's `lock` (`PushDrop.ts:146-201`) through
//!   `createMinimallyEncodedScriptChunk` (`:20-51`): an empty field and a
//!   one-byte zero field are `OP_0` (`:21-28`), a longer field that starts
//!   with a zero byte is a direct push (`:37-41`). The node's
//!   `CheckMinimalPush` would push the one-byte zero as `01 00`
//!   (`bsv-script-lean@5dc337e` `lean/BsvScript/Machine.lean:69-75`); the
//!   reference's `OP_0` is read back as the field `00` (`PushDrop.ts:104-105`)
//!   and executes as a push the trailer drops, so this crate writes as the
//!   reference writes;
//! * a script whose first chunk is no key is read lock-after, and the
//!   reference's `'after'` refuses a two-chunk one for its last chunk or its
//!   key (`PushDrop.ts:79-94`), never for its length;
//! * two tokens are equal when the reference reads the same key (its
//!   compressed text, `PublicKey.toString`) and the same fields at the same
//!   position (the crate's `PartialEq`, `src/script/templates/CLAUDE.md`).
//!
//! The sibling `bsv-script-lean` (at `5dc337e`) has no PushDrop rule: its
//! `corpus/`, `lean/` and `spec/` name no PushDrop. A full-corpus run of each
//! of the eleven mutants (`harness/run --impl bsv-rs --corpus all --spec
//! recorded`) moved no verdict, so the vectors below come from the reference.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_hex, PublicKey};
use bsv_rs::script::templates::{LockPosition, PushDrop};
use bsv_rs::script::LockingScript;
use bsv_rs::Error;
use serde_json::Value;

fn section(name: &str) -> Vec<Value> {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/pushdrop_decode_618.json")).unwrap();
    assert_eq!(recorded["runtime"].as_str().unwrap(), "node v22.18.0");
    recorded[name].as_array().unwrap().clone()
}

fn entry(section_name: &str, name: &str) -> Value {
    section(section_name)
        .into_iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("unrecorded {section_name} entry {name}"))
}

fn script(entry: &Value) -> LockingScript {
    LockingScript::from_hex(entry["locking_script"].as_str().unwrap()).unwrap()
}

fn position(entry: &Value) -> LockPosition {
    match entry["position"].as_str().unwrap() {
        "before" => LockPosition::Before,
        "after" => LockPosition::After,
        other => panic!("unrecorded position {other}"),
    }
}

/// The token the reference's reading of `entry` names: its key and fields.
fn reference_token(entry: &Value) -> PushDrop {
    let reading = &entry["reading"];
    assert!(reading["error"].is_null(), "{}", entry["name"]);
    let key = PublicKey::from_hex(reading["locking_public_key"].as_str().unwrap()).unwrap();
    let fields = reading["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| from_hex(field.as_str().unwrap()).unwrap())
        .collect();
    PushDrop::new(key, fields).with_position(position(entry))
}

fn decoded(name: &str) -> PushDrop {
    PushDrop::decode(&script(&entry("locks_603", name))).unwrap()
}

/// Kills `||` to `&&` (`pushdrop.rs:165:28`) and `==` to `!=` (`:165:43`) in
/// `create_minimally_encoded_chunk`: the reference's lock of `00` is `OP_0`
/// and of `0001` and `0000` a two-byte push (`PushDrop.ts:21-41`).
#[test]
fn a_zero_byte_field_is_op_0_and_a_longer_one_a_push_pushdrop_ts_20_41_locks_603() {
    for name in [
        "minimal_pushes_before",
        "minimal_pushes_after",
        "minimal_pushes_before_other_key",
        "other_fields_before",
    ] {
        let entry = entry("locks_603", name);
        let key =
            PublicKey::from_hex(entry["reading"]["locking_public_key"].as_str().unwrap()).unwrap();
        let fields = entry["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| from_hex(field.as_str().unwrap()).unwrap())
            .collect();
        let locked = PushDrop::new(key, fields)
            .with_position(position(&entry))
            .lock();
        assert_eq!(
            locked.to_hex(),
            entry["locking_script"].as_str().unwrap(),
            "{name}"
        );
    }
}

/// Kills `<` to `<=` and `<` to `==` (`pushdrop.rs:290:25`) in
/// `decode_lock_after`: a two-chunk script without a key first is refused
/// for its last chunk or its key as the reference's `'after'` refuses it
/// (`PushDrop.ts:81-92`), not as too short.
#[test]
fn a_two_chunk_lock_after_is_refused_for_its_checksig_or_key_pushdrop_ts_79_94_two_chunks_603() {
    let short_key = PublicKey::from_bytes(&[1, 2, 3, 4, 5]).unwrap_err();
    for (name, reference_words, refusal) in [
        (
            "op_1_op_1",
            "Expected OP_CHECKSIG at the end of the script",
            Error::ScriptParseError("Expected OP_CHECKSIG at end".into()),
        ),
        (
            "op_1_checksig",
            "public key chunk data must have value",
            Error::ScriptParseError("Expected public key before OP_CHECKSIG".into()),
        ),
        ("short_push_checksig", "Unknown point format", short_key),
    ] {
        let entry = entry("two_chunks_603", name);
        assert_eq!(entry["after"]["error"], reference_words, "{name}");
        let script = script(&entry);
        assert_eq!(script.chunks().len(), 2, "{name}");
        assert_eq!(PushDrop::decode(&script).unwrap_err(), refusal, "{name}");
    }
}

/// Kills `eq` to `false` (`pushdrop.rs:463:9`) and each `==` to `!=`
/// (`:463:49`, `:464:28`, `:465:35`): a decoded token equals the token of the
/// reference's reading, and a token whose key is pushed uncompressed equals
/// the compressed one, the reference reading the same key text for both.
#[test]
fn tokens_the_reference_reads_alike_are_equal_pushdrop_ts_63_121_locks_603() {
    let before = entry("locks_603", "minimal_pushes_before");
    assert!(decoded("minimal_pushes_before") == reference_token(&before));
    let after = entry("locks_603", "minimal_pushes_after");
    assert!(decoded("minimal_pushes_after") == reference_token(&after));

    let uncompressed = entry("locks_603", "minimal_pushes_before_uncompressed_key");
    assert_eq!(uncompressed["reading"], before["reading"]);
    assert_eq!(
        script(&uncompressed).chunks()[0]
            .data
            .as_ref()
            .unwrap()
            .len(),
        65
    );
    assert!(decoded("minimal_pushes_before_uncompressed_key") == decoded("minimal_pushes_before"));
}

/// Kills `eq` to `true` (`pushdrop.rs:463:9`) and the second `&&` to `||`
/// (`:465:13`): the reference reads the same key and fields at both
/// positions, and the two tokens are not equal.
#[test]
fn tokens_differing_in_position_alone_are_unequal_pushdrop_ts_197_201_locks_603() {
    let before = entry("locks_603", "minimal_pushes_before");
    let after = entry("locks_603", "minimal_pushes_after");
    assert_eq!(before["reading"], after["reading"]);
    assert!(decoded("minimal_pushes_before") != decoded("minimal_pushes_after"));
}

/// Kills the first `&&` to `||` (`pushdrop.rs:464:13`), from each side: the
/// same key and position with other fields, and the same fields and
/// position under another key (key ID '2'), are not equal.
#[test]
fn tokens_differing_in_key_or_fields_alone_are_unequal_pushdrop_ts_63_121_locks_603() {
    let base = entry("locks_603", "minimal_pushes_before");
    let other_fields = entry("locks_603", "other_fields_before");
    assert_eq!(
        other_fields["reading"]["locking_public_key"],
        base["reading"]["locking_public_key"]
    );
    assert_ne!(other_fields["reading"]["fields"], base["reading"]["fields"]);
    assert!(decoded("minimal_pushes_before") != decoded("other_fields_before"));

    let other_key = entry("locks_603", "minimal_pushes_before_other_key");
    assert_eq!(other_key["reading"]["fields"], base["reading"]["fields"]);
    assert_ne!(
        other_key["reading"]["locking_public_key"],
        base["reading"]["locking_public_key"]
    );
    assert!(decoded("minimal_pushes_before") != decoded("minimal_pushes_before_other_key"));
}

#[test]
fn every_recorded_603_entry_is_pinned() {
    assert_eq!(section("locks_603").len(), 5);
    assert_eq!(section("two_chunks_603").len(), 3);
}
