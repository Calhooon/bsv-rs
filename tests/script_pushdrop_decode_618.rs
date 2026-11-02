//! #618: the public `PushDrop::decode` reads a key-only script and a token
//! whose second chunk is not `OP_CHECKSIG` as the reference's
//! `PushDrop.decode` reads them at its default position, `'before'`
//! (`ts-stack@edf6e03` `PushDrop.ts:63-121`): the key the first chunk, the
//! second chunk never read, the fields from the third. The vector
//! `tests/vectors/pushdrop_decode_618.json` is the reference's reading of
//! each shape at both positions, written by
//! `tests/support/pushdrop_decode_618.mjs` under Node 22.
//!
//! The rest of the door is unchanged: a first chunk that is no 33- or
//! 65-byte push is read lock-after (the reference's `'after'`), a script of
//! fewer than two chunks that is not a key is `Script too short for
//! PushDrop`, and a key the reference refuses is refused in this crate's
//! parse's words.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::to_hex;
use bsv_rs::script::templates::{LockPosition, PushDrop};
use bsv_rs::script::{op, LockingScript, ScriptChunk};
use bsv_rs::Error;
use serde_json::{json, Value};

fn cases() -> Vec<Value> {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/pushdrop_decode_618.json")).unwrap();
    assert_eq!(recorded["runtime"].as_str().unwrap(), "node v22.18.0");
    recorded["cases"].as_array().unwrap().clone()
}

fn case(name: &str) -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("unrecorded case {name}"))
}

fn script(case: &Value) -> LockingScript {
    LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap()
}

/// The decoded token as the recording writes a reading.
fn reading(token: &PushDrop) -> (Vec<String>, String) {
    let fields = token.fields.iter().map(|field| to_hex(field)).collect();
    (fields, token.locking_public_key.to_hex())
}

fn recorded_reading(reading: &Value) -> (Vec<String>, String) {
    let fields = reading["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_string())
        .collect();
    let key = reading["locking_public_key"].as_str().unwrap().to_string();
    (fields, key)
}

/// `name` decodes here as the reference's default position reads it.
fn assert_reads_as_the_reference(name: &str) {
    let case = case(name);
    assert!(case["before"]["error"].is_null(), "{name}");
    let token = PushDrop::decode(&script(&case)).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(token.lock_position, LockPosition::Before, "{name}");
    assert_eq!(reading(&token), recorded_reading(&case["before"]), "{name}");
}

#[test]
fn a_key_only_token_reads_as_the_reference_reads_it_pushdrop_ts_73_97_618() {
    for name in ["key_only", "key_only_uncompressed"] {
        assert_reads_as_the_reference(name);
        assert_eq!(case(name)["before"]["fields"], serde_json::json!([]));
    }
}

#[test]
fn a_token_without_checksig_second_reads_as_the_reference_reads_it_pushdrop_ts_73_115_618() {
    for name in [
        "no_checksig",
        "no_checksig_nop",
        "no_checksig_no_field",
        // A lock-after token whose first field is a point: the reference's
        // default position reads it lock-before, its second chunk unread and
        // a DROP at the third read as an empty field (`PushDrop.ts:96-115`).
        "lock_after_point_first",
    ] {
        assert_reads_as_the_reference(name);
    }
}

#[test]
fn the_shapes_around_them_read_as_before_the_change_618() {
    // The writer's lock-before token and the lock alone: the reference's
    // default reading.
    assert_reads_as_the_reference("lock_before_three_fields");
    assert_reads_as_the_reference("lock_only");
    // The writer's lock-after token: read lock-after here, the reference's
    // `'after'` reading (its default refuses the first field as a key).
    let case = case("lock_after_three_fields");
    assert_eq!(
        case["before"]["error"].as_str().unwrap(),
        "Unknown point format"
    );
    let token = PushDrop::decode(&script(&case)).unwrap();
    assert_eq!(token.lock_position, LockPosition::After);
    assert_eq!(reading(&token), recorded_reading(&case["after"]));
}

#[test]
fn what_the_reference_refuses_is_refused_618() {
    let too_short = Error::ScriptParseError("Script too short for PushDrop".into());
    for (name, reference_words, ours) in [
        (
            "empty",
            "Cannot read properties of undefined (reading 'data')",
            too_short.clone(),
        ),
        (
            "one_chunk_op_true",
            "script.chunks[0].data must have value",
            too_short.clone(),
        ),
        ("one_chunk_short_push", "Unknown point format", too_short),
        (
            "key_only_off_curve",
            "Invalid point",
            Error::InvalidPublicKey("Point not on curve".into()),
        ),
        (
            "no_checksig_off_curve",
            "Invalid point",
            Error::InvalidPublicKey("Point not on curve".into()),
        ),
    ] {
        let case = case(name);
        assert_eq!(case["before"]["error"].as_str().unwrap(), reference_words);
        assert!(!case["after"]["error"].is_null(), "{name}");
        assert_eq!(
            PushDrop::decode(&script(&case)).unwrap_err(),
            ours,
            "{name}"
        );
    }
}

/// `name`, built by this crate's writer from `chunks`, decoded at the
/// position the door detects: this crate's reading and the reference's at
/// that position.
type Reading = (Vec<String>, String);

fn readings_at_its_position(name: &str, chunks: Vec<ScriptChunk>) -> (Reading, Reading) {
    let case = case(name);
    let script = LockingScript::from_chunks(chunks);
    assert_eq!(
        script.to_hex(),
        case["locking_script"].as_str().unwrap(),
        "{name}"
    );
    let token = PushDrop::decode(&script).unwrap_or_else(|e| panic!("{name}: {e}"));
    let position = match token.lock_position {
        LockPosition::Before => "before",
        LockPosition::After => "after",
    };
    assert!(case[position]["error"].is_null(), "{name}");
    (reading(&token), recorded_reading(&case[position]))
}

/// The fold's shapes (`PushDrop.ts:96-115`) at each lock position: the
/// shape's chunks after `<key> OP_CHECKSIG`, then before it.
fn fold_shapes(shape: &str) -> (Vec<ScriptChunk>, Vec<ScriptChunk>) {
    let key = LockingScript::from_hex(case("key_only")["locking_script"].as_str().unwrap())
        .unwrap()
        .chunks()[0]
        .clone();
    let hi = ScriptChunk::new(2, Some(vec![0x68, 0x69]));
    let opcode = ScriptChunk::new_opcode;
    let chunks = match shape {
        "checksig_drop" => vec![opcode(op::OP_DROP)],
        "checksig_2drop" => vec![opcode(op::OP_2DROP)],
        "checksig_field_drop" => vec![hi, opcode(op::OP_DROP)],
        "reserved_field" => vec![hi, opcode(op::OP_RESERVED), opcode(op::OP_2DROP)],
        "op_0_op_1_fields" => vec![opcode(op::OP_0), opcode(op::OP_1), opcode(op::OP_2DROP)],
        shape => panic!("unrecorded shape {shape}"),
    };
    let lock = [key, opcode(op::OP_CHECKSIG)];
    let before = lock.iter().chain(&chunks).cloned().collect();
    let after = chunks.iter().chain(&lock).cloned().collect();
    (before, after)
}

/// `shape` at both positions reads here as the reference reads it.
fn assert_fold_shape_reads_as_the_reference(shape: &str) {
    let (before, after) = fold_shapes(shape);
    let (ours_before, reference_before) = readings_at_its_position(shape, before);
    let (ours_after, reference_after) =
        readings_at_its_position(&format!("{shape}_lock_after"), after);
    assert_eq!(
        (ours_before, ours_after),
        (reference_before, reference_after),
        "{shape}: (lock-before, lock-after)"
    );
}

#[test]
fn a_trailing_drop_is_an_empty_field_pushdrop_ts_96_115_618_fold() {
    assert_fold_shape_reads_as_the_reference("checksig_drop");
    assert_eq!(case("checksig_drop")["before"]["fields"], json!([""]));
}

#[test]
fn a_trailing_2drop_is_an_empty_field_pushdrop_ts_96_115_618_fold() {
    assert_fold_shape_reads_as_the_reference("checksig_2drop");
    assert_eq!(case("checksig_2drop")["before"]["fields"], json!([""]));
}

#[test]
fn a_field_before_a_drop_ends_the_read_pushdrop_ts_111_114_618_fold() {
    assert_fold_shape_reads_as_the_reference("checksig_field_drop");
}

#[test]
fn an_op_reserved_field_is_its_opcode_less_0x50_pushdrop_ts_99_109_618_fold() {
    assert_fold_shape_reads_as_the_reference("reserved_field");
    assert_eq!(
        case("reserved_field")["before"]["fields"],
        json!(["6869", "00"])
    );
}

#[test]
fn op_0_and_op_1_fields_read_as_the_reference_reads_them_618_fold() {
    assert_fold_shape_reads_as_the_reference("op_0_op_1_fields");
}

#[test]
fn every_recorded_shape_is_pinned_618() {
    assert_eq!(cases().len(), 24);
}
