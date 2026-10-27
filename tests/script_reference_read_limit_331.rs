//! The default mode's read limit, the reference's (bsv-rs#331, the keeper's
//! word of 2026-10-27): an operand whose magnitude passes 536,870,888 bits,
//! V8's longest string, fails at the reference's read under Node 22
//! (`ts-stack@edf6e03` `BigNumber.ts:450`, `toString(2)`), rethrown by
//! `#readScriptNumber` as a script error (`Spend.ts:525-535`), and is invalid
//! here in the default mode with its words; one at the figure is read. Under
//! a word the node's number length decides (32,000,000 bytes after
//! Chronicle). By hand: each operand is 64 MiB, the file 0.14 s and 472 MB
//! resident in release under `--test-threads=1` (the figure holds one test
//! at a time; the default threads peaked at 1.68 GB in the re-review).
//!
//! `cargo test --release --test script_reference_read_limit_331 -- --ignored --test-threads=1`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::op::{OP_1, OP_1ADD, OP_DROP};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptEvaluationError, ScriptFlags, Spend, SpendParams,
    UnlockingScript,
};

/// `operand OP_1ADD OP_DROP OP_1` at version 2, under `word` if given (the
/// error boxed: it carries the stacks).
fn increment(
    operand: &[u8],
    word: Option<ScriptFlags>,
) -> Result<bool, Box<ScriptEvaluationError>> {
    let mut unlock = Script::new();
    unlock.write_bin(operand);
    let mut lock = Script::new();
    lock.write_opcode(OP_1ADD)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if let Some(word) = word {
        spend.set_flags(word);
    }
    spend.validate().map_err(Box::new)
}

/// 67,108,861 bytes of `ff` and a sign byte: 536,870,888 bits, read.
fn at_the_limit() -> Vec<u8> {
    let mut bytes = vec![0xff; 67_108_862];
    bytes[67_108_861] = 0x00;
    bytes
}

#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn an_operand_of_67_108_863_bytes_is_invalid_with_the_references_words() {
    let mut operand = vec![0xff; 67_108_863];
    operand[67_108_862] = 0x7f;
    let error = increment(&operand, None).expect_err("the reference's verdict");
    assert!(!error.is_resource_limit(), "a verdict, not a decline");
    assert_eq!(error.message, "Invalid string length");
}

#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn an_operand_of_67_108_862_bytes_at_536_870_888_bits_is_read() {
    assert_eq!(
        increment(&at_the_limit(), None).map_err(|e| e.message),
        Ok(true)
    );
}

#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn a_536_870_889th_bit_in_67_108_862_bytes_is_invalid() {
    let mut operand = at_the_limit();
    operand[67_108_861] = 0x01;
    let error = increment(&operand, None).expect_err("the reference's verdict");
    assert!(!error.is_resource_limit());
    assert_eq!(error.message, "Invalid string length");
}

#[test]
#[ignore = "by hand: a 64 MiB operand"]
fn under_a_word_the_nodes_number_length_decides() {
    let word = ScriptFlags::block(ProtocolEra::PostChronicle);
    let error = increment(&at_the_limit(), Some(word)).expect_err("the node's overflow");
    assert_eq!(
        error.message,
        "Script number overflow: 67108862 bytes, the limit is 32000000 bytes."
    );
}
