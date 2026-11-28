//! The default evaluation mode refuses the `SIGHASH_CHRONICLE` (`0x20`)
//! hash-type bit at a transaction version of 1 or below, as the reference does
//! (Chronicle requires version > 1; public issue #397).
//!
//! The reference's gate is `transactionVersion > 1` (`Spend.ts:338-341`,
//! `:586-591` at `ts-stack@edf6e03`): a version-1 input whose signature carries
//! the Chronicle bit is refused before the signature check. Because the gate is
//! thrown inside `#checkSignatureEncoding`'s DER-enforcing `try` whose `catch`
//! rethrows the DER wrapper's words, the caller sees `The signature format is
//! invalid.` (`ScriptEvaluationError.ts:38`). The node refuses the Chronicle
//! bit outside the Chronicle era under STRICTENC (`interpreter.cpp:296-303`,
//! `SCRIPT_ERR_ILLEGAL_CHRONICLE`); the default mode has no word and, before
//! this gate, admitted the bit at every version and reached verification.
//!
//! The door under test is `Spend` without a flag word — the mode
//! `Transaction::verify`, `verify_stream` and `AsyncStreamVerifier` all run on
//! outside input. The word paths (block / standard) are asserted unchanged: a
//! word carrying CHRONICLE admits the bit, a post-Chronicle word without it
//! refuses it in its own words, at every version, exactly as before.
//!
//! Every outpoint is synthetic; the previous output never existed on any chain.
//! The gate is reached before the signature check, so the signature's digest is
//! immaterial: it is a well-formed low-S DER body re-typed with each hash type.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// `<pubkey> OP_CHECKSIG` (a 33-byte push then `0xac`).
const LOCK: &str = "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac";
/// A well-formed low-S 70-byte DER signature body, no hash-type byte.
const DER: &str = "3044022064a7c97306f384b1c0189ca11ea35b638c277c6e7d07d93dbc9559b9a8e3309302200f77d025cfe41099d5808179ae4764fa8d4bca3238b97506c4d56e9147d6e900";

/// The signature does not verify here, so the admitted bit reaches a false top
/// in the default mode (which never enforces NULLFAIL).
const EVAL_FALSE: &str = "The top stack element must be truthy after script evaluation.";
/// Under a node word the admitted bit reaches the signature check, which fails,
/// and the word's NULLFAIL refuses the non-empty failing signature. The point
/// is that the hash-type gate ADMITTED the bit (it was reached), unchanged here.
const NULLFAIL: &str = "OP_CHECKSIG requires failing signatures to be empty.";
/// The reference's caller-visible words for the refused Chronicle bit (#397).
const SIG_FORMAT: &str = "The signature format is invalid.";
/// The post-Chronicle word without CHRONICLE refuses the bit in these words.
const CHRONICLE_BEFORE: &str = "The signature must not use SIGHASH_CHRONICLE before Chronicle.";

#[derive(Clone, Copy)]
enum Mode {
    /// `Spend` without a flag word: the TypeScript SDK's default mode.
    Default,
    /// `ScriptFlags::block(PostChronicle)` — carries CHRONICLE and STRICTENC.
    Block,
    /// `ScriptFlags::standard(PostChronicle)`.
    Standard,
    /// The post-Chronicle block word with CHRONICLE cleared (STRICTENC kept).
    BlockWithoutChronicle,
}

/// `<DER || hash_type>` as a 71-byte push.
fn unlock_with(hash_type: u8) -> Vec<u8> {
    let mut u = vec![0x47];
    u.extend(from_hex(DER).unwrap());
    u.push(hash_type);
    u
}

fn run(hash_type: u8, version: i32, mode: Mode) -> Result<bool, String> {
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(LOCK).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&unlock_with(hash_type)).unwrap(),
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    match mode {
        Mode::Default => {}
        Mode::Block => spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
        Mode::Standard => spend.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
        Mode::BlockWithoutChronicle => spend.set_flags(
            ScriptFlags::block(ProtocolEra::PostChronicle).without(ScriptFlags::CHRONICLE),
        ),
    }
    spend.validate().map_err(|e| e.message)
}

/// ALL | FORKID | CHRONICLE.
const CHRONICLE: u8 = 0x61;
/// ALL | FORKID (no Chronicle bit).
const PLAIN: u8 = 0x41;

/// THE GAP: at version 1 the default mode refuses the Chronicle bit in the
/// reference's words. Before #397 the bit was admitted and verification reached
/// (a false top). This is the row that is RED on 0.8.13.
#[test]
fn the_default_mode_refuses_the_chronicle_bit_at_version_one() {
    assert_eq!(run(CHRONICLE, 1, Mode::Default), Err(SIG_FORMAT.into()));
}

/// At version > 1 the default mode admits the bit (the reference relaxes): the
/// signature check is reached. The v1 ≠ v2 split isolates the version gate.
#[test]
fn the_default_mode_admits_the_chronicle_bit_at_version_two() {
    assert_eq!(run(CHRONICLE, 2, Mode::Default), Err(EVAL_FALSE.into()));
}

/// The gate is Chronicle-specific: a plain FORKID signature at version 1 is not
/// refused by it (it reaches the signature check).
#[test]
fn a_plain_signature_at_version_one_is_not_touched_by_the_gate() {
    assert_eq!(run(PLAIN, 1, Mode::Default), Err(EVAL_FALSE.into()));
}

/// The word path is unchanged: a word carrying CHRONICLE admits the bit at
/// version 1 (where the default refuses it) and reaches the signature check.
#[test]
fn a_chronicle_word_admits_the_bit_at_version_one() {
    assert_eq!(run(CHRONICLE, 1, Mode::Block), Err(NULLFAIL.into()));
    assert_eq!(run(CHRONICLE, 1, Mode::Standard), Err(NULLFAIL.into()));
}

/// The word path is unchanged: a post-Chronicle word WITHOUT CHRONICLE refuses
/// the bit in its own words, independently of the transaction version.
#[test]
fn a_word_without_chronicle_refuses_the_bit_in_its_own_words() {
    assert_eq!(
        run(CHRONICLE, 1, Mode::BlockWithoutChronicle),
        Err(CHRONICLE_BEFORE.into())
    );
    assert_eq!(
        run(CHRONICLE, 2, Mode::BlockWithoutChronicle),
        Err(CHRONICLE_BEFORE.into())
    );
}
