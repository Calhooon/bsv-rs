//! An undefined base hash type on a witness from the differential run against
//! bitcoin-sv v1.2.2 (`879fc8b`), Calhooon/bsv-rs#23. Under
//! `SCRIPT_VERIFY_STRICTENC` the reference's `CheckSignatureEncoding` refuses a
//! signature whose hash type is not defined (`interpreter.cpp:291-294`,
//! `SCRIPT_ERR_SIG_HASHTYPE`): `SigHashType::isDefined` (`sighashtype.h:82-90`)
//! clears the CHRONICLE, FORKID and ANYONECANPAY bits and requires what is left
//! to be ALL (1), NONE (2) or SINGLE (3). Both the block word and the mempool
//! word carry STRICTENC. 0.3.28 tested the DER form, the low-S rule and the
//! FORKID bit and never the base type, so a signature made over the BIP143
//! digest of an undefined type verified.
//!
//! The witness: a version-2 P2PK spend of a coin created after Chronicle whose
//! signature carries the hash type `0x44` (base 4 | FORKID), made over that
//! type's BIP143 digest: `SCRIPT_ERR_SIG_HASHTYPE` on the reference on both
//! paths, valid on 0.3.28 under every word and mode. Its two siblings carry
//! `0x40` (base 0) and `0x5f` (base 31). The boundary cases re-type the
//! witness's DER signature: a defined base passes the encoding test and the
//! signature then fails to verify (a false top), an undefined one is refused
//! before verification.
//!
//! Every outpoint is synthetic; the previous outputs never existed on any chain.
use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// The witness (143 bytes): the hash type `0x44`.
const TX_BASE_4: &str = "020000000125791529f09e5a55816bbaa4af97e10d2daa713ba646c10f49188d48c34592cd0000000048473044022064a7c97306f384b1c0189ca11ea35b638c277c6e7d07d93dbc9559b9a8e3309302200f77d025cfe41099d5808179ae4764fa8d4bca3238b97506c4d56e9147d6e90044ffffffff02010000000000000001510200000000000000015100000000";
/// Its siblings: the hash type `0x40` (base 0) and `0x5f` (base 31).
const TX_BASE_0: &str = "0200000001a6b53aec60ece796f2dc6140d671898132231b4854fe03b836187b5949e5d4090000000049483045022100b1a8c03572e265631ae89a64d2f3f524ac16b15044526d8ce64f09ecf18b683b0220290753b242c9df3829720dbbf4a4d12308a40cc2bca6f7c9746f43e32006241c40ffffffff02010000000000000001510200000000000000015100000000";
const TX_BASE_31: &str = "0200000001b8cabbfe87152537c5154412d0825e123a651140d5eaff48b4b9c204513cedfb000000004847304402206b2433a71007fad0eb1d50ef805434adb3de41503652764695eb20cf3c3982c8022038ecd8cade4bcb6abe917417ed7c2e1ba44a957e6c6641d7fcf9d88c9bdfde865fffffffff02010000000000000001510200000000000000015100000000";
/// `<pubkey> OP_CHECKSIG`, the coin all three spend (1,000 satoshis, created after Chronicle).
const LOCK: &str = "2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac";
/// The witness's 70-byte DER signature without its hash-type byte.
const DER: &str = "3044022064a7c97306f384b1c0189ca11ea35b638c277c6e7d07d93dbc9559b9a8e3309302200f77d025cfe41099d5808179ae4764fa8d4bca3238b97506c4d56e9147d6e900";

const EVAL_FALSE: &str = "The top stack element must be truthy after script evaluation.";

fn sig_hashtype(t: u8) -> String {
    format!("The signature's hash type (0x{t:02x}) has no defined base type.")
}

#[derive(Clone, Copy)]
enum Mode {
    Block,
    Standard,
    Default,
    /// The block word without STRICTENC: the reference does not test the base
    /// type without the flag.
    BlockWithoutStrictenc,
}

fn spend_with(tx_hex: &str, unlock: Option<Vec<u8>>, mode: Mode) -> Result<bool, String> {
    let tx = parse_transaction(&from_hex(tx_hex).unwrap()).unwrap();
    let input = &tx.inputs[0];
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    let unlocking = unlock.unwrap_or_else(|| input.script.clone());
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(LOCK).unwrap(),
        transaction_version: tx.version,
        other_inputs: vec![],
        outputs,
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&unlocking).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
    });
    match mode {
        Mode::Block => spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
        Mode::Standard => spend.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
        Mode::BlockWithoutStrictenc => spend.set_flags(
            ScriptFlags::block(ProtocolEra::PostChronicle).without(ScriptFlags::STRICTENC),
        ),
        Mode::Default => {}
    }
    spend.set_utxo_after_chronicle(true);
    spend.validate().map_err(|e| e.message)
}

fn run(tx_hex: &str, mode: Mode) -> Result<bool, String> {
    spend_with(tx_hex, None, mode)
}

/// The witness's signature with another hash-type byte.
fn run_type(hash_type: u8, mode: Mode) -> Result<bool, String> {
    let mut unlock = vec![0x47];
    unlock.extend(from_hex(DER).unwrap());
    unlock.push(hash_type);
    spend_with(TX_BASE_4, Some(unlock), mode)
}

/// The witness under the block word: refused before verification.
#[test]
fn the_witness_is_refused_under_the_block_word() {
    assert_eq!(run(TX_BASE_4, Mode::Block), Err(sig_hashtype(0x44)));
}

/// And on the mempool path.
#[test]
fn the_witness_is_refused_under_the_standard_word() {
    assert_eq!(run(TX_BASE_4, Mode::Standard), Err(sig_hashtype(0x44)));
}

/// And in the default mode (the TypeScript SDK refuses it too).
#[test]
fn the_witness_is_refused_in_the_default_mode() {
    assert_eq!(run(TX_BASE_4, Mode::Default), Err(sig_hashtype(0x44)));
}

/// The two siblings: base 0 and base 31.
#[test]
fn the_siblings_with_base_0_and_base_31_are_refused() {
    assert_eq!(run(TX_BASE_0, Mode::Block), Err(sig_hashtype(0x40)));
    assert_eq!(run(TX_BASE_31, Mode::Block), Err(sig_hashtype(0x5f)));
    assert_eq!(run(TX_BASE_0, Mode::Default), Err(sig_hashtype(0x40)));
    assert_eq!(run(TX_BASE_31, Mode::Default), Err(sig_hashtype(0x5f)));
}

/// Without STRICTENC the reference does not test the base type: the witness's
/// signature, made over the BIP143 digest of `0x44`, then verifies.
#[test]
fn without_strictenc_the_base_type_is_not_tested() {
    assert_eq!(run(TX_BASE_4, Mode::BlockWithoutStrictenc), Ok(true));
}

/// A defined base passes the test whatever the other bits (cleared before the
/// comparison): the re-typed signature then fails to verify, a false top.
#[test]
fn a_defined_base_passes_the_test_with_any_of_the_other_bits() {
    for t in [
        0x41u8, 0x42, 0x43, 0xc1, 0xc2, 0xc3, 0x61, 0x62, 0x63, 0xe1, 0xe2, 0xe3,
    ] {
        assert_eq!(
            run_type(t, Mode::Block),
            Err(EVAL_FALSE.to_string()),
            "type 0x{t:02x}"
        );
        assert_eq!(
            run_type(t, Mode::Default),
            Err(EVAL_FALSE.to_string()),
            "type 0x{t:02x}"
        );
    }
}

/// An undefined base is refused whatever the other bits.
#[test]
fn an_undefined_base_is_refused_with_any_of_the_other_bits() {
    for t in [0x40u8, 0x44, 0x5f, 0xc0, 0xc4, 0x60, 0x64, 0x7f, 0xff] {
        assert_eq!(
            run_type(t, Mode::Block),
            Err(sig_hashtype(t)),
            "type 0x{t:02x}"
        );
        assert_eq!(
            run_type(t, Mode::Standard),
            Err(sig_hashtype(t)),
            "type 0x{t:02x}"
        );
        assert_eq!(
            run_type(t, Mode::Default),
            Err(sig_hashtype(t)),
            "type 0x{t:02x}"
        );
    }
}
