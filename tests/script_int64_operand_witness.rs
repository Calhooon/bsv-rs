//! Fixed-width splice witnesses under bitcoin-sv v1.2.3 at
//! `6504a3aff65ba97c0f6c80962b033e35ecbfed4b` (Calhooon/bsv-rs#41).
//! `int_serialization.h:61-118` defines the checked sign-magnitude decoding;
//! `script_num.cpp:80-91` and `interpreter.cpp:1807-1809` define its error.
//! Both node words and the TypeScript SDK default mode are exercised.
use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// The witness transaction (61 bytes, one input, one output); its locking
/// script is `LOCK_9_SIGN`. The boundary cases below reuse the transaction
/// with another locking script: nothing in these scripts signs.
const TX: &str = "0200000001bd713e289714213b3d76b5168a550fe3bc8bee30363eb9a72795e051c88686500000000000ffffffff010100000000000000015100000000";

/// `<00..0f> <04 00 00 00 00 00 00 00 80> OP_4 OP_SUBSTR <04050607> OP_EQUAL`: the witness.
const LOCK_9_SIGN: &str = "10000102030405060708090a0b0c0d0e0f0904000000000000008054b3040405060787";
/// The same with an 8-byte operand `04 00 00 00 00 00 00 80`: −4 as a script number on both sides.
const LOCK_8_SIGN: &str = "10000102030405060708090a0b0c0d0e0f08040000000000008054b3040405060787";
/// The same with a 9-byte operand whose ninth byte is zero: 4 on both sides.
const LOCK_9_PAD: &str = "10000102030405060708090a0b0c0d0e0f0904000000000000000054b3040405060787";
/// The same with a 10-byte operand: outside the fixed-width encoding limit.
const LOCK_10_PAD: &str =
    "10000102030405060708090a0b0c0d0e0f0a0400000000000000000054b3040405060787";
/// `<00..0f> <04 00 00 00 00 00 00 00 80> OP_LEFT <00010203> OP_EQUAL`: the same reading on the length operand of `OP_LEFT`.
const LOCK_LEFT_9_SIGN: &str =
    "10000102030405060708090a0b0c0d0e0f09040000000000000080b4040001020387";
/// `<00..0f> <04 00 00 00 00 00 00 00 80> OP_RIGHT <0c0d0e0f> OP_EQUAL`: and of `OP_RIGHT`.
const LOCK_RIGHT_9_SIGN: &str =
    "10000102030405060708090a0b0c0d0e0f09040000000000000080b5040c0d0e0f87";
/// `<00..0f> <ff ff ff ff ff ff ff 7f> OP_4 OP_SUBSTR <04050607> OP_EQUAL`: an
/// 8-byte offset of `INT64_MAX`, saturated to `INT_MAX` by the reference's
/// `getint` (`script_num.cpp:396-422`) and out of range on both sides.
const LOCK_8_MAX: &str = "10000102030405060708090a0b0c0d0e0f08ffffffffffffff7f54b3040405060787";

#[derive(Clone, Copy)]
enum Mode {
    Block,
    Standard,
    Default,
}

fn run(lock_hex: &str, mode: Mode) -> Result<bool, String> {
    let lock_hex: String = lock_hex.chars().filter(|c| !c.is_whitespace()).collect();
    let tx = parse_transaction(&from_hex(TX).unwrap()).unwrap();
    let input = &tx.inputs[0];
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(&lock_hex).unwrap(),
        transaction_version: tx.version,
        other_inputs: vec![],
        outputs,
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
    });
    match mode {
        Mode::Block => spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
        Mode::Standard => spend.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
        Mode::Default => {}
    }
    // the coin was created after Chronicle: the opcodes are live
    spend.set_utxo_after_chronicle(true);
    spend.validate().map_err(|e| e.message)
}

const RANGE_REFUSAL_MINUS_4: &str =
    "OP_SUBSTR offset (-4) must be in range [0, 16) and length (4) must be in range [0, 20]";

/// The witness under the block word: the operand is -4, outside the range.
#[test]
fn the_witness_is_a_range_refusal_under_the_block_word() {
    assert_eq!(
        run(LOCK_9_SIGN, Mode::Block),
        Err(RANGE_REFUSAL_MINUS_4.to_string())
    );
}

/// And on the mempool path: the operand is not required minimal at version 2
/// (the non-malleability gate, `interpreter.cpp:40-44`), so the same reading.
#[test]
fn the_witness_is_a_range_refusal_under_the_standard_word() {
    assert_eq!(
        run(LOCK_9_SIGN, Mode::Standard),
        Err(RANGE_REFUSAL_MINUS_4.to_string())
    );
}

/// The default mode keeps the TypeScript SDK's reading: −4, a range refusal
/// under the TypeScript SDK number reader.
#[test]
fn the_witness_is_a_range_refusal_in_the_default_mode() {
    assert_eq!(
        run(LOCK_9_SIGN, Mode::Default),
        Err(RANGE_REFUSAL_MINUS_4.to_string())
    );
}

/// Eight bytes with the sign bit set is −4 on both sides: the ordinary
/// sign-magnitude reading, refused as out of range under a word and in the
/// default mode.
#[test]
fn an_8_byte_operand_with_its_sign_bit_set_is_minus_4_on_both_sides() {
    assert_eq!(
        run(LOCK_8_SIGN, Mode::Block),
        Err(RANGE_REFUSAL_MINUS_4.to_string())
    );
    assert_eq!(
        run(LOCK_8_SIGN, Mode::Default),
        Err(RANGE_REFUSAL_MINUS_4.to_string())
    );
}

/// Nine bytes with a zero ninth byte is 4 on both sides.
#[test]
fn a_9_byte_operand_with_a_zero_ninth_byte_is_4() {
    assert_eq!(run(LOCK_9_PAD, Mode::Block), Ok(true));
    assert_eq!(run(LOCK_9_PAD, Mode::Default), Ok(true));
}

/// The fixed-width path refuses ten bytes; the default mode reads 4.
#[test]
fn a_10_byte_operand_is_refused_under_a_word() {
    for mode in [Mode::Block, Mode::Standard] {
        assert_eq!(
            run(LOCK_10_PAD, mode),
            Err("Script number overflow: operand does not fit int64.".to_string())
        );
    }
    assert_eq!(run(LOCK_10_PAD, Mode::Default), Ok(true));
}

/// The same reading on the length operand of `OP_LEFT` and `OP_RIGHT`
/// (`interpreter.cpp:655-656`, `680-681`).
#[test]
fn op_left_and_op_right_read_their_length_the_same_way() {
    for mode in [Mode::Block, Mode::Standard] {
        assert_eq!(
            run(LOCK_LEFT_9_SIGN, mode),
            Err("OP_LEFT length (-4) must be in range [0, 16]".to_string())
        );
        assert_eq!(
            run(LOCK_RIGHT_9_SIGN, mode),
            Err("OP_RIGHT length (-4) must be in range [0, 16]".to_string())
        );
    }
    assert_eq!(
        run(LOCK_LEFT_9_SIGN, Mode::Default),
        Err("OP_LEFT length (-4) must be in range [0, 16]".to_string())
    );
    assert_eq!(
        run(LOCK_RIGHT_9_SIGN, Mode::Default),
        Err("OP_RIGHT length (-4) must be in range [0, 16]".to_string())
    );
}

/// An 8-byte `INT64_MAX` offset saturates to `INT_MAX` on the reference and
/// is out of range on both sides.
#[test]
fn a_large_8_byte_offset_is_out_of_range_on_both_sides() {
    assert!(run(LOCK_8_MAX, Mode::Block).is_err());
    assert!(run(LOCK_8_MAX, Mode::Default).is_err());
}
