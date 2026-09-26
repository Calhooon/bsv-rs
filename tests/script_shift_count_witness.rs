//! The two bounds of the numeric shifts on a witness from the differential run
//! against bitcoin-sv v1.2.2 (`879fc8b`), Calhooon/bsv-rs#21. The reference
//! reads the count and the value of `OP_LSHIFTNUM`/`OP_RSHIFTNUM` as big
//! integers (`interpreter.cpp:708-711`, `744-747`) and applies
//! `CScriptNum::operator<<=` / `operator>>=` (`script_num.cpp`): a count above
//! `INT_MAX` throws `big_int_error` (`big_int.cpp:359-369`, `383-393`), caught
//! as `SCRIPT_ERR_BIG_INT` (`interpreter.cpp:1819-1821`); a left shift first
//! refuses a result whose size, the value's serialized size plus `count / 8`
//! bytes, would exceed the era's maximum number length (`script_num.cpp:305-308`,
//! `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`), before any allocation. 0.3.28 shifted by
//! any count (`1 OP_RSHIFTNUM 2147483648` was 0, a valid spend) and tested a
//! left shift only against its local memory budget (a resource limit, not a
//! verdict). The default mode keeps the TypeScript SDK's behaviour.
use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::evaluation_error::ScriptEvaluationError;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// The witness: `OP_1 <00 00 00 80 00> OP_RSHIFTNUM OP_DROP OP_1`, a count of
/// 2,147,483,648 (`INT_MAX + 1`) on a coin created after Chronicle.
const TX_RSHIFT_MAX_PLUS_1: &str = "0200000001829896aed1733429283adb214280217591f00929568490f2c8530c8a9f7260310000000000ffffffff010100000000000000015100000000";
const LOCK_RSHIFT_MAX_PLUS_1: &str = "51050000008000b77551";
/// `OP_1 <ff ff ff 7f> OP_LSHIFTNUM OP_DROP OP_1`: a count of `INT_MAX`; the
/// result would be 268,435,456 bytes, over the 32,000,000-byte limit.
const TX_LSHIFT_MAX: &str = "0200000001503dd6f80c4ebe381c7c8fb609d1555c2ea5fa2aa59f002acd05151f46c7ad5d0000000000ffffffff010100000000000000015100000000";
const LOCK_LSHIFT_MAX: &str = "5104ffffff7fb67551";
/// `OP_1 <00 00 00 80 00> OP_LSHIFTNUM OP_DROP OP_1`: `INT_MAX + 1`; the size
/// test runs before the count test, so an overflow.
const TX_LSHIFT_MAX_PLUS_1: &str = "02000000012a4aa0d24750ee397d887a857a0de7c12a20d98fe721c56397326a6216513ff90000000000ffffffff010100000000000000015100000000";
const LOCK_LSHIFT_MAX_PLUS_1: &str = "51050000008000b67551";
/// Boundary locks, run on the witness transaction (nothing here signs).
/// `OP_1 <ff ff ff 7f> OP_RSHIFTNUM OP_DROP OP_1`: a right shift by `INT_MAX` is 0, valid.
const LOCK_RSHIFT_MAX: &str = "5104ffffff7fb77551";
/// `OP_0 <00 00 00 80 00> OP_LSHIFTNUM OP_DROP OP_1`: the size test counts the
/// shift alone (0 + 2^28 bytes), an overflow even on a zero value.
const LOCK_LSHIFT_ZERO_MAX_PLUS_1: &str = "00050000008000b67551";
/// `OP_0 <00 00 00 80 00> OP_RSHIFTNUM OP_DROP OP_1`: no size test on a right
/// shift, so the count test: a big-integer error even on a zero value.
const LOCK_RSHIFT_ZERO_MAX_PLUS_1: &str = "00050000008000b77551";
/// `OP_1 OP_8 OP_LSHIFTNUM <256 as 00 01> OP_EQUAL`: an ordinary shift, unchanged.
const LOCK_LSHIFT_SMALL: &str = "5158b6020001 87";

#[derive(Clone, Copy)]
enum Mode {
    Block,
    Standard,
    Default,
}

/// The interpreter's error is boxed here only to keep the `Result` small for
/// clippy; the assertions read its fields through the box.
fn spend(
    tx_hex: &str,
    lock_hex: &str,
    mode: Mode,
    utxo_after_chronicle: bool,
) -> Result<bool, Box<ScriptEvaluationError>> {
    let lock_hex: String = lock_hex.chars().filter(|c| !c.is_whitespace()).collect();
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
    let mut s = Spend::new(SpendParams {
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
        Mode::Block => s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
        Mode::Standard => s.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
        Mode::Default => {}
    }
    s.set_utxo_after_chronicle(utxo_after_chronicle);
    s.validate().map_err(Box::new)
}

fn run(tx_hex: &str, lock_hex: &str, mode: Mode) -> Result<bool, String> {
    spend(tx_hex, lock_hex, mode, true).map_err(|e| e.message)
}

const BIG_INT: &str = "OP_RSHIFTNUM count (2147483648) does not fit an int.";
/// 1 byte (the value 1) + 2,147,483,647 / 8 = 268,435,456 bytes.
const OVERFLOW_MAX: &str = "Script number overflow: 268435456 bytes, the limit is 32000000 bytes.";
/// 1 byte + 2,147,483,648 / 8 = 268,435,457 bytes.
const OVERFLOW_MAX_PLUS_1: &str =
    "Script number overflow: 268435457 bytes, the limit is 32000000 bytes.";
/// 0 bytes (the value 0) + 268,435,456.
const OVERFLOW_ZERO_MAX_PLUS_1: &str =
    "Script number overflow: 268435456 bytes, the limit is 32000000 bytes.";

/// The witness under the block word: the count does not fit an `int`.
#[test]
fn the_witness_is_a_big_integer_error_under_the_block_word() {
    assert_eq!(
        run(TX_RSHIFT_MAX_PLUS_1, LOCK_RSHIFT_MAX_PLUS_1, Mode::Block),
        Err(BIG_INT.to_string())
    );
}

/// And under the standard word.
#[test]
fn the_witness_is_a_big_integer_error_under_the_standard_word() {
    assert_eq!(
        run(TX_RSHIFT_MAX_PLUS_1, LOCK_RSHIFT_MAX_PLUS_1, Mode::Standard),
        Err(BIG_INT.to_string())
    );
}

/// The default mode shifts by any count, as the TypeScript SDK does: 0, valid
/// (0.3.28's verdict under every word).
#[test]
fn the_witness_is_valid_in_the_default_mode() {
    assert_eq!(
        run(TX_RSHIFT_MAX_PLUS_1, LOCK_RSHIFT_MAX_PLUS_1, Mode::Default),
        Ok(true)
    );
}

/// A right shift by `INT_MAX` fits the count's bound: 1 >> INT_MAX is 0, valid.
#[test]
fn a_right_shift_by_int_max_is_valid() {
    assert_eq!(
        run(TX_RSHIFT_MAX_PLUS_1, LOCK_RSHIFT_MAX, Mode::Block),
        Ok(true)
    );
    assert_eq!(
        run(TX_RSHIFT_MAX_PLUS_1, LOCK_RSHIFT_MAX, Mode::Default),
        Ok(true)
    );
}

/// The left shift by `INT_MAX`: the size test before the shift refuses a
/// 268,435,456-byte result, no allocation. 0.3.28 stopped at its memory
/// budget with no verdict; the default mode still does.
#[test]
fn a_left_shift_by_int_max_overflows_the_number_length_under_a_word() {
    assert_eq!(
        run(TX_LSHIFT_MAX, LOCK_LSHIFT_MAX, Mode::Block),
        Err(OVERFLOW_MAX.to_string())
    );
    // the mempool path tests against the node's policy default of 10,000 bytes
    assert_eq!(
        run(TX_LSHIFT_MAX, LOCK_LSHIFT_MAX, Mode::Standard),
        Err("Script number overflow: 268435456 bytes, the limit is 10000 bytes.".to_string())
    );
    let default = spend(TX_LSHIFT_MAX, LOCK_LSHIFT_MAX, Mode::Default, true).unwrap_err();
    assert!(
        default.resource_limit.is_some(),
        "the default mode's local budget, not a verdict"
    );
}

/// The left shift by `INT_MAX + 1`: the size test runs first, so an overflow,
/// not the big-integer error.
#[test]
fn a_left_shift_by_int_max_plus_1_overflows_before_the_count_test() {
    assert_eq!(
        run(TX_LSHIFT_MAX_PLUS_1, LOCK_LSHIFT_MAX_PLUS_1, Mode::Block),
        Err(OVERFLOW_MAX_PLUS_1.to_string())
    );
    let default = spend(
        TX_LSHIFT_MAX_PLUS_1,
        LOCK_LSHIFT_MAX_PLUS_1,
        Mode::Default,
        true,
    )
    .unwrap_err();
    assert!(
        default.resource_limit.is_some(),
        "the default mode's local budget, not a verdict"
    );
}

/// On a zero value: the left shift's size test counts the shift alone
/// (`script_num.cpp:305-307`), an overflow; the right shift has no size test,
/// so the count test, a big-integer error.
#[test]
fn a_zero_value_follows_the_same_tests() {
    assert_eq!(
        run(
            TX_RSHIFT_MAX_PLUS_1,
            LOCK_LSHIFT_ZERO_MAX_PLUS_1,
            Mode::Block
        ),
        Err(OVERFLOW_ZERO_MAX_PLUS_1.to_string())
    );
    assert_eq!(
        run(
            TX_RSHIFT_MAX_PLUS_1,
            LOCK_RSHIFT_ZERO_MAX_PLUS_1,
            Mode::Block
        ),
        Err(BIG_INT.to_string())
    );
    // the default mode: 0 shifted is 0 either way, valid
    assert_eq!(
        run(
            TX_RSHIFT_MAX_PLUS_1,
            LOCK_LSHIFT_ZERO_MAX_PLUS_1,
            Mode::Default
        ),
        Ok(true)
    );
    assert_eq!(
        run(
            TX_RSHIFT_MAX_PLUS_1,
            LOCK_RSHIFT_ZERO_MAX_PLUS_1,
            Mode::Default
        ),
        Ok(true)
    );
}

/// An ordinary shift is unchanged: 1 << 8 = 256.
#[test]
fn an_ordinary_left_shift_is_unchanged() {
    assert_eq!(
        run(TX_RSHIFT_MAX_PLUS_1, LOCK_LSHIFT_SMALL, Mode::Block),
        Ok(true)
    );
    assert_eq!(
        run(TX_RSHIFT_MAX_PLUS_1, LOCK_LSHIFT_SMALL, Mode::Default),
        Ok(true)
    );
}

/// For a coin created before Chronicle the two opcodes are NOPs under the
/// block word (`interpreter.cpp:700-706`, `738-744`), whatever the count.
#[test]
fn a_coin_created_before_chronicle_sees_a_nop() {
    assert_eq!(
        spend(
            TX_RSHIFT_MAX_PLUS_1,
            LOCK_RSHIFT_MAX_PLUS_1,
            Mode::Block,
            false
        )
        .map_err(|e| e.message),
        Ok(true)
    );
    assert_eq!(
        spend(
            TX_LSHIFT_MAX_PLUS_1,
            LOCK_LSHIFT_MAX_PLUS_1,
            Mode::Block,
            false
        )
        .map_err(|e| e.message),
        Ok(true)
    );
}
