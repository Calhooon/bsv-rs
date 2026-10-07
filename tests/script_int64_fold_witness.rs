//! Splice operand boundary cases for bitcoin-sv v1.2.3 at
//! `6504a3aff65ba97c0f6c80962b033e35ecbfed4b` (Calhooon/bsv-rs#41).
//! The witness ids and bytes are retained from the specification's public
//! corpus. Expectations follow `int_serialization.h:61-118`,
//! `script_num.cpp:80-91`, and `interpreter.cpp:1807-1809`.
use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// The witness transaction of `script_int64_operand_witness.rs` (61 bytes,
/// version 2, an empty unlocking script): nothing in these scripts signs.
const TX: &str = "0200000001bd713e289714213b3d76b5168a550fe3bc8bee30363eb9a72795e051c88686500000000000ffffffff010100000000000000015100000000";

/// The 16 bytes the lock pushes.
const DATA: &str = "000102030405060708090a0b0c0d0e0f";

#[derive(Clone, Copy)]
enum Mode {
    Block,
    Standard,
    Default,
}

/// `<00..0f> <operand> <tail>`, the operand as a direct push (or `OP_4` when
/// `operand` is `None`, the record's `f1-control-offset-op4`).
fn lock(operand: Option<&[u8]>, tail: &str) -> String {
    let push = match operand {
        Some(bytes) => {
            assert!((1..=75).contains(&bytes.len()));
            format!("{:02x}{}", bytes.len(), to_hex(bytes))
        }
        None => "54".to_string(),
    };
    format!("10{DATA}{push}{tail}")
}

/// The record's lock: `OP_4 OP_SUBSTR <expected> OP_EQUAL`.
fn substr_lock(operand: Option<&[u8]>, expected: &str) -> String {
    lock(operand, &format!("54b304{expected}87"))
}

fn run(lock_hex: &str, mode: Mode) -> Result<bool, String> {
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
        locking_script: LockingScript::from_hex(lock_hex).unwrap(),
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

/// The operand reads `value` (0 to 12) under both words: the record's lock
/// against `04050607` is valid exactly when the value is 4, and the same lock
/// against the 4 bytes at `value` is valid.
fn assert_reads(operand: Option<&[u8]>, value: usize) {
    let data = from_hex(DATA).unwrap();
    let at_value = to_hex(&data[value..value + 4]);
    for mode in [Mode::Block, Mode::Standard] {
        assert_eq!(run(&substr_lock(operand, &at_value), mode), Ok(true));
        assert_eq!(
            run(&substr_lock(operand, "04050607"), mode).unwrap_or(false),
            value == 4
        );
    }
}

/// The refusal of a negative or oversized offset under both words.
fn assert_out_of_range(operand: &[u8], value: i64) {
    let refusal = format!(
        "OP_SUBSTR offset ({value}) must be in range [0, 16) and length (4) must be in range [0, {}]",
        16 - value
    );
    for mode in [Mode::Block, Mode::Standard] {
        assert_eq!(
            run(&substr_lock(Some(operand), "04050607"), mode),
            Err(refusal.clone())
        );
    }
}

fn assert_fixed_width_refusal(operand: &[u8]) {
    for mode in [Mode::Block, Mode::Standard] {
        assert_eq!(
            run(&substr_lock(Some(operand), "04050607"), mode),
            Err("Script number overflow: operand does not fit int64.".to_string())
        );
    }
}

#[test]
fn f1_offset_10_bytes_is_refused() {
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 1]);
}

#[test]
fn f1_control_offset_op4_reads_4() {
    assert_reads(None, 4);
}

#[test]
fn f1_control_offset_9_bytes_with_magnitude_in_the_sign_byte_is_refused() {
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 4]);
}

#[test]
fn gen_00796_is_refused() {
    assert_fixed_width_refusal(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn f1_offset_16_bytes_is_refused() {
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn f1_offset_17_bytes_is_refused() {
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn f1_control_offset_17_bytes_byte0_is_refused() {
    assert_fixed_width_refusal(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn length_8_uses_sign_magnitude() {
    assert_reads(Some(&[4, 0, 0, 0, 0, 0, 0, 0]), 4);
    assert_out_of_range(&[4, 0, 0, 0, 0, 0, 0, 0x80], -4);
}

#[test]
fn length_9_checks_and_respects_its_sign_byte() {
    assert_reads(Some(&[4, 0, 0, 0, 0, 0, 0, 0, 0]), 4);
    assert_out_of_range(&[4, 0, 0, 0, 0, 0, 0, 0, 0x80], -4);
    assert_fixed_width_refusal(&[4, 0, 0, 0, 0, 0, 0, 0, 0x7f]);
    assert_fixed_width_refusal(&[0xff; 9]);
}

#[test]
fn length_10_is_refused() {
    assert_fixed_width_refusal(&[1, 0, 0, 0, 0, 0, 0, 0, 4, 1]);
    assert_fixed_width_refusal(&[4, 0, 0, 0, 0, 0, 0, 0, 4, 1]);
    assert_fixed_width_refusal(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0x84]);
}

#[test]
fn length_11_is_refused() {
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]);
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1]);
}

#[test]
fn length_17_is_refused() {
    assert_fixed_width_refusal(&[2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x81]);
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 1]);
}

#[test]
fn length_18_is_refused() {
    assert_fixed_width_refusal(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 1]);
    assert_fixed_width_refusal(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1]);
}

#[test]
fn op_left_and_op_right_use_the_checked_length() {
    let operand = [0, 0, 0, 0, 0, 0, 0, 0, 4, 1];
    for mode in [Mode::Block, Mode::Standard] {
        for tail in ["b4040001020387", "b5040c0d0e0f87"] {
            assert_eq!(
                run(&lock(Some(&operand), tail), mode),
                Err("Script number overflow: operand does not fit int64.".to_string())
            );
        }
    }
}

#[test]
fn the_default_mode_keeps_the_script_number_reading() {
    let operand = [0, 0, 0, 0, 0, 0, 0, 0, 4, 1];
    assert!(run(&substr_lock(Some(&operand), "04050607"), Mode::Default).is_err());
    assert_eq!(
        run(
            &substr_lock(Some(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0]), "04050607"),
            Mode::Default
        ),
        Ok(true)
    );
}
