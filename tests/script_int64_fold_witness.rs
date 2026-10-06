//! The `int64` operand reader above 8 bytes, as the node reads it: the cases
//! of the public reading record of the specification's ruling R1
//! (bsv-script-lean, `docs/records/20261006-010651-r1-reading-public.md`,
//! section 3 the cases, section 4 the rule). Each case is the record's lock,
//! `<00..0f> <offset> OP_4 OP_SUBSTR <04050607> OP_EQUAL`, in a version-2 spend
//! of a coin created after Chronicle; only the offset operand varies. For an
//! operand of 9 bytes and more the measured builds of bitcoin-sv v1.2.2
//! (`879fc8b`) OR every byte but the last into a 64-bit pattern at bit
//! position `8 * (i mod 8)`, drop the last byte, read no sign bit, and take
//! the pattern as a two's-complement `int64` (`int_serialization.h:70-82`; the
//! shift at `:75` is undefined in C++ from the tenth byte, so the rule is the
//! measured builds'). 0.3.31 read the first 8 bytes alone: 0 where the node
//! reads 4 on the record's 10-byte, 16-byte and 17-byte operands.
//!
//! Lengths 1, 9 and 10 are measured on the node; 16 and 17 on builds of the
//! same source, the node's own runs owed; 11 through 15 and 18 and above are
//! UNMEASURED, the rule extended by its mechanism (the specification's D178
//! scope). The default mode keeps the TypeScript SDK's script-number reading.
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

// ---- the record's section 3, one test for each case ----

/// `f1-offset-10-bytes`, `00 x8 04 01`: the ninth byte folds onto byte 0's
/// position and the tenth is dropped, so 4 and VALID on the block and the
/// mempool path (measured on the node). 0.3.31 read 0.
#[test]
fn f1_offset_10_bytes_reads_4() {
    assert_reads(Some(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 1]), 4);
}

/// `f1-control-offset-op4`, `04` pushed by `OP_4`: 4, the defined region.
#[test]
fn f1_control_offset_op4_reads_4() {
    assert_reads(None, 4);
}

/// `f1-control-offset-9-bytes`, `00 x8 04`: the ninth byte is the last and is
/// dropped, so 0, the substring `00010203`, unequal (the node's
/// `SCRIPT_ERR_EVAL_FALSE`).
#[test]
fn f1_control_offset_9_bytes_reads_0() {
    let operand = [0, 0, 0, 0, 0, 0, 0, 0, 4];
    assert_reads(Some(&operand), 0);
    assert!(!run(&substr_lock(Some(&operand), "04050607"), Mode::Block).unwrap_or(false));
}

/// gen-00796, `04 00 x9`: byte 0 at bits 0 to 7 and zeros after it, so 4 and
/// VALID under both words (measured on the node; it cannot tell the fold from
/// the first-8-bytes reading).
#[test]
fn gen_00796_reads_4() {
    assert_reads(Some(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 4);
}

/// `f1-offset-16-bytes`, `00 x8 04 00 x6 01`: 4 (measured on builds of the
/// reference source, the node's own run owed). 0.3.31 read 0.
#[test]
fn f1_offset_16_bytes_reads_4() {
    assert_reads(Some(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 1]), 4);
}

/// `f1-offset-17-bytes`, `00 x8 04 00 x7 01`: 4, the scalar reading of the
/// record's rule (two of the three measured builds; the vectorized arm64
/// archive reads 0, and the node's own run is owed). 0.3.31 read 0.
#[test]
fn f1_offset_17_bytes_reads_4() {
    assert_reads(
        Some(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1]),
        4,
    );
}

/// `f1-control-offset-17-bytes-byte0`, `04 00 x15 01`: 4 on every measured build.
#[test]
fn f1_control_offset_17_bytes_byte0_reads_4() {
    assert_reads(
        Some(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        4,
    );
}

// ---- the boundary lengths ----

/// 8 bytes, the end of the defined region: the sign-magnitude reading, the
/// last byte's bit 7 the sign. Unchanged.
#[test]
fn length_8_is_the_defined_sign_magnitude_reading() {
    assert_reads(Some(&[4, 0, 0, 0, 0, 0, 0, 0]), 4);
    assert_out_of_range(&[4, 0, 0, 0, 0, 0, 0, 0x80], -4);
}

/// 9 bytes: the first 8 as a two's-complement `int64`, the ninth dropped
/// whatever it is, no sign bit read.
#[test]
fn length_9_drops_its_ninth_byte() {
    assert_reads(Some(&[4, 0, 0, 0, 0, 0, 0, 0, 0x80]), 4);
    assert_reads(Some(&[4, 0, 0, 0, 0, 0, 0, 0, 0x7f]), 4);
    // ff x8 is -1 in two's complement, saturated by nothing, out of range
    assert_out_of_range(&[0xff; 9], -1);
}

/// 10 bytes: the ninth byte is OR-ed onto byte 0's position (not added, not
/// replacing it) and the tenth is dropped.
#[test]
fn length_10_ors_its_ninth_byte_onto_byte_0() {
    assert_reads(Some(&[1, 0, 0, 0, 0, 0, 0, 0, 4, 1]), 5);
    assert_reads(Some(&[4, 0, 0, 0, 0, 0, 0, 0, 4, 1]), 4);
    assert_reads(Some(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0x84]), 2);
}

/// 11 bytes, the smallest length no record measures on any build
/// (UNMEASURED): by the rule's mechanism byte 9 lands on byte 1's position,
/// so `00 x9 01 01` is 256, out of range, and byte 8 still lands on byte 0's.
#[test]
fn length_11_unmeasured_folds_with_period_8() {
    assert_out_of_range(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1], 256);
    assert_reads(Some(&[0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1]), 3);
}

/// 17 bytes, the largest measured length: byte 16 is the last and dropped,
/// bytes 8 to 15 fold onto positions 0 to 7.
#[test]
fn length_17_the_largest_measured_drops_byte_16() {
    assert_reads(
        Some(&[2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x81]),
        6,
    );
    // byte 15 on position 7: the pattern's top bit, a negative int64
    // saturated to INT_MIN by the reference's getint
    assert_out_of_range(
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 1],
        i64::from(i32::MIN),
    );
}

/// 18 bytes, the smallest length above every measurement (UNMEASURED): by the
/// rule's mechanism byte 16 starts the third period on byte 0's position.
#[test]
fn length_18_unmeasured_folds_its_third_period() {
    assert_reads(
        Some(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 1]),
        7,
    );
    assert_reads(
        Some(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1]),
        4,
    );
}

/// The same reader on the length operand of `OP_LEFT` and `OP_RIGHT`
/// (`interpreter.cpp:651-653`, `676-678`; the record measured `OP_SUBSTR`'s
/// offset, these two sites share its `CScriptNum` constructor by the source).
#[test]
fn op_left_and_op_right_read_the_folded_length() {
    let operand = [0, 0, 0, 0, 0, 0, 0, 0, 4, 1];
    for mode in [Mode::Block, Mode::Standard] {
        assert_eq!(run(&lock(Some(&operand), "b4040001020387"), mode), Ok(true));
        assert_eq!(run(&lock(Some(&operand), "b5040c0d0e0f87"), mode), Ok(true));
    }
}

/// The default mode is unchanged: the record's 10-byte operand is a script
/// number too large for the range, as the TypeScript SDK reads it.
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
