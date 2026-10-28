//! The splice operands' reading in the default mode is the reference's
//! (bsv-rs#382; `ts-stack@edf6e03` `packages/sdk/src/script/Spend.ts`), each
//! verdict below the one the reference gives under Node 22 for the same
//! script (`@bsv/sdk` bundled at `edf6e03`; the outcomes quoted per test).
//!
//! `OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` read their operands with
//! `#readSpliceOperand` (`Spend.ts:540-561`): the minimal-encoding check when
//! MINIMALDATA holds, an operand of at most 8 bytes as a script number, a
//! longer one as its first 8 bytes in two's complement (`BigInt.asIntN(64,
//! ..)`, the bytes after the eighth unread), the value clamped to the `int`
//! range. Until #382 this crate read every byte of a longer operand as a
//! sign-magnitude number and clamped nothing. `OP_SPLIT`'s position and
//! `OP_NUM2BIN`'s size are read whole (`#readScriptNumber`, `:1913`,
//! `:1930`); the size's refusals are the reference's words in its order
//! (`:1931-1950`). Under a word nothing moves: the node's fixed-width reading
//! of 0.3.33 (bsv-rs#41, `tests/script_int64_operand_witness.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// A push of `hex` (at most 75 bytes; the empty push is `OP_0`).
fn push(hex: &str) -> String {
    let n = hex.len() / 2;
    assert!(n < 76);
    if n == 0 {
        "00".to_string()
    } else {
        format!("{n:02x}{hex}")
    }
}

/// The unlocking script pushes `pushes`; the locking script is `lock`. No
/// memory budget unless `memory_limit` names one.
fn spend(version: i32, pushes: &[&str], lock: &str, memory_limit: Option<usize>) -> Spend {
    let unlock: String = pushes.iter().map(|p| push(p)).collect();
    Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_binary(&from_hex(lock).unwrap()).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&from_hex(&unlock).unwrap()).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit,
        work_limit: None,
    })
}

/// The default mode at transaction version 2 (relaxed: no MINIMALDATA).
fn default_v2(pushes: &[&str], lock: &str) -> Result<bool, String> {
    spend(2, pushes, lock, None)
        .validate()
        .map_err(|e| e.message)
}

/// The block word after Chronicle, on a coin created after it.
fn block_word(pushes: &[&str], lock: &str) -> Result<bool, String> {
    let mut s = spend(2, pushes, lock, None);
    s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    s.set_utxo_after_chronicle(true);
    s.validate().map_err(|e| e.message)
}

const DATA: &str = "aabbcc";
/// `OP_LEFT`, `OP_RIGHT`, `OP_SUBSTR`, `OP_SPLIT`, `OP_NUM2BIN`, `OP_EQUAL`.
const LEFT: &str = "b4";
const RIGHT: &str = "b5";
const SUBSTR: &str = "b3";
const SPLIT: &str = "7f";
const NUM2BIN: &str = "80";

/// 2^64 + 2: minimal in 9 bytes, its first 8 bytes the number 2.
const NINE_TWO: &str = "020000000000000001";
/// 2^64 + 1: its first 8 bytes the number 1.
const NINE_ONE: &str = "010000000000000001";
/// 2^64: its first 8 bytes zero.
const NINE_ZERO: &str = "000000000000000001";
/// `fe`, `ff` seven times, `01`: its first 8 bytes -2 in two's complement
/// (a huge positive number in sign-magnitude, read as -1 before #382).
const NINE_MINUS_TWO: &str = "feffffffffffffff01";
/// -2 in 9 bytes, not minimal (the sign in the ninth byte): its first 8 bytes
/// the number 2.
const NINE_TWO_SIGNED: &str = "020000000000000080";
/// 2^56 + 2: the longest operand the reference reads as a script number.
const EIGHT_BIG: &str = "0200000000000001";
/// 2^31: one past `INT_MAX` in 5 bytes.
const FIVE_2POW31: &str = "0000008000";
/// -(2^31 + 1): past `INT_MIN`.
const FIVE_BELOW_INT_MIN: &str = "0100008080";

const SPLIT_RANGE: &str = "OP_SPLIT requires the first stack item to be a non-negative number less than or equal to the size of the second-from-top stack item.";

// ============================================================================
// OP_LEFT
// ============================================================================

/// Reference: `ok true`. A 9-byte length is its first 8 bytes, 2: `aabb`.
/// Before #382: `OP_LEFT length (-1) must be in range [0, 3]` (2^64 past an
/// `i64`, read as -1).
#[test]
fn issue_382_a_9_byte_left_length_is_its_first_8_bytes() {
    assert_eq!(default_v2(&[DATA, NINE_TWO], "b402aabb87"), Ok(true));
}

/// Reference: `The top stack element must be truthy after script
/// evaluation.`: the first 8 bytes of 2^64 are 0, `OP_LEFT` leaves the empty
/// element. Before #382: the range refusal at -1.
#[test]
fn issue_382_a_9_byte_left_length_whose_first_8_bytes_are_zero_takes_nothing() {
    assert_eq!(
        default_v2(&[DATA, NINE_ZERO], LEFT),
        Err("The top stack element must be truthy after script evaluation.".to_string())
    );
}

/// Reference: `OP_LEFT length (-2) must be in range [0, 3]`: two's complement,
/// not sign-magnitude, past the eighth byte.
#[test]
fn issue_382_a_9_byte_left_length_is_read_in_twos_complement() {
    assert_eq!(
        default_v2(&[DATA, NINE_MINUS_TWO], LEFT),
        Err("OP_LEFT length (-2) must be in range [0, 3]".to_string())
    );
}

/// Reference: `ok true` at version 2 (no MINIMALDATA): a non-minimal 9-byte
/// -2 whose first 8 bytes are 2. Before #382: `OP_LEFT length (-2) ...`.
#[test]
fn issue_382_a_non_minimal_9_byte_length_is_read_without_minimaldata() {
    assert_eq!(default_v2(&[DATA, NINE_TWO_SIGNED], "b402aabb87"), Ok(true));
}

/// Reference: `non-minimally encoded script number` at version 1
/// (MINIMALDATA): refused before it is read, in the reference's words since
/// #397 (the same verdict before #382), and `0xb4` run as `OP_LEFT` at
/// version 1 in the default mode as the reference runs it (#397).
#[test]
fn a_non_minimal_9_byte_length_is_refused_under_minimaldata() {
    let got = spend(1, &[DATA, NINE_TWO_SIGNED], LEFT, None)
        .validate()
        .map_err(|e| e.message);
    assert_eq!(got, Err("non-minimally encoded script number".to_string()));
}

/// Reference: `OP_LEFT length (2147483647) must be in range [0, 3]`: the
/// longest operand read as a number (8 bytes), clamped to `INT_MAX`. Before
/// #382: `OP_LEFT length (72057594037927938) ...`.
#[test]
fn issue_382_an_8_byte_left_length_is_clamped_to_int_max() {
    assert_eq!(
        default_v2(&[DATA, EIGHT_BIG], LEFT),
        Err("OP_LEFT length (2147483647) must be in range [0, 3]".to_string())
    );
}

/// Reference: `OP_LEFT length (2147483647) ...` for 2^31 and
/// `OP_LEFT length (-2147483648) ...` for -(2^31 + 1): the clamp at both ends.
#[test]
fn issue_382_a_left_length_past_the_int_range_is_clamped_at_both_ends() {
    assert_eq!(
        default_v2(&[DATA, FIVE_2POW31], LEFT),
        Err("OP_LEFT length (2147483647) must be in range [0, 3]".to_string())
    );
    assert_eq!(
        default_v2(&[DATA, FIVE_BELOW_INT_MIN], LEFT),
        Err("OP_LEFT length (-2147483648) must be in range [0, 3]".to_string())
    );
}

// ============================================================================
// OP_RIGHT and OP_SUBSTR
// ============================================================================

/// Reference: `ok true`: a 9-byte length of first-8-bytes 1 takes `cc`.
#[test]
fn issue_382_a_9_byte_right_length_is_its_first_8_bytes() {
    assert_eq!(default_v2(&[DATA, NINE_ONE], "b501cc87"), Ok(true));
}

/// Reference: `ok true`: offset and length both 9 bytes of first-8-bytes 1,
/// `bb`.
#[test]
fn issue_382_9_byte_substr_operands_are_their_first_8_bytes() {
    assert_eq!(
        default_v2(&[DATA, NINE_ONE, NINE_ONE], "b301bb87"),
        Ok(true)
    );
}

/// Reference: `OP_SUBSTR offset (2147483647) must be in range [0, 3) and
/// length (1) must be in range [0, -2147483644]`: an 8-byte offset clamped.
#[test]
fn issue_382_an_8_byte_substr_offset_is_clamped_to_int_max() {
    assert_eq!(
        default_v2(&[DATA, EIGHT_BIG, "01"], SUBSTR),
        Err("OP_SUBSTR offset (2147483647) must be in range [0, 3) and length (1) must be in range [0, -2147483644]".to_string())
    );
}

/// Reference: `ok true` for a 100-byte length whose first 8 bytes are 1: the
/// bytes after the eighth are never read (no number of them is built).
#[test]
fn issue_382_the_bytes_after_the_eighth_are_unread() {
    let long = format!("01{}{}", "00".repeat(98), "7f");
    let lock = format!("4c64{long}{RIGHT}01cc87");
    assert_eq!(default_v2(&[DATA], &lock), Ok(true));
}

// ============================================================================
// OP_SPLIT and OP_NUM2BIN: read whole, as before
// ============================================================================

/// Reference: the range refusal for a 9-byte and an 8-byte position (read
/// whole, `#readScriptNumber`); `ok true` for a non-minimal 8-byte 1 at
/// version 2. The same here before and after #382.
#[test]
fn split_reads_its_position_whole() {
    assert_eq!(
        default_v2(&[DATA, NINE_ONE], SPLIT),
        Err(SPLIT_RANGE.to_string())
    );
    assert_eq!(
        default_v2(&[DATA, "0100000000000001"], SPLIT),
        Err(SPLIT_RANGE.to_string())
    );
    assert_eq!(
        default_v2(&[DATA, "0100000000000000"], "7f02bbcc8801aa87"),
        Ok(true)
    );
}

/// Reference: `OP_NUM2BIN size exceeds the node int32 push limit.` for 2^64 +
/// 1 and for 2^31. Before #382: `It's not currently possible to push data
/// larger than 1073741824 bytes or negative size.`
#[test]
fn issue_382_a_num2bin_size_above_int32_max_is_the_references_refusal() {
    for size in [NINE_ONE, FIVE_2POW31] {
        assert_eq!(
            default_v2(&["01", size], NUM2BIN),
            Err("OP_NUM2BIN size exceeds the node int32 push limit.".to_string())
        );
    }
}

/// Reference: `It's not currently possible to push data larger than Infinity
/// bytes or negative size.` (its push size unbounded in the default mode).
/// Before #382: the same sentence with 1073741824.
#[test]
fn issue_382_a_negative_num2bin_size_is_the_references_refusal() {
    assert_eq!(
        default_v2(&["01", "81"], NUM2BIN),
        Err(
            "It's not currently possible to push data larger than Infinity bytes or negative size."
                .to_string()
        )
    );
}

/// The reference refuses a size above a caller's budget as `element-size`
/// before anything else allocates (`Spend.ts:1944-1950`); above the 1 GiB
/// element bound too (this crate's bound, which the reference has not).
/// Before #382 a size past 1 GiB was the bound's verdict under any budget.
#[test]
fn issue_382_a_num2bin_size_past_1_gib_under_a_budget_is_a_decline() {
    let err = spend(2, &["01", "ffffff7f"], NUM2BIN, Some(1 << 20))
        .validate()
        .expect_err("a decline");
    assert!(err.is_resource_limit(), "{}", err.message);
    assert_eq!(err.resource_limit.unwrap().attempted, 0x7fff_ffff);
}

// ============================================================================
// Under a word: the node's reading of 0.3.33, unchanged
// ============================================================================

/// The block word reads a 9-byte operand as the node's checked `int64`: a
/// ninth byte other than 0 or 0x80 overflows; the clamp after it is the
/// node's `getint`.
#[test]
fn under_the_block_word_the_nodes_reading_holds() {
    let overflow = Err("Script number overflow: operand does not fit int64.".to_string());
    assert_eq!(block_word(&[DATA, NINE_TWO], LEFT), overflow);
    assert_eq!(block_word(&[DATA, NINE_ONE], RIGHT), overflow);
    assert_eq!(block_word(&[DATA, NINE_ONE, "01"], SUBSTR), overflow);
    assert_eq!(
        block_word(&[DATA, EIGHT_BIG], LEFT),
        Err("OP_LEFT length (2147483647) must be in range [0, 3]".to_string())
    );
    assert_eq!(
        block_word(&[DATA, NINE_ONE], SPLIT),
        Err(SPLIT_RANGE.to_string())
    );
    assert_eq!(
        block_word(&["01", FIVE_2POW31], NUM2BIN),
        Err("OP_NUM2BIN requires a size from 0 to 2147483647, found 2147483648.".to_string())
    );
}
