//! The stack memory budget under a word, on witnesses from the differential
//! run against bitcoin-sv v1.2.2 (`879fc8b`), Calhooon/bsv-rs#30. After Genesis
//! the reference bounds a script's memory by one budget per path, and by
//! nothing else (`src/consensus/consensus.h:81-82`): the node counts the main
//! and the alt stack together (the alt stack is a child of the main stack,
//! `src/script/interpreter.cpp:1993`, `src/script/limitedstack.cpp:196-199`),
//! each element at its size plus 32 bytes (`LimitedVector::ELEMENT_OVERHEAD`,
//! `src/script/limitedstack.h:43`), and refuses a growth that would exceed the
//! budget before it happens (`limitedstack.cpp:194-209`; a pad is charged
//! before the resize, `:66` then `:68`), `SCRIPT_ERR_STACK_SIZE`
//! (`interpreter.cpp:1815-1817`). On the block path the budget is no constant
//! but the operator's mandatory `-maxstackmemoryusageconsensus` (the node does
//! not start without it, `src/bitcoind.cpp:140-157`; 0 means `INT64_MAX`,
//! `src/configscriptpolicy.cpp:280-283`, `consensus.h:82`); on the mempool
//! path it is the node's `-maxstackmemoryusagepolicy`, 100,000,000 bytes by
//! default (`src/policy/policy.h:153`; `GetMaxStackMemoryUsage`,
//! `src/configscriptpolicy.cpp:139-154`).
//! `OP_NUM2BIN` refuses a size below 0 or above `INT32_MAX` with
//! `SCRIPT_ERR_PUSH_SIZE` before anything is allocated
//! (`interpreter.cpp:1747-1749`).
//!
//! 0.3.29 applied a local 32,000,000-byte budget in every mode, each stack
//! apart, counting the bytes alone, and stopped every witness below with a
//! resource limit (no verdict) where the reference decides. Under a word
//! 0.3.30 counts as the node counts, with a local budget of 100,000,000 bytes
//! on both paths (on the block path a resource limit, the node's own figure
//! being its operator's setting, which this crate cannot know) and the
//! policy's verdict on the mempool path; the default mode keeps 0.3.29's
//! budget and count. The two `OP_LSHIFTNUM` witnesses of
//! the same family, by `INT_MAX` and `INT_MAX + 1`, are pinned since 0.3.29 in
//! `tests/script_shift_count_witness.rs`.
//!
//! Every row names what it allocates; the rows that allocate tens of megabytes
//! run one at a time (`HEAVY`).
use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::flags::{DEFAULT_STACK_MEMORY_USAGE_POLICY, STACK_ELEMENT_OVERHEAD};
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, ScriptResource, Spend, SpendParams, UnlockingScript,
};
use std::sync::{Mutex, MutexGuard};

/// gen-00009: `OP_1 <32,000,001> OP_NUM2BIN OP_1ADD OP_DROP OP_1` on a coin
/// created after Chronicle. The node builds the element (32,000,033 bytes on
/// its count) and `OP_1ADD`'s read refuses it at the era's number length:
/// `SCRIPT_ERR_SCRIPTNUM_OVERFLOW` on both paths.
const TX_READ_32000001: &str = "02000000010282f68044beaa91d8f3424e5499046c9a2fc62222344f786bdf10882a0dcb050000000000ffffffff010100000000000000015100000000";
const LOCK_READ_32000001: &str = "51040148e801808b7551";
/// gen-00837: `OP_1 <255,999,992> OP_LSHIFTNUM OP_DROP OP_1`: 2^255,999,992 is
/// exactly 32,000,000 bytes: valid on the block path, over the policy's number
/// length on the mempool path.
const TX_SHIFT_AT_WIDTH: &str = "020000000188ff7652209492801e7845ba25b446b8bfe34cd1840af382dd6d55dc323f86510000000000ffffffff010100000000000000015100000000";
const LOCK_SHIFT_AT_WIDTH: &str = "5104f83f420fb67551";
/// gen-00838: `OP_1 <256,000,000> OP_LSHIFTNUM OP_DROP OP_1`: the size test
/// before the shift fails (1 + 32,000,000 bytes).
const TX_SHIFT_OVER_WIDTH: &str = "02000000019b4268a2acf6c06f35a22cd21ddd350d89b57a588e9aab80a90369f1406a47a00000000000ffffffff010100000000000000015100000000";
const LOCK_SHIFT_OVER_WIDTH: &str = "51040040420fb67551";
/// gen-00839: `OP_1 <255,999,999> OP_LSHIFTNUM OP_DROP OP_1`: the size test
/// before the shift passes (1 + 31,999,999 bytes) and the result's top byte is
/// 0x80, so it takes a sign byte, 32,000,001 bytes: the size test after the
/// shift fails (`src/script/script_num.cpp:315-316`).
const TX_SHIFT_SIGN_BYTE: &str = "020000000130764b0bd4e481b72d3e25340480db3adfe11d0af95c2a7880e9116be3f7b5110000000000ffffffff010100000000000000015100000000";
const LOCK_SHIFT_SIGN_BYTE: &str = "5104ff3f420fb67551";
/// stack-00227: the unlocking script `OP_1`, the locking script
/// `<40,000,000> OP_NUM2BIN OP_SIZE <40,000,000> OP_EQUAL OP_NIP`: a
/// 40,000,000-byte element, within the node's budget on both paths: valid.
const TX_NUM2BIN_40M: &str = "02000000016f34f2d0251b3daa8f4fceda5679f220b289f671eaafef33213ff7143d935c75000000000151ffffffff010100000000000000015100000000";
const LOCK_NUM2BIN_40M: &str = "04005a6202808204005a62028777";
/// stack-00217: the unlocking script `OP_1`, the locking script
/// `<2^31> OP_NUM2BIN OP_1`: a size above `INT32_MAX`, `SCRIPT_ERR_PUSH_SIZE`.
const TX_NUM2BIN_2POW31: &str = "020000000187a34732a06ac0f3edeca5c9a239399da4c91d80f507fbd34c06ce985d415f27000000000151ffffffff010100000000000000015100000000";
const LOCK_NUM2BIN_2POW31: &str = "0500000080008051";

/// Boundary locks, run on gen-00009's transaction (an empty unlocking script;
/// nothing here signs). `OP_1 <w> OP_NUM2BIN OP_DROP OP_1` costs the node
/// 33 bytes for `OP_1`, then `w - 1` bytes of pad: `w + 32` at its peak.
/// `w` = 99,999,968: exactly 100,000,000 on the node's count.
const LOCK_PAD_AT_POLICY: &str = "5104e0e0f505807551";
/// `w` = 99,999,969: 100,000,001.
const LOCK_PAD_OVER_POLICY: &str = "5104e1e0f505807551";
/// Two elements of 49,999,968 bytes, one moved to the alt stack:
/// `OP_1 <w> OP_NUM2BIN OP_TOALTSTACK OP_1 <w> OP_NUM2BIN OP_DROP OP_FROMALTSTACK
/// OP_DROP OP_1`: 2 × (49,999,968 + 32) = 100,000,000 over the two stacks.
const LOCK_SPLIT_AT_POLICY: &str = "510460f0fa02806b510460f0fa0280756c7551";
/// The second element one byte longer: 100,000,001.
const LOCK_SPLIT_OVER_SECOND: &str = "510460f0fa02806b510461f0fa0280756c7551";
/// The first element one byte longer: 100,000,001 at the second pad.
const LOCK_SPLIT_OVER_FIRST: &str = "510461f0fa02806b510460f0fa0280756c7551";
/// An unlocking script that leaves one element of 49,999,968 bytes on the alt
/// stack: `OP_1 <w> OP_NUM2BIN OP_TOALTSTACK` (not push-only: a version-2
/// spend after Chronicle).
const UNLOCK_ALT_RESIDUE: &str = "510460f0fa02806b";
/// `OP_1 <49,999,968> OP_NUM2BIN OP_DROP OP_1`: 50,000,000 on top of the residue.
const LOCK_PAD_HALF: &str = "510460f0fa02807551";
/// `OP_1 <49,999,969> OP_NUM2BIN OP_DROP OP_1`: 50,000,001 on top of it.
const LOCK_PAD_HALF_PLUS_1: &str = "510461f0fa02807551";
/// `OP_1 <INT32_MAX> OP_NUM2BIN OP_DROP OP_1`: 33 + 2,147,483,646 of pad.
const LOCK_PAD_INT32_MAX: &str = "5104ffffff7f807551";
/// `OP_1 OP_1NEGATE OP_NUM2BIN OP_DROP OP_1`.
const LOCK_PAD_NEGATIVE: &str = "514f807551";

#[derive(Clone, Copy, Debug)]
enum Mode {
    Block,
    Standard,
    Default,
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Valid,
    Verdict(String),
    Resource {
        resource: ScriptResource,
        limit: usize,
        attempted: usize,
    },
}

use Outcome::{Resource, Valid, Verdict};

/// The rows that allocate tens of megabytes run one at a time, so this binary
/// holds about 100 MB at its peak whatever the test threads.
static HEAVY: Mutex<()> = Mutex::new(());

fn heavy() -> MutexGuard<'static, ()> {
    HEAVY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs `lock` against the input of `tx_hex` (its own unlocking script, or
/// `unlock_hex`) under `mode` on a coin created after Chronicle, `tune`
/// applied after the word.
fn outcome(
    tx_hex: &str,
    unlock_hex: Option<&str>,
    lock_hex: &str,
    mode: Mode,
    memory_limit: Option<usize>,
    tune: impl FnOnce(&mut Spend),
) -> Outcome {
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
    let unlocking_script = match unlock_hex {
        Some(hex) => UnlockingScript::from_hex(hex).unwrap(),
        None => UnlockingScript::from_binary(&input.script).unwrap(),
    };
    let mut s = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(lock_hex).unwrap(),
        transaction_version: tx.version,
        other_inputs: vec![],
        outputs,
        input_index: 0,
        unlocking_script,
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit,
    });
    match mode {
        Mode::Block => s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
        Mode::Standard => s.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
        Mode::Default => {}
    }
    s.set_utxo_after_chronicle(true);
    tune(&mut s);
    match s.validate() {
        Ok(valid) => {
            assert!(valid, "validate returns Ok(true) or an error");
            Valid
        }
        Err(e) => match e.resource_limit {
            Some(limit) => Resource {
                resource: limit.resource,
                limit: limit.limit,
                attempted: limit.attempted,
            },
            None => Verdict(e.message),
        },
    }
}

/// The witness transaction's own unlocking script, the default local budget.
fn run(tx_hex: &str, lock_hex: &str, mode: Mode) -> Outcome {
    outcome(tx_hex, None, lock_hex, mode, None, |_| {})
}

fn verdict(message: &str) -> Outcome {
    Verdict(message.to_string())
}

/// The word's local budget on the node's count.
fn over_word_budget(attempted: usize) -> Outcome {
    Resource {
        resource: ScriptResource::Stack,
        limit: 100_000_000,
        attempted,
    }
}

fn over_policy(attempted: usize) -> Outcome {
    verdict(&format!(
        "Stack size limit exceeded: {attempted} bytes, the stack memory policy is 100000000 bytes."
    ))
}

const OVERFLOW_READ_BLOCK: &str =
    "Script number overflow: 32000001 bytes, the limit is 32000000 bytes.";
const OVERFLOW_READ_POLICY: &str =
    "Script number overflow: 32000001 bytes, the limit is 10000 bytes.";
const OVERFLOW_32000000_POLICY: &str =
    "Script number overflow: 32000000 bytes, the limit is 10000 bytes.";
const PUSH_SIZE_2POW31: &str = "OP_NUM2BIN requires a size from 0 to 2147483647, found 2147483648.";
const PUSH_SIZE_NEGATIVE: &str = "OP_NUM2BIN requires a size from 0 to 2147483647, found -1.";
const DEFAULT_PUSH_SIZE: &str =
    "It's not currently possible to push data larger than 1073741824 bytes or negative size.";

// ============================================================================
// The witnesses
// ============================================================================

/// gen-00009 under the block word: the 32,000,001-byte element is built, then
/// `OP_1ADD`'s read refuses it at the era's number length. Allocates 32 MB.
#[test]
fn the_32000001_byte_read_overflows_under_the_block_word() {
    let _heavy = heavy();
    assert_eq!(
        run(TX_READ_32000001, LOCK_READ_32000001, Mode::Block),
        verdict(OVERFLOW_READ_BLOCK)
    );
}

/// gen-00009 under the standard word: the same element, the read refused at
/// the policy's number length. Allocates 32 MB.
#[test]
fn the_32000001_byte_read_overflows_under_the_standard_word() {
    let _heavy = heavy();
    assert_eq!(
        run(TX_READ_32000001, LOCK_READ_32000001, Mode::Standard),
        verdict(OVERFLOW_READ_POLICY)
    );
}

/// gen-00009 in the default mode: 0.3.29's local budget, refused before the
/// allocation, as before. Allocates nothing.
#[test]
fn the_32000001_byte_read_is_the_default_modes_resource_limit() {
    assert_eq!(
        run(TX_READ_32000001, LOCK_READ_32000001, Mode::Default),
        Resource {
            resource: ScriptResource::ElementSize,
            limit: 32_000_000,
            attempted: 32_000_001,
        }
    );
}

/// gen-00837: the shift to exactly 32,000,000 bytes is valid on the block
/// path (0.3.29: its estimate of 32,000,001 bytes stopped at the local
/// budget). Allocates 32 MB.
#[test]
fn a_left_shift_to_exactly_32000000_bytes_is_valid_under_the_block_word() {
    let _heavy = heavy();
    assert_eq!(
        run(TX_SHIFT_AT_WIDTH, LOCK_SHIFT_AT_WIDTH, Mode::Block),
        Valid
    );
}

/// gen-00837 on the mempool path: the size test before the shift, against the
/// policy's number length. Allocates nothing.
#[test]
fn a_left_shift_to_exactly_32000000_bytes_overflows_the_policy() {
    assert_eq!(
        run(TX_SHIFT_AT_WIDTH, LOCK_SHIFT_AT_WIDTH, Mode::Standard),
        verdict(OVERFLOW_32000000_POLICY)
    );
    assert_eq!(
        run(TX_SHIFT_AT_WIDTH, LOCK_SHIFT_AT_WIDTH, Mode::Default),
        Resource {
            resource: ScriptResource::ElementSize,
            limit: 32_000_000,
            attempted: 32_000_001,
        }
    );
}

/// gen-00838: the size test before the shift, on both paths. Allocates nothing.
#[test]
fn a_left_shift_over_the_width_overflows_before_the_shift() {
    assert_eq!(
        run(TX_SHIFT_OVER_WIDTH, LOCK_SHIFT_OVER_WIDTH, Mode::Block),
        verdict(OVERFLOW_READ_BLOCK)
    );
    assert_eq!(
        run(TX_SHIFT_OVER_WIDTH, LOCK_SHIFT_OVER_WIDTH, Mode::Standard),
        verdict(OVERFLOW_READ_POLICY)
    );
}

/// gen-00839: the size test after the shift, decided on the result's exact
/// length before it is allocated (0.3.29: its estimate of 32,000,002 bytes
/// stopped at the local budget). Allocates nothing.
#[test]
fn a_left_shift_whose_result_takes_a_sign_byte_overflows_after_the_shift() {
    assert_eq!(
        run(TX_SHIFT_SIGN_BYTE, LOCK_SHIFT_SIGN_BYTE, Mode::Block),
        verdict(OVERFLOW_READ_BLOCK)
    );
    assert_eq!(
        run(TX_SHIFT_SIGN_BYTE, LOCK_SHIFT_SIGN_BYTE, Mode::Standard),
        verdict(OVERFLOW_32000000_POLICY)
    );
    assert_eq!(
        run(TX_SHIFT_SIGN_BYTE, LOCK_SHIFT_SIGN_BYTE, Mode::Default),
        Resource {
            resource: ScriptResource::ElementSize,
            limit: 32_000_000,
            attempted: 32_000_002,
        }
    );
}

/// stack-00227: a 40,000,000-byte element, valid on both paths (0.3.29: the
/// local budget). Allocates 40 MB per word.
#[test]
fn a_40000000_byte_element_is_valid_under_both_words() {
    let _heavy = heavy();
    assert_eq!(run(TX_NUM2BIN_40M, LOCK_NUM2BIN_40M, Mode::Block), Valid);
    assert_eq!(run(TX_NUM2BIN_40M, LOCK_NUM2BIN_40M, Mode::Standard), Valid);
    assert_eq!(
        run(TX_NUM2BIN_40M, LOCK_NUM2BIN_40M, Mode::Default),
        Resource {
            resource: ScriptResource::ElementSize,
            limit: 32_000_000,
            attempted: 40_000_000,
        }
    );
}

/// stack-00217: a size above `INT32_MAX` is `SCRIPT_ERR_PUSH_SIZE` under a word
/// (0.3.29's message named its 1 GiB element bound; the default mode keeps
/// it). Allocates nothing.
#[test]
fn a_num2bin_size_above_int32_max_is_a_push_size_refusal() {
    assert_eq!(
        run(TX_NUM2BIN_2POW31, LOCK_NUM2BIN_2POW31, Mode::Block),
        verdict(PUSH_SIZE_2POW31)
    );
    assert_eq!(
        run(TX_NUM2BIN_2POW31, LOCK_NUM2BIN_2POW31, Mode::Standard),
        verdict(PUSH_SIZE_2POW31)
    );
    assert_eq!(
        run(TX_NUM2BIN_2POW31, LOCK_NUM2BIN_2POW31, Mode::Default),
        verdict(DEFAULT_PUSH_SIZE)
    );
}

// ============================================================================
// The budget's edges at the node's figures
// ============================================================================

/// A negative size is `SCRIPT_ERR_PUSH_SIZE` too. Allocates nothing.
#[test]
fn a_negative_num2bin_size_is_a_push_size_refusal() {
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_NEGATIVE, Mode::Block),
        verdict(PUSH_SIZE_NEGATIVE)
    );
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_NEGATIVE, Mode::Default),
        verdict(DEFAULT_PUSH_SIZE)
    );
}

/// A size of `INT32_MAX` passes the size bound; its growth is charged before
/// the resize, so it is refused with nothing allocated: the policy's verdict
/// on the mempool path, the local budget on the block path (a node run with
/// `-maxstackmemoryusageconsensus=0` allocates 2 GiB and goes on; this crate
/// declines).
#[test]
fn a_num2bin_to_int32_max_is_refused_before_it_is_allocated() {
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_INT32_MAX, Mode::Standard),
        over_policy(2_147_483_679)
    );
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_INT32_MAX, Mode::Block),
        over_word_budget(2_147_483_679)
    );
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_INT32_MAX, Mode::Default),
        verdict(DEFAULT_PUSH_SIZE)
    );
}

/// The policy's edge on the mempool path: exactly 100,000,000 on the node's
/// count is accepted (the test is `>`, `limitedstack.cpp:202`). Allocates
/// 100 MB.
#[test]
fn the_stack_memory_policy_admits_exactly_its_figure() {
    let _heavy = heavy();
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_AT_POLICY, Mode::Standard),
        Valid
    );
}

/// One byte more is the policy's verdict, refused before the pad. Allocates
/// nothing.
#[test]
fn one_byte_over_the_stack_memory_policy_is_a_verdict() {
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_OVER_POLICY, Mode::Standard),
        over_policy(100_000_001)
    );
}

/// The block path at the same figures: exactly 100,000,000 is within the local
/// budget (allocates 100 MB); one byte more is a resource limit, never a
/// verdict (allocates nothing).
#[test]
fn the_block_path_declines_above_its_local_budget() {
    let _heavy = heavy();
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_AT_POLICY, Mode::Block),
        Valid
    );
    assert_eq!(
        run(TX_READ_32000001, LOCK_PAD_OVER_POLICY, Mode::Block),
        over_word_budget(100_000_001)
    );
}

/// The main and the alt stack share one budget: two elements of 49,999,968
/// bytes, one on each stack, are exactly 100,000,000. Allocates 100 MB per
/// word.
#[test]
fn the_two_stacks_share_one_budget() {
    let _heavy = heavy();
    assert_eq!(
        run(TX_READ_32000001, LOCK_SPLIT_AT_POLICY, Mode::Standard),
        Valid
    );
    assert_eq!(
        run(TX_READ_32000001, LOCK_SPLIT_AT_POLICY, Mode::Block),
        Valid
    );
}

/// One byte more on either element is over the one budget, though each stack
/// holds half of it. Allocates 50 MB per row.
#[test]
fn one_byte_over_the_shared_budget_on_either_stack() {
    let _heavy = heavy();
    for lock in [LOCK_SPLIT_OVER_SECOND, LOCK_SPLIT_OVER_FIRST] {
        assert_eq!(
            run(TX_READ_32000001, lock, Mode::Standard),
            over_policy(100_000_001)
        );
        assert_eq!(
            run(TX_READ_32000001, lock, Mode::Block),
            over_word_budget(100_000_001)
        );
    }
}

/// An alt stack the unlocking script leaves non-empty stays charged while the
/// locking script runs, as on the node, whose alt stack is created per script
/// and dropped without releasing its elements' charge (`LimitedStack`
/// declares no destructor, `limitedstack.h:78-151`). Allocates 100 MB.
#[test]
fn the_unlocking_scripts_alt_stack_stays_charged() {
    let _heavy = heavy();
    assert_eq!(
        outcome(
            TX_READ_32000001,
            Some(UNLOCK_ALT_RESIDUE),
            LOCK_PAD_HALF,
            Mode::Standard,
            None,
            |_| {}
        ),
        Valid
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            Some(UNLOCK_ALT_RESIDUE),
            LOCK_PAD_HALF_PLUS_1,
            Mode::Standard,
            None,
            |_| {}
        ),
        over_policy(100_000_001)
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            Some(UNLOCK_ALT_RESIDUE),
            LOCK_PAD_HALF_PLUS_1,
            Mode::Block,
            None,
            |_| {}
        ),
        over_word_budget(100_000_001)
    );
}

/// A policy of 0 is no policy verdict (the node's consensus figure): the row
/// one byte over is the local budget's resource limit. Allocates nothing.
#[test]
fn a_policy_of_zero_leaves_the_local_budget() {
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            LOCK_PAD_OVER_POLICY,
            Mode::Standard,
            None,
            |s| s.set_stack_memory_policy(0)
        ),
        over_word_budget(100_000_001)
    );
}

/// An explicit budget wins in every mode: `Some(1000)` under a word stops at
/// 1,000 bytes on the node's count, a resource limit, not the policy's
/// verdict. Allocates nothing to speak of.
#[test]
fn an_explicit_budget_wins_under_a_word() {
    // `OP_1 <968> OP_NUM2BIN OP_DROP OP_1`: 968 + 32 = 1,000
    let at = "5102c803807551";
    // `OP_1 <969> OP_NUM2BIN OP_DROP OP_1`: 1,001
    let over = "5102c903807551";
    for mode in [Mode::Block, Mode::Standard] {
        assert_eq!(
            outcome(TX_READ_32000001, None, at, mode, Some(1000), |_| {}),
            Valid
        );
        assert_eq!(
            outcome(TX_READ_32000001, None, over, mode, Some(1000), |_| {}),
            Resource {
                resource: ScriptResource::Stack,
                limit: 1000,
                attempted: 1001,
            }
        );
    }
}

/// The two knobs are independent: a local budget above the policy leaves the
/// policy's verdict at its figure on the mempool path (allocates nothing),
/// and admits the element on the block path (allocates 100 MB).
#[test]
fn a_local_budget_above_the_policy_leaves_the_verdict() {
    let _heavy = heavy();
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            LOCK_PAD_OVER_POLICY,
            Mode::Standard,
            Some(200_000_000),
            |_| {}
        ),
        over_policy(100_000_001)
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            LOCK_PAD_OVER_POLICY,
            Mode::Block,
            Some(200_000_000),
            |_| {}
        ),
        Valid
    );
}

// ============================================================================
// The node's count at small figures (a small policy or budget; allocates
// nothing to speak of)
// ============================================================================

/// Each element costs its size plus 32 bytes under a word: three `OP_1` are
/// 99 bytes, four 132, over a budget of 100; the default mode counts the
/// bytes alone.
#[test]
fn each_element_costs_32_bytes_beyond_its_own() {
    assert_eq!(STACK_ELEMENT_OVERHEAD, 32);
    assert_eq!(DEFAULT_STACK_MEMORY_USAGE_POLICY, 100_000_000);
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            "515151",
            Mode::Block,
            Some(100),
            |_| {}
        ),
        Valid
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            "51515151",
            Mode::Block,
            Some(100),
            |_| {}
        ),
        Resource {
            resource: ScriptResource::Stack,
            limit: 100,
            attempted: 132,
        }
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            "51515151",
            Mode::Default,
            Some(100),
            |_| {}
        ),
        Valid
    );
}

/// The alt stack draws on the same budget under a word; the default mode
/// counts each stack apart.
#[test]
fn the_alt_stack_draws_on_the_same_budget() {
    // `OP_1 OP_TOALTSTACK` three times, then `OP_1`: 4 × 33 = 132
    let lock = "516b516b516b51";
    assert_eq!(
        outcome(TX_READ_32000001, None, lock, Mode::Block, Some(100), |_| {}),
        Resource {
            resource: ScriptResource::Stack,
            limit: 100,
            attempted: 132,
        }
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            lock,
            Mode::Default,
            Some(100),
            |_| {}
        ),
        Valid
    );
}

/// The policy's verdict, at a policy of 100 bytes: the mempool path refuses
/// the fourth `OP_1`; the block path ignores the policy.
#[test]
fn the_policy_is_a_verdict_on_the_mempool_path_only() {
    let policy_100 = |s: &mut Spend| s.set_stack_memory_policy(100);
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            "51515151",
            Mode::Standard,
            None,
            policy_100
        ),
        verdict("Stack size limit exceeded: 132 bytes, the stack memory policy is 100 bytes.")
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            "51515151",
            Mode::Block,
            None,
            policy_100
        ),
        Valid
    );
}

/// The unlocking script's alt stack stays charged, at a policy of 100 bytes:
/// two elements left there (66 bytes) and one `OP_1` in the locking script
/// (99) pass; a second `OP_1` (132) is refused though the main stack holds 33.
#[test]
fn the_alt_stack_residue_at_a_small_policy() {
    let policy_100 = |s: &mut Spend| s.set_stack_memory_policy(100);
    assert_eq!(
        outcome(
            TX_READ_32000001,
            Some("516b516b"),
            "51",
            Mode::Standard,
            None,
            policy_100
        ),
        Valid
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            Some("516b516b"),
            "5151",
            Mode::Standard,
            None,
            policy_100
        ),
        verdict("Stack size limit exceeded: 132 bytes, the stack memory policy is 100 bytes.")
    );
}

/// `OP_NUM2BIN`'s pad at a policy of 100 bytes: `OP_1 <w> OP_NUM2BIN` costs
/// `w + 32` at the pad: 67 and 68 pass, 69 is refused.
#[test]
fn the_pad_is_charged_before_the_resize() {
    let policy_100 = |s: &mut Spend| s.set_stack_memory_policy(100);
    for (w, expected) in [
        ("43", Valid),
        ("44", Valid),
        (
            "45",
            verdict("Stack size limit exceeded: 101 bytes, the stack memory policy is 100 bytes."),
        ),
    ] {
        let lock = format!("5101{w}807551");
        assert_eq!(
            outcome(
                TX_READ_32000001,
                None,
                &lock,
                Mode::Standard,
                None,
                policy_100
            ),
            expected,
            "OP_1 <0x{w}> OP_NUM2BIN"
        );
    }
}

/// The left shift's result is sized exactly before it is computed, one byte
/// per 8 bits of the magnitude plus the count and one for the sign's room: at
/// a number length of 16, 1 << 120 and 1 << 126 are 16 bytes, valid; 1 << 127
/// takes a sign byte, 17 bytes, the size test after the shift (the test before
/// it, 1 + 127 / 8 = 16, passes).
#[test]
fn the_left_shifts_result_is_sized_exactly() {
    let length_16 = |s: &mut Spend| s.set_script_num_length_policy(16);
    for (count, expected) in [
        ("0178", Valid),
        ("017e", Valid),
        (
            "017f",
            verdict("Script number overflow: 17 bytes, the limit is 16 bytes."),
        ),
    ] {
        let lock = format!("51{count}b67551");
        assert_eq!(
            outcome(
                TX_READ_32000001,
                None,
                &lock,
                Mode::Standard,
                None,
                length_16
            ),
            expected,
            "OP_1 <{count}> OP_LSHIFTNUM"
        );
    }
}

/// The left shift's result is charged as its push will charge it, before it is
/// computed: at a policy of 100 bytes, 1 << 480 (61 bytes, 93 on the count)
/// passes and 1 << 544 (69 bytes, 101) is refused.
#[test]
fn the_left_shifts_result_is_charged_before_it_is_computed() {
    let tune = |s: &mut Spend| {
        s.set_script_num_length_policy(1000);
        s.set_stack_memory_policy(100);
    };
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            "5102e001b67551",
            Mode::Standard,
            None,
            tune
        ),
        Valid
    );
    assert_eq!(
        outcome(
            TX_READ_32000001,
            None,
            "51022002b67551",
            Mode::Standard,
            None,
            tune
        ),
        verdict("Stack size limit exceeded: 101 bytes, the stack memory policy is 100 bytes.")
    );
}

/// The budgets in force, as the accessors report them.
#[test]
fn the_budgets_in_force() {
    let spend = |mode: Mode, memory_limit: Option<usize>| {
        let mut s = Spend::new(SpendParams {
            source_txid: [0; 32],
            source_output_index: 0,
            source_satoshis: 1000,
            locking_script: LockingScript::from_hex("51").unwrap(),
            transaction_version: 2,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::from_hex("").unwrap(),
            input_sequence: 0xffff_ffff,
            lock_time: 0,
            memory_limit,
        });
        match mode {
            Mode::Block => s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
            Mode::Standard => s.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
            Mode::Default => {}
        }
        s
    };
    assert_eq!(spend(Mode::Default, None).memory_limit(), 32_000_000);
    assert_eq!(spend(Mode::Block, None).memory_limit(), 100_000_000);
    assert_eq!(spend(Mode::Standard, None).memory_limit(), 100_000_000);
    assert_eq!(spend(Mode::Block, Some(7)).memory_limit(), 7);
    assert_eq!(spend(Mode::Default, Some(7)).memory_limit(), 7);
    assert_eq!(spend(Mode::Default, None).stack_memory_policy(), None);
    assert_eq!(spend(Mode::Block, None).stack_memory_policy(), None);
    assert_eq!(
        spend(Mode::Standard, None).stack_memory_policy(),
        Some(100_000_000)
    );
    let mut s = spend(Mode::Standard, None);
    s.set_stack_memory_policy(0);
    assert_eq!(s.stack_memory_policy(), None);
    assert_eq!(
        ScriptFlags::standard(ProtocolEra::PostChronicle).max_stack_memory_usage(5),
        Some(5)
    );
    assert_eq!(
        ScriptFlags::block(ProtocolEra::PostChronicle).max_stack_memory_usage(5),
        None
    );
}
