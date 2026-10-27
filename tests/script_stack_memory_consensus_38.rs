//! The block path's stack memory budget as the node's verdict (bsv-rs#38).
//! bitcoin-sv v1.2.3 (`6504a3a`) does not start without
//! `-maxstackmemoryusageconsensus` (`src/bitcoind.cpp:140-157`; 0 means
//! `INT64_MAX`, `src/consensus/consensus.h:82`,
//! `src/configscriptpolicy.cpp:280-287`), picks it on the block path
//! (`GetMaxStackMemoryUsage`, `:139-154`) and refuses a growth above it before
//! it happens (`src/script/limitedstack.cpp:202-205`), `SCRIPT_ERR_STACK_SIZE`
//! (`src/script/interpreter.cpp:1815-1817`): a verdict, the site the mempool
//! path's policy verdict already mirrors. An operator may set it below
//! 100,000,000; `Spend::set_stack_memory_consensus` models that node, where
//! `memory_limit: Some(X)` models it only as a decline above `X`.
//!
//! The scripts are `OP_1`s on the node's count, 33 bytes each: three are 99
//! bytes, four 132.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, ScriptResource, ScriptResourceLimit, Spend,
    SpendParams, UnlockingScript,
};

const FOUR: &str = "51515151";

#[derive(Clone, Copy)]
enum Mode {
    Block,
    Standard,
    Default,
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Valid,
    Verdict(String),
    Declined(ScriptResourceLimit),
}

use Outcome::{Declined, Valid, Verdict};

/// `lock_hex` spent by an empty unlocking script in a version-2 transaction
/// on a coin created after Chronicle, `tune` applied after the word.
fn outcome(
    lock_hex: &str,
    mode: Mode,
    memory_limit: Option<usize>,
    tune: impl FnOnce(&mut Spend),
) -> Outcome {
    let mut s = Spend::new(SpendParams {
        source_txid: [0x11; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(lock_hex).unwrap(),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::new(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit,
        work_limit: None,
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
            Some(limit) => {
                assert!(e.is_resource_limit());
                Declined(limit)
            }
            None => {
                assert!(!e.is_resource_limit());
                Verdict(e.message)
            }
        },
    }
}

fn consensus_100(s: &mut Spend) {
    s.set_stack_memory_consensus(100);
}

fn stack(limit: u64, attempted: u64) -> Outcome {
    Declined(ScriptResourceLimit {
        resource: ScriptResource::Stack,
        limit,
        attempted,
        work_spent: None,
    })
}

/// Under the block word, a growth above the consensus figure is the node's
/// verdict, refused before it happens, in the policy verdict's shape.
#[test]
fn a_growth_above_the_consensus_figure_is_a_verdict_on_the_block_path() {
    assert_eq!(
        outcome(FOUR, Mode::Block, None, consensus_100),
        Verdict(
            "Stack size limit exceeded: 132 bytes, the stack memory consensus limit is 100 bytes."
                .to_string()
        )
    );
    assert_eq!(outcome("515151", Mode::Block, None, consensus_100), Valid);
}

/// The figure answers what it is in force: the block word's, not the mempool
/// word's or the default mode's; 0 selects none.
#[test]
fn the_consensus_figure_is_in_force_on_the_block_path_only() {
    let figure = |mode: Mode, bytes: usize| {
        let mut s = Spend::new(SpendParams {
            source_txid: [0; 32],
            source_output_index: 0,
            source_satoshis: 0,
            locking_script: LockingScript::new(),
            transaction_version: 2,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: UnlockingScript::new(),
            input_sequence: 0,
            lock_time: 0,
            memory_limit: None,
            work_limit: None,
        });
        match mode {
            Mode::Block => s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
            Mode::Standard => s.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
            Mode::Default => {}
        }
        s.set_stack_memory_consensus(bytes);
        s.stack_memory_consensus()
    };
    assert_eq!(figure(Mode::Block, 100), Some(100));
    assert_eq!(figure(Mode::Block, 0), None);
    assert_eq!(figure(Mode::Standard, 100), None);
    assert_eq!(figure(Mode::Default, 100), None);
}

/// Without the knob the block path has no verdict: the script is valid at the
/// 100,000,000-byte local budget, and a decline above a `memory_limit` below
/// it (the decline, not the node's verdict: `memory_limit: Some(100)` models a
/// node set to 100 only so).
#[test]
fn without_the_knob_the_block_path_declines_and_never_decides() {
    assert_eq!(outcome(FOUR, Mode::Block, None, |_| {}), Valid);
    assert_eq!(
        outcome(FOUR, Mode::Block, Some(100), |_| {}),
        stack(100, 132)
    );
}

/// The local budget below the consensus figure stops the evaluation first,
/// with a decline; above it the verdict fires at its figure.
#[test]
fn the_local_budget_and_the_consensus_figure_are_separate_knobs() {
    assert_eq!(
        outcome(FOUR, Mode::Block, Some(100), |s| s
            .set_stack_memory_consensus(1_000)),
        stack(100, 132)
    );
    assert_eq!(
        outcome(FOUR, Mode::Block, Some(1_000), consensus_100),
        Verdict(
            "Stack size limit exceeded: 132 bytes, the stack memory consensus limit is 100 bytes."
                .to_string()
        )
    );
}

/// The mempool word keeps the policy's verdict and ignores the consensus
/// figure; the default mode ignores both.
#[test]
fn the_mempool_word_and_the_default_mode_ignore_the_consensus_figure() {
    assert_eq!(outcome(FOUR, Mode::Standard, None, consensus_100), Valid);
    assert_eq!(
        outcome(FOUR, Mode::Standard, None, |s| {
            s.set_stack_memory_consensus(1_000);
            s.set_stack_memory_policy(100);
        }),
        Verdict(
            "Stack size limit exceeded: 132 bytes, the stack memory policy is 100 bytes."
                .to_string()
        )
    );
    assert_eq!(outcome(FOUR, Mode::Default, None, consensus_100), Valid);
}

/// A policy above the consensus figure, which the node refuses at start
/// (`src/configscriptpolicy.cpp:298-305`), is taken as given: each path is
/// judged by its own figure, nothing clamped.
#[test]
fn a_policy_above_the_consensus_figure_is_not_clamped() {
    let both = |s: &mut Spend| {
        s.set_stack_memory_consensus(100);
        s.set_stack_memory_policy(1_000);
    };
    assert_eq!(outcome(FOUR, Mode::Standard, None, both), Valid);
    assert_eq!(
        outcome(FOUR, Mode::Block, None, both),
        Verdict(
            "Stack size limit exceeded: 132 bytes, the stack memory consensus limit is 100 bytes."
                .to_string()
        )
    );
}
