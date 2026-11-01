//! #603: each `NotJudgedCause` renders its own sentence, never an empty one.
//!
//! The rule: a cause is not a verdict. The sibling's spec verdict is
//! `valid | invalid reason` (`bsv-script-lean@5dc337e` `lean/BsvScript/Machine.lean:418-425`),
//! and its harness reads an input an engine does not judge (bsv-rs before
//! Genesis) as `undecided`, apart from both (`docs/DESIGN.md:140-150`); this
//! crate carries that refusal as a typed cause whose text is the embedder's
//! only diagnostic (`CLAUDE.md`: a decline an embedder never reads as
//! invalid). Seven of the eight sentences are the ones the crate's witnesses
//! pin through the verifiers (`tests/beef_not_judged_452.rs`,
//! `tests/transaction_work_budget_519.rs`,
//! `src/transaction/beef_stream/not_judged_tests.rs`), here at the cause
//! itself, so the script surface's selection pins them too. The witnesses
//! match `SourceHeightOverflow` by its fields only; its sentence is first
//! pinned here, in the form `b6b3c4b8`'s changelog entry gives every cause
//! (one sentence naming the bound it falls outside, with the height; never
//! "Script validation failed").
#![cfg(all(feature = "script", feature = "block"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #603 regression witnesses.

use bsv_rs::block::{ActivationHeightsError, ChainParams};
use bsv_rs::script::{NotJudgedCause, Word};

const GENESIS: u32 = 620_538;

fn refusal(chain: &ChainParams, spend: Option<u32>, source: Option<u32>) -> NotJudgedCause {
    chain
        .word_for_input(Word::Standard, spend, source)
        .expect_err("a cause the resolver refuses")
}

#[test]
fn every_not_judged_cause_renders_its_own_sentence_603() {
    let mainnet = ChainParams::mainnet();
    assert_eq!(mainnet.genesis_height, GENESIS);
    let mut zero_genesis = ChainParams::mainnet();
    zero_genesis.genesis_height = 0;
    let mut zero_chronicle = ChainParams::mainnet();
    zero_chronicle.chronicle_height = 0;
    let cases = [
        // The resolver's own refusals (#452, #520).
        (
            refusal(&mainnet, Some(GENESIS), Some(GENESIS - 1)),
            "coin height 620537 is before Genesis height 620538.",
        ),
        (
            refusal(&mainnet, Some(GENESIS - 1), None),
            "spend height 620537 is before Genesis height 620538.",
        ),
        (
            refusal(&zero_genesis, None, None),
            "Genesis activation height 0 is outside the supported range 1..=4294967295.",
        ),
        (
            refusal(&zero_chronicle, None, None),
            "Chronicle activation height 0 is outside the supported range 1..=4294967295.",
        ),
        // The verifiers' refusals, at their witnesses' values.
        (
            NotJudgedCause::TipHeightOverflow { tip: u32::MAX },
            "tip height 4294967295 cannot produce a spend height within u32 (maximum 4294967295).",
        ),
        (
            NotJudgedCause::WorkBudgetExceeded {
                input: 0,
                budget: 0,
                work_done: 0,
            },
            "exceeded work budget 0 units after 0 units of work.",
        ),
        (
            NotJudgedCause::TransactionWorkBudgetExceeded {
                input: 1,
                limit: 70,
                total: 74,
            },
            "exceeded transaction work budget 70 units after 74 units of work.",
        ),
        (
            NotJudgedCause::SourceHeightOverflow {
                height: u64::from(u32::MAX) + 1,
            },
            "coin height 4294967296 exceeds the supported maximum height 4294967295.",
        ),
    ];
    assert!(matches!(
        cases[2].0,
        NotJudgedCause::ZeroActivationHeight(ActivationHeightsError::ZeroGenesis)
    ));
    assert!(matches!(
        cases[3].0,
        NotJudgedCause::ZeroActivationHeight(ActivationHeightsError::ZeroChronicle)
    ));
    for (cause, sentence) in cases {
        assert_eq!(cause.to_string(), sentence, "{cause:?}");
        assert!(!sentence.contains("Script validation failed"));
    }
}
