//! #452: the actual input check returns a typed SpendRefusal before conversion.
#![allow(clippy::unwrap_used, clippy::panic)] // Hermetic regression witnesses (#452).

use super::*;
use crate::block::{ActivationHeightsError, ChainParams};
use crate::script::{LockingScript, NotJudgedCause, UnlockingScript};
use crate::transaction::{MerklePath, Transaction, TransactionInput, TransactionOutput};

#[cfg(test)] // Keep the fixture visibly test-only to the lexical architecture guard.
fn stop(chain: ChainParams, coin: u32, tip_height: u32) -> Stop {
    stop_with_evaluation(
        Evaluation {
            chain: Some(chain),
            ..Evaluation::NONE
        },
        coin,
        tip_height,
    )
}

#[cfg(test)]
fn stop_with_evaluation(evaluation: Evaluation, coin: u32, tip_height: u32) -> Stop {
    let mut parent = Transaction::new();
    let mut input = TransactionInput::new("aa".repeat(32), 0);
    input.set_unlocking_script(UnlockingScript::new());
    parent.add_input(input).unwrap();
    parent
        .add_output(TransactionOutput::new(
            1_000,
            LockingScript::from_hex("51").unwrap(),
        ))
        .unwrap();
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), coin));
    let mut tx = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.set_unlocking_script(UnlockingScript::new());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        900,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    #[allow(deprecated)] // Populate the compatibility field; only ChainParams is read (#451).
    let tip = Some(ChainTip {
        height: tip_height,
        median_time_past: 0,
        genesis_height: 1,
        csv_height: 0,
        next_block_time: None,
    });
    let mut index = BeefIndex::new();
    for element in BeefStream::new(tx.to_beef(false).unwrap().as_slice()) {
        let result = match element.unwrap() {
            Element::Bump(bump) => index.fold_bump(&bump, true),
            element => index
                .fold_one(&element, 0, &mut || false, &evaluation, tip)
                .map(|_| ()),
        };
        if let Err(stop) = result {
            return stop;
        }
    }
    panic!("expected an input outside the verifier's scope")
}

fn assert_refusal(stop: Stop, expected: NotJudgedCause, sentence: &str) {
    match &stop {
        Stop::Spend {
            input: Some(0),
            why: why @ SpendRefusal::NotJudged { input: 0, cause },
            ..
        } => {
            assert_eq!(*cause, expected);
            assert_eq!(why.to_string(), sentence);
            assert!(!why.to_string().contains("Script validation failed"));
        }
        other => panic!("expected a typed NotJudged spend refusal, got {other:?}"),
    }
    assert!(
        matches!(Verdict::from(stop), Verdict::NotJudged { input: 0, cause, .. } if cause == expected)
    );
}

#[test]
fn a_pre_genesis_coin_returns_a_not_judged_spend_refusal_452() {
    assert_refusal(
        stop(ChainParams::regtest(), 9_999, 15_000),
        NotJudgedCause::PreGenesisCoin {
            height: 9_999,
            genesis_height: 10_000,
        },
        "input 0 not judged: coin height 9999 is before Genesis height 10000.",
    );
}

#[test]
fn an_overflowing_tip_returns_a_not_judged_spend_refusal_452() {
    assert_refusal(stop(ChainParams::regtest(), 10_000, u32::MAX),
        NotJudgedCause::TipHeightOverflow { tip: u32::MAX },
        "input 0 not judged: tip height 4294967295 cannot produce a spend height within u32 (maximum 4294967295).");
}

#[test]
fn a_zero_activation_returns_a_not_judged_spend_refusal_452() {
    let mut chain = ChainParams::regtest();
    chain.genesis_height = 0;
    assert_refusal(stop(chain, 10_000, 15_000),
        NotJudgedCause::ZeroActivationHeight(ActivationHeightsError::ZeroGenesis),
        "input 0 not judged: Genesis activation height 0 is outside the supported range 1..=4294967295.");
    let mut chain = ChainParams::regtest();
    chain.chronicle_height = 0;
    assert_refusal(stop(chain, 10_000, 15_000),
        NotJudgedCause::ZeroActivationHeight(ActivationHeightsError::ZeroChronicle),
        "input 0 not judged: Chronicle activation height 0 is outside the supported range 1..=4294967295.");
}

#[test]
fn work_exhaustion_returns_a_not_judged_spend_refusal_378() {
    assert_refusal(
        stop_with_evaluation(
            Evaluation {
                work: crate::transaction::WorkBudget::default().with_per_input(Some(0)),
                ..Evaluation::NONE
            },
            10_000,
            15_000,
        ),
        NotJudgedCause::WorkBudgetExceeded {
            input: 0,
            budget: 0,
            work_done: 0,
        },
        "input 0 not judged: exceeded work budget 0 units after 0 units of work.",
    );
}
