//! `Transaction::fee` over two or more change outputs (#868).
//!
//! The random distribution divided by `log10(1)` (zero) where the reference
//! divides by `Math.log10(10)` (`ts-stack@edf6e03`
//! `packages/sdk/src/transaction/Transaction.ts:894-897`), so the factor was
//! infinite and its cast `u64::MAX` (an overflow panic at the add in a debug
//! build; in a release build the add wrapped to 0, every change output but the
//! last 0, the last the whole change). These tests pin the reference's distribution at the pin
//! (`Transaction.ts:864-897`): every change output but the last takes
//! `floor(remaining * log10(1 + 1/d))` for a digit `d` of 1 to 9, the last
//! takes what remains; the equal arm writes `floor(change / n)` to every
//! change output and the remainder to the last; an output may be 0 satoshis
//! (the reference gives no output a minimum). The change is the inputs less
//! the other outputs less the fee; with none, the change outputs are removed.
//! A sum of a caller's amounts past `u64` is refused in the reference's
//! words (`addSatoshiAmount`, `Transaction.ts:80-86`).

#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{ChangeDistribution, Transaction, TransactionInput, TransactionOutput};

const RUNS: usize = 2_000;
const FEE: u64 = 100;
const PAYMENT: u64 = 1_000;

fn script() -> LockingScript {
    // OP_TRUE: the distribution reads no script.
    LockingScript::from_hex("51").unwrap()
}

fn source(amounts: &[u64]) -> Transaction {
    let mut tx = Transaction::new();
    for &a in amounts {
        tx.add_output(TransactionOutput::new(a, script())).unwrap();
    }
    tx
}

/// A transaction whose change (inputs less the payment less `FEE`) is `change`,
/// with `n` change outputs after the payment.
fn spend(change: u64, n: usize) -> Transaction {
    let mut tx = Transaction::new();
    let src = source(&[change + PAYMENT + FEE]);
    tx.add_input(TransactionInput::with_source_transaction(src, 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(PAYMENT, script()))
        .unwrap();
    for _ in 0..n {
        tx.add_output(TransactionOutput::new_change(script()))
            .unwrap();
    }
    tx
}

fn change_amounts(tx: &Transaction) -> Vec<u64> {
    tx.outputs()
        .iter()
        .filter(|o| o.change)
        .map(|o| o.satoshis.expect("a change output is written"))
        .collect()
}

/// Whether `portion` is the reference's `#benfordNumber(0, remaining)` for
/// some digit 1 to 9 (`Math.floor(0 + (remaining - 0) * log10(1 + 1/d) / log10(10))`).
fn is_benford_portion(portion: u64, remaining: u64) -> bool {
    (1..=9u32).any(|d| {
        let f = (1.0 + 1.0 / f64::from(d)).log10() / 10f64.log10();
        (remaining as f64 * f).floor() as u64 == portion
    })
}

/// The six amounts: a typical one, a large one, the count, 2, 1 and 0.
fn changes(n: usize) -> [u64; 6] {
    [12_345, 2_000_000_000_000_000, n as u64, 2, 1, 0]
}

#[tokio::test]
async fn random_change_never_panics_and_sums_to_the_change_868() {
    // The issue's cell: a typical change first, so the divisor's failure is the
    // one shown (a debug overflow panic; in release the add wraps to 0, so
    // the sum holds and this test passes there).
    for n in [2usize, 3, 5] {
        for change in [12_345u64, 2_000_000_000_000_000, n as u64, 2, 1] {
            for _ in 0..RUNS {
                let mut tx = spend(change, n);
                tx.fee(Some(FEE), ChangeDistribution::Random).await.unwrap();
                let amounts = change_amounts(&tx);
                assert_eq!(amounts.len(), n);
                assert!(
                    amounts.iter().all(|&a| a <= change),
                    "n {n}, change {change}: an amount above the change: {amounts:?}"
                );
                let sum: u128 = amounts.iter().map(|&a| u128::from(a)).sum();
                assert_eq!(sum, u128::from(change), "n {n}: {amounts:?}");
            }
        }
    }
}

#[tokio::test]
async fn random_change_over_two_or_more_outputs_is_the_reference_distribution_868() {
    for n in [2usize, 3, 5] {
        for change in changes(n) {
            for _ in 0..RUNS {
                let mut tx = spend(change, n);
                tx.fee(Some(FEE), ChangeDistribution::Random).await.unwrap();
                if change == 0 {
                    assert!(
                        tx.outputs().iter().all(|o| !o.change),
                        "no change: the change outputs are removed"
                    );
                    assert_eq!(tx.outputs().len(), 1);
                    continue;
                }
                let amounts = change_amounts(&tx);
                assert_eq!(amounts.len(), n);
                let mut remaining = change;
                for (i, &a) in amounts.iter().enumerate() {
                    assert!(
                        a <= change,
                        "n {n}, change {change}: output {i} holds {a}, above the change ({amounts:?})"
                    );
                    if i + 1 < n {
                        assert!(
                            is_benford_portion(a, remaining),
                            "n {n}, change {change}: output {i} holds {a}, not a Benford portion of {remaining} ({amounts:?})"
                        );
                        remaining -= a;
                    } else {
                        assert_eq!(a, remaining, "the last change output takes what remains");
                    }
                }
                let sum: u128 = amounts.iter().map(|&a| u128::from(a)).sum();
                assert_eq!(sum, u128::from(change), "n {n}: {amounts:?}");
                assert_eq!(tx.get_fee().unwrap(), FEE);
            }
        }
    }
}

#[tokio::test]
async fn random_change_below_the_output_count_leaves_outputs_at_zero_868() {
    // floor(r * log10(1 + 1/d)) is 0 for every r below 1 / log10(2) (about 3.32),
    // so the reference's answer is fixed here: every output but the last 0.
    for (change, n, expected) in [
        (1u64, 2usize, vec![0u64, 1]),
        (1, 3, vec![0, 0, 1]),
        (2, 5, vec![0, 0, 0, 0, 2]),
        (3, 3, vec![0, 0, 3]),
    ] {
        for _ in 0..RUNS {
            let mut tx = spend(change, n);
            tx.fee(Some(FEE), ChangeDistribution::Random).await.unwrap();
            assert_eq!(change_amounts(&tx), expected, "change {change} over {n}");
        }
    }
}

#[tokio::test]
async fn equal_change_writes_the_floor_to_each_and_the_remainder_to_the_last_868() {
    for (change, n, expected) in [
        (5u64, 3usize, vec![1u64, 1, 3]),
        (1, 3, vec![0, 0, 1]),
        (12_345, 5, vec![2_469; 5]),
        (12_346, 5, vec![2_469, 2_469, 2_469, 2_469, 2_470]),
        (10, 4, vec![2, 2, 2, 4]),
    ] {
        let mut tx = spend(change, n);
        tx.fee(Some(FEE), ChangeDistribution::Equal).await.unwrap();
        assert_eq!(change_amounts(&tx), expected, "change {change} over {n}");
    }
}

#[tokio::test]
async fn an_input_total_past_u64_is_refused_in_the_reference_words_868() {
    let mut tx = Transaction::new();
    let src = source(&[u64::MAX, 1]);
    tx.add_input(TransactionInput::with_source_transaction(src.clone(), 0))
        .unwrap();
    tx.add_input(TransactionInput::with_source_transaction(src, 1))
        .unwrap();
    tx.add_output(TransactionOutput::new_change(script()))
        .unwrap();
    let err = tx
        .fee(Some(FEE), ChangeDistribution::Random)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "transaction error: Transaction input total exceeds the maximum valid monetary range."
    );
}

#[tokio::test]
async fn an_output_total_past_u64_is_refused_in_the_reference_words_868() {
    let mut tx = spend(10, 2);
    tx.add_output(TransactionOutput::new(u64::MAX, script()))
        .unwrap();
    let err = tx
        .fee(Some(FEE), ChangeDistribution::Equal)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "transaction error: Transaction output total exceeds the maximum valid monetary range."
    );
}

#[test]
fn get_fee_refuses_a_total_past_u64_and_the_output_sum_saturates_868() {
    // The class of the two sums above: `get_fee` (the reference's `getFee`,
    // `Transaction.ts:904-931`, the same `addSatoshiAmount` words) and
    // `total_output_satoshis`, which returns a `u64` and saturates.
    let mut tx = Transaction::new();
    let src = source(&[u64::MAX, 1]);
    tx.add_input(TransactionInput::with_source_transaction(src.clone(), 0))
        .unwrap();
    tx.add_input(TransactionInput::with_source_transaction(src, 1))
        .unwrap();
    assert_eq!(
        tx.get_fee().unwrap_err().to_string(),
        "transaction error: Transaction input total exceeds the maximum valid monetary range."
    );

    let mut tx = spend(10, 0);
    tx.add_output(TransactionOutput::new(u64::MAX, script()))
        .unwrap();
    assert_eq!(
        tx.get_fee().unwrap_err().to_string(),
        "transaction error: Transaction output total exceeds the maximum valid monetary range."
    );
    assert_eq!(tx.total_output_satoshis(), u64::MAX);
}
