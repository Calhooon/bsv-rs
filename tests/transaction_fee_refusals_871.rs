//! `Transaction::fee` and `get_fee` refuse what the reference refuses (#871),
//! against `vectors/transaction_fee_refusals_871.json`, the reference's
//! answers (`ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts`:
//! `requireSatoshiAmount` and `addSatoshiAmount` at `:65-86`, `fee` at
//! `:770-830`, `#calculateChange` at `:832-862`, `getFee` at `:899-933`)
//! recorded under Node v22.18.0 by `support/transaction_fee_refusals_871.mjs`.
//!
//! Each cell is built here with this crate's own types from the vector's
//! description (each input's source output amounts and the index it spends,
//! each output's amount and change flag, the fee, the distribution) and
//! `fee` and `get_fee` asked; the answer, the outputs' amounts or the error's
//! words, is the recorded one, in the reference's order of checks where two
//! refusals apply. Two rows are stated, not followed: (e), no fee given,
//! is one satoshi per byte of `estimate_size` here where the reference asks
//! its live fee policy (recorded offline at its fallback, 100 sat/kB); and
//! (f), `get_fee` where the outputs exceed the inputs, 0 here where the
//! reference answers a negative number.

#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{ChangeDistribution, Transaction, TransactionInput, TransactionOutput};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/transaction_fee_refusals_871.json");

fn cells() -> Vec<Value> {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    v["cells"].as_array().unwrap().clone()
}

fn amount(v: &Value) -> Option<u64> {
    v.as_u64()
}

fn script() -> LockingScript {
    LockingScript::from_hex("51").unwrap()
}

/// The cell's transaction, built by this crate's types.
fn build(cell: &Value) -> Transaction {
    let mut tx = Transaction::new();
    for input in cell["inputs"].as_array().unwrap() {
        let index = input["index"].as_u64().unwrap() as u32;
        let mut built = match input["source"].as_array() {
            None => TransactionInput::new("aa".repeat(32).parse().unwrap(), index),
            Some(amounts) => {
                let mut src = Transaction::new();
                for a in amounts {
                    src.outputs_mut().push(TransactionOutput {
                        satoshis: amount(a),
                        locking_script: script(),
                        change: false,
                    });
                }
                TransactionInput::with_source_transaction(src, index)
            }
        };
        built.set_unlocking_script(UnlockingScript::from_hex("51").unwrap());
        tx.inputs_mut().push(built);
    }
    for output in cell["outputs"].as_array().unwrap() {
        // Pushed through the door: `add_output` refuses a non-change output
        // with no amount, as the reference's `addOutput` does; the recorder
        // built them through its constructor.
        tx.outputs_mut().push(TransactionOutput {
            satoshis: amount(&output["satoshis"]),
            locking_script: script(),
            change: output["change"].as_bool().unwrap(),
        });
    }
    tx
}

fn distribution(cell: &Value) -> ChangeDistribution {
    match cell["distribution"].as_str().unwrap() {
        "random" => ChangeDistribution::Random,
        _ => ChangeDistribution::Equal,
    }
}

/// `fee`'s answer as the vector writes it: the outputs or the words.
fn fee_answer(cell: &Value) -> Value {
    let mut tx = build(cell);
    let before = tx.to_hex();
    let fee = cell["fee"].as_u64();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    match rt.block_on(tx.fee(fee, distribution(cell))) {
        Ok(()) => serde_json::json!({
            "ok": tx.outputs().iter().map(|o| serde_json::json!({
                "satoshis": o.satoshis,
                "change": o.change,
            })).collect::<Vec<_>>()
        }),
        Err(e) => {
            assert_eq!(tx.to_hex(), before, "{}: changed on Err", cell["name"]);
            serde_json::json!({ "err": words(&e) })
        }
    }
}

fn get_fee_answer(cell: &Value) -> Value {
    match build(cell).get_fee() {
        Ok(n) => serde_json::json!({ "ok": n }),
        Err(e) => serde_json::json!({ "err": words(&e) }),
    }
}

/// The error's words without the crate's family prefix.
fn words(e: &bsv_rs::Error) -> String {
    match e {
        bsv_rs::Error::TransactionError(w) => w.clone(),
        other => panic!("not a TransactionError: {other:?}"),
    }
}

/// Every cell of `row`, `fee` and `get_fee` against the recording; every
/// difference gathered before the assertion.
fn replay(row: &str) {
    let mut diffs = Vec::new();
    let mut seen = 0;
    for cell in cells().iter().filter(|c| c["row"] == row) {
        seen += 1;
        let got = fee_answer(cell);
        if got != cell["fee_answer"] {
            diffs.push(format!(
                "{} fee: got {got}, reference {}",
                cell["name"], cell["fee_answer"]
            ));
        }
        let got = get_fee_answer(cell);
        let want = &cell["get_fee_answer"];
        // (f): a negative reference answer is 0 here (stated).
        let want = match want["ok"].as_i64() {
            Some(n) if n < 0 => serde_json::json!({ "ok": 0 }),
            _ => want.clone(),
        };
        if got != want {
            diffs.push(format!(
                "{} getFee: got {got}, reference {want}",
                cell["name"]
            ));
        }
    }
    assert!(seen > 0, "no cell of row {row}");
    assert!(
        diffs.is_empty(),
        "{} answers of {seen} cells differ:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

#[test]
fn inputs_that_cannot_pay_the_outputs_and_the_fee_are_refused_871() {
    replay("a");
}

#[test]
fn an_amount_or_a_total_past_21e14_is_refused_871() {
    replay("b");
}

#[test]
fn an_output_with_no_amount_is_refused_871() {
    replay("c");
}

#[test]
fn a_source_output_that_does_not_exist_is_refused_871() {
    replay("d");
}

#[test]
fn of_two_refusals_the_reference_s_earlier_is_answered_871() {
    replay("order");
}

#[test]
fn the_change_distributions_are_the_reference_s_871() {
    replay("dist");
}

/// (f), stated: where the outputs exceed the inputs `get_fee` answers 0 and
/// the reference a negative number (`Transaction.ts:932`); `fee` refuses the
/// same transaction in the reference's words.
#[test]
fn get_fee_answers_0_where_the_reference_answers_a_negative_fee_stated_871() {
    replay("f");
    for cell in cells().iter().filter(|c| c["row"] == "f") {
        assert!(cell["get_fee_answer"]["ok"].as_i64().unwrap() < 0);
        assert_eq!(get_fee_answer(cell), serde_json::json!({ "ok": 0 }));
    }
}

/// (e), stated: no fee given is one satoshi per byte of `estimate_size`
/// here; the reference's default, its live policy, recorded with no network
/// at its fallback of 100 sat/kB, is `ceil(size * 100 / 1000)` of the same
/// size (`SatoshisPerKilobyte.ts`, `LivePolicy.ts:91-99`).
#[test]
fn no_fee_given_is_one_satoshi_per_byte_where_the_reference_asks_its_live_policy_stated_871() {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(v["default_fee_model"]["asked"].as_array().unwrap().len(), 1);
    let mut seen = 0;
    for cell in cells().iter().filter(|c| c["row"] == "e") {
        seen += 1;
        let tx = build(cell);
        let size = tx.estimate_size() as u64;
        let total_in: u64 = tx
            .inputs()
            .iter()
            .map(|i| i.source_satoshis().unwrap())
            .sum();
        let paid: u64 = tx
            .outputs()
            .iter()
            .filter_map(|o| if o.change { None } else { o.satoshis })
            .sum();
        let ours = fee_answer(cell);
        match cell["fee_answer"].get("ok") {
            Some(outputs) => {
                let theirs: u64 = outputs
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|o| o["change"] == true)
                    .map(|o| o["satoshis"].as_u64().unwrap())
                    .sum();
                assert_eq!(
                    theirs,
                    total_in - paid - size.div_ceil(10),
                    "{}",
                    cell["name"]
                );
                let change: u64 = ours["ok"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|o| o["change"] == true)
                    .map(|o| o["satoshis"].as_u64().unwrap())
                    .sum();
                assert_eq!(change, total_in - paid - size, "{}", cell["name"]);
            }
            None => assert_eq!(ours, cell["fee_answer"], "{}", cell["name"]),
        }
    }
    assert_eq!(seen, 3);
}

/// An amount past `u64`'s reach of the reference (a JavaScript number past
/// 2^53 is not exact): refused here in the same words as 21e14 + 1.
#[test]
fn an_amount_at_u64_max_is_refused_in_the_amount_words_871() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut src = Transaction::new();
    src.add_output(TransactionOutput::new(u64::MAX, script()))
        .unwrap();
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::with_source_transaction(src, 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script())).unwrap();
    let want = "Input 0 source amount must be a non-negative safe integer no greater than 21e14.";
    assert_eq!(
        words(
            &rt.block_on(tx.fee(Some(0), ChangeDistribution::Equal))
                .unwrap_err()
        ),
        want
    );
    assert_eq!(words(&tx.get_fee().unwrap_err()), want);
    assert_eq!(
        words(
            &rt.block_on(tx.fee(Some(u64::MAX), ChangeDistribution::Equal))
                .unwrap_err()
        ),
        "Computed transaction fee must be a non-negative safe integer no greater than 21e14."
    );
}

/// The vector's census: 65 cells, each row present.
#[test]
fn the_vector_holds_every_row_871() {
    let all = cells();
    assert_eq!(all.len(), 65);
    for row in ["a", "b", "c", "d", "order", "e", "f", "dist"] {
        assert!(all.iter().any(|c| c["row"] == row), "{row}");
    }
}
