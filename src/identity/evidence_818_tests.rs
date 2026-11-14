#![cfg(test)]
//! #818: the transactions bound counts the BEEF's entries, a repeated txid
//! each time it is written, as the reference's `parseEvidence` does
//! (`ts-stack@edf6e03` `TransactionEvidence.ts:116-117`:
//! `if (beef.txs.length > limits.transactions)`). #730's two bound shapes
//! hold distinct txids alone, so a count of distinct txids passed every test.
//! The two BEEFs of `tests/vectors/identity_evidence_818.json` (recorded
//! under Node v22.18.0 by `tests/support/identity_evidence_818.mjs`) rebuilt
//! by this crate's writer (`tests/support/identity_evidence_818.rs`) to the
//! recorded SHA-256, one txid-only entry written twice: 255 distinct txids in
//! 256 entries read to the subject, 256 distinct txids in 257 entries `limit`
//! at `:117`, each judged by [`parse_evidence`] to the recorded code and line.
//!
//! #907 (the strength read's 5b): the vector's `output_index`, `repeated_txid`
//! and `outcome` are read too, and the parsers' door [`admit`] is run on each
//! shape: the output index asked is the recorded one, the txid written twice
//! is the recorded one and no other, and `admit` reads the shape at the bound
//! and fails the discovery over it in the words the reference's wallet
//! answers (`outcome`).

use super::*;
use crate as sdk;
use crate::primitives::{sha256, to_hex};
use std::collections::HashSet;

#[path = "../../tests/support/identity_evidence_818.rs"]
mod build;

/// The shape `name` rebuilt to the recorded bytes, with its case.
fn rebuilt(name: &str) -> (Vec<u8>, serde_json::Value) {
    let case = build::case(name);
    let beef = build::build_repeating(
        case["size"].as_u64().unwrap() as usize,
        case["repeated"] == "raw",
    );
    assert_eq!(
        (beef.len() as u64, to_hex(&sha256(&beef))),
        (
            case["beef_bytes"].as_u64().unwrap(),
            case["beef_sha256"].as_str().unwrap().to_string()
        ),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    // the shape is what its name says: every entry held, one txid twice
    let parsed = sdk::transaction::Beef::from_binary(&beef).unwrap();
    let distinct: HashSet<String> = parsed.txs.iter().map(BeefTx::txid).collect();
    assert_eq!(
        (parsed.txs.len() as u64, distinct.len() as u64),
        (
            case["entries"].as_u64().unwrap(),
            case["distinct_txids"].as_u64().unwrap()
        ),
        "{name}: the entries and the distinct txids"
    );
    (beef, case)
}

#[test]
fn a_repeated_entry_counts_toward_the_transactions_bound_818() {
    assert_eq!(build::vector()["shapes"].as_array().unwrap().len(), 4);
    assert_eq!(
        build::vector()["limits"]["transactions"].as_u64().unwrap(),
        TRANSACTIONS as u64
    );

    // 255 distinct txids in 256 entries: at the bound, read
    let (beef, case) = rebuilt("repeat_at_bound");
    assert_eq!(
        (case["entries"].as_u64(), case["distinct_txids"].as_u64()),
        (Some(256), Some(255))
    );
    assert!(case["code"].is_null() && case["site"].is_null());
    assert_eq!(
        parse_evidence(&beef, 0).map(|tx| tx.id()),
        Ok(case["selected_txid"].as_str().unwrap().to_string())
    );
    assert_eq!(case["selected_txid"], case["subject_txid"]);

    // 256 distinct txids in 257 entries: over it by the repeat alone
    let (beef, case) = rebuilt("repeat_over_bound");
    assert_eq!(
        (case["entries"].as_u64(), case["distinct_txids"].as_u64()),
        (Some(257), Some(256))
    );
    let refusal = parse_evidence(&beef, 0).map(|tx| tx.id()).unwrap_err();
    assert_eq!(
        (refusal.code.as_str(), refusal.site),
        (
            case["code"].as_str().unwrap(),
            case["site"].as_str().unwrap()
        )
    );
    assert_eq!(refusal, limit("TransactionEvidence.ts:117"));
    assert_eq!(
        format!("refused: Transaction evidence: {}", refusal.code.as_str()),
        case["selected_txid"].as_str().unwrap()
    );
    assert_eq!(
        case["refused_at"].as_str().unwrap(),
        format!("{}: 257 transactions", refusal.site)
    );
}

/// The entries of `beef` holding `txid`.
fn written(beef: &[u8], txid: &str) -> usize {
    let parsed = sdk::transaction::Beef::from_binary(beef).unwrap();
    parsed.txs.iter().filter(|tx| tx.txid() == txid).count()
}

#[test]
fn the_parsers_door_reads_the_bound_and_fails_the_discovery_over_it_907() {
    for name in [
        "repeat_at_bound",
        "repeat_over_bound",
        "raw_repeat_at_bound",
        "raw_repeat_over_bound",
    ] {
        let (beef, case) = rebuilt(name);
        // the one txid written twice is the recorded one
        let repeated = case["repeated_txid"].as_str().unwrap();
        assert_eq!(written(&beef, repeated), 2, "{name}: the repeated txid");
        let parsed = sdk::transaction::Beef::from_binary(&beef).unwrap();
        let twice: Vec<String> = parsed
            .txs
            .iter()
            .map(BeefTx::txid)
            .filter(|txid| written(&beef, txid) > 1)
            .collect();
        assert_eq!(twice, [repeated, repeated], "{name}: no other txid twice");

        let output = OutputListItem {
            beef,
            output_index: case["output_index"].as_u64().unwrap() as u32,
            context: None,
            txid: None,
        };
        let contradictions = HintContradictions::default();
        let outcome = match admit(&output, &contradictions) {
            Ok(Some(subject)) => {
                assert_eq!(subject.id(), case["subject_txid"].as_str().unwrap());
                "read".to_string()
            }
            Ok(None) => "skipped".to_string(),
            Err(Error::IdentityError(words)) => format!("refused: {words}"),
            Err(other) => panic!("{name}: {other:?}"),
        };
        assert_eq!(outcome, case["outcome"].as_str().unwrap(), "{name}");
        assert_eq!(contradictions.0.load(Ordering::Relaxed), 0, "{name}");

        // an index past the subject's outputs is no evidence, at either size
        let past = OutputListItem {
            output_index: output.output_index + 1,
            ..output
        };
        match (name, admit(&past, &contradictions)) {
            ("repeat_at_bound" | "raw_repeat_at_bound", Ok(None)) => {}
            ("repeat_over_bound" | "raw_repeat_over_bound", Err(Error::IdentityError(words))) => {
                assert_eq!(words, "Transaction evidence: limit")
            }
            (_, other) => panic!("{name}: an index past the outputs: {other:?}"),
        }
    }
}

/// #907: a RAW entry written twice counts twice too. The proven subject
/// written raw twice behind 254 txid-only entries (256 entries, 255 distinct)
/// is read to the subject; behind 255 (257 entries, 256 distinct) it is
/// `limit` at `TransactionEvidence.ts:117`, the reference's recorded answers.
#[test]
fn a_raw_entry_written_twice_counts_twice_toward_the_transactions_bound_907() {
    let (beef, case) = rebuilt("raw_repeat_at_bound");
    assert_eq!(
        (case["entries"].as_u64(), case["distinct_txids"].as_u64()),
        (Some(256), Some(255))
    );
    assert_eq!(case["repeated_txid"], case["subject_txid"]);
    assert_eq!(
        parse_evidence(&beef, 0).map(|tx| tx.id()),
        Ok(case["selected_txid"].as_str().unwrap().to_string())
    );

    let (beef, case) = rebuilt("raw_repeat_over_bound");
    assert_eq!(
        (case["entries"].as_u64(), case["distinct_txids"].as_u64()),
        (Some(257), Some(256))
    );
    let refusal = parse_evidence(&beef, 0).map(|tx| tx.id()).unwrap_err();
    assert_eq!(refusal, limit("TransactionEvidence.ts:117"));
    assert_eq!(
        (refusal.code.as_str(), refusal.site),
        (
            case["code"].as_str().unwrap(),
            case["site"].as_str().unwrap()
        )
    );
}
