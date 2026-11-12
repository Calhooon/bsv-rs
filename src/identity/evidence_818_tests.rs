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

use super::*;
use crate as sdk;
use crate::primitives::{sha256, to_hex};
use std::collections::HashSet;

#[path = "../../tests/support/identity_evidence_818.rs"]
mod build;

/// The shape `name` rebuilt to the recorded bytes, with its case.
fn rebuilt(name: &str) -> (Vec<u8>, serde_json::Value) {
    let case = build::case(name);
    let beef = build::build(case["size"].as_u64().unwrap() as usize);
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
    assert_eq!(build::vector()["shapes"].as_array().unwrap().len(), 2);
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
