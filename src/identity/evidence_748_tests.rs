#![cfg(test)]
//! #748: the evidence walk's visited set (`assertUnconfirmedGraph`,
//! `ts-stack@edf6e03` `TransactionEvidence.ts:155-177`, the set at
//! `:162-166`). Each BEEF of `tests/vectors/identity_evidence_748.json`
//! rebuilt by this crate's writer (`tests/support/identity_evidence_748.rs`)
//! to the recorded SHA-256 and judged by [`parse_evidence`] to the reference
//! `parseEvidence`'s selected txid (recorded under Node v22.18.0 by
//! `tests/support/identity_evidence_748.mjs`). Both shapes reach one
//! grandparent G through two unproven parents: G unproven over a proven GG
//! (without the set, GG:0 spent twice, `invalid-evidence` at `:149`), or G
//! proven with 4092 inputs (without the set, 8188 inputs, `limit` at
//! `:170-171`); the recorder's replay with the set's skip removed names each
//! of those lines. #736's and #741's pins reach a node many times too (an
//! unproven parent 2048 times, a proven G 4094 times) and go RED under the
//! removal by the inputs and script-bytes sums; these two give it its own
//! witnesses: a skip through the spent set, the inputs sum at a proven node.

use super::*;
use crate as sdk;
use crate::primitives::{sha256, to_hex};

#[path = "../../tests/support/identity_evidence_748.rs"]
mod build;

/// The shape `name` rebuilt to the recorded bytes and its parsed BEEF, after
/// the transactions under the subject are checked against the vector's.
fn rebuilt(name: &str) -> (build::Built, sdk::transaction::Beef, serde_json::Value) {
    let case = build::case(name);
    let built = build::build(name);
    assert_eq!(
        (built.beef.len() as u64, to_hex(&sha256(&built.beef))),
        (
            case["beef_bytes"].as_u64().unwrap(),
            case["beef_sha256"].as_str().unwrap().to_string()
        ),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    assert_eq!(
        built.subject,
        case["subject_txid"].as_str().unwrap(),
        "{name}"
    );
    let txids = &build::vector()["txids"][name];
    assert_eq!(
        [&built.p1, &built.p2, &built.g].map(|t| t.as_str()),
        ["p1", "p2", "g"].map(|k| txids[k].as_str().unwrap()),
        "{name}: the transactions under the subject"
    );
    assert_eq!(built.gg.as_deref(), txids["gg"].as_str(), "{name}: GG");
    let beef = sdk::transaction::Beef::from_binary(&built.beef).unwrap();
    // G reached twice: one input of each parent names it.
    let pushes: usize = [&built.p1, &built.p2]
        .iter()
        .flat_map(|p| beef.find_txid(p).and_then(BeefTx::tx).unwrap().inputs())
        .filter(|i| i.source_txid.as_deref() == Some(built.g.as_str()))
        .count();
    assert_eq!(pushes as u64, case["g_pushes"].as_u64().unwrap(), "{name}");
    (built, beef, case)
}

/// `parse_evidence`'s answer in the vector's form: the selected txid, or
/// `refused: Transaction evidence: <code>`, and the line.
fn judged(beef: &[u8]) -> (String, Option<&'static str>) {
    match parse_evidence(beef, 0) {
        Ok(tx) => (tx.id(), None),
        Err(r) => (
            format!("refused: Transaction evidence: {}", r.code.as_str()),
            Some(r.site),
        ),
    }
}

#[test]
fn a_grandparent_shared_by_two_unproven_paths_is_walked_once_748() {
    let name = "shared_unproven_grandparent";
    let (built, beef, case) = rebuilt(name);
    let g = beef.find_txid(&built.g).and_then(BeefTx::tx).unwrap();
    assert!(beef.find_bump(&built.g).is_none(), "{name}: G unproven");
    let gg = built.gg.as_deref().unwrap();
    assert!(beef.find_bump(gg).is_some(), "{name}: GG proven");
    assert_eq!(g.inputs().len(), 1, "{name}: G spends GG:0 alone");
    assert_eq!(case["outcome"], "read", "{name}: the reference reads it");
    let (selected, site) = judged(&built.beef);
    assert_eq!(selected, case["selected_txid"].as_str().unwrap(), "{name}");
    assert_eq!(site, case["site"].as_str(), "{name}: the line");
}

#[test]
fn a_proven_grandparent_reached_twice_is_summed_once_748() {
    let name = "proven_grandparent_reached_twice";
    let (built, beef, case) = rebuilt(name);
    assert!(beef.find_bump(&built.g).is_some(), "{name}: G proven");
    let graph: usize = beef
        .txs
        .iter()
        .map(|e| e.tx().unwrap().inputs().len())
        .sum();
    let g = beef.find_txid(&built.g).and_then(BeefTx::tx).unwrap();
    assert_eq!(graph, INPUTS, "{name}: the graph's inputs, G once");
    assert!(
        graph + g.inputs().len() > INPUTS,
        "{name}: G twice over the bound"
    );
    assert_eq!(case["outcome"], "read", "{name}: the reference reads it");
    let (selected, site) = judged(&built.beef);
    assert_eq!(selected, case["selected_txid"].as_str().unwrap(), "{name}");
    assert_eq!(site, case["site"].as_str(), "{name}: the line");
}
