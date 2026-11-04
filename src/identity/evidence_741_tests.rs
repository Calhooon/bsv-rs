#![cfg(test)]
//! #741: the evidence check's inputs bound over two unproven branches. Each
//! BEEF of `tests/vectors/identity_evidence_741.json` rebuilt by this
//! crate's writer (`tests/support/identity_evidence_741.rs`) to the recorded
//! SHA-256 and judged by [`parse_evidence`] to the reference
//! `parseEvidence`'s code and line (`ts-stack@edf6e03`
//! `TransactionEvidence.ts`, recorded under Node v22.18.0 by
//! `tests/support/identity_evidence_741.mjs`), or to its selected txid: a
//! subject of 2 inputs, unproven parents P1 of 2047 inputs and P2 of 2048
//! (2047), one proven grandparent with none. The running sum over every
//! visited transaction (`assertUnconfirmedGraph`, `:155-177`) reaches 4097
//! (`limit` at `:170-171`) or 4096 (read); along either path alone it is at
//! most 2050, so a walk summing each branch alone reads both shapes, where
//! #736's single-chain pins stay green.

use super::*;
use crate as sdk;
use crate::primitives::{sha256, to_hex};

#[path = "../../tests/support/identity_evidence_741.rs"]
mod build;

/// The shape `name` rebuilt to the recorded bytes, and its case.
fn rebuilt(name: &str) -> (build::Built, serde_json::Value) {
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
        [&built.g, &built.p1, &built.p2].map(|t| t.as_str()),
        ["g", "p1", "p2"].map(|k| txids[k].as_str().unwrap()),
        "{name}: the three transactions under the subject"
    );
    (built, case)
}

/// The inputs along the path through `parent`: the subject's, the parent's
/// and the grandparent's.
fn path_inputs(beef: &sdk::transaction::Beef, built: &build::Built, parent: &str) -> usize {
    [built.subject.as_str(), parent, built.g.as_str()]
        .iter()
        .map(|t| beef.find_txid(t).and_then(BeefTx::tx).unwrap().inputs.len())
        .sum()
}

#[test]
fn the_inputs_bound_sums_over_two_unproven_branches_741() {
    let v = build::vector();
    let shapes = v["shapes"].as_array().unwrap();
    assert_eq!(shapes.len(), 2);
    for (name, total) in [
        ("two_branches_over_bound", INPUTS + 1),
        ("two_branches_at_bound", INPUTS),
    ] {
        let (built, case) = rebuilt(name);
        let beef = sdk::transaction::Beef::from_binary(&built.beef).unwrap();
        let graph: usize = beef.txs.iter().map(|e| e.tx().unwrap().inputs.len()).sum();
        assert_eq!(graph, total, "{name}: the graph's inputs");
        for parent in [built.p1.as_str(), built.p2.as_str()] {
            assert!(
                path_inputs(&beef, &built, parent) <= INPUTS / 2 + 2,
                "{name}: the path through {parent} alone within the bound"
            );
        }
        let (code, site, selected) = match parse_evidence(&built.beef, 0) {
            Ok(tx) => (None, None, tx.id()),
            Err(r) => (
                Some(r.code.as_str()),
                Some(r.site),
                format!("refused: Transaction evidence: {}", r.code.as_str()),
            ),
        };
        assert_eq!(code, case["code"].as_str(), "{name}: the code");
        assert_eq!(site, case["site"].as_str(), "{name}: the line");
        assert_eq!(selected, case["selected_txid"].as_str().unwrap(), "{name}");
    }
}
