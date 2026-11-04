#![cfg(test)]
//! #725: the two `ls_identity` parsers on the BEEFs of
//! `tests/vectors/identity_beef_subject_725.json` handed to them directly.
//! Every public door reaches them through `LookupResolver`'s dedup, which
//! drops an output whose BEEF `Transaction::from_beef` refuses, as the
//! reference's resolver does (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:2232-2237`), so the
//! atomic header naming an absent txid never reaches a parser there; here
//! the parsers' own rule is pinned: that shape skipped (until #721
//! `beef.txs.first()` read the token's transaction), the chain read from its
//! subject, and the txid-only parent read where the reference's
//! `assertUnconfirmedGraph` refuses it (`TransactionEvidence.ts:143`), #553's
//! stated evidence-layer residue (`tests/identity_beef_subject_725.rs`).

use super::*;

/// The shapes the reference skips and this crate's parsers read (#553's
/// evidence-layer residue: no unconfirmed-graph check here).
const READ_HERE: [&str; 2] = ["txid_only_parent", "txid_only_parent_atomic"];

#[tokio::test]
async fn the_parsers_read_each_725_beef_from_its_subject_save_the_stated_residue_725() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/identity_beef_subject_725.json"
    ))
    .unwrap();
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    let mut differ = Vec::new();
    for case in v["shapes"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let output = OutputListItem {
            beef: crate::primitives::from_hex(case["beef"].as_str().unwrap()).unwrap(),
            output_index: 0,
            context: None,
        };
        let reference = case["outcome"] == "read";
        let expected = reference != READ_HERE.contains(&name);
        let certificate = client.parse_output_to_certificate(&output).await.unwrap();
        let verifiable = client
            .parse_output_to_verifiable_certificate(&output)
            .await
            .unwrap();
        let got = (certificate.is_some(), verifiable.is_some());
        if got != (expected, expected) {
            differ.push(format!("{name}: {got:?}, expected {expected}"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}
